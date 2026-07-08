#include "AgentService.h"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <unistd.h>
#include <sys/stat.h>

#include "Agent.h"
#include "Configuration.h"
#include "Logger.h"
#include "WebServer.h"

static void
Daemonize()
{
	pid_t processID = ::fork();
	if (processID < 0) {
		Logger::Log(LOG_ERR, "Failed to daemonize. Exiting...");
		// Return failure in exit status
		::exit(1);
	}

	// Exit the parent process
	if (processID > 0)
		::exit(0);

	::umask(0);
	if (::chdir("/") < 0)
		; // Ignore

	//set new session
	pid_t sid = ::setsid();
	if (sid < 0)
		::exit(1);

	::close(STDIN_FILENO);
	::close(STDOUT_FILENO);
	::close(STDERR_FILENO);
}


AgentService::AgentService()
	:
	fServer(nullptr),
	fAgent(nullptr),
	fRunning(false)
{
	fAgent = new Agent();
}


AgentService::~AgentService()
{
	if (fInventoryThread.joinable())
		fInventoryThread.join();

	if (fServer != nullptr) {
		fServer->Stop();
		delete fServer;
	}
	delete fAgent;
}


void
AgentService::Run()
{
	Daemonize();

	fServer = new WebServer(*this);

	fRunning = true;

	fInventoryThread =
		std::thread(&AgentService::_InventoryLoop, this);

	// TODO: add configuration
#if 1
	// Start the web server
	fServer->Start(62354, "");

	while (fRunning)
		sleep(60);

#endif
}


void
AgentService::RunOneShot()
{
	Configuration* config = Configuration::Get();
	bool noSoftware = (config->KeyValue(CONF_NO_SOFTWARE) == CONF_VALUE_TRUE);
	fAgent->RunInventory(noSoftware);
	if (config->KeyValue(CONF_OUTPUT_STDOUT) == CONF_VALUE_TRUE)
		fAgent->PrintToStream();
	else if (config->LocalInventory()) {
		std::string fullFileName = config->OutputFileName();
		if (fullFileName[fullFileName.length() - 1] == '/')
			fullFileName.append(config->DeviceID()).append(".xml");
		fAgent->SaveToFile(fullFileName);
	} else {
		fAgent->SendToServer(config->ServerURL());
	}
}


void
AgentService::ScheduleInventory()
{
	Logger::Log(LOG_INFO, "AgentService: Inventory scheduled");
	{
		std::lock_guard lock(fMutex);
		fInventoryRequested = true;
	}

	fCondition.notify_one();
}


void
AgentService::_InventoryLoop()
{
	while (fRunning) {
		std::unique_lock lock(fMutex);

		fCondition.wait(lock,
			[this]
			{
				return fInventoryRequested || !fRunning;
			});

		if (!fRunning)
			break;

		fInventoryRequested = false;

		lock.unlock();

		try {
			fAgent->RunInventory(true);
			fAgent->SendToServer(Configuration::Get()->ServerURL());
		} catch (std::exception& ex) {
			Logger::Log(LOG_ERR, ex.what());
		}
	}
}

#include "AgentService.h"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <unistd.h>

#include "Agent.h"
#include "Configuration.h"
#include "Logger.h"
#include "WebServer.h"

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
	fServer->Stop();
	delete fServer;
	delete fAgent;
}


void
AgentService::Run()
{
	fServer = new WebServer();

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
AgentService::ScheduleInventory()
{
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

#include "AgentService.h"

#include <chrono>
#include <condition_variable>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

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
	fInventoryRequested(false),
	fInventoryRunning(false),
	fRunning(false)
{
	// Schedule the first inventory in one minute from now so it runs when the system is completely up
	// (X takes some time on our old machines)

	// TODO: make it configurable
	fNextScheduledInventory = std::chrono::steady_clock::now() + std::chrono::minutes(1);

	fAgent = new Agent();
}


AgentService::~AgentService()
{
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
	fSchedulerThread =
		std::thread(&AgentService::_SchedulingLoop, this);

#if 1
	// TODO: add configuration
	// Start the web server
	fServer->Start(62354, "");

	while (fRunning)
		sleep(1);

	if (fInventoryThread.joinable())
		fInventoryThread.join();

	if (fSchedulerThread.joinable())
		fSchedulerThread.join();

	fServer->Stop();

	delete fServer;
	fServer = nullptr;
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
AgentService::Stop()
{
	{
		std::lock_guard lock(fMutex);
		fRunning = false;
	}

	fCondition.notify_all();
}


AgentStatus
AgentService::Status() const
{
	if (fInventoryRunning)
		return AgentStatus::InventoryRunning;

	return AgentStatus::Waiting;
}


std::string
AgentService::StatusString() const
{
	std::string statusString;
	switch (Status()) {
		case AgentStatus::Waiting:
			statusString = "waiting";
			break;
		case AgentStatus::InventoryRunning:
			statusString = "running";
			break;
		default:
			statusString = "waiting";
			break;
	}

	return statusString;
}


std::string
AgentService::LastInventoryTime() const
{
	std::time_t timePoint = std::chrono::system_clock::to_time_t(fLastInventoryEnd);
	std::ostringstream s;
	s << std::put_time(std::localtime(&timePoint), "%Y-%m-%d %X");
	return s.str();
}


std::string
AgentService::LastInventoryRequestedTime() const
{
	std::time_t timePoint = std::chrono::system_clock::to_time_t(fLastInventoryRequest);
	std::ostringstream s;
	s << std::put_time(std::localtime(&timePoint), "%Y-%m-%d %X");
	return s.str();
}


AgentStatus
AgentService::ScheduleInventory()
{
	std::lock_guard lock(fMutex);

	auto now = std::chrono::system_clock::now();
	if (now - fLastInventoryRequest < std::chrono::minutes(1)) {
		Logger::Log(LOG_INFO, "AgentService: inventory request ignored (rate limited)");
		return AgentStatus::RateLimited;
	}

	fLastInventoryRequest = now;

	if (!fInventoryRequested && !fInventoryRunning) {
		fInventoryRequested = true;

		Logger::Log(LOG_INFO, "AgentService: inventory scheduled");

		fCondition.notify_one();
	}

	return AgentStatus::InventoryScheduled;
}


bool
AgentService::InventoryRequested() const
{
	return fInventoryRequested;
}


bool
AgentService::InventoryRunning() const
{
	return fInventoryRunning;
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
			fInventoryRunning = true;
			fLastInventoryStart = std::chrono::system_clock::now();
			bool noSoftware = (Configuration::Get()->KeyValue(CONF_NO_SOFTWARE) == CONF_VALUE_TRUE);
			fAgent->RunInventory(noSoftware);
			// TODO: What if we don't have a server url ?
			fAgent->SendToServer(Configuration::Get()->ServerURL());
			fLastInventoryEnd = std::chrono::system_clock::now();
		} catch (std::exception& ex) {
			Logger::Log(LOG_ERR, ex.what());

		}
		fInventoryRunning = false;
	}
}


void
AgentService::_SchedulingLoop()
{
	Logger::Log(LOG_DEBUG, "AgentService: _SchedulingLoop started");

	while (fRunning) {
		// Check if it's time to run scheduled inventory
		if (_ShouldRunScheduledInventory()) {
			Logger::Log(LOG_DEBUG, "AgentService: scheduled inventory trigger");
			ScheduleInventory();
			fLastScheduledInventoryRun = std::chrono::steady_clock::now();
		}

		std::this_thread::sleep_for(std::chrono::seconds(2));
	}

	Logger::Log(LOG_DEBUG, "AgentService: _SchedulingLoop exiting");
}


bool
AgentService::_ShouldRunScheduledInventory()
{
	bool shouldRun  = false;
	auto now = std::chrono::steady_clock::now();
	if (now >= fNextScheduledInventory && fLastScheduledInventoryRun < fNextScheduledInventory) {
		shouldRun = true;
	}

	Configuration* config = Configuration::Get();
	// Check interval-based scheduling (e.g., every 3600 seconds)
	std::string intervalStr = config->KeyValue("schedule_interval");
	if (!intervalStr.empty()) {
		try {
			int intervalSeconds = std::stoi(intervalStr);
			if (intervalSeconds > 0) {
				if (shouldRun) {
					fNextScheduledInventory = now +
						std::chrono::seconds(intervalSeconds);
				}
			}
		} catch (...) {
			Logger::Log(LOG_ERR, "AgentService: invalid schedule-interval value");
		}
	}

	return shouldRun;
}

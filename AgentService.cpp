#include "AgentService.h"

#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

#include "Agent.h"
#include "Configuration.h"
#include "Logger.h"
#ifndef NO_WEBSERVER
#include "WebServer.h"
#endif

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
	if (::chdir("/") < 0) {
		; // Ignore
	}

	//set new session
	pid_t sid = ::setsid();
	if (sid < 0)
		::exit(1);

	// Redirect the standard descriptors to /dev/null instead of just
	// closing them: otherwise the next opened sockets would get fds 0-2,
	// and any stray write to stdout/stderr would end up on the network
	int nullFD = ::open("/dev/null", O_RDWR);
	if (nullFD < 0) {
		::close(STDIN_FILENO);
		::close(STDOUT_FILENO);
		::close(STDERR_FILENO);
		return;
	}

	::dup2(nullFD, STDIN_FILENO);
	::dup2(nullFD, STDOUT_FILENO);
	::dup2(nullFD, STDERR_FILENO);
	if (nullFD > STDERR_FILENO)
		::close(nullFD);
}


AgentService::AgentService()
	:
	fServer(nullptr),
	fAgent(nullptr),
	fInventoryRequested(false),
	fInventoryRunning(false),
	fRunning(false)
{
	fAgent = new Agent();
}


AgentService::~AgentService()
{
	_StopWebServer();
	delete fAgent;
}


void
AgentService::Run()
{
	Daemonize();

	fRunning = true;

	// Schedule the first inventory in one minute from now so it runs when the system is completely up
	// (X takes some time on our old machines)
	// TODO: make it configurable
	// Must be set before starting the scheduler thread, which owns it afterwards
	fNextScheduledInventory = std::chrono::steady_clock::now() + std::chrono::minutes(1);

	fInventoryThread =
		std::thread(&AgentService::_InventoryLoop, this);
	fSchedulerThread =
		std::thread(&AgentService::_SchedulingLoop, this);

	_StartWebServer();

	while (fRunning)
		sleep(1);

	// Wake up the inventory thread, in case the stop was
	// requested from a signal handler
	Stop();

	if (fInventoryThread.joinable())
		fInventoryThread.join();

	if (fSchedulerThread.joinable())
		fSchedulerThread.join();

	_StopWebServer();
}


bool
AgentService::RunOneShot()
{
	const Configuration* config = Configuration::Get();

	// -w/--wait: wait before building the inventory. Can be
	// interrupted by SIGINT/SIGTERM, which clear fRunning.
	fRunning = true;
	for (int seconds = _WaitTime(); seconds > 0 && fRunning; seconds--)
		::sleep(1);
	if (!fRunning)
		return false;

	bool noSoftware = (config->KeyValue(CONF_NO_SOFTWARE) == CONF_VALUE_TRUE);
	fAgent->RunInventory(noSoftware);
	if (config->KeyValue(CONF_OUTPUT_STDOUT) == CONF_VALUE_TRUE) {
		fAgent->PrintToStream();
		return true;
	}

	if (config->LocalInventory()) {
		std::string fullFileName = config->OutputFileName();
		if (fullFileName[fullFileName.length() - 1] == '/')
			fullFileName.append(config->DeviceID()).append(".xml");
		return fAgent->SaveToFile(fullFileName);
	}

	return fAgent->SendToServer(config->ServerURL());
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


void
AgentService::RequestStop()
{
	static_assert(std::atomic_bool::is_always_lock_free,
		"std::atomic_bool must be lock free to be used in a signal handler");
	fRunning = false;
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


static std::string
FormatTime(const std::chrono::system_clock::time_point& time)
{
	if (time == std::chrono::system_clock::time_point{})
		return "<never>";

	const std::time_t timePoint = std::chrono::system_clock::to_time_t(time);
	struct tm timeInfo;
	std::ostringstream s;
	s << std::put_time(::localtime_r(&timePoint, &timeInfo), "%Y-%m-%d %X");
	return s.str();
}


std::string
AgentService::LastInventoryTime() const
{
	std::chrono::system_clock::time_point lastInventoryEnd;
	{
		std::lock_guard lock(fMutex);
		lastInventoryEnd = fLastInventoryEnd;
	}
	return FormatTime(lastInventoryEnd);
}


std::string
AgentService::LastInventoryRequestedTime() const
{
	std::chrono::system_clock::time_point lastInventoryRequest;
	{
		std::lock_guard lock(fMutex);
		lastInventoryRequest = fLastInventoryRequest;
	}
	return FormatTime(lastInventoryRequest);
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
		fLastInventoryStart = std::chrono::system_clock::now();

		lock.unlock();

		try {
			fInventoryRunning = true;
			bool noSoftware = (Configuration::Get()->KeyValue(CONF_NO_SOFTWARE) == CONF_VALUE_TRUE);
			fAgent->RunInventory(noSoftware);
			// TODO: What if we don't have a server url ?
			// Only successful inventories are reported as "last inventory"
			if (fAgent->SendToServer(Configuration::Get()->ServerURL())) {
				std::lock_guard endLock(fMutex);
				fLastInventoryEnd = std::chrono::system_clock::now();
			}
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
		}

		std::this_thread::sleep_for(std::chrono::seconds(2));
	}

	Logger::Log(LOG_DEBUG, "AgentService: _SchedulingLoop exiting");
}


bool
AgentService::_ShouldRunScheduledInventory()
{
	auto now = std::chrono::steady_clock::now();
	if (now < fNextScheduledInventory)
		return false;

	fNextScheduledInventory = now + _ScheduleInterval();
	return true;
}


/* static */
int
AgentService::_WaitTime()
{
	std::string waitString = Configuration::Get()->KeyValue(CONF_WAIT_TIME);
	if (waitString.empty())
		return 0;

	try {
		size_t end = 0;
		int seconds = std::stoi(waitString, &end);
		if (end == waitString.length() && seconds >= 0)
			return seconds;
	} catch (...) {
	}

	Logger::LogFormat(LOG_ERR, "AgentService: invalid wait time '%s', ignored", waitString.c_str());
	return 0;
}


void
AgentService::_StartWebServer()
{
#ifdef NO_WEBSERVER
	Logger::Log(LOG_INFO, "AgentService: built without web server");
#else
	int port = _WebServerPort();
	if (port == 0) {
		Logger::Log(LOG_INFO, "AgentService: web server disabled");
		return;
	}

	fServer = new WebServer(*this);
	if (!fServer->Start(port, ""))
		Logger::LogFormat(LOG_ERR, "AgentService: cannot start the web server on port %d", port);
#endif
}


void
AgentService::_StopWebServer()
{
#ifndef NO_WEBSERVER
	if (fServer != nullptr) {
		fServer->Stop();
		delete fServer;
		fServer = nullptr;
	}
#endif
}


/* static */
int
AgentService::_WebServerPort()
{
	const int kDefaultPort = 62354;

	// httpd-port=0 disables the web server
	std::string portString = Configuration::Get()->KeyValue("httpd-port");
	if (portString.empty())
		return kDefaultPort;

	try {
		size_t end = 0;
		int port = std::stoi(portString, &end);
		if (end == portString.length() && port >= 0 && port <= 65535)
			return port;
	} catch (...) {
	}

	Logger::LogFormat(LOG_ERR, "AgentService: invalid httpd-port value '%s', using %d",
		portString.c_str(), kDefaultPort);
	return kDefaultPort;
}


/* static */
std::chrono::seconds
AgentService::_ScheduleInterval()
{
	// Same as the default PROLOG_FREQ of OCS Inventory NG
	const std::chrono::seconds kDefaultInterval = std::chrono::hours(24);

	// Interval between two scheduled inventories, in seconds (e.g. 3600).
	// Note that ScheduleInventory() doesn't accept more than one
	// request per minute, so shorter intervals are not effective.
	std::string intervalString = Configuration::Get()->KeyValue("schedule_interval");
	if (intervalString.empty())
		return kDefaultInterval;

	try {
		int intervalSeconds = std::stoi(intervalString);
		if (intervalSeconds > 0)
			return std::chrono::seconds(intervalSeconds);
	} catch (...) {
	}

	Logger::LogFormat(LOG_ERR, "AgentService: invalid schedule_interval value '%s', using %ld seconds",
		intervalString.c_str(), static_cast<long>(kDefaultInterval.count()));
	return kDefaultInterval;
}

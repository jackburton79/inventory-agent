#include "AgentService.h"

#include <chrono>
#include <mutex>
#include <unistd.h>

#include "Agent.h"
#include "Logger.h"
#include "WebServer.h"

AgentService::AgentService()
	:
	fRunning(false)
{
}


void
AgentService::Run()
{
	fRunning = true;

	fInventoryThread =
		std::thread(&AgentService::_InventoryLoop, this);

	// TODO: add configuration
#if 1
	// Start the web server
	WebServer server;
	server.Start(62354, "");

	while (fRunning)
		sleep(60);
#endif
}


void
AgentService::_InventoryLoop()
{
	while (fRunning) {
		try {
			Agent agent;
			agent.RunInventory(true);

			std::string xml = agent.LastInventoryXML();

			Logger::Log(LOG_INFO, "Inventory cache updated");
		} catch (std::exception& ex) {
			Logger::Log(LOG_ERR, ex.what());
		}

		std::this_thread::sleep_for(std::chrono::hours(1));
	}
}

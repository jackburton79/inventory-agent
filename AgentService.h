#include <condition_variable>
#include <mutex>
#include <thread>

#pragma once

class Agent;
class WebServer;
class AgentService {
public:
	AgentService();
	~AgentService();

	void Run();
	void ScheduleInventory();

private:
	void _InventoryLoop();

private:
	std::thread fInventoryThread;

	std::condition_variable fCondition;
	std::mutex fMutex;

	bool fInventoryRequested;

	WebServer* fServer;
	Agent* fAgent;

	bool fRunning;
};

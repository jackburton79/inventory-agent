#include <atomic>
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
	void RunOneShot();
	void ScheduleInventory();

	bool InventoryRequested() const;
	bool InventoryRunning() const;
private:

	void _InventoryLoop();

	std::thread fInventoryThread;

	std::condition_variable fCondition;
	std::mutex fMutex;

	WebServer* fServer;
	Agent* fAgent;

	std::atomic_bool fInventoryRequested;
	std::atomic_bool fInventoryRunning;
	std::atomic_bool fRunning;
};

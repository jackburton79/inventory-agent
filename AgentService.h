#include <atomic>
#include <condition_variable>
#include <chrono>
#include <mutex>
#include <thread>

#pragma once


enum class AgentStatus {
	Waiting,
	InventoryRunning,
	InventoryScheduled,
	RateLimited
};


class Agent;
class WebServer;
class AgentService {
public:
	AgentService();
	~AgentService();

	void Run();
	void RunOneShot();

	AgentStatus Status() const;

	bool InventoryRequested() const;
	bool InventoryRunning() const;

	AgentStatus ScheduleInventory();

private:

	void _InventoryLoop();

	std::thread fInventoryThread;
	std::condition_variable fCondition;
	std::mutex fMutex;

	WebServer* fServer;
	Agent* fAgent;

	std::chrono::steady_clock::time_point fLastInventoryRequest;
	std::atomic_bool fInventoryRequested;
	std::atomic_bool fInventoryRunning;
	std::atomic_bool fRunning;
};

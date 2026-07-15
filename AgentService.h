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

	void Stop();

	AgentStatus Status() const;
	std::string StatusString() const;

	std::string LastInventoryTime() const;
	std::string LastInventoryRequestedTime() const;

	bool InventoryRequested() const;
	bool InventoryRunning() const;

	AgentStatus ScheduleInventory();

	// disabled
	AgentService(const AgentService&) = delete;
	AgentService& operator=(const AgentService& other) = delete;

private:
	void _InventoryLoop();
	void _SchedulingLoop();
	bool _ShouldRunScheduledInventory();

	WebServer* fServer;
	Agent* fAgent;

	std::thread fInventoryThread;
	std::thread fSchedulerThread;
	std::condition_variable fCondition;
	std::mutex fMutex;

	std::chrono::system_clock::time_point fLastInventoryRequest;
	std::chrono::system_clock::time_point fLastInventoryStart;
	std::chrono::system_clock::time_point fLastInventoryEnd;
	std::chrono::steady_clock::time_point fNextScheduledInventory;
	std::chrono::steady_clock::time_point fLastScheduledInventoryRun;

	std::atomic_bool fInventoryRequested;
	std::atomic_bool fInventoryRunning;
	std::atomic_bool fRunning;
};

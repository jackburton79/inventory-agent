#include <thread>

#pragma once

class AgentService {
public:
	AgentService();

	void Run();

private:
	void _InventoryLoop();

private:
	std::thread fInventoryThread;

	bool fRunning;
};

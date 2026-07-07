#include <thread>

#pragma once

class Agent;
class AgentService {
public:
	AgentService();
	~AgentService();

	void Run();

private:
	void _InventoryLoop();

private:
	std::thread fInventoryThread;

	Agent* fAgent;

	bool fRunning;
};

/*
 * Agent.cpp
 *
 *  Created on: 11/lug/2013
 *      Author: Stefano Ceccherini
 */


#include "Agent.h"
#include "Components.h"
#include "Configuration.h"
#include "Inventory.h"
#include "Logger.h"
#include "backends/CPUInfoBackend.h"
#include "backends/DMIDataBackend.h"
#include "backends/DMIDecodeBackend.h"
#include "backends/LSHWBackend.h"
#include "backends/MemInfoBackend.h"
#include "backends/OSInfoBackend.h"
#include "backends/UnameBackend.h"

#include "WebServer.h"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <unistd.h>


const char* kVersion = "3.1.0";

std::string Agent::sAgentString;


Agent::Agent()
	:
	fInventory(nullptr)
{
	fInventory = new Inventory();
}


Agent::~Agent()
{
	delete fInventory;
}


void
Agent::RunInventory(bool noSoftware)
{
	Logger::Log(LOG_INFO, "Agent::RunInventory()");

	// TODO: Move these away from here
	DMIDataBackend().Run();
	DMIDecodeBackend().Run();
	CPUInfoBackend().Run();
	OSInfoBackend().Run();
	LSHWBackend().Run();
	MemInfoBackend().Run();
	UnameBackend().Run();

	if (!fInventory->Initialize())
		throw std::runtime_error("Cannot initialize Inventory");

	if (!fInventory->Build(noSoftware))
		return;

	Logger::Log(LOG_INFO, "Agent::RunInventory(): inventory built correctly");
}


std::string
Agent::LastInventoryXML() const
{
	return fInventory->ToString();
}


void
Agent::PrintToStream()
{
	fInventory->Print();
}


void
Agent::SaveToFile(const std::string& filePathName)
{
	fInventory->Save(filePathName.c_str());
}


bool
Agent::SendToServer(const std::string& serverString)
{
	try {
		return fInventory->Send(serverString.c_str());
	} catch (...) {
		Logger::Log(LOG_ERR, "Agent: cannot send inventory!");
	}
	return false;
}


/* static */
std::string
Agent::Version()
{
	return kVersion;
}


/* static */
std::string
Agent::LegacyAgentString()
{
	return "OCS-NG_unified_unix_agent_v";
}


/* static */
std::string
Agent::AgentString()
{
	if (sAgentString.empty()) {
		std::string agentString = Configuration::Get()->KeyValue(CONF_AGENT_STRING);
		if (!agentString.empty())
			sAgentString = agentString;
		else {
			sAgentString = "jack_lite_inventory_agent_v";
			sAgentString.append(Version());
		}
	}
	return sAgentString;
}

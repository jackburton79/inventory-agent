/*
 * Agent.cpp
 *
 *  Created on: 11/lug/2013
 *      Author: Stefano Ceccherini
 */


#include <Components.h>
#include "Agent.h"
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

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <unistd.h>


const char* kVersion = "2.1.1";

std::string Agent::sAgentString;


Agent::Agent()
{
}


Agent::~Agent()
{
}


void
Agent::Run()
{
	// TODO: Move these away from here
	DMIDataBackend().Run();
	DMIDecodeBackend().Run();
	CPUInfoBackend().Run();
	OSInfoBackend().Run();
	LSHWBackend().Run();
	MemInfoBackend().Run();
	UnameBackend().Run();

	Configuration* config = Configuration::Get();

	Inventory inventory;
	if (!inventory.Initialize())
		throw std::runtime_error("Cannot initialize Inventory");

	bool noSoftware = (config->KeyValue(CONF_NO_SOFTWARE) == CONF_VALUE_TRUE);
	unsigned long waitSeconds = ::strtoul(
		config->KeyValue(CONF_WAIT_TIME).c_str(), NULL, 10);

	if (waitSeconds > 0) {
		Logger::LogFormat(LOG_INFO, "Waiting %lu seconds...", waitSeconds);
		::sleep(waitSeconds);
	}

	if (!inventory.Build(noSoftware))
		return;

	if (config->KeyValue(CONF_OUTPUT_STDOUT) == CONF_VALUE_TRUE)
		inventory.Print();
	else if (config->LocalInventory()) {
		std::string fullFileName = config->OutputFileName();
		if (fullFileName[fullFileName.length() - 1] == '/')
			fullFileName.append(config->DeviceID()).append(".xml");
		inventory.Save(fullFileName.c_str());
	} else {
		inventory.Send(config->ServerURL().c_str());
	}
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

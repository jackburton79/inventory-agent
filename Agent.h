/*
 * Agent.h
 *
 *  Created on: 11/lug/2013
 *      Author: Stefano Ceccherini
 */

#ifndef AGENT_H_
#define AGENT_H_

#include <string>

class Inventory;

class Agent {
public:
	Agent();
	~Agent();

	void RunInventory(bool noSoftware);
	std::string LastInventoryXML() const;
	time_t LastUpdated() const;

	void PrintToStream();
	void SaveToFile(const std::string& filePathName);
	bool SendToServer(const std::string& serverString);

	static std::string Version();
	static std::string LegacyAgentString();
	static std::string AgentString();

private:
	void _RetrieveInventory();
	void _PrintInventory();
	void _SendInventory();

	Inventory* fInventory;
	time_t fLastUpdate;
	static std::string sAgentString;
};

#endif /* AGENT_H_ */

/*
 * InventoryFormatOCS.h
 *
 *  Created on: 31/aug/2022
 *      Author: Stefano Ceccherini
 */

#pragma once

#include <string>

namespace tinyxml2 {
	class XMLDocument;
	class XMLElement;
}

class HTTP;
class Machine;
class Inventory {
public:
	Inventory();
	~Inventory();

	bool Initialize();
	void Clear();

	std::string GenerateDeviceID() const;

	bool Build(bool noSoftware = false);
	bool Save(const char* fileName);
	bool Send(const char* serverUrl);

	std::string ToString();
	void Print();

private:
	int Checksum() const;

	void _AddAccountInfo();
	void _AddBIOSInfo();
	void _AddOperatingSystemInfo();
	void _AddCPUsInfo();
	void _AddStoragesInfo();
	void _AddMemoriesInfo();
	void _AddDrivesInfo();
	void _AddHardwareInfo();
	void _AddNetworksInfo();
	void _AddProcessesInfo();
	void _AddSoftwaresInfo();
	void _AddUsersInfo();
	void _AddVideosInfo();
	void _AddMonitorsInfo();

	bool _WriteProlog(tinyxml2::XMLDocument& document) const;
	bool _HandleResponse(HTTP& http);

	tinyxml2::XMLDocument* fDocument;
	tinyxml2::XMLElement* fContent;
};


/*
 * DMIDecode.cpp
 *
 *  Created on: 6 mar 2021
 *      Author: stefano
 */

#include "DMIDecodeBackend.h"

#include "Components.h"
#include "Logger.h"
#include "Support.h"

const char* kBIOSInfo = "BIOS Information";
const char* kSystemInfo = "System Information";
const char* kProcessorInfo = "Processor Information";
const char* kMemoryDevice = "Memory Device";

DMIDecodeBackend::DMIDecodeBackend()
{
}


DMIDecodeBackend::~DMIDecodeBackend()
{
}


/* virtual */
bool
DMIDecodeBackend::IsAvailable() const
{
	if (!CommandExists("dmidecode"))
		return false;
	return true;
}


/* virtual */
int
DMIDecodeBackend::Run()
{
	if (!IsAvailable())
		return -1;

	try {
		CommandStreamBuffer dmi("dmidecode", "r");
		std::istream iStream(&dmi);
		std::string string;
		dmi_db dmiDatabase;

		int numericHandle = 0;
		bool insideHandle = false;
		while (std::getline(iStream, string)) {
			if (string.find("Handle") == 0) {
				size_t numStart = string.find_first_of(" 0");
				size_t numEnd = string.find_first_of(",", numStart);
				std::string handle = string.substr(numStart + 1, numEnd - numStart - 1);

				numericHandle = ::strtol(handle.c_str(), NULL, 16);

				std::string name;
				std::getline(iStream, name);

				string_map dbEntry;
				dbEntry["DMIHANDLE"] = trimmed(handle);
				dbEntry["NAME"] = trimmed(name);

				dmiDatabase[numericHandle] = dbEntry;
				insideHandle = true;

			} else if (insideHandle) {
				if (string.empty() || string == "") {
					insideHandle = false;
					continue;
				}

				size_t pos = string.find(":");
				if (pos == std::string::npos)
					continue;
				try {
					std::string name = trimmed(string.substr(0, pos));
					std::string value = trimmed(string.substr(pos + 2, std::string::npos));
					dmiDatabase[numericHandle][name] = value;
				} catch (...) {
				}
			}
		}

		_ExtractDataFromDMIDB(dmiDatabase);
	} catch (...) {
		return -1;
	}

	return 0;
}


// DMIExtractor
DMIExtractor::DMIExtractor(const dmi_db& db)
	:
	fDMIDB(db)
{
}


int
DMIExtractor::CountEntries(const std::string& context) const
{
	dmi_db::const_iterator dbIterator;
	int count = 0;
	for (dbIterator = fDMIDB.begin(); dbIterator != fDMIDB.end(); dbIterator++) {
		string_map entry = (*dbIterator).second;
		string_map::const_iterator i = entry.find("NAME");
		if (i != entry.end() && i->second == context) {
			count++;
		}
	}

	return count;
}


std::vector<string_map>
DMIExtractor::ExtractEntry(const std::string& context) const
{
	dmi_db::const_iterator dbIterator;
	string_map entry;
	std::vector<string_map> entries;
	for (dbIterator = fDMIDB.begin(); dbIterator != fDMIDB.end(); dbIterator++) {
		entry = dbIterator->second;
		string_map::const_iterator i = entry.find("NAME");
		if (i != entry.end() && i->second == context)
			entries.push_back(entry);
	}

	return entries;
}


string_map
DMIExtractor::ExtractHandle(const std::string& handle) const
{
	int numericHandle = strtol(handle.c_str(), NULL, 0);
	dmi_db::const_iterator i = fDMIDB.find(numericHandle);
	if (i == fDMIDB.end())
		throw std::runtime_error("DMIExtractor::ExtractHandle: cannot find requested handle");
	return i->second;
}


static std::string
GetValueFromMap(dmi_db &db, std::string key, std::string context)
{
	DMIExtractor extractor(db);
	if (extractor.CountEntries(context) <= 0)
		return "";

	std::vector<string_map> entryVector
		= extractor.ExtractEntry(context);

	string_map &map = entryVector[0];
	string_map::const_iterator i;
	i = map.find(key);
	if (i != map.end())
		return i->second;

	return "";
}


void
DMIDecodeBackend::_ExtractDataFromDMIDB(dmi_db dmiDb)
{
	Component biosInfo;
	biosInfo.fields["release_date"] = GetValueFromMap(dmiDb, "Release Date", kBIOSInfo);
	biosInfo.fields["vendor"] = GetValueFromMap(dmiDb, "Vendor", kBIOSInfo);
	biosInfo.fields["version"] = GetValueFromMap(dmiDb, "Version", kBIOSInfo);
	gComponents.Merge("BIOS", biosInfo);

	Component systemInfo;
	systemInfo.fields["name"] = GetValueFromMap(dmiDb, "Product Name", kSystemInfo);
	systemInfo.fields["version"] = GetValueFromMap(dmiDb, "Version", kSystemInfo);
	systemInfo.fields["uuid"] = GetValueFromMap(dmiDb, "UUID", kSystemInfo);
	systemInfo.fields["serial"] = GetValueFromMap(dmiDb, "Serial Number", kSystemInfo);
	systemInfo.fields["vendor"] = GetValueFromMap(dmiDb, "Manufacturer", kSystemInfo);
	gComponents.Merge("SYSTEM", systemInfo);

	Component chassisInfo;
	chassisInfo.fields["asset_tag"] = GetValueFromMap(dmiDb, "Asset Tag", "Chassis Information");
	chassisInfo.fields["serial"] = GetValueFromMap(dmiDb, "Serial Number", "Chassis Information");
	chassisInfo.fields["type"] = GetValueFromMap(dmiDb, "Type", "Chassis Information");
	chassisInfo.fields["vendor"] = GetValueFromMap(dmiDb, "Manufacturer", "Chassis Information");
	chassisInfo.fields["version"] = GetValueFromMap(dmiDb, "Version",  "Chassis Information");
	gComponents.Merge("CHASSIS", chassisInfo);

	Component boardInfo;
	boardInfo.fields["asset_tag"] = GetValueFromMap(dmiDb, "Asset Tag", "Base Board Information");
	boardInfo.fields["name"] = GetValueFromMap(dmiDb, "Product Name", "Base Board Information");
	boardInfo.fields["vendor"] = GetValueFromMap(dmiDb, "Manufacturer", "Base Board Information");
	boardInfo.fields["version"] = GetValueFromMap(dmiDb, "Version", "Base Board Information");
	boardInfo.fields["serial"] = GetValueFromMap(dmiDb, "Serial Number", "Base Board Information");
	gComponents.Merge("BOARD", boardInfo);

	// TODO: multiple cpus
	Component cpuInfo;
	cpuInfo.fields["vendor"] = GetValueFromMap(dmiDb, "Manufacturer", kProcessorInfo);

	std::string CPUSpeedString = GetValueFromMap(dmiDb, "Max Speed", kProcessorInfo);
	unsigned int CPUSpeedNumber = ::strtoul(CPUSpeedString.c_str(), NULL, 0);
	if (CPUSpeedNumber > 0)
		cpuInfo.fields["speed"] = uint_to_string(CPUSpeedNumber);
	cpuInfo.fields["type"] = GetValueFromMap(dmiDb, "Version", kProcessorInfo);
	cpuInfo.fields["serial"] = GetValueFromMap(dmiDb, "Serial Number", kProcessorInfo);
	cpuInfo.fields["cores"] = GetValueFromMap(dmiDb, "Core Count", kProcessorInfo);
	cpuInfo.fields["logical_cpus"] = GetValueFromMap(dmiDb, "Thread Count", kProcessorInfo);
	cpuInfo.fields["voltage"] = GetValueFromMap(dmiDb, "Voltage", kProcessorInfo);
	gComponents.Merge("CPU", cpuInfo);

	std::vector<string_map> valuesVector;
	DMIExtractor dmiExtractor(dmiDb);
	std::vector<string_map>::iterator i;
	/*
	// Graphics cards
	if (fVideoInfo.size() == 0) {
		valuesVector = dmiExtractor.ExtractEntry("Display");
		for (i = valuesVector.begin(); i != valuesVector.end(); i++) {
			string_map& entry = *i;
			video_info info;
			try {
				string_map::const_iterator mapIter;
				mapIter = entry.find("Manufacturer");
				if (mapIter != entry.end())
					info.vendor = mapIter->second;
				mapIter = entry.find("Product Name");
				if (mapIter != entry.end())
					info.name = mapIter->second;
				mapIter = entry.find("description");
				if (mapIter != entry.end())
					info.chipset = mapIter->second;
				fVideoInfo.push_back(info);
			} catch (...) {
			}
		}
	}
*/
	// Memory slots
	int slotNum = 0;
	std::ostringstream s;
	s << "MEMORY" << slotNum;
	components_map::iterator ramSlotIterator = gComponents.find(s.str());
	// already some slot info, bail out
	if (ramSlotIterator != gComponents.end()) {
		// just log. dmidecode's output is usually better than other backends's
		Logger::LogFormat(LOG_INFO, "DMIDecodeBackend: will overwrite memory info");
	}

	valuesVector = dmiExtractor.ExtractEntry(kMemoryDevice);
	for (i = valuesVector.begin(); i != valuesVector.end(); i++) {
		Component ramSlot;
		string_map& entry = *i;
		try {
			string_map::const_iterator mapIter;
			mapIter = entry.find("Type");
			if (mapIter != entry.end())
				ramSlot.fields["type"] = mapIter->second;

			mapIter = entry.find("Size");
			if (mapIter != entry.end()) {
				ramSlot.fields["size"] = int_to_string(convert_to_MBytes(mapIter->second));
			} else
				ramSlot.fields["size"] = "0";

			// if size == 0, it's an empty slot
			if (ramSlot.fields["size"] == "0")
				ramSlot.fields["type"] = "Empty Slot";

			mapIter = entry.find("Locator");
			if (mapIter != entry.end())
				ramSlot.fields["description"] = mapIter->second;


			mapIter = entry.find("Speed");
			if (mapIter != entry.end()) {
				unsigned long ramSpeed = ::strtoul(mapIter->second.c_str(), NULL, 10);
				ramSlot.fields["speed"] = int_to_string(ramSpeed);
			}

			mapIter = entry.find("Manufacturer");
			if (mapIter != entry.end())
				ramSlot.fields["vendor"] = mapIter->second;
			mapIter = entry.find("Asset Tag");
			if (mapIter != entry.end())
				ramSlot.fields["asset_tag"] = mapIter->second;
			mapIter = entry.find("Serial Number");
			if (mapIter != entry.end())
				ramSlot.fields["serial"] = mapIter->second;

			mapIter = entry.find("Array Handle");
			if (mapIter != entry.end()) {
				std::string parentHandle = mapIter->second;
				string_map arrayHandle = dmiExtractor.ExtractHandle(parentHandle);
				mapIter = arrayHandle.find("Use");
				if (mapIter != arrayHandle.end())
					ramSlot.fields["purpose"] = mapIter->second;
				mapIter = arrayHandle.find("Use");
				if (mapIter != arrayHandle.end())
					ramSlot.fields["caption"] = mapIter->second;
			}
		} catch (...) {
		}

		// Make sure we have at least some valid info
		if (ramSlot.fields.find("caption") != ramSlot.fields.end()
			|| ramSlot.fields.find("purpose") != ramSlot.fields.end()
			|| ramSlot.fields.find("type") != ramSlot.fields.end()
			|| ramSlot.fields.find("serial") != ramSlot.fields.end()
			|| ramSlot.fields.find("speed") != ramSlot.fields.end()) {
				std::ostringstream s;
				s << "MEMORY" << slotNum;
				gComponents.Merge(s.str(), ramSlot);
				slotNum++;
		}
	}
}


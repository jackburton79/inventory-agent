/*
 * Configuration.cpp
 *
 *  Created on: 13/lug/2013
 *      Author: Stefano Ceccherini
 */

#include "Configuration.h"
#include "Support.h"

#include <algorithm>
#include <iostream>
#include <fstream>
#include <set>
#include <vector>

#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>


const static char* kServer = "server";
const static char* kDeviceID = "deviceID";
const static char* kOutputFileName = "outputFileName";
const static char* kUseCurrentTimeInDeviceID = "currentTimeInDeviceID";

static Configuration* sConfiguration;

Configuration::Configuration()
{
}


Configuration::~Configuration()
{
}


/* static */
Configuration*
Configuration::Get()
{
	if (sConfiguration == NULL)
		sConfiguration = new Configuration;
	return sConfiguration;
}


bool
Configuration::Load(const char* fileName)
{
	std::lock_guard<std::mutex> lock(fLock);
	fConfigFileName = fileName;
	try {
		std::ifstream configFile(fileName);
		if (!configFile.is_open())
			return false;
		std::string line;
		std::string key;
		std::string value;
		while (std::getline(configFile, line)) {
			if (_ParseLine(line, key, value))
				fValues[key] = value;
		}
	} catch (...) {
		return false;
	}

	return true;
}


bool
Configuration::Save(const char* fileName)
{
	std::lock_guard<std::mutex> lock(fLock);
	// The file may contain credentials: if it doesn't exist yet,
	// create it readable only by the owner
	int fd = ::open(fileName, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd >= 0)
		::close(fd);

	try {
		// Keep the comments, the empty lines and the order of the
		// existing file: only update the changed values, in place,
		// and append the new ones
		std::vector<std::string> lines;
		std::set<std::string> written;
		std::ifstream existingFile(fileName);
		std::string line;
		std::string key;
		std::string value;
		while (std::getline(existingFile, line)) {
			if (_ParseLine(line, key, value)) {
				if (written.count(key) > 0)
					continue; // duplicate key, the value is already written
				auto i = fValues.find(key);
				if (i != fValues.end()) {
					written.insert(key);
					if (i->second != value)
						line = key + "=" + i->second;
				}
			}
			lines.push_back(line);
		}
		existingFile.close();

		for (const auto& keyValue: fValues) {
			if (written.count(keyValue.first) == 0)
				lines.push_back(keyValue.first + "=" + keyValue.second);
		}

		std::ofstream configFile(fileName, std::ios_base::out | std::ios_base::trunc);
		for (const std::string& outLine: lines)
			configFile << outLine << std::endl;
		configFile.close();
		return !configFile.fail();
	} catch (...) {
		return false;
	}
}


bool
Configuration::Save()
{
	std::string fileName;
	{
		std::lock_guard<std::mutex> lock(fLock);
		fileName = fConfigFileName;
	}
	if (fileName.empty())
		return false;

	return Save(fileName.c_str());
}


void
Configuration::Print() const
{
	std::lock_guard<std::mutex> lock(fLock);
	std::cout << "Configuration:" << std::endl;
	try {
		std::cout << "Persistent:" << std::endl;
		for (const auto& value: fValues) {
			std::cout << value.first << "=" << value.second << std::endl;
		}
		std::cout << "Volatile:" << std::endl;
		for (const auto& volatileValues: fVolatileValues) {
			std::cout << volatileValues.first << "=" << volatileValues.second << std::endl;
		}
	} catch (...) {
	}
}


void
Configuration::SetServer(const char* serverUrl)
{
	std::lock_guard<std::mutex> lock(fLock);
	// Server set from the command line: don't store it in the
	// configuration file, since it may contain credentials
	fVolatileValues[kServer] = serverUrl;
}


void
Configuration::SetOutputFileName(const char* fileName)
{
	std::lock_guard<std::mutex> lock(fLock);
	fValues[kOutputFileName] = fileName;
}


void
Configuration::SetKeyValueBoolean(const char* key, bool value)
{
	std::lock_guard<std::mutex> lock(fLock);
	fValues[key] = _BooleanToString(value);
}


void
Configuration::SetVolatileKeyValueBoolean(const char* key, bool value)
{
	std::lock_guard<std::mutex> lock(fLock);
	fVolatileValues[key] = _BooleanToString(value);
}


bool
Configuration::KeyValueBoolean(const char* key) const
{
	std::string string = KeyValue(key);
	if (string == "")
		return false;
	return _StringToBoolean(string);
}


void
Configuration::SetKeyValue(const char* key, const char* value)
{
	std::lock_guard<std::mutex> lock(fLock);
	fValues[key] = value;
}


std::string
Configuration::KeyValue(const char* key) const
{
	std::lock_guard<std::mutex> lock(fLock);
	std::map<std::string, std::string>::const_iterator i;
	i = fValues.find(key);
	if (i != fValues.end())
		return i->second;

	// Try volatile values
	i = fVolatileValues.find(key);
	if (i != fVolatileValues.end())
		return i->second;

	return "";
}


void
Configuration::SetVolatileKeyValue(const char* key, const char* value)
{
	std::lock_guard<std::mutex> lock(fLock);
	fVolatileValues[key] = value;
}



std::string
Configuration::DeviceID() const
{
	std::lock_guard<std::mutex> lock(fLock);
	std::map<std::string, std::string>::const_iterator i;
	i = fValues.find(kDeviceID);
	if (i == fValues.end())
		return "";

	return i->second;
}


void
Configuration::SetDeviceID(const char* deviceID)
{
	std::lock_guard<std::mutex> lock(fLock);
	fValues[kDeviceID] = deviceID;
}


std::string
Configuration::ServerURL() const
{
	std::lock_guard<std::mutex> lock(fLock);
	// The server specified on the command line wins
	std::map<std::string, std::string>::const_iterator i;
	i = fVolatileValues.find(kServer);
	if (i != fVolatileValues.end())
		return i->second;

	i = fValues.find(kServer);
	if (i != fValues.end())
		return i->second;

	return "";
}


bool
Configuration::LocalInventory() const
{
	return ServerURL().empty();
}


std::string
Configuration::OutputFileName() const
{
	std::lock_guard<std::mutex> lock(fLock);
	std::map<std::string, std::string>::const_iterator i;
	i = fValues.find(kOutputFileName);
	if (i != fValues.end())
		return i->second;
	return "";
}


bool
Configuration::UseCurrentTimeInDeviceID() const
{
	std::lock_guard<std::mutex> lock(fLock);
	std::map<std::string, std::string>::const_iterator i;
	i = fValues.find(kUseCurrentTimeInDeviceID);
	if (i == fValues.end())
		return false;

	return _StringToBoolean(i->second);
}


void
Configuration::SetUseCurrentTimeInDeviceID(bool use)
{
	std::lock_guard<std::mutex> lock(fLock);
	fValues[kUseCurrentTimeInDeviceID] = _BooleanToString(use);
}


/* static */
bool
Configuration::_ParseLine(const std::string& line, std::string& key, std::string& value)
{
	// Format: "key = value". Empty lines and lines
	// starting with '#' or ';' are ignored.
	std::string string = trimmed(line);
	if (string.empty() || string[0] == '#' || string[0] == ';')
		return false;

	size_t pos = string.find('=');
	if (pos == std::string::npos)
		return false;

	key = trimmed(string.substr(0, pos));
	value = trimmed(string.substr(pos + 1));
	return !key.empty();
}


std::string
Configuration::_BooleanToString(bool value)
{
	return std::string(value ? "true" : "false");
}


bool
Configuration::_StringToBoolean(const std::string& string)
{
	std::string lowerCaseString = string;
	std::transform(lowerCaseString.begin(), lowerCaseString.end(),
		lowerCaseString.begin(), ::tolower);
	if (lowerCaseString.compare("yes") == 0
		|| lowerCaseString.compare("true") == 0)
		return true;
	return false;
}

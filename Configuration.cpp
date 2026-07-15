/*
 * Configuration.cpp
 *
 *  Created on: 13/lug/2013
 *      Author: Stefano Ceccherini
 */

#include "Configuration.h"

#include <algorithm>
#include <iostream>
#include <fstream>

#include <assert.h>


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
	fConfigFileName = fileName;
	try {
		std::ifstream configFile(fileName);
		std::string line;
		while (std::getline(configFile, line)) {
			size_t pos = line.find("=");
			if (pos != std::string::npos) {
				fValues[line.substr(0, pos)] = line.substr(pos + 1, std::string::npos);
			}
		}
	} catch (...) {
	}

	return true;
}


bool
Configuration::Save(const char* fileName)
{
	try {
		std::ofstream configFile(fileName, std::ios_base::out);
		for (const auto& value: fValues) {
			configFile << value.first << "=" << value.second << std::endl;
		}
	} catch (...) {
		return false;
	}
	return true;
}


bool
Configuration::Save()
{
	if (fConfigFileName == "")
		return false;

	return Save(fConfigFileName.c_str());
}


void
Configuration::Print() const
{
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
	fValues[kServer] = serverUrl;
}


void
Configuration::SetOutputFileName(const char* fileName)
{
	fValues[kOutputFileName] = fileName;
}


void
Configuration::SetKeyValueBoolean(const char* key, bool value)
{
	fValues[key] = _BooleanToString(value);
}


void
Configuration::SetVolatileKeyValueBoolean(const char* key, bool value)
{
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
	fValues[key] = value;
}


std::string
Configuration::KeyValue(const char* key) const
{
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
	fVolatileValues[key] = value;
}



std::string
Configuration::DeviceID() const
{
	std::map<std::string, std::string>::const_iterator i;
	i = fValues.find(kDeviceID);
	if (i == fValues.end())
		return "";

	return i->second;
}


void
Configuration::SetDeviceID(const char* deviceID)
{
	fValues[kDeviceID] = deviceID;
}


std::string
Configuration::ServerURL() const
{
	std::map<std::string, std::string>::const_iterator i;
	i = fValues.find(kServer);
	if (i != fValues.end())
		return i->second;

	return "";
}


bool
Configuration::LocalInventory() const
{
	return fValues.find(kServer) == fValues.end();
}


std::string
Configuration::OutputFileName() const
{
	std::map<std::string, std::string>::const_iterator i;
	i = fValues.find(kOutputFileName);
	if (i != fValues.end())
		return i->second;
	return "";
}


bool
Configuration::UseCurrentTimeInDeviceID() const
{
	std::map<std::string, std::string>::const_iterator i;
	i = fValues.find(kUseCurrentTimeInDeviceID);
	if (i == fValues.end())
		return false;

	return _StringToBoolean(i->second);
}


void
Configuration::SetUseCurrentTimeInDeviceID(bool use)
{
	fValues[kUseCurrentTimeInDeviceID] = _BooleanToString(use);
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

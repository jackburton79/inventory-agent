/*
 * RunningProcesses.cpp
 *
 *  Created on: 16/lug/2013
 *      Author: Stefano Ceccherini
 */

#include "ProcessRoster.h"

#include "ProcReader.h"
#include "Support.h"

#include <cstdlib>
#include <dirent.h>
#include <iostream>
#include <pwd.h>


static bool
IsNumber(const std::string& string)
{
	return !string.empty()
			&& string.find_first_not_of("0123456789") == std::string::npos;
}


RunningProcessesList::RunningProcessesList()
{
	DIR* dir = ::opendir("/proc/");
	if (dir != NULL) {
		dirent* entry = NULL;
		while ((entry = ::readdir(dir)) != NULL) {
			std::string procPid = entry->d_name;
			if (IsNumber(procPid)) {
				std::string fullName = "/proc/";
				fullName.append(procPid);
				process_info info;
				_ReadProcessInfo(info, procPid);
				if (!info.cmdline.empty())
					fItems.push_back(info);
			}
		}
		::closedir(dir);
	}
	Rewind();
}


RunningProcessesList::~RunningProcessesList()
{
}



void
RunningProcessesList::_ReadProcessInfo(process_info& info, std::string pid)
{
	info.pid = strtol(pid.c_str(), NULL, 10);
	info.cmdline = ProcReader(("/proc/" + pid + std::string("/cmdline")).c_str()).ReadLine();

	std::string loginUid = ProcReader(("/proc/" + pid + std::string("/loginuid")).c_str()).ReadLine();
	struct passwd* passwdStruct = getpwuid(strtoull(loginUid.c_str(), NULL, 10));
	if (passwdStruct != NULL)
		info.user = passwdStruct->pw_name;
	else {
		// TODO: Not nice. What to do in this case ?
		info.user = "root";
	}
		// TODO: Refactor, too much duplicated code
	ProcReader status(("/proc/" + pid + std::string("/status")).c_str());

	std::istream stream(&status);
	std::string line;
	try {
		while (std::getline(stream, line)) {
			if (line.find("VmSize") != std::string::npos) {
				size_t pos = line.find(":");
				if (pos == std::string::npos)
					continue;
				std::string valueString = line.substr(pos + 2, std::string::npos);
				info.memory = strtol(trim(valueString).c_str(), NULL, 10);
			} else if (line.find("VmSwap") != std::string::npos) {
				size_t pos = line.find(":");
				if (pos == std::string::npos)
					continue;
				std::string valueString = line.substr(pos + 2, std::string::npos);
				info.virtualmem = strtol(trim(valueString).c_str(), NULL, 10);
			}
		}
	} catch (...) {
	}
}

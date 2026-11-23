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
		const dirent* entry = NULL;
		while ((entry = ::readdir(dir)) != NULL) {
			std::string procPid = entry->d_name;
			if (IsNumber(procPid)) {
				process_info info;
				try {
					_ReadProcessInfo(info, procPid);
				} catch (...) {
					// Process could have exited between readdir
					// and the above call
					continue;
				}
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



long
RunningProcessesList::_TotalMemory()
{
	static long total = -1;
	if (total >= 0)
		return total;
	total = 0;
	try {
		ProcReader meminfo("/proc/meminfo");
		std::istream stream(&meminfo);
		std::string line;
		while (std::getline(stream, line)) {
			if (starts_with(line, "MemTotal:")) {
				total = strtol(line.c_str() + 9, NULL, 10);
				break;
			}
		}
	} catch (...) {
	}
	return total;
}


void
RunningProcessesList::_ReadProcessInfo(process_info& info, const std::string& pid)
{
	info.pid = strtol(pid.c_str(), NULL, 10);
	info.cmdline = ProcReader(("/proc/" + pid + std::string("/cmdline")).c_str()).ReadLine();

	std::string loginUid;
	try {
		loginUid = ProcReader(("/proc/" + pid + std::string("/loginuid")).c_str()).ReadLine();
	} catch (...) {
		// loginuid is not available on non-audit kernels,
		// fallback to default user
	}
	const struct passwd* passwdStruct = getpwuid(strtoull(loginUid.c_str(), NULL, 10));
	if (passwdStruct != NULL)
		info.user = passwdStruct->pw_name;
	else {
		// TODO: Not nice. What to do in this case ?
		info.user = "root";
	}
		// Resident and virtual sizes, in kB
	long rss = 0;
	long vsize = 0;
	ProcReader status(("/proc/" + pid + std::string("/status")).c_str());

	std::istream stream(&status);
	std::string line;
	try {
		while (std::getline(stream, line)) {
			if (starts_with(line, "VmRSS:") || starts_with(line, "VmSize:")) {
				size_t pos = line.find(":");
				std::string valueString = line.substr(pos + 1);
				long value = strtol(trim(valueString).c_str(), NULL, 10);
				if (line[2] == 'R')
					rss = value;
				else
					vsize = value;
			}
		}
	} catch (...) {
	}

	// GLPI expects MEM as the percentage of physical memory used (like ps's %MEM),
	// and VIRTUALMEMORY as the virtual size in kB (like ps's VSZ)
	info.virtualmem = vsize;
	long total = _TotalMemory();
	info.memory = total > 0 ? (float)rss * 100.0f / (float)total : 0;
}

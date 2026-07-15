/*
 * MemInfoBackend.cpp
 *
 *  Created on: 22 mar 2021
 *      Author: Stefano Ceccherini
 */

#include "MemInfoBackend.h"

#include "Components.h"
#include "ProcReader.h"
#include "Support.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <unistd.h>


MemInfoBackend::MemInfoBackend()
{
}


MemInfoBackend::~MemInfoBackend()
{
}


/* virtual */
bool
MemInfoBackend::IsAvailable() const
{
	return ::access("/proc/meminfo", F_OK) != -1;
}


/* virtual */
int
MemInfoBackend::Run()
{
	if (!IsAvailable())
		return -1;

	ProcReader proc("/proc/meminfo");
	std::istream stream(&proc);

	Component os;
	std::string string;
	while (std::getline(stream, string)) {
		const std::string swapLabel = "SwapTotal";
		const std::string memLabel = "MemTotal";
		if ((string.compare(0, swapLabel.length(), swapLabel))) {
			size_t pos = string.find(":");
			std::string swapString = string.substr(pos + 1, std::string::npos);
			int swapInt = ::strtol(trim(swapString).c_str(), NULL, 10) / 1000;
			os.fields["swap"] = int_to_string(swapInt);
		} else if ((string.compare(0, memLabel.length(), memLabel))) {
			size_t pos = string.find(":");
			std::string memString = string.substr(pos + 1, std::string::npos);
			int memInt = ::strtol(trim(memString).c_str(), NULL, 10) / 1000;
			os.fields["memory"] = int_to_string(memInt);
		}
	}

	gComponents.Merge("OS", os);

	return 0;
}

/*
 * VolumeReader.cpp
 *
 *  Created on: 19/lug/2013
 *      Author: Stefano Ceccherini
 */

#include "VolumeRoster.h"

#include "Support.h"

#include <iostream>
#include <sstream>

VolumeRoster::VolumeRoster(const char* options)
{
	std::string string("export LC_ALL=C; ");
	string.append("df -T").append(options);
	CommandStreamBuffer df(string.c_str(), "r");
	std::istream stream(&df);

	std::string line;
	std::getline(stream, line); // Skip the first line
	while (std::getline(stream, line)) {
		std::istringstream iss(line);

		volume_info info;
		std::string dummy;
		iss >> info.name;
		iss >> info.filesystem;
		iss >> info.total;
		iss >> dummy;
		iss >> info.free;
		iss >> dummy;
		iss >> info.type;

		info.label = info.name;
		// TODO: we could use -x to exclude these filesystems,
		// but some "df" version doesn't support it (i.e. busybox)
		if (info.filesystem != "tmpfs" &&
			info.filesystem != "efivarfs" &&
			info.filesystem != "overlay") {
			fItems.push_back(info);
		}
	}

	Rewind();
}


VolumeRoster::~VolumeRoster()
{
}

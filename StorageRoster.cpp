/*
 * Storages.cpp
 *
 *      Author: Stefano Ceccherini
 */

#include "StorageRoster.h"

#include "ProcReader.h"
#include "Support.h"

#include <iostream>
#include <istream>


// A fixed-width column of a /proc/scsi/scsi line. Safe on short lines.
static std::string
Column(const std::string& line, size_t position, size_t length)
{
	if (position >= line.length())
		return "";

	std::string column = line.substr(position, length);
	trim(column);
	return column;
}


StorageRoster::StorageRoster()
{
	_ReadStoragesInfo();
}


void
StorageRoster::_ReadStoragesInfo()
{
	try {
		ProcReader procReader("/proc/scsi/scsi");

		std::istream stream(&procReader);

		for (;;) {
			std::string dummy;
			if (!std::getline(stream, dummy))
				break;
			std::string hostLine;
			std::string vendorLine;
			std::string typeLine;
			if (!std::getline(stream, hostLine))
				break;
			if (!std::getline(stream, vendorLine))
				break;
			if (!std::getline(stream, typeLine))
				break;	

			storage_info info;
			info.manufacturer = Column(vendorLine, 10, 9);
			info.model = Column(vendorLine, 26, 17); 
			// TODO: Name = Model ?
			info.name = info.model;
			info.type = Column(typeLine, 10, 26);

			fItems.push_back(info);
		}
	} catch (...) {
	}

	Rewind();
}


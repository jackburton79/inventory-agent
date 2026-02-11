/*
 * Screens.cpp
 *
 *  Created on: 15/lug/2015
 *      Author: Stefano Ceccherini
 */

#include "Screens.h"

#include "EDID.h"
#include "Support.h"

#include <cstring>
#include <iostream>
#include <string>

struct pnp_id {
	const char* id;
	const char* manufacturer;
	bool operator==(const pnp_id& a) const { return ::strcasecmp(a.id, id) == 0; };
	bool operator()(const pnp_id& a, const pnp_id& b) const { return ::strcasecmp(a.id, b.id) < 0; };
};

static const struct pnp_id kPNPIDs[] = {
#include "pnp_ids.h"
};

Screens::Screens()
{
	if (CommandExists("find")) {
		CommandStreamBuffer buf("find /sys/devices/ -name edid", "r");
		std::istream stream(&buf);
		std::string line;
		while (std::getline(stream, line)) {
			screen_info info;
			edid_info edidInfo;
			info.name = line;
			if (get_edid_info(line.c_str(), &edidInfo) == 0) {
				info.description = edidInfo.description;
				info.manufacturer = GetManufacturerFromID(edidInfo.manufacturer);
				info.type = edidInfo.type;
				info.model = edidInfo.model;
				info.serial_number = trimmed(edidInfo.serial_number);
				fItems.push_back(info);
			}
		}
	}

	Rewind();
}


std::string
GetManufacturerFromID(const std::string& string)
{
	// We assume the array is sorted
	const size_t numElements = sizeof(kPNPIDs) / sizeof(kPNPIDs[0]);
	const struct pnp_id key = { string.c_str(), "dummy" };
	const pnp_id* lastElement = kPNPIDs + numElements;
	const pnp_id* element = std::find(kPNPIDs, lastElement, key);
	if (element == lastElement) {
		//  can't find the supplied vendor code, return it as is
		return string;
	}

	return element->manufacturer;
}

/*
 * Sounds.cpp
 */

#include "Sounds.h"

#include "ProcReader.h"
#include "Support.h"

#include <cstdlib>
#include <iostream>


static std::string
ReadFile(const std::string& path)
{
	try {
		return trimmed(ProcReader(path.c_str()).ReadLine());
	} catch (...) {
		return "";
	}
}


// Look up a PCI vendor name (id is like "0x8086") in the pci.ids database
static std::string
PCIVendorName(const std::string& vendorID)
{
	if (vendorID.size() < 3)
		return "";

	std::string id = vendorID.substr(2);
	for (size_t i = 0; i < id.size(); i++)
		id[i] = ::tolower(id[i]);

	static const char* kPaths[] = {
		"/usr/share/hwdata/pci.ids",
		"/usr/share/misc/pci.ids",
		"/usr/share/pci.ids"
	};
	for (size_t i = 0; i < sizeof(kPaths) / sizeof(kPaths[0]); i++) {
		try {
			ProcReader reader(kPaths[i]);
			std::istream stream(&reader);
			std::string line;
			// Vendor lines start at column 0, followed by the id and two spaces
			while (std::getline(stream, line)) {
				if (line.compare(0, id.size(), id) == 0 && line.compare(id.size(), 2, "  ") == 0)
					return trimmed(line.substr(id.size() + 2));
			}
		} catch (...) {
		}
	}
	return "";
}


static std::string
ManufacturerForCard(int card)
{
	std::string devicePath = "/sys/class/sound/card" + int_to_string(card) + "/device/";

	// USB audio devices expose the manufacturer string on the parent device
	std::string manufacturer = ReadFile(devicePath + "../manufacturer");
	if (!manufacturer.empty())
		return manufacturer;

	// PCI devices
	return PCIVendorName(ReadFile(devicePath + "vendor"));
}


SoundCards::SoundCards()
{
	try {
		ProcReader reader("/proc/asound/cards");
		std::istream stream(&reader);
		std::string line;
		while (std::getline(stream, line)) {
			// Each card takes two lines:
			//  0 [PCH            ]: HDA-Intel - HDA Intel PCH
			//                       HDA Intel PCH at 0xec240000 irq 145
			size_t open = line.find('[');
			size_t close = line.find(']');
			size_t colon = line.find(':', close);
			if (open == std::string::npos || close == std::string::npos
					|| colon == std::string::npos
					|| line.find_first_not_of(" 0123456789") != open)
				continue;

			sound_info info;
			info.card = strtol(line.c_str(), NULL, 10);
			info.id = trimmed(line.substr(open + 1, close - open - 1));

			std::string rest = trimmed(line.substr(colon + 1));
			size_t dash = rest.find(" - ");
			if (dash != std::string::npos) {
				info.driver = trimmed(rest.substr(0, dash));
				info.name = trimmed(rest.substr(dash + 3));
			} else
				info.name = rest;

			if (std::getline(stream, line))
				info.description = trimmed(line);

			info.manufacturer = ManufacturerForCard(info.card);
			fItems.push_back(info);
		}
	} catch (...) {
		// No ALSA support: no sound cards
	}
	Rewind();
}

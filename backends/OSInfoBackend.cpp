/*
 * OSInfoBackend.cpp
 *
 *  Created on: 24 gen 2022
 *      Author: Stefano Ceccherini
 */

#include "OSInfoBackend.h"

#include "Components.h"
#include "ProcReader.h"
#include "Support.h"

#ifdef __linux
#include <sys/sysinfo.h>
#endif

#include <unistd.h>


// OSInfoBackend
OSInfoBackend::OSInfoBackend()
{
}


/* virtual */
OSInfoBackend::~OSInfoBackend()
{
}


/* virtual */
int
OSInfoBackend::Run()
{
	std::string line;
	std::string osDescription;
	Component os;
	if (::access("/etc/os-release", F_OK) != -1) {
		ProcReader osReader("/etc/os-release");
		try {
			while ((line = osReader.ReadLine()) != "") {
				if (line.find("PRETTY_NAME") != std::string::npos) {
					size_t pos = line.find('=');
					if (pos != std::string::npos) {
						std::string value = line.substr(pos + 1, std::string::npos);
						value = trim(value);
						// remove quotes
						osDescription = value.substr(1, value.length() - 2);
						break;
					}
				}
			}
		} catch (...) {
			// not an error
		}
	} else if (CommandExists("lsb_release")) {
		CommandStreamBuffer lsb;
		lsb.open("lsb_release -a", "r");
		std::istream lsbStream(&lsb);
		while (std::getline(lsbStream, line)) {
			if (line.find("Description") != std::string::npos) {
				size_t pos = line.find(':');
				if (pos != std::string::npos) {
					std::string value = line.substr(pos + 1, std::string::npos);
					osDescription = trim(value);
					break;
				}
			}
		}
	} else if (::access("/etc/thinstation.global", F_OK) != -1) {
		osDescription = "Thinstation";
		char* tsVersion = ::getenv("TS_VERSION");
		if (tsVersion != NULL) {
			osDescription += " ";
			osDescription += tsVersion;
		}
	} else {
		try {
			osDescription = trimmed(ProcReader("/etc/redhat-release").ReadLine());
		} catch (...) {
			osDescription = "Unknown";
		}
	}

	os.fields["description"] = osDescription;

#ifdef __linux
	struct sysinfo info;
	if (sysinfo(&info) == 0) {
		time_t now = time(NULL);
		if (now == (time_t)-1) {
			return EXIT_FAILURE;
		}
		// Calculate boot time
		time_t bootTime = now - info.uptime;
		struct tm *bootTm = localtime(&bootTime);
		if (bootTm != NULL) {
			char buffer[64];
			if (strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", bootTm) != 0)
				os.fields["boot_time"] = buffer;
		}
	}
#endif

	gComponents.Merge("OS", os);
	return 0;
}



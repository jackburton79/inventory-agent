/*
 * Softwares.cpp
 *
 *      Author: Jonathan ORSEL
 */

#include "Softwares.h"
#include "ProcReader.h"
#include "Support.h"

#include <iostream>
#include <istream>


// Value of a "Key        : value" line of "rpm -qi", starting at
// the given column. Safe on short lines.
static std::string
FieldValue(const std::string& line, size_t maxLength = std::string::npos)
{
	const size_t kValueColumn = 13;
	if (line.length() <= kValueColumn)
		return "";

	std::string value = line.substr(kValueColumn, maxLength);
	trim(value);
	return value;
}


Softwares::Softwares()
{
	_ReadSoftwaresInfo();
}


void
Softwares::_ReadSoftwaresInfo()
{
	try {
		if (!CommandExists("rpm"))
			return;

		CommandStreamBuffer rpms("export LC_ALL=C; rpm -qai", "r");
		std::istream iStreamRpms(&rpms);
		std::string string;
		std::string strtmp;

		std::string comments = "";
		std::string size = "";
		std::string from = "";
		std::string installdate = "";
		std::string name = "";
		std::string version = "";

		while (std::getline(iStreamRpms, string)) {
			if (starts_with(string, "Name        :")) {
				// new rpm, add last in defined
				if (name != "") {
					software_info info;
					info.comments = comments;
					info.size = size;
					info.from = from;
					info.installdate = installdate;
					info.name = name;
					info.version = version;
					fItems.push_back(info);
				}
				// then update name
				name = FieldValue(string);
			} else if (starts_with(string, "Version     :")) {
				version = FieldValue(string);
			} else if (starts_with(string, "Architecture:")) {
				name = name + '.' + FieldValue(string);
			} else if (starts_with(string, "Release     :")) {
				version = version + '-' + FieldValue(string);
			} else if (starts_with(string, "Install Date:")) {
				installdate = FieldValue(string, 50);
			} else if (starts_with(string, "Size        :")) {
				size = FieldValue(string, 35);
			} else if (starts_with(string, "Summary     :")) {
				comments = FieldValue(string, 100);
			} else if (starts_with(string, "Vendor      :")) {
				from = "RPM-" + FieldValue(string, 35);
			}
		}
		//last one ?
		if (name != "") {
			software_info info;
			info.comments = comments;
			info.size = size;
			info.from = from;
			info.installdate = installdate;
			info.name = name;
			info.version = version;
			fItems.push_back(info);
		}
	} catch (...) {
		std::cerr << "No software info" << std::endl;
	}

	Rewind();
}

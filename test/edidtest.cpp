/*
 * edidtest.cpp
 *
 * Tests for the EDID parser (edid-decode.c)
 */

#include "EDID.h"

#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>


static int sFailures = 0;


static void
Check(bool condition, const std::string& testName, const std::string& what)
{
	if (!condition) {
		std::cout << "  FAILED: " << testName << ": " << what << std::endl;
		sFailures++;
	}
}


static void
WriteFile(const std::string& fileName, const std::vector<unsigned char>& data)
{
	std::ofstream file(fileName, std::ios::binary | std::ios::trunc);
	file.write(reinterpret_cast<const char*>(data.data()), data.size());
}


// Builds a minimal, valid, 128 bytes EDID block
static std::vector<unsigned char>
BuildEDID()
{
	std::vector<unsigned char> edid(128, 0);
	const unsigned char header[] = { 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };
	::memcpy(&edid[0], header, sizeof(header));
	// Manufacturer "DEL" (5 bits per letter, 'A' = 1)
	edid[0x08] = 0x10;
	edid[0x09] = 0xAC;
	// Product code, serial number
	edid[0x0A] = 0x64;
	edid[0x0B] = 0x40;
	edid[0x0C] = 0x01;
	// Week and year of manufacture (2018), EDID version 1.4
	edid[0x10] = 1;
	edid[0x11] = 28;
	edid[0x12] = 1;
	edid[0x13] = 4;
	// Digital input, screen size in cm
	edid[0x14] = 0x80;
	edid[0x15] = 52;
	edid[0x16] = 32;
	// Monitor name descriptor
	const unsigned char name[] = { 0x00, 0x00, 0x00, 0xFC, 0x00,
		'T', 'E', 'S', 'T', 'M', 'O', 'N', '\n', ' ', ' ', ' ', ' ', ' ' };
	::memcpy(&edid[0x5A], name, sizeof(name));
	// Serial number descriptor
	const unsigned char serial[] = { 0x00, 0x00, 0x00, 0xFF, 0x00,
		'S', 'N', '1', '2', '3', '4', '\n', ' ', ' ', ' ', ' ', ' ', ' ' };
	::memcpy(&edid[0x6C], serial, sizeof(serial));

	unsigned char sum = 0;
	for (size_t i = 0; i < 127; i++)
		sum += edid[i];
	edid[127] = static_cast<unsigned char>(0x100 - sum);
	return edid;
}


static void
TestFile(const std::string& name, const std::string& fileName,
	const std::vector<unsigned char>& data, bool shouldSucceed)
{
	std::cout << name << std::endl;
	WriteFile(fileName, data);
	struct edid_info info;
	int result = get_edid_info(fileName.c_str(), &info);
	Check((result == 0) == shouldSucceed, name,
		std::string("get_edid_info() should ") + (shouldSucceed ? "succeed" : "fail"));
}


int main()
{
	char dirTemplate[] = "/tmp/edidtest.XXXXXX";
	const char* dir = ::mkdtemp(dirTemplate);
	if (dir == NULL) {
		std::cerr << "cannot create temporary directory" << std::endl;
		return 2;
	}
	const std::string fileName = std::string(dir) + "/edid";

	// The edid files of disconnected outputs in /sys are empty
	TestFile("empty file", fileName, {}, false);
	TestFile("short file", fileName, { 0x00, 0xFF, 0xFF, 0xFF }, false);
	TestFile("garbage", fileName, std::vector<unsigned char>(200, 'x'), false);
	TestFile("exactly 1023 bytes", fileName, std::vector<unsigned char>(1023, 0xAB), false);

	std::vector<unsigned char> edid = BuildEDID();
	TestFile("valid EDID", fileName, edid, true);

	struct edid_info info;
	if (get_edid_info(fileName.c_str(), &info) == 0) {
		Check(std::string(info.manufacturer) == "DEL", "valid EDID",
			std::string("wrong manufacturer: ") + info.manufacturer);
		Check(std::string(info.description) == "DEL.4064.000000000 (1/2018)",
			"valid EDID", std::string("wrong description: ") + info.description);
		Check(std::string(info.model).find("TESTMON") != std::string::npos,
			"valid EDID", std::string("wrong model: ") + info.model);
		Check(std::string(info.serial_number).find("SN1234") != std::string::npos,
			"valid EDID", std::string("wrong serial number: ") + info.serial_number);
	}

	std::vector<unsigned char> badHeader = edid;
	badHeader[1] = 0x00;
	TestFile("bad header", fileName, badHeader, false);

	::unlink(fileName.c_str());
	::rmdir(dir);

	if (sFailures > 0) {
		std::cout << sFailures << " check(s) failed" << std::endl;
		std::cout << "Test Failed !!!" << std::endl;
		return 1;
	}

	std::cout << "All tests passed!" << std::endl;
	return 0;
}

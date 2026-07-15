/*
 * Support.cpp
 *
 *  Created on: 11/lug/2013
 *      Author: Stefano Ceccherini
 *      Code for popen_streambuf found here:
 *      http://stackoverflow.com/questions/1683051/file-and-istream-connect-the-two
 */


#include "Support.h"

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <streambuf>
#include <string>


CommandStreamBuffer::CommandStreamBuffer()
	:
	fFile(NULL),
	fBuffer(NULL)
{
}


CommandStreamBuffer::CommandStreamBuffer(const char* fileName, const char* mode)
	:
	fFile(NULL),
	fBuffer(NULL)
{
	const CommandStreamBuffer* buf = open(fileName, mode);
	if (buf == NULL)
		throw std::runtime_error("CommandStreamBuffer: cannot open file");
}


CommandStreamBuffer::~CommandStreamBuffer()
{
	close();
}


CommandStreamBuffer*
CommandStreamBuffer::open(const char* fileName, const char* mode)
{
	fFile = ::popen(fileName, mode);
	if (fFile == NULL)
		return NULL;

	fBuffer = new char[512];
	if (fBuffer == NULL)
		return NULL;

	setg(fBuffer, fBuffer, fBuffer);
	return this;
}


void
CommandStreamBuffer::close()
{
	if (fFile != NULL) {
		::pclose(fFile);
		fFile = NULL;
	}

	delete[] fBuffer;
}


std::streamsize
CommandStreamBuffer::xsgetn(char_type* ptr, std::streamsize num)
{
	std::streamsize howMany = showmanyc();
	if (num < howMany) {
		::memcpy(ptr, gptr(), num * sizeof(char_type));
		gbump(num);
		return num;
	}

	::memcpy(ptr, gptr(), howMany * sizeof(char_type));
	gbump(howMany);

	if (traits_type::eof() == underflow())
		return howMany;

	return howMany + xsgetn(ptr + howMany, num - howMany);
}


CommandStreamBuffer::traits_type::int_type
CommandStreamBuffer::underflow()
{
	if (gptr() == 0)
		return traits_type::eof();

	if (gptr() < egptr())
		return traits_type::to_int_type(*gptr());

	size_t len = ::fread(eback(), sizeof(char_type), 512, fFile);
	setg(eback(), eback(), eback() + sizeof(char_type) * len);
	if (len == 0)
		return traits_type::eof();
	return traits_type::to_int_type(*gptr());
}


std::streamsize
CommandStreamBuffer::showmanyc()
{
	if (gptr() == 0)
		return 0;
	if (gptr() < egptr())
		return egptr() - gptr();
	return 0;
}


bool
CommandExists(const char* command)
{
	std::string fullCommand;
	fullCommand.append("type ").append(command).append(" > /dev/null 2>&1");

	int systemStatus = ::system(fullCommand.c_str());

	return systemStatus == 0;
}


std::string
RAM_type_from_description(const std::string& description)
{
	std::string type;
	if (!description.empty()) {
		// TODO: Not the cleanest approach, but lshw doesn't
		// seem to return this in any other field
		if (description.find("SDRAM") != std::string::npos)
			type = "SDRAM";
		else if (description.find("FLASH") != std::string::npos)
			type = "FLASH";
		else if (description.find("DDR4") != std::string::npos)
			type = "DDR4";
		else if (description.find("DDR3") != std::string::npos)
			type = "DDR3";
		else if (description.find("DDR2") != std::string::npos)
			type = "DDR2";
		else if (description.find("DDR") != std::string::npos)
			type = "DDR";
		// TODO: Handle empty slots like we do for dmidecode
	}
	return type;
}


// Returns size, in MBytes,
// starting from a string like '3GB' or '1024 KB'
unsigned int
convert_to_MBytes(const std::string& string)
{
	char *memoryUnit = NULL;
	unsigned int memorySize = ::strtol(string.c_str(), &memoryUnit, 10);
	std::string unit = memoryUnit;
	trim(unit);
	if (::strcasecmp(unit.c_str(), "KB") == 0
		|| ::strcasecmp(unit.c_str(), "KiB") == 0)
		memorySize /= 1024;
	else if (::strcasecmp(unit.c_str(), "GB") == 0
		 || ::strcasecmp(unit.c_str(), "GiB") == 0)
		memorySize *= 1024;
	return memorySize;
}


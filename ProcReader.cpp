/*
 * ProcReader.cpp
 *
 *  Created on: 15/lug/2013
 *      Author: Stefano Ceccherini
 */

#include "ProcReader.h"

#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <unistd.h>
#include <sys/ioctl.h>


ProcReader::ProcReader(const char* fullPath)
{
	if (ProcReader::open(fullPath, "r") == NULL) {
		std::string errorString;
		errorString.append("File not found: ");
		errorString.append(fullPath);
		throw std::runtime_error(errorString);
	}
}


ProcReader::~ProcReader()
{
	close();
}


std::string
ProcReader::ReadLine()
{
	std::string line;
	std::istream buf(this);
	std::getline(buf, line);

	return line;
}


ProcReader*
ProcReader::open(const char* fileName, const char* mode)
{
	fFD = ::open(fileName, O_RDONLY);
	if (fFD < 0)
		return NULL;

	fBuffer = new char[512];
	if (fBuffer == NULL)
		return NULL;

	setg(fBuffer, fBuffer, fBuffer);
	return this;
}


void
ProcReader::close()
{
	if (fFD >= 0) {
		::close(fFD);
		fFD = -1;
	}

	delete[] fBuffer;
	fBuffer = NULL;
}


std::streamsize
ProcReader::xsgetn(char_type* ptr, std::streamsize num)
{
	std::streamsize howMany = showmanyc();
	if (num < howMany) {
		memcpy(ptr, gptr(), num * sizeof(char_type));
		gbump(num);
		return num;
	}

	memcpy(ptr, gptr(), howMany * sizeof(char_type));
	gbump(howMany);

	if (traits_type::eof() == underflow())
		return howMany;

	return howMany + xsgetn(ptr + howMany, num - howMany);
}


ProcReader::traits_type::int_type
ProcReader::underflow()
{
	if (gptr() == 0)
		return traits_type::eof();

	if (gptr() < egptr())
		return traits_type::to_int_type(*gptr());

	ssize_t len;
	do {
		len = ::read(fFD, eback(), sizeof(char_type) * 512);
	} while (len < 0 && errno == EINTR);

	// End of file, or a read error: nothing more to read
	if (len <= 0)
		return traits_type::eof();

	setg(eback(), eback(), eback() + len);
	return traits_type::to_int_type(*gptr());
}


std::streamsize
ProcReader::showmanyc()
{
	if (gptr() == 0)
		return 0;
	if (gptr() < egptr())
		return egptr() - gptr();
	return 0;
}

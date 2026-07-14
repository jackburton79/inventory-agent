/*
 * Support.h
 *
 *  Created on: 11/lug/2013
 *      Author: Stefano Ceccherini
 */

#ifndef SUPPORT_H_
#define SUPPORT_H_

#include <algorithm>
#include <sstream>
#include <stdio.h>
#include <streambuf>
#include <string>


class CommandStreamBuffer : public std::streambuf {
public:
	CommandStreamBuffer();
	CommandStreamBuffer(const char* fileName, const char* mode);
	virtual ~CommandStreamBuffer();

	CommandStreamBuffer* open(const char* command, const char* mode);
	void close();
	std::streamsize xsgetn(char_type* ptr, std::streamsize n);
	int_type underflow();
	std::streamsize showmanyc();
private:
	FILE* fFile;
	char_type* fBuffer;
};


bool CommandExists(const char* command);

std::string RAM_type_from_description(const std::string& description);

unsigned int convert_to_MBytes(const std::string& string);

static inline std::string& ltrim(std::string& s) {
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char c) {
		return std::isspace(c);
	}));
	return s;
}


static inline std::string& rtrim(std::string& s) {
	s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char c) {
		return std::isspace(c);
	}).base(), s.end());
	return s;
}


static inline std::string& trim(std::string& s) {
	return ltrim(rtrim(s));
}


static inline std::string trimmed(const std::string& s) {
	std::string newString = s;
	ltrim(rtrim(newString));
	return newString;
}


static inline std::string int_to_string(int i) {
	std::ostringstream stream;
	stream << i;
	return stream.str();
}

static inline std::string uint_to_string(unsigned int i) {
	std::ostringstream stream;
	stream << i;
	return stream.str();
}

#endif /* SUPPORT_H_ */

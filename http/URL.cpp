/*
 * URL.cpp
 *
 *  Created on: 12/07/2017
 *  Copyright 2017 Stefano Ceccherini (stefano.ceccherini@gmail.com)
 */

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "URL.h"

URL::URL()
	:
	fURLString(""),
	fProtocol(""),
	fHost(""),
	fPort(-1),
	fPath(""),
	fUsername(""),
	fPassword("")
{
}


URL::URL(const std::string& url)
	:
	fURLString(url),
	fProtocol(""),
	fHost(""),
	fPort(-1),
	fPath(""),
	fUsername(""),
	fPassword("")
{
	_DecodeURLString(url);
}


void
URL::SetTo(const std::string& url)
{
	fURLString = url;
	fProtocol = "";
	fHost = "";
	fPort = -1;
	fPath = "";
	fUsername = "";
	fPassword = "";
	_DecodeURLString(url);
}


std::string
URL::URLString() const
{
	return fURLString;
}


std::string
URL::Protocol() const
{
	return fProtocol;
}


std::string
URL::Host() const
{
	return fHost;
}


int
URL::Port() const
{
	return fPort;
}


std::string
URL::Path() const
{
	return fPath;
}


std::string
URL::Username() const
{
	return fUsername;
}


std::string
URL::Password() const
{
	return fPassword;
}


bool
URL::IsRelative() const
{
	return fURLString.length() > 0 && fURLString[0] == '/';
}


void
URL::_DecodeURLString(const std::string& string)
{
	// TODO: Handle more malformed urls
	std::string result = string;
	size_t suffixPos = string.find(":/");
	if (suffixPos != std::string::npos) {
		// Remove protocol part (<proto>://)
		fProtocol = string.substr(0, suffixPos);
		// convert to lowercase
		std::transform(fProtocol.begin(), fProtocol.end(),
				fProtocol.begin(), ::tolower);
		size_t endProtocol = string.find_first_not_of(":/", suffixPos + 1);
		result = string.substr(endProtocol, std::string::npos);
	}

	// User/Password
	size_t authPos = result.find("@");
	if (authPos != std::string::npos) {
		size_t passPos = result.find(":");
		if (passPos != std::string::npos) {
			size_t passLen = authPos - passPos - 1;
			fUsername = result.substr(0, passPos);
			fPassword = result.substr(passPos + 1, passLen);
		}
		result = result.substr(authPos + 1, std::string::npos);
	}
	size_t portPos = result.find(":");
	if (portPos != std::string::npos) {
		fHost = result.substr(0, portPos);
		size_t slashPos = result.find("/", portPos);
		if (slashPos != std::string::npos)
			fPath = _NormalizedPath(result, slashPos);
		fPort = ::strtol(result.substr(portPos + 1, result.length()).c_str(),
			NULL, 10);
	} else {
		if (fProtocol == "https")
			fPort = 443;
		else
			fPort = 80;
		size_t slashPos = result.find("/");
		if (slashPos != std::string::npos) {
			fHost = result.substr(0, slashPos);
			fPath = _NormalizedPath(result, slashPos);
		} else
			fHost = result;
	}
}


/* static */
std::string
URL::_NormalizedPath(const std::string& string, size_t slashPos)
{
	// Collapse the leading slashes into one
	size_t endSlash = string.find_first_not_of("/", slashPos);
	if (endSlash == std::string::npos)
		return "/";
	return string.substr(endSlash - 1, std::string::npos);
}

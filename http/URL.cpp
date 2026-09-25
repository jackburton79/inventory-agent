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

	// The authority ([user[:password]@]host[:port]) ends at the first '/'
	size_t slashPos = result.find('/');
	std::string authority = result.substr(0, slashPos);
	if (slashPos != std::string::npos)
		fPath = _NormalizedPath(result, slashPos);

	// User/Password
	size_t authPos = authority.rfind('@');
	if (authPos != std::string::npos) {
		std::string userInfo = authority.substr(0, authPos);
		size_t passPos = userInfo.find(':');
		fUsername = userInfo.substr(0, passPos);
		if (passPos != std::string::npos)
			fPassword = userInfo.substr(passPos + 1);
		authority = authority.substr(authPos + 1);
	}

	std::string portString;
	if (!authority.empty() && authority[0] == '[') {
		// IPv6 address: [address]:port
		size_t endBracket = authority.find(']');
		fHost = authority.substr(1, endBracket == std::string::npos
			? std::string::npos : endBracket - 1);
		if (endBracket != std::string::npos && endBracket + 1 < authority.length()
			&& authority[endBracket + 1] == ':')
			portString = authority.substr(endBracket + 2);
	} else {
		size_t portPos = authority.find(':');
		fHost = authority.substr(0, portPos);
		if (portPos != std::string::npos)
			portString = authority.substr(portPos + 1);
	}

	if (!portString.empty())
		fPort = ::strtol(portString.c_str(), NULL, 10);
	else
		fPort = DefaultPort();
}


int
URL::DefaultPort() const
{
	return fProtocol == "https" ? 443 : 80;
}


std::string
URL::HostHeader() const
{
	// Host header value (RFC 7230): IPv6 addresses go in brackets,
	// the port is only needed when it's not the default one
	std::string host = fHost;
	if (host.find(':') != std::string::npos)
		host = "[" + host + "]";
	if (!host.empty() && fPort != DefaultPort())
		host.append(":").append(std::to_string(fPort));
	return host;
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

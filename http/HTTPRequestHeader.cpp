/*
 * HTTPRequestHeader.cpp
 *
 *  Created on: 23/lug/2013
 *  Copyright 2013-2024 Stefano Ceccherini (stefano.ceccherini@gmail.com)
 */

#include "HTTPDefines.h"
#include "HTTPRequestHeader.h"
#include "URL.h"
#include "Utils.h"

#include <iostream>


HTTPRequestHeader::HTTPRequestHeader()
{
	_Init();
}


HTTPRequestHeader::HTTPRequestHeader(const HTTPRequestHeader& header)
{
	//Full copy is done in the operator=()

	*this = header;
}


HTTPRequestHeader::HTTPRequestHeader(const std::string& method,
		const std::string& url, int majorVer, int minorVer)
{
	_Init();
	SetRequest(method, url);
}


HTTPRequestHeader::~HTTPRequestHeader()
{
}


std::string
HTTPRequestHeader::UserAgent() const
{
	return fUserAgent;
}


void
HTTPRequestHeader::SetUserAgent(const std::string& agent)
{
	fUserAgent = agent;
}


std::string
HTTPRequestHeader::Method() const
{
	return fMethod;
}


std::string
HTTPRequestHeader::URL() const
{
	return fURL;
}


void
HTTPRequestHeader::SetAuthentication(int type, std::string userName, std::string password)
{
	if (type != HTTP_AUTH_TYPE_BASIC)
		return;

	std::string auth("Basic ");
	std::string authString;
	authString.append(userName).append(":").append(password);
	authString = Base64Encode(authString);
	auth.append(authString);
	SetValue("Authorization", auth);
}


std::string
HTTPRequestHeader::ToString() const
{
	::URL url(fURL);
	std::string resource = url.Path();
	std::string string;
	string.append(fMethod).append(" ");
	string.append(resource).append(" ");
	string.append("HTTP/1.1").append(CRLF);
	string.append(HTTPUserAgent).append(": ").append(fUserAgent).append(CRLF);
	string.append(HTTPHeader::ToString());

	return string;
}


void
HTTPRequestHeader::SetRequest(const std::string& method,
		const std::string& url, int majorVer, int minorVer)
{
	fMethod = method;
	fURL = url;

	std::string hostName = ::URL(url).Host();
	if (hostName != "")
		fValues[HTTPHost] = hostName;
}



/* virtual */
void
HTTPRequestHeader::Clear()
{
	HTTPHeader::Clear();
	fMethod = "";
	fURL = "";

	_Init();
}


HTTPRequestHeader&
HTTPRequestHeader::operator=(const HTTPRequestHeader& header)
{
	HTTPHeader::operator=(header);

	SetRequest(header.fMethod, header.fURL);
	fUserAgent = header.fUserAgent;
	return *this;
}


void
HTTPRequestHeader::_Init()
{
	fUserAgent = "Borked HTTP Library";
}

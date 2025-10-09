/*
 * HTTPResponseHeader.cpp
 *
 *  Created on: 23/lug/2013
 *  Copyright 2013-2014 Stefano Ceccherini (stefano.ceccherini@gmail.com)
 */

#include "HTTPDefines.h"
#include "HTTPResponseHeader.h"

#include <iostream>

HTTPResponseHeader::HTTPResponseHeader()
	:
	fCode(0),
	fData(NULL)
{
}


HTTPResponseHeader::HTTPResponseHeader(int code, const std::string& text,
		const int majVersion, const int minVersion)
	:
	fCode(0),
	fData(NULL)
{
	SetStatusLine(code, text, majVersion, minVersion);
}


HTTPResponseHeader::HTTPResponseHeader(const HTTPResponseHeader& header)
	:
	fCode(0),
	fData(NULL)
{
	*this = header;
}


HTTPResponseHeader::~HTTPResponseHeader()
{
	delete[] fData;
}


std::string
HTTPResponseHeader::ReasonPhrase() const
{
	return fText;
}


void
HTTPResponseHeader::SetStatusLine(int code, const std::string& text,
		const int majVersion, const int minVersion)
{
	fCode = code;
	fText = text;
}


int
HTTPResponseHeader::StatusCode() const
{
	return fCode;
}


std::string
HTTPResponseHeader::StatusString() const
{
	return fText;
}


std::string
HTTPResponseHeader::ToString() const
{
	std::string string;
	string.append(fText).append(CRLF);
	string.append(HTTPHeader::ToString());

	return string;
}


/* virtual */
void
HTTPResponseHeader::Clear()
{
	HTTPHeader::Clear();
	fCode = 0;
	fText = "";
	delete[] fData;
	fData = NULL;
}


const char*
HTTPResponseHeader::Data() const
{
	return fData;
}


void
HTTPResponseHeader::SetData(char* data)
{
	fData = data;
}


HTTPResponseHeader&
HTTPResponseHeader::operator=(const HTTPResponseHeader& header)
{
	HTTPHeader::operator=(header);

	fText = header.fText;
	fCode = header.fCode;

	return *this;
}

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
	fData(NULL),
	fDataLength(0)
{
}


HTTPResponseHeader::HTTPResponseHeader(int code, const std::string& text,
		const int majVersion, const int minVersion)
	:
	fCode(0),
	fData(NULL),
	fDataLength(0)
{
	SetStatusLine(code, text, majVersion, minVersion);
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
	fDataLength = 0;
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


bool
HTTPResponseHeader::HasData() const
{
	return fDataLength > 0;
}


size_t
HTTPResponseHeader::DataLength() const
{
	return fDataLength;
}


void
HTTPResponseHeader::SetDataLength(size_t length)
{
	fDataLength = length;
}


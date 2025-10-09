/*
 * HTTP.cpp
 *
 *  Created on: 23/lug/2013
 *  Copyright 2013-2024 Stefano Ceccherini (stefano.ceccherini@gmail.com)
 */

#include "HTTP.h"
#include "HTTPDefines.h"
#include "HTTPRequestHeader.h"
#include "HTTPResponseHeader.h"
#include "Socket.h"
#include "SocketGetter.h"
#include "Support.h"
#include "URL.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <sstream>
#include <stdexcept>

HTTP::HTTP()
	:
	fPort(-1),
	fSocket(NULL),
	fLastError(0)
{
}


HTTP::HTTP(const std::string& string)
	:
	fPort(-1),
	fSocket(NULL),
	fLastError(0)
{
	SetHost(string);
}


HTTP::~HTTP()
{
	Close();
}


void
HTTP::Close()
{
	if (fSocket != NULL) {
		fSocket->Close();
		delete fSocket;
		fSocket = NULL;
	}
}


const HTTPRequestHeader&
HTTP::CurrentRequest() const
{
	return fCurrentRequest;
}


int
HTTP::Error() const
{
	return fLastError;
}


std::string
HTTP::ErrorString() const
{
	return ::strerror(fLastError);
}


const HTTPResponseHeader&
HTTP::LastResponse() const
{
	return fLastResponse;
}


int
HTTP::SetHost(const std::string& hostName)
{
	try {
		URL url(hostName.c_str());
		fHost = url.Host();
		fPort = url.Port();
		fLastError = 0;
	} catch (...) {
		fLastError = -1;
	}
	return fLastError;
}


int
HTTP::Get(const std::string& path)
{
	HTTPRequestHeader requestHeader("GET", path);
	return Request(requestHeader);
}


int
HTTP::Put(const std::string& path, const char* data, const size_t dataLength)
{
	HTTPRequestHeader requestHeader("PUT", path);
	return Request(requestHeader, data, dataLength);
}


int
HTTP::Post(const std::string& path, const char* data, const size_t dataLength)
{
	HTTPRequestHeader requestHeader("POST", path);
	return Request(requestHeader, data, dataLength);
}


int
HTTP::Read(void* data,  const size_t& length)
{
	if (fSocket->Read(data, length) != length) {
		fLastError = errno;
		return errno;
	}

	return length;
}


int
HTTP::Request(const HTTPRequestHeader& header, const void* data, const size_t dataLength)
{
	if (!_HandleConnection(header.URL()))
		return -1;

	fCurrentRequest = header;
	if (fCurrentRequest.URL() == "")
		fCurrentRequest.SetValue(HTTPHost, fHost);

	std::string string = fCurrentRequest.ToString().append(CRLF);

	if (fSocket->Write(string.c_str(), string.length()) != string.length()) {
		fLastError = errno;
		return errno;
	}

	if (data != NULL && dataLength != 0) {
		if (fSocket->Write(data, dataLength) != dataLength) {
			fLastError = errno;
			return errno;
		}
	}

	std::string replyString;
	try {
		_ReadLineFromSocket(replyString, fSocket);
	} catch (int error) {
		fLastError = error;
		return error;
	}

	int code;
	::sscanf(replyString.c_str(), "HTTP/1.%*d %03d", &code);
	try {
		fLastResponse.Clear();
		fLastResponse.SetStatusLine(code, replyString);
		while (_ReadLineFromSocket(replyString, fSocket)) {
			size_t pos = replyString.find(":");
			std::string value = replyString.substr(pos + 1, std::string::npos);
			trim(value);
			fLastResponse.SetValue(replyString.substr(0, pos), value);
		}
	} catch (int error) {
		fLastError = error;
		return error;
	} catch (...) {
		fLastError = -1;
		return -1;
	}

	if (fLastResponse.HasContentLength()) {
		const size_t contentLength = fLastResponse.ContentLength();
		// Read data
		char* resultData = new char[contentLength];
		int read = Read(resultData, contentLength);
		if (read != (int)contentLength) {
			fLastError = read;
			delete[] resultData;
			return fLastError;
		}
		fLastResponse.SetData(resultData);
	}
	return 0;
}


bool
HTTP::_HandleConnection(const std::string& string)
{
	URL url(string.c_str());
	std::string hostName = url.Host();
	int port = url.Port();
	if (url.IsRelative()) {
		// url is relative, reuse the old host/port
		hostName = fHost;
		port = fPort;
	}

	if (hostName == "")
		return false;

	// Check if we are already connected to this server,
	// so we can reuse the existing connection
	if (fSocket != NULL && fSocket->IsOpened()) {
		if (hostName == fHost && port == fPort) {
			// But not if the server closed it from its side
			HTTPResponseHeader lastResponse = LastResponse();
			if (!lastResponse.HasKey("connection")
				|| lastResponse.Value("connection") != "close") {
				return true;
			}
		}
		// Different server, or same server, but connection closed
		delete fSocket;
		fSocket = NULL;
	}

	fHost = hostName;
	fPort = port;

	try {
		fSocket = SocketGetter().GetSocket(url.Protocol());
		if (fSocket->Open(AF_INET, SOCK_STREAM, 0) < 0)
			throw errno;
	} catch (int& error) {
		fLastError = error;
		delete fSocket;
		fSocket = NULL;
		return false;
	} catch (...) {
		fLastError = -1;
		delete fSocket;
		fSocket = NULL;
		return false;
	}

	struct timeval tv;
	tv.tv_sec = 15;
	tv.tv_usec = 0;

	fSocket->SetOption(SOL_SOCKET, SO_KEEPALIVE, 0, 0);
	fSocket->SetOption(SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));
	fSocket->SetOption(SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(struct timeval));

	int status = fSocket->Connect(fHost.c_str(), fPort);
	if (status != 0) {
		fLastError = status;
		delete fSocket;
		fSocket = NULL;
		return false;
	}

	fLastError = 0;

	return true;
}


/* static */
bool
HTTP::_ReadLineFromSocket(std::string& string, Socket* socket)
{
	std::ostringstream s;
	char byte;
	int sizeRead = 0;
	while ((sizeRead = socket->Read(&byte, 1)) > 0) {
		if (byte == '\012')
			break;
		if (byte != '\015')
			s.write(&byte, sizeRead);
	}

	if (sizeRead < 0)
		throw errno;

	string = s.str();

	if (string == "")
		return false;

	return true;
}

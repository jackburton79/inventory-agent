/*
 * Socket.cpp
 *
 *  Created on: 12/07/2017
 *  Copyright 2017-2023 Stefano Ceccherini
 */

#include "Socket.h"

#include <arpa/inet.h>
#include <string>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <netdb.h>
#include <stdexcept>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


Socket::Socket(const std::string& options)
	:
	fFD(-1)
{
}


Socket::~Socket()
{
	Socket::Close();
}


int
Socket::Open(int domain, int type, int protocol)
{
	if (fFD >= 0)
		return -1;
	fFD = ::socket(domain, type, protocol);
	return fFD;
}


void
Socket::Close()
{
	if (fFD >= 0) {
		::close(fFD);
		fFD = -1;
	}
	fHostName = "";
}


int
Socket::FD() const
{
	return fFD;
}


std::string
Socket::HostName() const
{
	return fHostName;
}


bool
Socket::IsOpened() const
{
	return fFD >= 0;
}


void
Socket::SetOption(int level, int name, const void *value, socklen_t len)
{
	::setsockopt(fFD, level, name, value, len);
}


int
Socket::Connect(const struct sockaddr *address, socklen_t addrLen)
{
	return ::connect(fFD, address, addrLen);
}


int
Socket::Connect(const struct hostent* hostEnt, const int port)
{
	struct sockaddr_in serverAddr;
	::memset(&serverAddr, 0, sizeof(serverAddr));
	::memcpy(&serverAddr.sin_addr, hostEnt->h_addr, hostEnt->h_length);
	serverAddr.sin_family = hostEnt->h_addrtype;
	serverAddr.sin_port = (unsigned short)htons(port);

	return Connect((const struct sockaddr*)&serverAddr, sizeof(serverAddr));
}


int
Socket::Connect(const char* hostName, const int port)
{
	struct hostent* hostEnt = ::gethostbyname(hostName);
	if (hostEnt == NULL)
		return h_errno;

	fHostName = hostName;
	return Connect(hostEnt, port);
}


size_t
Socket::Read(void* data, const size_t& length)
{
	char* ptr = static_cast<char*>(data);
	size_t totalRead = 0;
	while (totalRead < length) {
		ssize_t bytesRead = ::read(fFD, ptr + totalRead, length - totalRead);
		if (bytesRead < 0) {
			if (errno == EINTR)
				continue;

			return totalRead;
		}

		if (bytesRead == 0)
			break;

		totalRead += bytesRead;
	}

	return totalRead;
}


size_t
Socket::Write(const void* data, const size_t& length)
{
	const char* ptr =
		static_cast<const char*>(data);
	size_t totalWritten = 0;
	while (totalWritten < length) {
		ssize_t bytesWritten = ::write(fFD, ptr + totalWritten, length - totalWritten);
		if (bytesWritten < 0) {
			if (errno == EINTR)
				continue;

			return totalWritten;
		}

		totalWritten += bytesWritten;
	}

	return totalWritten;
}

/*
 * Socket.cpp
 *
 *  Created on: 12/07/2017
 *  Copyright 2017 Stefano Ceccherini (stefano.ceccherini@gmail.com)
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


Socket::Socket()
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
	::memset((char*)&serverAddr, 0, sizeof(serverAddr));
	::memcpy((char*)&serverAddr.sin_addr, hostEnt->h_addr, hostEnt->h_length);
	serverAddr.sin_family = hostEnt->h_addrtype;
	serverAddr.sin_port = (unsigned short)htons(port);

	return Connect((const struct sockaddr*)&serverAddr,
			sizeof(serverAddr));
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
	return ::read(fFD, data, length);
}


size_t
Socket::Write(const void* data, const size_t& length)
{
	return ::write(fFD, data, length);
}

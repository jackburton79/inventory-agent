/*
 * Socket.cpp
 *
 *  Created on: 12/07/2017
 *  Copyright 2017-2023 Stefano Ceccherini
 */

#include "Socket.h"

#include "Logger.h"

#include <arpa/inet.h>
#include <string>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <iostream>
#include <netdb.h>
#include <stdexcept>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


Socket::Socket(const std::string& options)
	:
	fFD(-1),
	fType(SOCK_STREAM),
	fProtocol(0)
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
	fType = type;
	fProtocol = protocol;
	return _OpenFD(domain);
}


void
Socket::Close()
{
	_CloseFD();
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
	SocketOption option;
	option.level = level;
	option.name = name;
	if (value != NULL && len > 0) {
		const char* bytes = static_cast<const char*>(value);
		option.value.assign(bytes, bytes + len);
	}

	// Remember the option, replacing an older value
	bool found = false;
	for (SocketOption& existing : fOptions) {
		if (existing.level == level && existing.name == name) {
			existing = option;
			found = true;
			break;
		}
	}
	if (!found)
		fOptions.push_back(option);

	if (fFD >= 0)
		::setsockopt(fFD, level, name, value, len);
}


int
Socket::Connect(const struct sockaddr *address, socklen_t addrLen)
{
	if (::connect(fFD, address, addrLen) != 0)
		return errno;
	return 0;
}


int
Socket::Connect(const char* hostName, const int port)
{
	struct addrinfo hints;
	::memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = fType;
	hints.ai_protocol = fProtocol;

	const std::string service = std::to_string(port);
	struct addrinfo* addresses = NULL;
	int status = ::getaddrinfo(hostName, service.c_str(), &hints, &addresses);
	if (status != 0) {
		Logger::LogFormat(LOG_ERR, "Socket: cannot resolve %s: %s", hostName,
			::gai_strerror(status));
		return EHOSTUNREACH;
	}

	fHostName = hostName;

	int error = EHOSTUNREACH;
	for (struct addrinfo* address = addresses; address != NULL; address = address->ai_next) {
		char addressString[INET6_ADDRSTRLEN] = "";
		::getnameinfo(address->ai_addr, address->ai_addrlen, addressString,
			sizeof(addressString), NULL, 0, NI_NUMERICHOST);

		// (Re)open the socket with the family of this address
		_CloseFD();
		if (_OpenFD(address->ai_family) < 0) {
			error = errno;
			Logger::LogFormat(LOG_DEBUG, "Socket: cannot create a socket for %s: %s",
				addressString, ::strerror(error));
			continue;
		}

		error = Connect(address->ai_addr, address->ai_addrlen);
		if (error == 0)
			break;

		Logger::LogFormat(LOG_DEBUG, "Socket: cannot connect to %s (%s) port %d: %s",
			hostName, addressString, port, error > 0 ? ::strerror(error) : "protocol error");
	}
	::freeaddrinfo(addresses);

	if (error != 0) {
		_CloseFD();
		Logger::LogFormat(LOG_ERR, "Socket: cannot connect to %s port %d", hostName, port);
	}
	return error;
}


int
Socket::_OpenFD(int domain)
{
	fFD = ::socket(domain, fType, fProtocol);
	if (fFD < 0)
		return fFD;

	for (const SocketOption& option : fOptions) {
		::setsockopt(fFD, option.level, option.name,
			option.value.empty() ? NULL : option.value.data(),
			static_cast<socklen_t>(option.value.size()));
	}
	return fFD;
}


void
Socket::_CloseFD()
{
	if (fFD >= 0) {
		::close(fFD);
		fFD = -1;
	}
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

/*
 * Socket.h
 *
 *  Created on: 12/07/2017
 *  Copyright 2017 Stefano Ceccherini (stefano.ceccherini@gmail.com)
 */

#ifndef SOCKET_H
#define SOCKET_H

#include <netinet/in.h>
#include <string>

class Socket {
public:
	Socket();
	virtual ~Socket();

	virtual int Open(int domain, int type, int protocol);
	virtual void Close();

	int FD() const;
	std::string HostName() const;
	bool IsOpened() const;

	virtual int Connect(const struct sockaddr *address, socklen_t addrLen);
	int Connect(const struct hostent* hostEnt, const int port);
	int Connect(const char *hostName, const int port);

	void SetOption(int level, int name, const void *value, socklen_t len);

	virtual size_t Read(void* data, const size_t& length);
	virtual size_t Write(const void* data, const size_t& length);

private:
	int fFD;
	std::string fHostName;
};

#endif // SOCKET_H

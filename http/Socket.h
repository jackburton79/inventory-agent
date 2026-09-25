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
#include <vector>

class Socket {
public:
	Socket(const std::string& options = "");
	virtual ~Socket();

	virtual int Open(int domain, int type, int protocol);
	virtual void Close();

	int FD() const;
	std::string HostName() const;
	bool IsOpened() const;

	virtual int Connect(const struct sockaddr *address, socklen_t addrLen);
	// Resolves hostName (IPv4 and IPv6) and tries all its addresses
	// in turn, (re)opening the socket with the right address family.
	// Returns 0 on success, an errno value on failure.
	int Connect(const char *hostName, const int port);

	// The options are remembered and applied again when the socket
	// is reopened by Connect(), so they can be set before connecting.
	void SetOption(int level, int name, const void *value, socklen_t len);

	virtual size_t Read(void* data, const size_t& length);
	virtual size_t Write(const void* data, const size_t& length);

private:
	struct SocketOption {
		int level;
		int name;
		std::vector<char> value;
	};

	int _OpenFD(int domain);
	void _CloseFD();

	int fFD;
	int fType;
	int fProtocol;
	std::string fHostName;
	std::vector<SocketOption> fOptions;
};

#endif // SOCKET_H

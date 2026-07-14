/*
 * SSLSocket.h
 *
 *  Created on: 12/07/2017
 *  Copyright 2017 Stefano Ceccherini (stefano.ceccherini@gmail.com)
 */

#ifndef SSLSOCKET_H
#define SSLSOCKET_H

#include "Socket.h"

#include <openssl/ssl.h>

class SSLSocket : public Socket {
public:
	SSLSocket(const std::string& options = "");
	virtual ~SSLSocket();

	virtual int Open(int domain, int type, int protocol);
	virtual void Close();

	virtual int Connect(const struct sockaddr *address, socklen_t addrLen);

	virtual size_t Read(void* data, const size_t& length);
	virtual size_t Write(const void* data, const size_t& length);

private:
	void _SSLInit();
	bool _CheckCertificate();

	SSL* fSSLConnection;
	bool fNoSSLCheck;
};

#endif // SSLSOCKET_H

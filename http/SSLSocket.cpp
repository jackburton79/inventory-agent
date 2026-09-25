/*
 * SSLSocket.cpp
 *
 *  Created on: 12/07/2017
 *  Copyright 2017 Stefano Ceccherini (stefano.ceccherini@gmail.com)
 */

#include "SSLSocket.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <unistd.h>


#include "Logger.h"

static SSL_CTX* sSSLContext = NULL;


static bool
IsIPAddress(const std::string& string)
{
	struct in6_addr address;
	return ::inet_pton(AF_INET, string.c_str(), &address) == 1
		|| ::inet_pton(AF_INET6, string.c_str(), &address) == 1;
}


static const char*
SSLErrorString(int error)
{
	switch (error) {
		case SSL_ERROR_NONE:
			return "SSL_ERROR_NONE";

		case SSL_ERROR_ZERO_RETURN:
			return "SSL_ERROR_ZERO_RETURN";

		case SSL_ERROR_WANT_READ:
			return "SSL_ERROR_WANT_READ";

		case SSL_ERROR_WANT_WRITE:
			return "SSL_ERROR_WANT_WRITE";

		case SSL_ERROR_SYSCALL:
			return "SSL_ERROR_SYSCALL";

		case SSL_ERROR_SSL:
			return "SSL_ERROR_SSL";

		default:
			return "SSL_ERROR_UNKNOWN";
	}
}


SSLSocket::SSLSocket(const std::string& options)
	:
	fSSLConnection(NULL),
	fNoSSLCheck(false)
{
	if (sSSLContext == NULL)
		_SSLInit();

	if (options.find("no_ssl_check") != std::string::npos)
		fNoSSLCheck = true;
}


SSLSocket::~SSLSocket()
{
	Close();
}


int
SSLSocket::Open(int domain, int type, int protocol)
{
	return Socket::Open(domain, type, protocol);
}


void
SSLSocket::Close()
{
	if (fSSLConnection != NULL) {
		SSL_shutdown(fSSLConnection);
		SSL_free(fSSLConnection);
		fSSLConnection = NULL;
	}
	Socket::Close();
}


int
SSLSocket::Connect(const struct sockaddr *address, socklen_t addrLen)
{
	// Socket::Connect(hostName, port) calls us for every address of
	// the host: free the connection of a previous attempt, if any
	if (fSSLConnection != NULL) {
		SSL_free(fSSLConnection);
		fSSLConnection = NULL;
	}

	int status = Socket::Connect(address, addrLen);
	if (status != 0)
		return status;

	fSSLConnection = SSL_new(sSSLContext);
	if (fSSLConnection == NULL)
		return -1;
	// SNI must not be used with IP addresses (RFC 6066)
	if (!HostName().empty() && !IsIPAddress(HostName()))
		SSL_set_tlsext_host_name(fSSLConnection, HostName().c_str());

	if (!fNoSSLCheck && !_SetupVerification())
		return -1;

	SSL_set_fd(fSSLConnection, FD());
	status = SSL_connect(fSSLConnection);
	if (status != 1) {
		int sslError = SSL_get_error(fSSLConnection, status);
		Logger::LogFormat(LOG_ERR, "SSL_connect() failed: %s", SSLErrorString(sslError));
		long verifyResult = SSL_get_verify_result(fSSLConnection);
		if (!fNoSSLCheck && verifyResult != X509_V_OK) {
			Logger::LogFormat(LOG_ERR, "TLS certificate validation failed for host %s: %s",
				HostName().c_str(), X509_verify_cert_error_string(verifyResult));
		}
		// TODO: Pass the error to the upper layers ?
		return -1;
	}

	// Connection estabilished successfully.
	if (!fNoSSLCheck && !_CheckCertificate()) {
		Logger::LogFormat(LOG_DEBUG, "SSLSocket::Connect(): certificate error ");
		return -1;
	}
	return 0;
}


size_t
SSLSocket::Read(void* data, const size_t& length)
{
	// TODO: We don't report any error to the upper layers,
	// we only report the total read bytes
	char* ptr = static_cast<char*>(data);
	size_t totalRead = 0;

	while (totalRead < length) {
		int bytesRead =
			SSL_read(fSSLConnection, ptr + totalRead, static_cast<int>(length - totalRead));

		if (bytesRead <= 0)
			break;

		totalRead += bytesRead;
	}

	return totalRead;
}


size_t
SSLSocket::Write(const void* data, const size_t& length)
{
	// TODO: We don't report any error to the upper layers,
	// we only report the total written bytes
	const char* ptr = static_cast<const char*>(data);
	size_t totalWritten = 0;

	while (totalWritten < length) {
		int bytesWritten = SSL_write(fSSLConnection, ptr + totalWritten,
			static_cast<int>(length - totalWritten));

		if (bytesWritten <= 0)
			break;

		totalWritten += bytesWritten;
	}

	return totalWritten;
}


bool
SSLSocket::_SetupVerification()
{
	// Let OpenSSL verify the certificate chain and the hostname
	// (SAN/CN, including wildcards) during the handshake
	SSL_set_verify(fSSLConnection, SSL_VERIFY_PEER, NULL);

	const std::string hostName = HostName();
	if (hostName.empty()) {
		Logger::Log(LOG_ERR, "TLS: cannot verify certificate: unknown host name");
		return false;
	}

	X509_VERIFY_PARAM* param = SSL_get0_param(fSSLConnection);
	X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	// If the host is an IP address, match it against the IP SAN entries,
	// otherwise match the DNS name
	if (X509_VERIFY_PARAM_set1_ip_asc(param, hostName.c_str()) != 1
		&& X509_VERIFY_PARAM_set1_host(param, hostName.c_str(), 0) != 1) {
		Logger::LogFormat(LOG_ERR, "TLS: cannot set expected host name %s",
			hostName.c_str());
		return false;
	}

	return true;
}


void
SSLSocket::_SSLInit()
{
	if (sSSLContext == NULL) {
		sSSLContext = SSL_CTX_new(TLS_client_method());
		if (sSSLContext == NULL)
			throw std::runtime_error("SSL: can't initialize SSL Library");
		SSL_CTX_set_default_verify_paths(sSSLContext);
	}
}


bool
SSLSocket::_CheckCertificate()
{
	// Chain, validity period and hostname are verified by OpenSSL
	// during the handshake (see Connect()). Double check the result here.
	X509 *cert = SSL_get_peer_certificate(fSSLConnection);
	if (cert == NULL) {
		Logger::LogFormat(LOG_ERR, "TLS: no certificate presented by host %s",
			HostName().c_str());
		return false;
	}
	X509_free(cert);

	long verifyResult = SSL_get_verify_result(fSSLConnection);
	if (verifyResult != X509_V_OK) {
		Logger::LogFormat(LOG_ERR, "TLS certificate validation failed for host %s: %s",
			HostName().c_str(), X509_verify_cert_error_string(verifyResult));
		return false;
	}

	return true;
}

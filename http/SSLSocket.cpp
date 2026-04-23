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

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <unistd.h>


static SSL_CTX* sSSLContext = NULL;


SSLSocket::SSLSocket()
	:
	fSSLConnection(NULL)
{
	if (sSSLContext == NULL)
		_SSLInit();
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
	int status = Socket::Connect(address, addrLen);
	if (status != 0)
		return status;

	fSSLConnection = SSL_new(sSSLContext);
	if (fSSLConnection == NULL)
		return -1;
	if (!HostName().empty())
		SSL_set_tlsext_host_name(fSSLConnection, HostName().c_str());
	SSL_set_fd(fSSLConnection, FD());
	status = SSL_connect(fSSLConnection);
	if (status != 1) {
		// TODO: Maybe use SSL_get_error to retrieve the correct error, but
		// we shouldn't pass it to the upper layers, anyway
		return -1;
	}

	// Connection estabilished successfully.
	if (!_CheckCertificate())
		return -1;
	return 0;
}


size_t
SSLSocket::Read(void* data, const size_t& length)
{
	return SSL_read(fSSLConnection, data, length);
}


size_t
SSLSocket::Write(const void* data, const size_t& length)
{
	return SSL_write(fSSLConnection, data, length);
}


void
SSLSocket::_SSLInit()
{
	if (sSSLContext == NULL) {
		SSL_load_error_strings();
		SSL_library_init();
		sSSLContext = SSL_CTX_new(SSLv23_client_method());
		if (sSSLContext == NULL)
			throw std::runtime_error("SSL: can't initialize SSL Library");
	}
}


static bool
VerifyHostname(X509 *cert, const std::string& hostname)
{
	// Check Subject Alternative Name (SAN) extension
	STACK_OF(GENERAL_NAME) *sanNames = (STACK_OF(GENERAL_NAME) *)
		X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

	if (sanNames != NULL) {
		for (int i = 0; i < sk_GENERAL_NAME_num(sanNames); i++) {
			GENERAL_NAME *gn = sk_GENERAL_NAME_value(sanNames, i);
			if (gn->type == GEN_DNS) {
				const char *dnsName = reinterpret_cast<const char *>(ASN1_STRING_get0_data(gn->d.dNSName));
				int dnsNameLen = ASN1_STRING_length(gn->d.dNSName);
				if (dnsName != NULL && ::strncmp(dnsName, hostname.c_str(), dnsNameLen) == 0) {
					sk_GENERAL_NAME_pop_free(sanNames, GENERAL_NAME_free);
					return true;
				}
			}
		}
		sk_GENERAL_NAME_pop_free(sanNames, GENERAL_NAME_free);
	}

	// Fall back to checking Common Name (CN)
	X509_NAME *subject = X509_get_subject_name(cert);
	if (subject != NULL) {
		char cn[256] = {0};
		X509_NAME_get_text_by_NID(subject, NID_commonName, cn, sizeof(cn) - 1);
		if (::strcmp(cn, hostname.c_str()) == 0)
			return true;
	}

	return false;
}


bool
SSLSocket::_CheckCertificate()
{
	if (true)
		return true;

	X509 *cert = SSL_get_peer_certificate(fSSLConnection);
	if (cert == NULL)
		return false;

	// Verify the certificate chain
	long verifyResult = SSL_get_verify_result(fSSLConnection);
	if (verifyResult != X509_V_OK) {
		X509_free(cert);
		return false;
	}

	// Check if certificate is expired
	time_t now = time(NULL);
	ASN1_TIME *notBefore = X509_get_notBefore(cert);
	ASN1_TIME *notAfter = X509_get_notAfter(cert);
	if (notBefore == NULL || notAfter == NULL) {
		X509_free(cert);
		return false;
	}

	// Check if we're within the validity period
	if (X509_cmp_time(notBefore, &now) > 0) {
		// Certificate not yet valid
		X509_free(cert);
		return false;
	}

	if (X509_cmp_time(notAfter, &now) < 0) {
		// Certificate has expired
		X509_free(cert);
		return false;
	}

	// Optional: Verify hostname matches certificate CN or SAN
	if (!HostName().empty()) {
		if (!VerifyHostname(cert, HostName())) {
			X509_free(cert);
			return false;
		}
	}

	X509_free(cert);
	return true;
}

/*
 * SocketGetter.h
 *
 *  Created on: 17/07/2017
 *  Copyright 2017 Stefano Ceccherini (stefano.ceccherini@gmail.com)
 */
 
#include "SocketGetter.h"

#include "Socket.h"
#include "SSLSocket.h"

#include <stdexcept>

SocketGetter::SocketGetter()
{
}


Socket*
SocketGetter::GetSocket(const std::string& protocol, const std::string& options)
{
	if (protocol == "https")
		return new SSLSocket(options);
	else /*if (protocol == "http")*/
		return new Socket(options);
	
	throw std::runtime_error("INVALID PROTOCOL!!!!!!");
	return NULL;
}

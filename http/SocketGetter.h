/*
 * SocketGetter.h
 *
 *  Created on: 17/07/2017
 *  Copyright 2017 Stefano Ceccherini (stefano.ceccherini@gmail.com)
 */
 
#ifndef __SOCKETGETTER_H
#define __SOCKETGETTER_H

#include <string>

class Socket;
class SocketGetter {
public:
	SocketGetter();
	Socket* GetSocket(const std::string& protocol, const std::string& options = "");
};

#endif // __SOCKETGETTER_H

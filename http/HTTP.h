/*
 * HTTP.h
 *
 *  Created on: 23/lug/2013
 *  Copyright 2013-2024 Stefano Ceccherini (stefano.ceccherini@gmail.com)
 *
 *  HTTP Class.
 *  Interface roughly based on QT QHTTP class.
 */

#ifndef HTTP_H_
#define HTTP_H_

#include <string>

#include "HTTPDefines.h"
#include "HTTPRequestHeader.h"
#include "HTTPResponseHeader.h"

class Socket;
class HTTP {
public:
	HTTP();
	HTTP(const std::string& string);
	~HTTP();

	void Close();

	int SetHost(const std::string& hostName);

	int Get(const std::string& path);
	int Put(const std::string& path, const char* data, const size_t dataLength);
	int Post(const std::string& path, const char* data, const size_t dataLength);
	int Request(const HTTPRequestHeader& header, const void* data = NULL,
			const size_t dataLength = 0);

	int Read(void* data, const size_t& length);

	const HTTPRequestHeader& CurrentRequest() const;
	const HTTPResponseHeader& LastResponse() const;

	int Error() const;
	std::string ErrorString() const;
	
private:
	bool _HandleConnection(const std::string& string);

	static bool _ReadLineFromSocket(std::string& string, Socket* socket);
	static int _ReadChunkedData(Socket* socket, std::string& data);

	std::string fHost;
	int fPort;
	Socket* fSocket;
	int fLastError;

	HTTPRequestHeader fCurrentRequest;
	HTTPResponseHeader fLastResponse;
};


#endif /* HTTP_H_ */

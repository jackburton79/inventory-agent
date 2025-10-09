/*
 * HTTPResponseHeader.h
 *
 *  Created on: 23/lug/2013
 *  Copyright 2013-2024 Stefano Ceccherini (stefano.ceccherini@gmail.com)
 */

#ifndef HTTPRESPONSEHEADER_H_
#define HTTPRESPONSEHEADER_H_

#include "HTTPHeader.h"

class HTTPResponseHeader: public HTTPHeader {
public:
	HTTPResponseHeader();
	HTTPResponseHeader(int code, const std::string& text = "",
			const int majVersion = 1, const int minVersion = 1);
	HTTPResponseHeader(const HTTPResponseHeader& header);
	~HTTPResponseHeader();

	std::string ReasonPhrase() const;
	void SetStatusLine(int code, const std::string& text = "",
			const int majVersion = 1, const int minVersion = 1);
	int StatusCode() const;
	std::string StatusString() const;

	virtual std::string ToString() const;

	virtual void Clear();

	const char* Data() const;
	void SetData(char* data);

	HTTPResponseHeader& operator=(const HTTPResponseHeader& header);

private:
	std::string fText;
	int fCode;
	char* fData;
};

#endif /* HTTPRESPONSEHEADER_H_ */

/*
 * httptest.cpp
 *
 * Tests for the HTTP client response parsing, against a minimal local
 * server which sends canned replies.
 */

#include "http/HTTP.h"
#include "http/HTTPResponseHeader.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>


// Accepts one connection and, for each request received on it, sends
// the next canned reply. The connection is closed after the last reply.
class CannedServer {
public:
	CannedServer(const std::vector<std::string>& replies)
		:
		fReplies(replies),
		fListenFD(-1),
		fPort(0)
	{
		fListenFD = ::socket(AF_INET, SOCK_STREAM, 0);
		int reuse = 1;
		::setsockopt(fListenFD, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

		struct sockaddr_in address;
		::memset(&address, 0, sizeof(address));
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		address.sin_port = 0;
		if (::bind(fListenFD, (struct sockaddr*)&address, sizeof(address)) != 0
			|| ::listen(fListenFD, 1) != 0) {
			std::cerr << "CannedServer: cannot listen" << std::endl;
			::exit(2);
		}

		socklen_t length = sizeof(address);
		::getsockname(fListenFD, (struct sockaddr*)&address, &length);
		fPort = ntohs(address.sin_port);

		fThread = std::thread(&CannedServer::_Serve, this);
	}

	~CannedServer()
	{
		fThread.join();
		::close(fListenFD);
	}

	std::string URL(const std::string& path = "/test") const
	{
		return "http://127.0.0.1:" + std::to_string(fPort) + path;
	}

private:
	void _Serve()
	{
		int fd = ::accept(fListenFD, NULL, NULL);
		if (fd < 0)
			return;

		for (const std::string& reply : fReplies) {
			if (!_ReadRequest(fd))
				break;
			if (::write(fd, reply.data(), reply.length()) < 0)
				break;
		}
		::close(fd);
	}

	// Reads the request headers (the tests don't send bodies)
	static bool _ReadRequest(int fd)
	{
		std::string request;
		char byte;
		while (request.find("\r\n\r\n") == std::string::npos) {
			if (::read(fd, &byte, 1) != 1)
				return false;
			request.push_back(byte);
		}
		return true;
	}

	std::vector<std::string> fReplies;
	int fListenFD;
	int fPort;
	std::thread fThread;
};


static int sFailures = 0;


static void
Check(bool condition, const std::string& testName, const std::string& what)
{
	if (!condition) {
		std::cout << "  FAILED: " << testName << ": " << what << std::endl;
		sFailures++;
	}
}


static std::string
Body(const HTTPResponseHeader& response)
{
	if (response.Data() == NULL)
		return "";
	return std::string(response.Data(), response.DataLength());
}


static void
TestContentLength()
{
	const std::string name = "Content-Length body";
	std::cout << name << std::endl;
	CannedServer server({
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: application/xml\r\n"
		"Content-Length: 11\r\n"
		"\r\n"
		"hello world"
	});

	HTTP http;
	Check(http.Get(server.URL()) == 0, name, "Get() failed");
	const HTTPResponseHeader& response = http.LastResponse();
	Check(response.StatusCode() == 200, name, "wrong status code");
	Check(response.ContentType() == "application/xml", name, "wrong content type");
	Check(response.HasData(), name, "no data");
	Check(Body(response) == "hello world", name, "wrong body: '" + Body(response) + "'");
}


static void
TestChunked()
{
	const std::string name = "chunked body";
	std::cout << name << std::endl;
	CannedServer server({
		"HTTP/1.1 200 OK\r\n"
		"Transfer-Encoding: chunked\r\n"
		"\r\n"
		"5\r\nhello\r\n"
		"1;some-extension=1\r\n \r\n"
		"A\r\n0123456789\r\n"
		"0\r\n"
		"X-Trailer: value\r\n"
		"\r\n"
	});

	HTTP http;
	Check(http.Get(server.URL()) == 0, name, "Get() failed");
	const HTTPResponseHeader& response = http.LastResponse();
	Check(response.StatusCode() == 200, name, "wrong status code");
	Check(Body(response) == "hello 0123456789", name, "wrong body: '" + Body(response) + "'");
	Check(response.DataLength() == 16, name, "wrong data length");
}


static void
TestNoBody()
{
	const std::string name = "no body";
	std::cout << name << std::endl;
	CannedServer server({
		"HTTP/1.1 204 No Content\r\n"
		"Server: test\r\n"
		"\r\n"
	});

	HTTP http;
	Check(http.Get(server.URL()) == 0, name, "Get() failed");
	const HTTPResponseHeader& response = http.LastResponse();
	Check(response.StatusCode() == 204, name, "wrong status code");
	Check(!response.HasData(), name, "HasData() should be false");
	Check(response.DataLength() == 0, name, "DataLength() should be 0");
}


static void
TestKeepAlive()
{
	// Two requests on the same connection: the data of the first
	// reply must not leak into the second one
	const std::string name = "keep-alive";
	std::cout << name << std::endl;
	CannedServer server({
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 5\r\n"
		"\r\n"
		"first",
		"HTTP/1.1 404 Not Found\r\n"
		"Server: test\r\n"
		"\r\n"
	});

	HTTP http;
	Check(http.Get(server.URL()) == 0, name, "first Get() failed");
	Check(Body(http.LastResponse()) == "first", name, "wrong first body");
	Check(http.Get(server.URL()) == 0, name, "second Get() failed");
	const HTTPResponseHeader& response = http.LastResponse();
	Check(response.StatusCode() == 404, name, "wrong second status code");
	Check(!response.HasData(), name, "second reply should have no data");
	Check(!response.HasContentLength(), name, "stale Content-Length header");
}


static void
TestHeaders()
{
	const std::string name = "header parsing";
	std::cout << name << std::endl;
	CannedServer server({
		"HTTP/1.1 200 OK\r\n"
		"X-Spaces:    value with spaces   \r\n"
		"X-Colon: a:b:c\r\n"
		"this line has no colon\r\n"
		"content-length: 2\r\n"
		"\r\n"
		"ok"
	});

	HTTP http;
	Check(http.Get(server.URL()) == 0, name, "Get() failed");
	const HTTPResponseHeader& response = http.LastResponse();
	Check(response.Value("X-Spaces") == "value with spaces", name,
		"value not trimmed: '" + response.Value("X-Spaces") + "'");
	Check(response.Value("x-colon") == "a:b:c", name,
		"wrong value with colons: '" + response.Value("x-colon") + "'");
	Check(!response.HasKey("this line has no colon"), name,
		"a line without colon was parsed as header");
	Check(Body(response) == "ok", name, "wrong body (lowercase content-length)");
}


static void
TestMalformedStatusLine()
{
	const std::string name = "malformed status line";
	std::cout << name << std::endl;
	CannedServer server({
		"garbage\r\n"
		"\r\n"
	});

	HTTP http;
	Check(http.Get(server.URL()) != 0, name, "Get() should fail");
	Check(http.LastResponse().StatusCode() == 0, name, "status code should be 0");
}


static void
TestTruncatedBody()
{
	const std::string name = "truncated body";
	std::cout << name << std::endl;
	CannedServer server({
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 100\r\n"
		"\r\n"
		"short"
	});

	HTTP http;
	Check(http.Get(server.URL()) != 0, name, "Get() should fail");
	Check(!http.LastResponse().HasData(), name, "no data should be set");
}


static void
TestHugeContentLength()
{
	const std::string name = "huge Content-Length";
	std::cout << name << std::endl;
	CannedServer server({
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 1000000000000000\r\n"
		"\r\n"
		"short"
	});

	HTTP http;
	Check(http.Get(server.URL()) != 0, name, "Get() should fail");
}


static void
TestHugeChunk()
{
	const std::string name = "huge chunk";
	std::cout << name << std::endl;
	CannedServer server({
		"HTTP/1.1 200 OK\r\n"
		"Transfer-Encoding: chunked\r\n"
		"\r\n"
		"FFFFFFFF\r\n"
		"short"
	});

	HTTP http;
	Check(http.Get(server.URL()) != 0, name, "Get() should fail");
}


int main()
{
	TestContentLength();
	TestChunked();
	TestNoBody();
	TestKeepAlive();
	TestHeaders();
	TestMalformedStatusLine();
	TestTruncatedBody();
	TestHugeContentLength();
	TestHugeChunk();

	if (sFailures > 0) {
		std::cout << sFailures << " check(s) failed" << std::endl;
		std::cout << "Test Failed !!!" << std::endl;
		return 1;
	}

	std::cout << "All tests passed!" << std::endl;
	return 0;
}

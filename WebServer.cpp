extern "C" {
	#include "civetweb.h"
}

#include "WebServer.h"

#include "Logger.h"

WebServer::WebServer()
	:
	fContext(nullptr)
{
}


WebServer::~WebServer()
{
	Stop();
}


bool
WebServer::Start(int port, const std::string& certificateFile)
{
	std::string portStr = std::to_string(port) + "s";

	const char* options[] = {
		"listening_ports",
		portStr.c_str(),
		"ssl_certificate",
		certificateFile.c_str(),
		nullptr
	};

	fContext = mg_start(nullptr, nullptr, options);

	if (!fContext) {
		Logger::Log(LOG_ERR, "WebServer: Cannot create context");
		return false;
	}

	mg_set_request_handler(fContext, "/health", HealthHandler, this);
	mg_set_request_handler(fContext, "/inventory", InventoryHandler, this);

	return true;
}


void
WebServer::Stop()
{
	if (fContext) {
		mg_stop(fContext);
		fContext = nullptr;
	}
}


int
WebServer::HealthHandler(mg_connection* conn, void* cbdata)
{
	Logger::Log(LOG_INFO, "HealthHandler called");

	mg_printf(conn, "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/json\r\n"
		"\r\n"
		"{\"status\":\"ok\"}");

	return 200;
}


int
WebServer::InventoryHandler(mg_connection* conn, void* cbdata)
{
	Logger::Log(LOG_INFO, "InventoryHandler called");

	mg_printf(conn, "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/json\r\n"
		"\r\n"
		"{\"hostname\":\"test\"}");

	return 200;
}

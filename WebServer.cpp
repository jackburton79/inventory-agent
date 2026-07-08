extern "C" {
	#include "civetweb.h"
}

#include "WebServer.h"

#include <cstring>

#include "Agent.h"
#include "AgentService.h"
#include "Logger.h"

WebServer::WebServer(AgentService& agentService)
	:
	fContext(nullptr),
	fAgentService(agentService)
{
}


WebServer::~WebServer()
{
	Stop();
}


bool
WebServer::Start(int port, const std::string& certificateFile)
{
#if WEB_USE_SSL
	std::string portStr = std::to_string(port) + "s";
#else
	std::string portStr = std::to_string(port);
#endif
	const char* options[] = {
		"listening_ports",
		portStr.c_str(),
		"ssl_certificate",
		certificateFile.c_str(),
		nullptr
	};

	Logger::Log(LOG_INFO, "WebServer: starting...");
	fContext = mg_start(nullptr, nullptr, options);
	if (!fContext) {
		Logger::Log(LOG_ERR, "WebServer: Cannot create context");
		return false;
	}

	Logger::LogFormat(LOG_INFO, "WebServer: listening on port %s", portStr.c_str());

	mg_set_request_handler(fContext, "/", RootHandler, this);
	mg_set_request_handler(fContext, "/now", NowHandler, this);
	mg_set_request_handler(fContext, "/status", StatusHandler, this);
	//mg_set_request_handler(fContext, "/inventory", InventoryHandler, this);

	return true;
}


void
WebServer::Stop()
{
	Logger::Log(LOG_INFO, "WebServer: stopping...");

	if (fContext) {
		mg_stop(fContext);
		fContext = nullptr;
	}
}


int
WebServer::RootHandler(mg_connection* conn, void* cbdata)
{
	Logger::Log(LOG_INFO, "RootHandler called");

	const char* html =
		"<html>"
		"<head><title>Inventory Agent</title></head>"
		"<body>"
		"<h1>Inventory Agent</h1>"
		"<ul>"
		"<li>\"/status\"Status</a></li>"
		"<li>\"/inventory\"Inventory</a></li>"
		"<li>/now\"Run inventory now</a></li>"
		"</ul>"
		"</body>"
		"</html>";

	mg_printf(conn,
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: %zu\r\n"
		"\r\n%s",
		::strlen(html), html);

	return 200;
}


int
WebServer::StatusHandler(mg_connection* conn, void* cbdata)
{
	Logger::Log(LOG_INFO, "StatusHandler called");

	/*std::string json =
		"{"
		"\"status\":\"running\","
		"\"version\":\"" +
		Agent::Version() +
		"\""
		"}";
*/
	// TODO: use status
	//AgentService status = fAgentService.Status();

	mg_printf(conn,
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/plain\r\n"
		"\r\n"
		"status: waiting");

	return 200;
}


int
WebServer::InventoryHandler(mg_connection* conn, void* cbdata)
{
	Logger::Log(LOG_INFO, "InventoryHandler called");

	// TODO: update the inventory, then send
	mg_printf(conn, "HTTP/1.1 200 OK\r\n"
		"Content-Type: text/plain\r\n"
		"\r\n"
		"status: test");

	return 200;
}


int
WebServer::NowHandler(mg_connection* conn, void* cbdata)
{
	Logger::Log(LOG_INFO, "NowHandler called");

	// schedule an immediate inventory
	WebServer* thisPointer = reinterpret_cast<WebServer*>(cbdata);
	thisPointer->fAgentService.ScheduleInventory();

	// TODO: check the result of ScheduleInventory and reply with it

	const char* html =
		"<html>"
		"<head><title>GLPI-Agent</title></head>"
		"<body>"
		"<p>OK</p>"
		"</body>"
		"</html>";

	mg_printf(conn,
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: %zu\r\n"
		"\r\n%s",
		::strlen(html), html);

	return 200;
}

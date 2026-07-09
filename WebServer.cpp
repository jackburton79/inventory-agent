extern "C" {
	#include "civetweb.h"
}

#include "WebServer.h"

#include <arpa/inet.h>
#include <cstring>
#include <netdb.h>

#include "Agent.h"
#include "AgentService.h"
#include "Configuration.h"
#include "Logger.h"
#include "http/URL.h"

const std::string head = "<head>"
		"<meta content=\"text/html; charset=UTF-8\" http-equiv=\"content-type\" />"
		"<title>Inventory Agent</title>"
		"</head>";

static bool
IsTrusted(const std::string& address)
{
	std::string trustedIPs = Configuration::Get()->KeyValue("httpd-trust");

	if (address.compare("127.0.0.1") == 0 ||
			trustedIPs.find(address) != std::string::npos)
		return true;

	// TODO: move to its own method
	// The configured server is also trusted
	URL serverURL(Configuration::Get()->KeyValue("server"));
	std::string hostname = serverURL.Host();
	if (!serverURL.Host().empty()) {
		struct addrinfo hints;
		struct addrinfo* res = nullptr;
		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_CANONNAME;

		int status;
		if ((status = getaddrinfo(hostname.c_str(), NULL, &hints, &res)) != 0) {
			Logger::LogFormat(LOG_ERR, "getaddrinfo failed for %s: %s", hostname.c_str(),
				::strerror(errno));
			return false;
		}

		for (struct addrinfo* p = res; p != NULL; p = p->ai_next) {
			void *addr;
			const char *ipver;
			if (p->ai_family == AF_INET) {
				struct sockaddr_in *ipv4 = (struct sockaddr_in*)p->ai_addr;
				addr = &(ipv4->sin_addr);
				ipver = "IPv4";
			} else if (p->ai_family == AF_INET6) {
				struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*)p->ai_addr;
				addr = &(ipv6->sin6_addr);
				ipver = "IPv6";
			} else {
				continue;
			}

			char ipString[INET6_ADDRSTRLEN];
			if (inet_ntop(p->ai_family, addr, ipString, sizeof ipString) == nullptr) {
				Logger::LogFormat(LOG_ERR, "inet_ntop returned null");
				continue;
			}

			Logger::LogFormat(LOG_DEBUG, "Checking if %s (%s) is trusted:", ipString, ipver);
			if (address.compare(ipString) == 0) {
				freeaddrinfo(res);
				Logger::LogFormat(LOG_DEBUG, "%s (%s) is trusted", ipString, ipver);
				return true;
			}
		}

		freeaddrinfo(res);
	}

	return false;
}


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
	mg_set_request_handler(fContext, "/info", InfoHandler, this);

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
	const mg_request_info* requestInfo = mg_get_request_info(conn);
	Logger::LogFormat(LOG_INFO, "RootHandler called from %s", requestInfo->remote_addr);

	WebServer* thisPointer = reinterpret_cast<WebServer*>(cbdata);
	std::string statusString = thisPointer->fAgentService.StatusString();

	std::string html =
		std::string("<html>") +
		head + std::string(
		"<body>"
		"<div id='background'>"
		"<p id='version' class='block'>This is ") + Agent::AgentString() + std::string("</p>"
		"<div id='status'>"
		"<p>The current status is ") + statusString + std::string("</p>");

	if (IsTrusted(requestInfo->remote_addr)) {
		html += std::string(
			"<div id = 'force' class='block'>"
				"<p><a href='/now'>Force an inventory</a></p>"
			"</div>");
	}

	html += std::string("</div>"
		"</div>"
		"</body>"
		"</html>");

	mg_printf(conn,
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: %zu\r\n"
		"\r\n%s",
		html.length(), html.c_str());

	return 200;
}


int
WebServer::StatusHandler(mg_connection* conn, void* cbdata)
{
	const mg_request_info* requestInfo = mg_get_request_info(conn);
	Logger::LogFormat(LOG_INFO, "Status requested by %s", requestInfo->remote_addr);

	WebServer* thisPointer = reinterpret_cast<WebServer*>(cbdata);
	std::string statusString = thisPointer->fAgentService.StatusString();

	mg_printf(conn,
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/plain\r\n"
		"\r\n"
		"status: %s", statusString.c_str());

	return 200;
}


int
WebServer::InfoHandler(mg_connection* conn, void* cbdata)
{
	Logger::Log(LOG_INFO, "InfoHandler called");

	WebServer* thisPointer = reinterpret_cast<WebServer*>(cbdata);
	std::string statusString = thisPointer->fAgentService.StatusString();

	// TODO: update the inventory, then send
	mg_printf(conn, "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/json\r\n"
		"\r\n"
		"{"
		"\"version\": \"%s\","
		"\"status\": \"%s\""
		"}", Agent::Version().c_str(), statusString.c_str());

	return 200;
}


int
WebServer::NowHandler(mg_connection* conn, void* cbdata)
{
	const mg_request_info* requestInfo = mg_get_request_info(conn);

	Logger::LogFormat(LOG_INFO, "Remote inventory requested from %s", requestInfo->remote_addr);

	// TODO: Return access denied page
	if (!IsTrusted(requestInfo->remote_addr)) {
		std::string html = std::string("<html>") +
			head + std::string(
			"<body>"
			"<div id=\"background\">"
			"<p>Access denied</p>"
			"<p><a href=\"/\">Back</a></p>"
			"</div>"
			"</body>"
			"</html>");

		mg_printf(conn,
			"HTTP/1.1 400 OK\r\n"
			"Content-Type: text/html\r\n"
			"Content-Length: %zu\r\n"
			"\r\n%s",
			html.length(), html.c_str());
		return 200;
	}

	// schedule an immediate inventory
	WebServer* thisPointer = reinterpret_cast<WebServer*>(cbdata);
	thisPointer->fAgentService.ScheduleInventory();

	// TODO: check the result of ScheduleInventory and reply with it

	std::string html = std::string("<html>") +
		head + std::string(
		"<body>"
		"<p>OK</p>"
		"</body>"
		"</html>");

	mg_printf(conn,
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: %zu\r\n"
		"\r\n%s",
		html.length(), html.c_str());

	return 200;
}

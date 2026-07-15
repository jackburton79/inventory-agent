#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <string>

struct mg_context;
struct mg_connection;

class AgentService;
class WebServer {
public:
	WebServer(AgentService& agentService);
	~WebServer();

	bool Start(int port, const std::string& certificateFile);

	void Stop();

private:
	static int RootHandler(mg_connection* conn, void* cbdata);
	static int StatusHandler(mg_connection* conn, void* cbdata);
	static int InfoHandler(mg_connection* conn, void* cbdata);
	static int NowHandler(mg_connection* conn, void* cbdata);
	static int CSSHandler(mg_connection* conn, void* cbdata);

private:
	mg_context* fContext;
	AgentService& fAgentService;
};

#endif

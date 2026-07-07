#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <string>

struct mg_context;
struct mg_connection;

class WebServer {
public:
	WebServer();
	~WebServer();

	bool Start(int port, const std::string& certificateFile);

	void Stop();

private:
	static int HealthHandler(mg_connection* conn, void* cbdata);

	static int InventoryHandler(mg_connection* conn, void* cbdata);

private:
	mg_context* fContext;
};

#endif
/*
 * LoggedUsers.cpp
 *
 *  Created on: 15/lug/2013
 *      Author: Stefano Ceccherini
 */

#include "UsersRoster.h"

#include "Support.h"

#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <ctime>
#include <set>
#include <utmpx.h>
#include <iostream>

bool
operator<(const user_entry& A, const user_entry& B)
{
	if (A.login != B.login)
		return A.login < B.login;
	return A.logindomain < B.logindomain;
}


// Adds a user to the set. "user@domain" logins are split in login and domain.
static void
AddUser(std::set<user_entry>& users, const std::string& line, time_t loginTime)
{
	user_entry entry;
	size_t domainSeparatorPos = line.find("@");
	if (domainSeparatorPos == std::string::npos)
		entry.login = line;
	else {
		entry.login = line.substr(0, domainSeparatorPos);
		entry.logindomain = line.substr(domainSeparatorPos + 1);
	}
	entry.logintime = loginTime;

	struct tm timeInfoStruct;
	char timeString[64] = "";
	if (::localtime_r(&loginTime, &timeInfoStruct) != NULL)
		::strftime(timeString, sizeof(timeString), "%a %b %d %R", &timeInfoStruct);
	entry.logintimestring = timeString;
	users.insert(entry);
}


// Reads the sessions known by systemd-logind. Needed on systems where
// utmp is not available (or not written by the graphical sessions).
static void
ReadLogindSessions(std::set<user_entry>& users)
{
	const char* kSessionsDir = "/run/systemd/sessions";
	DIR* dir = ::opendir(kSessionsDir);
	if (dir == NULL)
		return;

	const dirent* dirEntry = NULL;
	while ((dirEntry = ::readdir(dir)) != NULL) {
		// Session files are named after the session id, "<id>.ref" and
		// the fifo "<id>.control" are not interesting
		const std::string name = dirEntry->d_name;
		if (name.empty() || name.find_first_not_of("0123456789") != std::string::npos)
			continue;

		std::ifstream file((std::string(kSessionsDir) + "/" + name).c_str());
		std::string line;
		std::string user;
		std::string sessionClass;
		std::string state;
		time_t loginTime = 0;
		while (std::getline(file, line)) {
			size_t pos = line.find('=');
			if (pos == std::string::npos)
				continue;
			const std::string key = line.substr(0, pos);
			const std::string value = line.substr(pos + 1);
			if (key == "USER")
				user = value;
			else if (key == "CLASS")
				sessionClass = value;
			else if (key == "STATE")
				state = value;
			else if (key == "REALTIME") // microseconds
				loginTime = static_cast<time_t>(::strtoull(value.c_str(), NULL, 10) / 1000000);
		}

		// Skip the "manager", "greeter" and "background" sessions, and closing ones
		if (user.empty() || sessionClass != "user" || state == "closing")
			continue;

		AddUser(users, user, loginTime);
	}
	::closedir(dir);
}


UsersRoster::UsersRoster()
{
	std::set<user_entry> userSet;

	::setutxent();
	struct utmpx* record = NULL;
	while ((record = ::getutxent()) != NULL) {
		if (record->ut_type == USER_PROCESS) {
			// ut_user is not necessarily NUL terminated
			AddUser(userSet, std::string(record->ut_user, ::strnlen(record->ut_user,
				sizeof(record->ut_user))), record->ut_tv.tv_sec);
		}
	}
	::endutxent();

	ReadLogindSessions(userSet);

	// Only insert one entry for user, otherwise GLPI rejects the inventory
	for (const auto& user : userSet) {
		fItems.push_back(user);
	}

	Rewind();
}

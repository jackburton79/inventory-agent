/*
 * LoggedUsers.cpp
 *
 *  Created on: 15/lug/2013
 *      Author: Stefano Ceccherini
 */

#include "UsersRoster.h"

#include "Support.h"

#include <cstring>
#include <ctime>
#include <set>
#include <utmpx.h>
#include <iostream>

bool
operator<(const user_entry& A, const user_entry& B)
{
	// TODO: Also compare domain
	return A.login.compare(B.login);
}


UsersRoster::UsersRoster()
{
	std::set<user_entry> userSet;
	setutxent();

	struct utmpx* record = NULL;
	while ((record = getutxent()) != NULL) {
		if (record->ut_type == USER_PROCESS) {
			user_entry entry;
			std::string line = record->ut_user;
			size_t domainSeparatorPos = line.find("@");
			if (domainSeparatorPos == std::string::npos)
				entry.login = record->ut_user;
			else {
				entry.login = line.substr(0, domainSeparatorPos);
				entry.logindomain = line.substr(domainSeparatorPos + 1);
			}
			time_t loginTime = record->ut_tv.tv_sec;
			entry.logintime = loginTime;
			struct tm timeInfoStruct;
			struct tm* timeinfo = localtime_r(&loginTime, &timeInfoStruct);
			char timeString[64];
			strftime(timeString, sizeof(timeString), "%a %b %d %R", timeinfo);
			entry.logintimestring = timeString;
			userSet.insert(entry);
		}
	}

	endutxent();

	// Only insert one entry for user, otherwise GLPI rejects the inventory
	std::set<user_entry>::const_iterator i;
	for (i = userSet.begin(); i != userSet.end(); i++) {
		fItems.push_back(*i);
	}

	Rewind();
}

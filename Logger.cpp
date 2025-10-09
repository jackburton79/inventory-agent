/*
 * Logger.cpp
 *
 *  Created on: 05/lug/2017
 *      Author: Stefano Ceccherini
 */

#include "Logger.h"


#include <cstdio>
#include <iostream>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

extern const char* __progname;


Logger::LOGGER_TYPE Logger::sLogType = LOGGER_TYPE_DEFAULT;
int Logger::sLevel;

void
Logger::SetLevel(int level)
{
	sLevel = level;
}


/* static */
void
Logger::Log(int level, const char* const string)
{
	if (level > sLevel)
		return;

	_DoLog(level, string);
}


/* static */
void
Logger::LogFormat(int level, const char* fmtString, ...)
{
	if (level > sLevel)
		return;

	char logString[1024];
	va_list argp;
	::va_start(argp, fmtString);
	::vsnprintf(logString, sizeof(logString), fmtString, argp);
	::va_end(argp);
	_DoLog(level, logString);
}


/* static */
void
Logger::SetLogger(LOGGER_TYPE loggerType)
{
	sLogType = loggerType;
}


/* static */
void
Logger::SetLogger(const std::string& loggerType)
{
	if (::strcasecmp(loggerType.c_str(), "STDERR") == 0)
		SetLogger(Logger::LOGGER_TYPE_STDERR);
	else if (::strcasecmp(loggerType.c_str(), "SYSLOG") == 0)
		SetLogger(Logger::LOGGER_TYPE_SYSLOG);
	else
		SetLogger(Logger::LOGGER_TYPE_DEFAULT);
}


/* static */
void
Logger::_DoLog(int level, const char* string)
{
	switch (sLogType) {
		case LOGGER_TYPE_SYSLOG:
			::syslog(level|LOG_PID|LOG_CONS|LOG_USER, "%s", (const char* const)string);
			break;
		case LOGGER_TYPE_STDERR:
			std::cerr << string << std::endl;
			break;
		case LOGGER_TYPE_DEFAULT:
		default:
			if (::isatty(STDIN_FILENO))
				std::cerr << string << std::endl;
			else
				::syslog(level|LOG_PID|LOG_CONS|LOG_USER, "%s", (const char* const)string);
			break;
	}
}


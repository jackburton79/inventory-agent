/*
 * RunningProcesses.h
 *
 *  Created on: 16/lug/2013
 *      Author: Stefano Ceccherini
 */

#ifndef RUNNINGPROCESSES_H_
#define RUNNINGPROCESSES_H_

#include <list>
#include <string>

#include "ItemsList.h"

struct process_info {
	std::string cmdline;
	int cpu_usage = 0;
	float memory = 0;
	int pid = 0;
	// int started;
	// int tty;
	std::string user;
	long virtualmem = 0;
};


class RunningProcessesList : public ItemsList<process_info>{
public:
	RunningProcessesList();
	~RunningProcessesList();

private:
	static long _TotalMemory();
	void _ReadProcessInfo(process_info& info, const std::string& pid);
};

#endif /* RUNNINGPROCESSES_H_ */

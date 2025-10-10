/*
 * DMIDecodeBackend.h
 *
 *  Created on: 6 mar 2021
 *      Author: Stefano Ceccherini
 */

#ifndef DMIDECODEBACKEND_H_
#define DMIDECODEBACKEND_H_

#include <map>
#include <string>
#include <vector>

#include "../Components.h"
#include "DataBackend.h"

typedef std::map<int, string_map> dmi_db;

class DMIDecodeBackend : public DataBackend {
public:
	DMIDecodeBackend();
	virtual ~DMIDecodeBackend();
	virtual bool IsAvailable() const;
	virtual int Run();
private:
	void _ExtractDataFromDMIDB(dmi_db dmiDb);
};


// TODO: This class is very inefficient:
// It iterates the full dmi_db for every call of CountEntries() or ExtractEntry()
class DMIExtractor {
public:
	DMIExtractor(const dmi_db& db);
	int CountEntries(const std::string& context) const;
	std::vector<string_map> ExtractEntry(const std::string& context) const;
	string_map ExtractHandle(const std::string& handle) const;
private:
	dmi_db fDMIDB;
};


#endif /* DMIDECODEBACKEND_H_ */

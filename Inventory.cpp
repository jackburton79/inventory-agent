/*
 * InventoryFormatOCS.cpp
 *
 *  Created on: 11/lug/2013
 *      Author: Stefano Ceccherini
 */

#include "Agent.h"
#include "Components.h"
#include "Configuration.h"
#include "Inventory.h"
#include "Logger.h"
#include "NetworkInterface.h"
#include "NetworkRoster.h"
#include "ProcessRoster.h"
#include "Screens.h"
#include "Softwares.h"
#include "StorageRoster.h"
#include "Support.h"
#include "UsersRoster.h"
#include "VolumeRoster.h"
#include "XML.h"
#include "ZLibCompressor.h"

#include "http/HTTP.h"
#include "http/URL.h"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <unistd.h>

#include "tinyxml2/tinyxml2.h"


Inventory::Inventory()
	:
	fDocument(NULL),
	fContent(NULL)
{
	fDocument = new tinyxml2::XMLDocument;
}


Inventory::~Inventory()
{
	delete fDocument;
}


bool
Inventory::Initialize()
{
	Clear();

	std::string deviceID = Configuration::Get()->DeviceID();
	if (deviceID.empty()) {
		deviceID = GenerateDeviceID();
		Configuration::Get()->SetDeviceID(deviceID.c_str());
	}

	Logger::LogFormat(LOG_INFO, "Inventory::Initialize(): Device ID: %s...", deviceID.c_str());

	tinyxml2::XMLDeclaration* declaration = fDocument->NewDeclaration();
	tinyxml2::XMLElement* request = fDocument->NewElement("REQUEST");
	fDocument->LinkEndChild(declaration);
	fDocument->LinkEndChild(request);
	fContent = fDocument->NewElement("CONTENT");
	request->LinkEndChild(fContent);

	tinyxml2::XMLElement* query = fDocument->NewElement("QUERY");

	// TODO: We only do Inventory
	query->LinkEndChild(fDocument->NewText("INVENTORY"));
	request->LinkEndChild(query);

 	tinyxml2::XMLElement* deviceIdElement = fDocument->NewElement("DEVICEID");
	deviceIdElement->LinkEndChild(fDocument->NewText(deviceID.c_str()));
	request->LinkEndChild(deviceIdElement);

	Logger::LogFormat(LOG_INFO, "Inventory::Initialize(): Device ID: %s... OK!", deviceID.c_str());
	return true;
}


void
Inventory::Clear()
{
	fDocument->Clear();
}


std::string
Inventory::GenerateDeviceID() const
{
	// Try system UUID.
	std::string deviceID = gComponents["SYSTEM"].fields["uuid"];

	// If it's empty, use the MAC address of the first NIC
	if (deviceID.length() <= 1) {
		NetworkRoster roster;
		NetworkInterface interface;
		unsigned int cookie = 0;
		while (roster.GetNextInterface(&cookie, interface) == 0) {
			if (!interface.IsLoopback()) {
				deviceID = interface.HardwareAddress();
				deviceID.erase(std::remove(deviceID.begin(), deviceID.end(), ':'),
						deviceID.end());
				break;
			}
		}
	}

	// If it's empty (unlikely), just use the hostname
	if (deviceID == "")
		deviceID = gComponents["SYSTEM"].fields["hostname"];

	struct tm biosDate;
	if (Configuration::Get()->UseCurrentTimeInDeviceID()) {
		time_t rawtime = time(NULL);
		localtime_r(&rawtime, &biosDate);
	} else {
		std::string biosDateString = gComponents["BIOS"].fields["release_date"];
		// On some machines, this can be empty. So use an harcoded
		// value, since we need a correct date for the device id
		if (biosDateString.length() <= 1)
			biosDateString = "01/01/2017";
		::strptime(biosDateString.c_str(), "%m/%d/%Y", &biosDate);
	}

	// DeviceID needs to have a date appended in this very format,
	// otherwise OCSInventoryNG will reject the inventory
	char dateString[256];
	::strftime(dateString, sizeof(dateString), "-%Y-%m-%d-00-00-00", &biosDate);

	deviceID.append(dateString);

	return deviceID;
}


bool
Inventory::Build(bool noSoftware)
{
	Logger::Log(LOG_INFO, "Building inventory...");
	std::string inventoryFormat = Configuration::Get()->KeyValue("format");
	if (inventoryFormat.empty()) {
		Logger::Log(LOG_WARNING, "No inventory format specified. Using lowest common denominator.");
	}
	try {
		// GLPI refuses the inventory if this field is missing, ocsinventory doesn't
		// care if it's present, so we always add it
		// TODO: get the real version of the agent

		tinyxml2::XMLElement* versionClient = fDocument->NewElement("VERSIONCLIENT");
		versionClient->LinkEndChild(fDocument->NewText(Agent::Version().c_str()));
		fContent->LinkEndChild(versionClient);

		_AddAccountInfo();
		_AddBIOSInfo();
		_AddOperatingSystemInfo();
		_AddCPUsInfo();
		_AddStoragesInfo();
		_AddDrivesInfo();
		_AddMemoriesInfo();
		_AddHardwareInfo();
		_AddNetworksInfo();
		_AddProcessesInfo();
		if (!noSoftware)
			_AddSoftwaresInfo();
		_AddUsersInfo();
		_AddVideosInfo();
		_AddMonitorsInfo();
	} catch (...) {
		// Something failed.
	}

	Logger::Log(LOG_INFO, "Building inventory... Done!");
	return true;
}


bool
Inventory::Save(const char* fileName)
{
	if (fileName == NULL)
		return false;

	Logger::LogFormat(LOG_INFO, "Saving %s inventory as %s", Configuration::Get()->DeviceID().c_str(), fileName);

	bool result = fDocument->SaveFile(fileName) == tinyxml2::XML_SUCCESS;
	if (result)
		Logger::Log(LOG_INFO, "Inventory saved correctly!");
	else
		Logger::Log(LOG_INFO, "Failed to save inventory!");
	return result;
}


bool
Inventory::Send(const char* serverUrl)
{
	// TODO: Refactor, this functions is too big!

	// TODO: OCSInventory supports compressed XML, while GLPI does not
	bool compress = false;

	URL inventoryUrl(serverUrl);

	// Prepare prolog
	Logger::LogFormat(LOG_INFO, "Inventory::Send(): server URL: %s", serverUrl);
	tinyxml2::XMLDocument prolog;
	_WriteProlog(prolog);
	char* prologData = NULL;
	size_t prologLength = 0;
	if (!XML::Serialize(prolog, prologData, prologLength)) {
		Logger::Log(LOG_ERR, "Error while serializing XML prolog!");
		return false;
	}

	if (compress) {
		Logger::Log(LOG_INFO, "Compressing prolog...");
		size_t destLength;
		char* destData = NULL;
		if (!ZLibCompressor::Compress(prologData, prologLength, destData, destLength)) {
			Logger::Log(LOG_ERR, "Error while compressing XML prolog!");
			return false;
		}
		Logger::Log(LOG_INFO, "Prolog compressed correctly!");
		delete[] prologData;
		prologData = destData;
		prologLength = destLength;
	}

	HTTPRequestHeader requestHeader;
	requestHeader.SetRequest("POST", inventoryUrl.URLString());
	requestHeader.SetValue("Pragma", "no-cache");
	requestHeader.SetValue("Keep-Alive", "300");
	requestHeader.SetValue("Connection", "Keep-Alive, TE");
	if (compress) {
		requestHeader.SetValue("TE", "deflate, gzip");
		requestHeader.SetContentType("application/x-compress");
	}
	requestHeader.SetContentLength(prologLength);

	// TODO: Improve.
	if (inventoryUrl.Username() != "") {
		requestHeader.SetAuthentication(HTTP_AUTH_TYPE_BASIC,
				inventoryUrl.Username(), inventoryUrl.Password());
	}

	std::string cookieValue;
	HTTP httpObject;
	std::string userAgentString;
	for (int c = 0; c < 2; c++) {
		// Try first with the new agent. If it fails, try with the old,
		// safe one.
		userAgentString = (c == 0) ? Agent::AgentString()
			: Agent::LegacyAgentString();
		requestHeader.SetUserAgent(userAgentString);

		Logger::Log(LOG_INFO, "Inventory::Send(): Prolog prepared!");
		Logger::LogFormat(LOG_DEBUG, "%s", requestHeader.ToString().c_str());
		if (httpObject.Request(requestHeader, prologData, prologLength) != 0) {
			delete[] prologData;
			Logger::LogFormat(LOG_INFO, "Inventory::Send(): Failed to send prolog: %s",
						httpObject.ErrorString().c_str());
			return false;
		}

		Logger::Log(LOG_INFO, "Inventory::Send(): Try to send prolog...");
		const HTTPResponseHeader& responseHeader = httpObject.LastResponse();
		if (responseHeader.StatusCode() == HTTP_BAD_REQUEST) {
			if (c == 0) {
				Logger::LogFormat(LOG_INFO, "Server didn't accept prolog. Try again with standard agent string.");
				continue;
			}
		}

		delete[] prologData;

		bool isOk = responseHeader.StatusCode() == HTTP_OK;
		if (isOk)
			Logger::LogFormat(LOG_INFO, "Prolog sent!");
		else
			Logger::LogFormat(LOG_ERR, "Sending prolog failed: %s", responseHeader.StatusString().c_str());

		if (!responseHeader.HasContentLength()) {
			Logger::Log(LOG_ERR, "Prolog sent, but server didn't reply correctly.");
			return false;
		}

		std::string contentType = responseHeader.ContentType();
		size_t contentLength = responseHeader.ContentLength();

		Logger::LogFormat(LOG_INFO, "Got reply with content type: '%s', content length: %lu",
			contentType.c_str(), static_cast<unsigned long>(contentLength));

		// responseHeader keeps the ownership
		const char* resultData = responseHeader.Data();

		// TODO: OCS Inventory always use "application/x-compressed" but
		// sends a non compressed XML if we didn't compress prolog
		if (!compress && contentType == "application/x-compressed")
			contentType = "application/xml";

		if (contentType == "application/x-compressed") {
			Logger::Log(LOG_INFO, "Inventory::Send(): Decompressing reply... ");
			char* decompressedData = NULL;
			size_t decompressedLength = 0;
			bool uncompress = ZLibCompressor::Uncompress(resultData, contentLength, decompressedData, decompressedLength);
			if (!uncompress) {
				Logger::Log(LOG_ERR, "failed to decompress data");
				return false;
			}
			resultData = decompressedData;
			contentLength = decompressedLength;
		} else if (contentType != "application/xml") {
			Logger::Log(LOG_ERR, "Unexpected reply");
			Logger::Log(LOG_ERR, httpObject.LastResponse().ToString().c_str());
			return false;
		}

		tinyxml2::XMLDocument document;
		bool deserializeResult = XML::Deserialize(resultData, contentLength, document);
		if (!deserializeResult) {
			Logger::Log(LOG_ERR, "failed to deserialize XML");
			return false;
		}

#if 0
		std::cout << XML::ToString(document) << std::endl;
#endif
		std::string serverResponse = XML::GetElementText(document, "RESPONSE");
		Logger::LogFormat(LOG_INFO, "Inventory::Send(): server replied %s", serverResponse.c_str());
		if (serverResponse == "SEND")
			break;
		Logger::LogFormat(LOG_ERR, "Server not ready to accept inventory: %s", serverResponse.c_str());
		return false;
	}

	char* inventoryData = NULL;
	size_t inventoryLength;
	Logger::Log(LOG_INFO, "Inventory::Send(): Serializing XML inventory data... ");
	if (!XML::Serialize(*fDocument, inventoryData, inventoryLength)) {
		Logger::Log(LOG_ERR, "Error while serializing XML data!");
		return false;
	}

	if (compress) {
		Logger::Log(LOG_INFO, "Inventory::Send(): Compressing inventory data... ");
		size_t compressedLength;
		char* compressedData = NULL;
		if (!ZLibCompressor::Compress(inventoryData, inventoryLength, compressedData, compressedLength)) {
			Logger::Log(LOG_ERR, "Error while compressing XML data!");
			return false;
		}
		delete[] inventoryData;
		inventoryData = compressedData;
		inventoryLength = compressedLength;
	}

	requestHeader.Clear();
	requestHeader.SetRequest("POST", inventoryUrl.URLString());
	requestHeader.SetValue("Pragma", "no-cache");
	requestHeader.SetValue("Keep-Alive", "300");
	requestHeader.SetValue("Connection", "Keep-Alive");
	if (compress) {
		requestHeader.SetValue("TE", "deflate, gzip");
		requestHeader.SetContentType("application/x-compress");
	} else
		requestHeader.SetContentType("application/xml");
	requestHeader.SetContentLength(inventoryLength);
	requestHeader.SetUserAgent(userAgentString);
	if (inventoryUrl.Username() != "") {
		requestHeader.SetAuthentication(HTTP_AUTH_TYPE_BASIC,
						inventoryUrl.Username(), inventoryUrl.Password());
	}

	Logger::LogFormat(LOG_INFO, "Inventory::Send(): Sending inventory data...");

	if (httpObject.Request(requestHeader, inventoryData, inventoryLength) != 0) {
		delete[] inventoryData;
		Logger::LogFormat(LOG_ERR, "Inventory::Send(): error while sending inventory: %s",
				httpObject.ErrorString().c_str());
		return false;
	}

	delete[] inventoryData;

	bool statusOk = _HandleResponse(httpObject);
	if (statusOk)
		Logger::Log(LOG_INFO, "Inventory::Send(): Inventory was accepted!");
	else
		Logger::Log(LOG_ERR, "Inventory::Send(): Inventory was rejected by server!");

	return true;
}


std::string
Inventory::ToString()
{
	return XML::ToString(*fDocument);
}


void
Inventory::Print()
{
	std::cout << ToString() << std::endl;
}


int
Inventory::Checksum() const
{
	return 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128 | 256 | 512 | 1024
			| 2048 | 4096 | 8192 | 16384 | 32768 | 65536 | 131072 | 262144;
}


// Private
void
Inventory::_AddAccountInfo()
{
	tinyxml2::XMLElement* accountInfo = fDocument->NewElement("ACCOUNTINFO");
	fContent->LinkEndChild(accountInfo);

	tinyxml2::XMLElement* keyName = fDocument->NewElement("KEYNAME");
	keyName->LinkEndChild(fDocument->NewText("TAG"));
	accountInfo->LinkEndChild(keyName);

	std::string tag = Configuration::Get()->KeyValue("TAG");
	if (tag == "")
		tag = "NA";

	tinyxml2::XMLElement* keyValue = fDocument->NewElement("KEYVALUE");
	keyValue->LinkEndChild(fDocument->NewText(tag.c_str()));
	accountInfo->LinkEndChild(keyValue);

	Logger::Log(LOG_DEBUG, "\tAdded Account Info!");
}


void
Inventory::_AddBIOSInfo()
{
	tinyxml2::XMLElement* bios = fDocument->NewElement("BIOS");
	fContent->LinkEndChild(bios);

	if (Configuration::Get()->KeyValue(CONF_NO_ASSETTAG) != CONF_VALUE_TRUE) {
		tinyxml2::XMLElement* assettag = fDocument->NewElement("ASSETTAG");
		assettag->LinkEndChild(fDocument->NewText(gComponents["CHASSIS"].fields["asset_tag"].c_str()));
		bios->LinkEndChild(assettag);
	}

	tinyxml2::XMLElement* bdate = fDocument->NewElement("BDATE");
	bdate->LinkEndChild(fDocument->NewText(gComponents["BIOS"].fields["release_date"].c_str()));
	bios->LinkEndChild(bdate);

	tinyxml2::XMLElement* bmanufacturer = fDocument->NewElement("BMANUFACTURER");
	bmanufacturer->LinkEndChild(fDocument->NewText(gComponents["BIOS"].fields["vendor"].c_str()));
	bios->LinkEndChild(bmanufacturer);

	tinyxml2::XMLElement* bversion = fDocument->NewElement("BVERSION");
	bversion->LinkEndChild(fDocument->NewText(gComponents["BIOS"].fields["version"].c_str()));
	bios->LinkEndChild(bversion);

	tinyxml2::XMLElement* mmanufacturer = fDocument->NewElement("MMANUFACTURER");
	mmanufacturer->LinkEndChild(fDocument->NewText(gComponents["BOARD"].fields["vendor"].c_str()));
	bios->LinkEndChild(mmanufacturer);

	tinyxml2::XMLElement* mSerial = fDocument->NewElement("MSN");
	mSerial->LinkEndChild(fDocument->NewText(gComponents["BOARD"].fields["serial"].c_str()));
	bios->LinkEndChild(mSerial);

	tinyxml2::XMLElement* sManufacturer = fDocument->NewElement("SMANUFACTURER");
	sManufacturer->LinkEndChild(fDocument->NewText(gComponents["SYSTEM"].fields["vendor"].c_str()));
	bios->LinkEndChild(sManufacturer);

	tinyxml2::XMLElement* systemModel = fDocument->NewElement("SMODEL");
	systemModel->LinkEndChild(fDocument->NewText(gComponents["SYSTEM"].fields["name"].c_str()));
	bios->LinkEndChild(systemModel);

	// TODO: Move into backend(s)
	// Some systems have this empty, or, like our MCP79s,
	// "To Be Filled by O.E.M.", which is pretty much useless,
	// so in that case we use the baseboard serial number
	std::string systemSerial;
	if (gComponents["SYSTEM"].fields["serial"].empty()
		|| gComponents["SYSTEM"].fields["serial"] == "To Be Filled By O.E.M.")
		systemSerial = gComponents["BOARD"].fields["serial"];
	else
		systemSerial = gComponents["SYSTEM"].fields["serial"];

	tinyxml2::XMLElement* ssn = fDocument->NewElement("SSN");
	ssn->LinkEndChild(fDocument->NewText(systemSerial.c_str()));
	bios->LinkEndChild(ssn);

	tinyxml2::XMLElement* type = fDocument->NewElement("TYPE");
	type->LinkEndChild(fDocument->NewText(gComponents["CHASSIS"].fields["type"].c_str()));
	bios->LinkEndChild(type);

	Logger::Log(LOG_DEBUG, "\tAdded BIOS Info!");
}


void
Inventory::_AddOperatingSystemInfo()
{
	if (Configuration::Get()->KeyValue("format") != "FORMAT_GLPI")
		return;

	tinyxml2::XMLElement* os = fDocument->NewElement("OPERATINGSYSTEM");
	fContent->LinkEndChild(os);

	tinyxml2::XMLElement* arch = fDocument->NewElement("ARCH");
	arch->LinkEndChild(fDocument->NewText(gComponents["OS"].fields["architecture"].c_str()));
	os->LinkEndChild(arch);

	tinyxml2::XMLElement* name = fDocument->NewElement("NAME");
	name->LinkEndChild(fDocument->NewText(gComponents["OS"].fields["description"].c_str()));
	os->LinkEndChild(name);

	tinyxml2::XMLElement* kernelName = fDocument->NewElement("KERNEL_NAME");
	kernelName->LinkEndChild(fDocument->NewText(gComponents["OS"].fields["kernelname"].c_str()));
	os->LinkEndChild(kernelName);

	tinyxml2::XMLElement* kernelVersion = fDocument->NewElement("KERNEL_VERSION");
	kernelVersion->LinkEndChild(fDocument->NewText(gComponents["OS"].fields["release"].c_str()));
	os->LinkEndChild(kernelVersion);

	tinyxml2::XMLElement* dnsDomain = fDocument->NewElement("DNS_DOMAIN");
	dnsDomain->LinkEndChild(fDocument->NewText(gComponents["OS"].fields["domainname"].c_str()));
	os->LinkEndChild(dnsDomain);

	tinyxml2::XMLElement* fqdn = fDocument->NewElement("FQDN");
	std::string fqdnString;
	fqdnString.append(gComponents["OS"].fields["hostname"]).append(gComponents["OS"].fields["domainname"]);
	fqdn->LinkEndChild(fDocument->NewText(fqdnString.c_str()));
	os->LinkEndChild(fqdn);

#if 0
	// TODO: Impelement these
	<BOOT_TIME>2024-03-26 07:58:04</BOOT_TIME>
	<FULL_NAME>
	<HOSTID>
	<INSTALL_DATE>
	<NAME>
	<SSH_KEY>
	<TIMEZONE>
	<NAME>Europe/Rome</NAME>
	<OFFSET>+0100</OFFSET>
	</TIMEZONE>
#endif
}


void
Inventory::_AddCPUsInfo()
{
	std::pair<components_map::iterator, components_map::iterator> CPUs = gComponents.equal_range("CPU");
	size_t cpuCount = 0;
	for (components_map::iterator i = CPUs.first; i != CPUs.second; i++) {
		cpuCount++;
		Component& cpuInfo = (*i).second;
		// TODO: Need something like "AddElement("NAME", "VALUE");
		tinyxml2::XMLElement* cpu = fDocument->NewElement("CPUS");
		fContent->LinkEndChild(cpu);

		// OCS Inventory
		if (Configuration::Get()->KeyValue("format") == "FORMAT_OCS") {
			// The official OCSInventory linux Agent always reports "CPU Enabled" here
			tinyxml2::XMLElement* serial = fDocument->NewElement("SERIALNUMBER");
			std::string cpuSerial = cpuInfo.fields["serial"];
			if (cpuSerial.empty())
				cpuSerial = "CPU Enabled";
			if (cpuSerial == "None")
				cpuSerial = "";
			serial->LinkEndChild(
					fDocument->NewText(cpuSerial.c_str()));
			cpu->LinkEndChild(serial);

			tinyxml2::XMLElement* currentSpeed = fDocument->NewElement("CURRENT_SPEED");
			currentSpeed->LinkEndChild(
			fDocument->NewText(cpuInfo.fields["current_speed"].c_str()));
			cpu->LinkEndChild(currentSpeed);

			tinyxml2::XMLElement* cores = fDocument->NewElement("CORES");
			cores->LinkEndChild(
				fDocument->NewText(cpuInfo.fields["cores"].c_str()));
			cpu->LinkEndChild(cores);
			tinyxml2::XMLElement* arch = fDocument->NewElement("CPUARCH");
			arch->LinkEndChild(
				fDocument->NewText(gComponents["OS"].fields["architecture"].c_str()));
			cpu->LinkEndChild(arch);
			tinyxml2::XMLElement* dataWidth = fDocument->NewElement("DATA_WIDTH");
			std::string dataWidthString = gComponents["CPU"].fields["width"];
			if (dataWidthString.empty()) {
				// TODO: This is not completely correct:
				// We could have a 64 bit capable CPU on a 32 bit OS.
				if (gComponents["OS"].fields["architecture"] == "x86_64")
					dataWidthString = "64";
				else
					dataWidthString = "32";
			}
			dataWidth->LinkEndChild(
				fDocument->NewText(dataWidthString.c_str()));
			cpu->LinkEndChild(dataWidth);
			// Not a copy/paste error: the fields are the same

			tinyxml2::XMLElement* currentAddressWidth = fDocument->NewElement("CURRENT_ADDRESS_WIDTH");
			currentAddressWidth->LinkEndChild(
				fDocument->NewText(dataWidthString.c_str()));
			cpu->LinkEndChild(currentAddressWidth);

			tinyxml2::XMLElement* cacheSize = fDocument->NewElement("L2CACHESIZE");
			cacheSize->LinkEndChild(
				fDocument->NewText(cpuInfo.fields["cache_size"].c_str()));
			cpu->LinkEndChild(cacheSize);

			tinyxml2::XMLElement* logicalCpu = fDocument->NewElement("LOGICAL_CPUS");
			logicalCpu->LinkEndChild(
				fDocument->NewText(cpuInfo.fields["logical_cpus"].c_str()));
			cpu->LinkEndChild(logicalCpu);

			tinyxml2::XMLElement* voltage = fDocument->NewElement("VOLTAGE");
			voltage->LinkEndChild(
				fDocument->NewText(cpuInfo.fields["voltage"].c_str()));
			cpu->LinkEndChild(voltage);

		} else if (Configuration::Get()->KeyValue("format") == "FORMAT_GLPI") {
			// GLPI
			tinyxml2::XMLElement* cores = fDocument->NewElement("CORE");
			cores->LinkEndChild(
			fDocument->NewText(cpuInfo.fields["cores"].c_str()));
			cpu->LinkEndChild(cores);
		}

		tinyxml2::XMLElement* manufacturer = fDocument->NewElement("MANUFACTURER");
		cpu->LinkEndChild(manufacturer);
		manufacturer->LinkEndChild(
			fDocument->NewText(cpuInfo.fields["vendor"].c_str()));

		tinyxml2::XMLElement* speed = fDocument->NewElement("SPEED");
		speed->LinkEndChild(
			fDocument->NewText(cpuInfo.fields["speed"].c_str()));
		cpu->LinkEndChild(speed);

		tinyxml2::XMLElement* model = fDocument->NewElement("TYPE");
		model->LinkEndChild(
			fDocument->NewText(cpuInfo.fields["type"].c_str()));
		cpu->LinkEndChild(model);

		// Not a copy/paste error
		tinyxml2::XMLElement* name = fDocument->NewElement("NAME");
		name->LinkEndChild(
			fDocument->NewText(cpuInfo.fields["type"].c_str()));
		cpu->LinkEndChild(name);
	}
	Logger::Log(LOG_DEBUG, "\tAdded CPUs Info!");
}


void
Inventory::_AddStoragesInfo()
{
	StorageRoster storages;
	storage_info info;
	while (storages.GetNext(info)) {
		tinyxml2::XMLElement* storage = fDocument->NewElement("STORAGES");
		fContent->LinkEndChild(storage);

		tinyxml2::XMLElement* manufacturer = fDocument->NewElement("MANUFACTURER");
		manufacturer->LinkEndChild(fDocument->NewText(info.manufacturer.c_str()));
		storage->LinkEndChild(manufacturer);

		tinyxml2::XMLElement* name = fDocument->NewElement("NAME");
		name->LinkEndChild(fDocument->NewText(info.name.c_str()));
		storage->LinkEndChild(name);

		tinyxml2::XMLElement* model = fDocument->NewElement("MODEL");
		model->LinkEndChild(fDocument->NewText(info.model.c_str()));
		storage->LinkEndChild(model);

		tinyxml2::XMLElement* description = fDocument->NewElement("DESCRIPTION");
		description->LinkEndChild(fDocument->NewText(info.description.c_str()));
		storage->LinkEndChild(description);

		tinyxml2::XMLElement* type = fDocument->NewElement("TYPE");
		type->LinkEndChild(fDocument->NewText(info.type.c_str()));
		storage->LinkEndChild(type);

		tinyxml2::XMLElement* diskSize = fDocument->NewElement("DISKSIZE");
		diskSize->LinkEndChild(fDocument->NewText(info.size.c_str()));
		storage->LinkEndChild(diskSize);

		tinyxml2::XMLElement* serialNumber = fDocument->NewElement("SERIALNUMBER");
		serialNumber->LinkEndChild(fDocument->NewText(info.serial_number.c_str()));
		storage->LinkEndChild(serialNumber);

		tinyxml2::XMLElement* firmware = fDocument->NewElement("FIRMWARE");
		firmware->LinkEndChild(fDocument->NewText(info.firmware.c_str()));
		storage->LinkEndChild(firmware);
	}

	Logger::Log(LOG_DEBUG, "\tAdded Storage Info!");
}


void
Inventory::_AddMemoriesInfo()
{
	int slotNum = 0;
	for (;;) {
		std::ostringstream s;
		s << "MEMORY" << slotNum;
		std::map<std::string, Component>::iterator i = gComponents.find(s.str());
		if (i == gComponents.end())
			break;

		tinyxml2::XMLElement* memory = fDocument->NewElement("MEMORIES");
		fContent->LinkEndChild(memory);

		tinyxml2::XMLElement* description = fDocument->NewElement("DESCRIPTION");
		Component ramSlot = i->second;
		description->LinkEndChild(fDocument->NewText(ramSlot.fields["description"].c_str()));
		memory->LinkEndChild(description);

		tinyxml2::XMLElement* caption = fDocument->NewElement("CAPTION");
		caption->LinkEndChild(fDocument->NewText(ramSlot.fields["caption"].c_str()));
		memory->LinkEndChild(caption);

		tinyxml2::XMLElement* capacity = fDocument->NewElement("CAPACITY");
		capacity->LinkEndChild(fDocument->NewText(ramSlot.fields["size"].c_str()));
		memory->LinkEndChild(capacity);

		tinyxml2::XMLElement* purpose = fDocument->NewElement("PURPOSE");
		purpose->LinkEndChild(fDocument->NewText(ramSlot.fields["purpose"].c_str()));
		memory->LinkEndChild(purpose);

		tinyxml2::XMLElement* type = fDocument->NewElement("TYPE");
		type->LinkEndChild(fDocument->NewText(ramSlot.fields["type"].c_str()));
		memory->LinkEndChild(type);

		tinyxml2::XMLElement* speed = fDocument->NewElement("SPEED");
		speed->LinkEndChild(fDocument->NewText(ramSlot.fields["speed"].c_str()));
		memory->LinkEndChild(speed);

		tinyxml2::XMLElement* numSlots = fDocument->NewElement("NUMSLOTS");
		numSlots->LinkEndChild(fDocument->NewText(int_to_string(slotNum + 1).c_str()));
		memory->LinkEndChild(numSlots);

		tinyxml2::XMLElement* serial = fDocument->NewElement("SERIALNUMBER");
		serial->LinkEndChild(fDocument->NewText(ramSlot.fields["serial"].c_str()));
		memory->LinkEndChild(serial);

		slotNum++;
	}
	Logger::Log(LOG_DEBUG, "\tAdded Memory Info!");
}


void
Inventory::_AddDrivesInfo()
{
	VolumeRoster reader;
	volume_info info;
	while (reader.GetNext(info)) {
		tinyxml2::XMLElement* drive = fDocument->NewElement("DRIVES");
		fContent->LinkEndChild(drive);

		tinyxml2::XMLElement* createDate = fDocument->NewElement("CREATEDATE");
		createDate->LinkEndChild(fDocument->NewText(info.create_date.c_str()));
		drive->LinkEndChild(createDate);

		tinyxml2::XMLElement* fileSystem = fDocument->NewElement("FILESYSTEM");
		fileSystem->LinkEndChild(fDocument->NewText(info.filesystem.c_str()));
		drive->LinkEndChild(fileSystem);

		tinyxml2::XMLElement* freeSpace = fDocument->NewElement("FREE");
		freeSpace->LinkEndChild(fDocument->NewText(int_to_string(info.free).c_str()));
		drive->LinkEndChild(freeSpace);

		tinyxml2::XMLElement* label = fDocument->NewElement("LABEL");
		label->LinkEndChild(fDocument->NewText(info.label.c_str()));
		drive->LinkEndChild(label);

		tinyxml2::XMLElement* serial = fDocument->NewElement("SERIAL");
		serial->LinkEndChild(fDocument->NewText(info.serial.c_str()));
		drive->LinkEndChild(serial);

		tinyxml2::XMLElement* total = fDocument->NewElement("TOTAL");
		total->LinkEndChild(fDocument->NewText(int_to_string(info.total).c_str()));
		drive->LinkEndChild(total);

		tinyxml2::XMLElement* type = fDocument->NewElement("TYPE");
		type->LinkEndChild(fDocument->NewText(info.type.c_str()));
		drive->LinkEndChild(type);

		tinyxml2::XMLElement* volumeName = fDocument->NewElement("VOLUMN");
		volumeName->LinkEndChild(fDocument->NewText(info.name.c_str()));
		drive->LinkEndChild(volumeName);
	}

	Logger::Log(LOG_DEBUG, "\tAdded Drives info!");
}


void
Inventory::_AddHardwareInfo()
{
	tinyxml2::XMLElement* hardware = fDocument->NewElement("HARDWARE");
	fContent->LinkEndChild(hardware);

	tinyxml2::XMLElement* checksum = fDocument->NewElement("CHECKSUM");
	checksum->LinkEndChild(fDocument->NewText(int_to_string(Checksum()).c_str()));
	hardware->LinkEndChild(checksum);

	// Find first active interface
	NetworkRoster roster;
	NetworkInterface interface;
	unsigned int cookie = 0;
	while (roster.GetNextInterface(&cookie, interface) == 0) {
		if (!interface.IsLoopback() && interface.HasIPAddress()
				&& interface.HasDefaultGateway()) {
			tinyxml2::XMLElement* ipAddress = fDocument->NewElement("IPADDR");
			ipAddress->LinkEndChild(fDocument->NewText(interface.IPAddress().c_str()));
			hardware->LinkEndChild(ipAddress);

			std::string defaultGateway = interface.DefaultGateway();
			tinyxml2::XMLElement* defaultGW = fDocument->NewElement("DEFAULTGATEWAY");
			defaultGW->LinkEndChild(fDocument->NewText(defaultGateway.c_str()));
			hardware->LinkEndChild(defaultGW);
			break;
		}
	}

	Component& osInfo = gComponents["OS"] ;
	tinyxml2::XMLElement* description = fDocument->NewElement("DESCRIPTION");
	std::string descriptionString;
	descriptionString.append(osInfo.fields["architecture"]).append("/");
	description->LinkEndChild(fDocument->NewText(descriptionString.c_str()));
	hardware->LinkEndChild(description);

	tinyxml2::XMLElement* memory = fDocument->NewElement("MEMORY");
	memory->LinkEndChild(fDocument->NewText(osInfo.fields["memory"].c_str()));
	hardware->LinkEndChild(memory);

	tinyxml2::XMLElement* name = fDocument->NewElement("NAME");
	name->LinkEndChild(fDocument->NewText(osInfo.fields["hostname"].c_str()));
	hardware->LinkEndChild(name);

	tinyxml2::XMLElement* osComments = fDocument->NewElement("OSCOMMENTS");
	osComments->LinkEndChild(fDocument->NewText(osInfo.fields["comments"].c_str()));
	hardware->LinkEndChild(osComments);

	tinyxml2::XMLElement* osName = fDocument->NewElement("OSNAME");
	osName->LinkEndChild(fDocument->NewText(osInfo.fields["description"].c_str()));
	hardware->LinkEndChild(osName);

	tinyxml2::XMLElement* osVersion = fDocument->NewElement("OSVERSION");
	osVersion->LinkEndChild(fDocument->NewText(osInfo.fields["release"].c_str()));
	hardware->LinkEndChild(osVersion);

	std::pair<components_map::iterator, components_map::iterator> CPUs = gComponents.equal_range("CPU");
	size_t cpuCount = 0;
	for (components_map::iterator i = CPUs.first; i != CPUs.second; i++) {
		cpuCount++;
		Component cpuInfo = (*i).second;
		tinyxml2::XMLElement* processorS = fDocument->NewElement("PROCESSORS");
		processorS->LinkEndChild(fDocument->NewText(cpuInfo.fields["speed"].c_str()));
		hardware->LinkEndChild(processorS);

		tinyxml2::XMLElement* processorT = fDocument->NewElement("PROCESSORT");
		processorT->LinkEndChild(fDocument->NewText(cpuInfo.fields["type"].c_str()));
		hardware->LinkEndChild(processorT);
	}
	tinyxml2::XMLElement* processorN = fDocument->NewElement("PROCESSORN");
	processorN->LinkEndChild(fDocument->NewText(int_to_string(cpuCount).c_str()));
	hardware->LinkEndChild(processorN);

	if (Configuration::Get()->KeyValue("format") == "FORMAT_OCS") {
		tinyxml2::XMLElement* arch = fDocument->NewElement("ARCH");
		arch->LinkEndChild(fDocument->NewText(osInfo.fields["architecture"].c_str()));
		hardware->LinkEndChild(arch);
	}

	tinyxml2::XMLElement* swap = fDocument->NewElement("SWAP");
	swap->LinkEndChild(fDocument->NewText(osInfo.fields["swap"].c_str()));
	hardware->LinkEndChild(swap);

	tinyxml2::XMLElement* userID = fDocument->NewElement("USERID");
	// TODO: Fix this. Use the process user ?
	userID->LinkEndChild(fDocument->NewText("root"));
	hardware->LinkEndChild(userID);

	tinyxml2::XMLElement* uuid = fDocument->NewElement("UUID");
	uuid->LinkEndChild(fDocument->NewText(gComponents["SYSTEM"].fields["uuid"].c_str()));
	hardware->LinkEndChild(uuid);

	tinyxml2::XMLElement* vmSystem = fDocument->NewElement("VMSYSTEM");
	vmSystem->LinkEndChild(fDocument->NewText("Physical"));
	hardware->LinkEndChild(vmSystem);

	tinyxml2::XMLElement* workGroup = fDocument->NewElement("WORKGROUP");
	workGroup->LinkEndChild(fDocument->NewText(osInfo.fields["domainname"].c_str()));
	hardware->LinkEndChild(workGroup);

	UsersRoster users;
	user_entry user;
	if (users.GetNext(user)) {
		tinyxml2::XMLElement* dateLastLoggedUser = fDocument->NewElement("DATELASTLOGGEDUSER");
		dateLastLoggedUser->LinkEndChild(fDocument->NewText(user.logintimestring.c_str()));
		hardware->LinkEndChild(dateLastLoggedUser);
		tinyxml2::XMLElement* lastLoggedUser = fDocument->NewElement("LASTLOGGEDUSER");
		lastLoggedUser->LinkEndChild(fDocument->NewText(user.login.c_str()));
		hardware->LinkEndChild(lastLoggedUser);
	}

	Logger::Log(LOG_DEBUG, "\tAdded Hardware info!");
}


void
Inventory::_AddNetworksInfo()
{
	NetworkRoster roster;
	NetworkInterface interface;
	unsigned int cookie = 0;
	while (roster.GetNextInterface(&cookie, interface) == 0) {
		if (interface.IsLoopback())
			continue;

		tinyxml2::XMLElement* networks = fDocument->NewElement("NETWORKS");
		fContent->LinkEndChild(networks);

		tinyxml2::XMLElement* description = fDocument->NewElement("DESCRIPTION");
		description->LinkEndChild(fDocument->NewText(interface.Name().c_str()));
		networks->LinkEndChild(description);

		tinyxml2::XMLElement* driver = fDocument->NewElement("DRIVER");
		driver->LinkEndChild(fDocument->NewText("pif"));
		networks->LinkEndChild(driver);

		tinyxml2::XMLElement* ipAddress = fDocument->NewElement("IPADDRESS");
		ipAddress->LinkEndChild(fDocument->NewText(interface.IPAddress().c_str()));
		networks->LinkEndChild(ipAddress);

		tinyxml2::XMLElement* ipDHCP = fDocument->NewElement("IPDHCP");
		ipDHCP->LinkEndChild(fDocument->NewText(""));
		networks->LinkEndChild(ipDHCP);

		tinyxml2::XMLElement* gateway = fDocument->NewElement("IPGATEWAY");
		std::string gatewayString = interface.DefaultGateway();
		gateway->LinkEndChild(fDocument->NewText(gatewayString.c_str()));
		networks->LinkEndChild(gateway);

		tinyxml2::XMLElement* ipMask = fDocument->NewElement("IPMASK");
		ipMask->LinkEndChild(fDocument->NewText(interface.NetMask().c_str()));
		networks->LinkEndChild(ipMask);

		tinyxml2::XMLElement* ipSubnet = fDocument->NewElement("IPSUBNET");
		ipSubnet->LinkEndChild(fDocument->NewText(interface.Network().c_str()));
		networks->LinkEndChild(ipSubnet);

		tinyxml2::XMLElement* mac = fDocument->NewElement("MACADDR");
		mac->LinkEndChild(fDocument->NewText(interface.HardwareAddress().c_str()));
		networks->LinkEndChild(mac);

		tinyxml2::XMLElement* pciSlot = fDocument->NewElement("PCISLOT");
		pciSlot->LinkEndChild(fDocument->NewText(""));
		networks->LinkEndChild(pciSlot);

		tinyxml2::XMLElement* status = fDocument->NewElement("STATUS");
		status->LinkEndChild(fDocument->NewText(interface.Status().c_str()));
		networks->LinkEndChild(status);

		tinyxml2::XMLElement* type = fDocument->NewElement("TYPE");
		type->LinkEndChild(fDocument->NewText(interface.Type().c_str()));
		networks->LinkEndChild(type);

		tinyxml2::XMLElement* speed = fDocument->NewElement("SPEED");
		speed->LinkEndChild(fDocument->NewText(interface.Speed().c_str()));
		networks->LinkEndChild(speed);

		tinyxml2::XMLElement* virtualDevice = fDocument->NewElement("VIRTUALDEV");
		virtualDevice->LinkEndChild(fDocument->NewText(""));
		networks->LinkEndChild(virtualDevice);
	}

	Logger::Log(LOG_DEBUG, "\tAdded Networks info!");
}


void
Inventory::_AddProcessesInfo()
{
	RunningProcessesList processList;
	process_info processInfo;
	while (processList.GetNext(processInfo)) {
		tinyxml2::XMLElement* process = fDocument->NewElement("PROCESSES");
		fContent->LinkEndChild(process);

		tinyxml2::XMLElement* cmd = fDocument->NewElement("CMD");
		cmd->LinkEndChild(fDocument->NewText(processInfo.cmdline.c_str()));
		process->LinkEndChild(cmd);
#if 0
		tinyxml2::XMLElement* cpuUsage = fDocument->NewElement("CPUUSAGE");
		cpuUsage->LinkEndChild(fDocument->NewText(""));
		process->LinkEndChild(cpuUsage);
#endif
		tinyxml2::XMLElement* mem = fDocument->NewElement("MEM");
		mem->LinkEndChild(fDocument->NewText(int_to_string(processInfo.memory).c_str()));
		process->LinkEndChild(mem);

		tinyxml2::XMLElement* pid = fDocument->NewElement("PID");
		pid->LinkEndChild(fDocument->NewText(int_to_string(processInfo.pid).c_str()));
		process->LinkEndChild(pid);

		tinyxml2::XMLElement* started = fDocument->NewElement("STARTED");
		started->LinkEndChild(fDocument->NewText(""));
		process->LinkEndChild(started);

		tinyxml2::XMLElement* tty = fDocument->NewElement("TTY");
		tty->LinkEndChild(fDocument->NewText(""));
		process->LinkEndChild(tty);

		tinyxml2::XMLElement* user = fDocument->NewElement("USER");
		std::string userString = processInfo.user.c_str();
		user->LinkEndChild(fDocument->NewText(userString.c_str()));
		process->LinkEndChild(user);

		tinyxml2::XMLElement* virtualMem = fDocument->NewElement("VIRTUALMEMORY");
		virtualMem->LinkEndChild(fDocument->NewText(int_to_string(processInfo.virtualmem).c_str()));
		process->LinkEndChild(virtualMem);
	}

	Logger::Log(LOG_DEBUG, "\tAdded Processes list!");
}


void
Inventory::_AddSoftwaresInfo()
{
	Softwares softwares;
	software_info info;
	while (softwares.GetNext(info)) {
		tinyxml2::XMLElement* software = fDocument->NewElement("SOFTWARES");
		fContent->LinkEndChild(software);

		tinyxml2::XMLElement* comments = fDocument->NewElement("COMMENTS");
		comments->LinkEndChild(fDocument->NewText(info.comments.c_str()));
		software->LinkEndChild(comments);

		tinyxml2::XMLElement* name = fDocument->NewElement("NAME");
		name->LinkEndChild(fDocument->NewText(info.name.c_str()));
		software->LinkEndChild(name);

		tinyxml2::XMLElement* size = fDocument->NewElement("FILESIZE");
		size->LinkEndChild(fDocument->NewText(info.size.c_str()));
		software->LinkEndChild(size);

		tinyxml2::XMLElement* from = fDocument->NewElement("FROM");
		from->LinkEndChild(fDocument->NewText(info.from.c_str()));
		software->LinkEndChild(from);

		tinyxml2::XMLElement* installdate = fDocument->NewElement("INSTALLDATE");
		installdate->LinkEndChild(fDocument->NewText(info.installdate.c_str()));
		software->LinkEndChild(installdate);

		tinyxml2::XMLElement* version = fDocument->NewElement("VERSION");
		version->LinkEndChild(fDocument->NewText(info.version.c_str()));
		software->LinkEndChild(version);
	}
	Logger::Log(LOG_DEBUG, "\tAdded Software list!");
}


void
Inventory::_AddUsersInfo()
{
	tinyxml2::XMLElement* users = fDocument->NewElement("USERS");
	fContent->LinkEndChild(users);

	UsersRoster usersInfo;
	user_entry userEntry;
	while (usersInfo.GetNext(userEntry)) {
		tinyxml2::XMLElement* domain = fDocument->NewElement("DOMAIN");
		domain->LinkEndChild(fDocument->NewText(userEntry.logindomain.c_str()));
		users->LinkEndChild(domain);

		tinyxml2::XMLElement* login = fDocument->NewElement("LOGIN");
		login->LinkEndChild(fDocument->NewText(userEntry.login.c_str()));
		users->LinkEndChild(login);
	}

	Logger::Log(LOG_DEBUG, "\tAdded User info!");
}


void
Inventory::_AddVideosInfo()
{
	// TODO: Multiple video cards
	for (int i = 0; i < 1; i++) {
		Component& info = gComponents["GRAPHICS"];

		tinyxml2::XMLElement* video = fDocument->NewElement("VIDEOS");
		fContent->LinkEndChild(video);

		// OCSInventoryFormatOCS uses the name as chipset, and the chipset as name
		tinyxml2::XMLElement* chipset = fDocument->NewElement("CHIPSET");
		chipset->LinkEndChild(fDocument->NewText(info.fields["name"].c_str()));
		video->LinkEndChild(chipset);

		tinyxml2::XMLElement* memory = fDocument->NewElement("MEMORY");
		memory->LinkEndChild(fDocument->NewText(info.fields["memory_size"].c_str()));
		video->LinkEndChild(memory);

		tinyxml2::XMLElement* name = fDocument->NewElement("NAME");
		name->LinkEndChild(fDocument->NewText(info.fields["type"].c_str()));
		video->LinkEndChild(name);

		tinyxml2::XMLElement* resolution = fDocument->NewElement("RESOLUTION");
		resolution->LinkEndChild(fDocument->NewText(info.fields["resolution"].c_str()));
		video->LinkEndChild(resolution);
	}
	Logger::Log(LOG_DEBUG, "\tAdded Video info!");
}


void
Inventory::_AddMonitorsInfo()
{
	Screens screens;
	screen_info info;
	while (screens.GetNext(info)) {
		tinyxml2::XMLElement* monitor = fDocument->NewElement("MONITORS");
		fContent->LinkEndChild(monitor);

		tinyxml2::XMLElement* caption = fDocument->NewElement("CAPTION");
		caption->LinkEndChild(fDocument->NewText(info.model.c_str()));
		monitor->LinkEndChild(caption);

		tinyxml2::XMLElement* description = fDocument->NewElement("DESCRIPTION");
		description->LinkEndChild(fDocument->NewText(info.description.c_str()));
		monitor->LinkEndChild(description);

		tinyxml2::XMLElement* type = fDocument->NewElement("TYPE");
		type->LinkEndChild(fDocument->NewText(info.type.c_str()));
		monitor->LinkEndChild(type);

		tinyxml2::XMLElement* manufacturer = fDocument->NewElement("MANUFACTURER");
		manufacturer->LinkEndChild(fDocument->NewText(info.manufacturer.c_str()));
		monitor->LinkEndChild(manufacturer);

		tinyxml2::XMLElement* serial = fDocument->NewElement("SERIAL");
		serial->LinkEndChild(fDocument->NewText(info.serial_number.c_str()));
		monitor->LinkEndChild(serial);
	}

	Logger::Log(LOG_DEBUG, "\tAdded Display info!");
}


bool
Inventory::_WriteProlog(tinyxml2::XMLDocument& document) const
{
	Configuration* config = Configuration::Get();

	tinyxml2::XMLDeclaration* declaration = document.NewDeclaration();
	document.LinkEndChild(declaration);

	tinyxml2::XMLElement* request = document.NewElement("REQUEST");
	document.LinkEndChild(request);

	tinyxml2::XMLElement* deviceID = document.NewElement("DEVICEID");
	deviceID->LinkEndChild(document.NewText(config->DeviceID().c_str()));
	request->LinkEndChild(deviceID);

	tinyxml2::XMLElement* query = document.NewElement("QUERY");
	query->LinkEndChild(document.NewText("PROLOG"));
	request->LinkEndChild(query);

	return true;
}


bool
Inventory::_HandleResponse(HTTP& httpObject)
{
	const HTTPResponseHeader& responseHeader2 = httpObject.LastResponse();
	bool statusOk = responseHeader2.StatusCode() == HTTP_OK;
	if (!responseHeader2.HasContentLength()) {
		if (!statusOk) {
			Logger::Log(LOG_ERR, "Sending inventory failed");
			return false;
		}
	}

	Logger::LogFormat(LOG_ERR, "Server replied %s", responseHeader2.StatusString().c_str());
	Logger::LogFormat(LOG_ERR, "%s", responseHeader2.ToString().c_str());

	size_t contentLength = responseHeader2.ContentLength();
	const char* resultData = responseHeader2.Data();

	if (responseHeader2.ContentType() == "application/xml") {
		Logger::Log(LOG_INFO, "Inventory::Send(): Deserialize XML... ");
		tinyxml2::XMLDocument reply;
		bool deserialized = XML::Deserialize(resultData, contentLength, reply);
		if (!deserialized) {
			Logger::Log(LOG_ERR, "failed to deserialize XML");
			return false;
		}
		Logger::Log(LOG_INFO, "Server replied:");
		Logger::Log(LOG_INFO, XML::ToString(reply).c_str());
	}
	return statusOk;
}


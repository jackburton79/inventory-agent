/*
 * configtest.cpp
 *
 * Tests for Configuration
 */

#include "Configuration.h"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>


static int sFailures = 0;


static void
Check(bool condition, const std::string& what)
{
	if (!condition) {
		std::cout << "  FAILED: " << what << std::endl;
		sFailures++;
	}
}


static std::string
ReadFile(const std::string& fileName)
{
	std::ifstream file(fileName);
	std::stringstream s;
	s << file.rdbuf();
	return s.str();
}


static mode_t
FileMode(const std::string& fileName)
{
	struct stat st;
	if (::stat(fileName.c_str(), &st) != 0)
		return 0;
	return st.st_mode & 0777;
}


int main()
{
	char dirTemplate[] = "/tmp/configtest.XXXXXX";
	const char* dir = ::mkdtemp(dirTemplate);
	if (dir == NULL) {
		std::cerr << "cannot create temporary directory" << std::endl;
		return 2;
	}
	const std::string confFile = std::string(dir) + "/agent.conf";
	const std::string savedFile = std::string(dir) + "/saved.conf";
	const std::string newFile = std::string(dir) + "/new.conf";

	{
		std::ofstream conf(confFile);
		conf << "server=https://user:pass@ocs.example.com/ocsinventory?a=b" << std::endl;
		conf << "TAG=office" << std::endl;
		conf << "a line without equal sign" << std::endl;
		conf << "yesvalue=Yes" << std::endl;
		conf << "truevalue=TRUE" << std::endl;
		conf << "falsevalue=false" << std::endl;
		conf << "empty=" << std::endl;
	}
	::chmod(confFile.c_str(), 0644);

	Configuration* config = Configuration::Get();

	std::cout << "Load" << std::endl;
	config->Load(confFile.c_str());
	Check(config->KeyValue("TAG") == "office", "TAG");
	Check(config->ServerURL() == "https://user:pass@ocs.example.com/ocsinventory?a=b",
		"value containing '=': " + config->ServerURL());
	Check(config->KeyValue("a line without equal sign").empty(), "line without '='");
	Check(config->KeyValue("missing").empty(), "missing key");
	Check(config->KeyValue("empty").empty(), "empty value");
	Check(!config->LocalInventory(), "LocalInventory() with a server");

	std::cout << "Booleans" << std::endl;
	Check(config->KeyValueBoolean("yesvalue"), "'Yes' should be true");
	Check(config->KeyValueBoolean("truevalue"), "'TRUE' should be true");
	Check(!config->KeyValueBoolean("falsevalue"), "'false' should be false");
	Check(!config->KeyValueBoolean("missing"), "missing key should be false");

	std::cout << "Volatile values" << std::endl;
	config->SetVolatileKeyValue("volatilekey", "volatilevalue");
	Check(config->KeyValue("volatilekey") == "volatilevalue", "volatile value");
	config->SetServer("http://cli.example.com/ocs");
	Check(config->ServerURL() == "http://cli.example.com/ocs",
		"the command line server should take precedence: " + config->ServerURL());

	std::cout << "Save" << std::endl;
	config->SetDeviceID("device-2017-01-01-00-00-00");
	Check(config->Save(savedFile.c_str()), "Save() failed");
	std::string saved = ReadFile(savedFile);
	Check(saved.find("server=https://user:pass@ocs.example.com/ocsinventory?a=b\n")
		!= std::string::npos, "server from the file not saved");
	Check(saved.find("cli.example.com") == std::string::npos,
		"the command line server must not be saved");
	Check(saved.find("volatilekey") == std::string::npos,
		"volatile values must not be saved");
	Check(saved.find("deviceID=device-2017-01-01-00-00-00\n") != std::string::npos,
		"device ID not saved");
	Check(saved.find("TAG=office\n") != std::string::npos, "TAG not saved");

	std::cout << "File permissions" << std::endl;
	::umask(022);
	config->Save(newFile.c_str());
	Check(FileMode(newFile) == 0600, "a new file should be created with mode 0600");
	config->Save(confFile.c_str());
	Check(FileMode(confFile) == 0644, "the mode of an existing file should be kept");

	::unlink(confFile.c_str());
	::unlink(savedFile.c_str());
	::unlink(newFile.c_str());
	::rmdir(dir);

	if (sFailures > 0) {
		std::cout << sFailures << " check(s) failed" << std::endl;
		std::cout << "Test Failed !!!" << std::endl;
		return 1;
	}

	std::cout << "All tests passed!" << std::endl;
	return 0;
}

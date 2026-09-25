#include "http/URL.h"

#include <cstdlib>
#include <cstring>
#include <iostream>


struct test_entry {
    const char* url;
    bool relative;
    const char* protocol;
    const char* host;
    const int port;
    const char* path;
    const char* user;
    const char* pass;
};


const struct test_entry kTestEntries[] = {
    { "http://www.test.com:90/test", false, "http", "www.test.com", 90,
        "/test", "", "" },
    { "http://www.test2.it", false, "http", "www.test2.it", 80, "", "", "" },
    { "https://differentURL.com/part/of/path/end.xml", false, "https",
        "differentURL.com", 443, "/part/of/path/end.xml", "", "" },
    { "www.withoutproto.com", false, "", "www.withoutproto.com", 80, "", "", "" },
    { "/pathonly/run.php", true, "", "", 80, "/pathonly/run.php", "", "" },
    { "user:pass@server/directory/file.xml", false, "", "server", 80,
        "/directory/file.xml", "user", "pass" },
    { "http://user:password@server:81/directory/", false, "http", "server",
        81, "/directory/", "user", "password" },
    { "http:/malformed_url.com/path", false, "http", "malformed_url.com", 80,
        "/path", "", "" },
    { "http://malformed_url.com///path", false, "http", "malformed_url.com", 80,
        "/path", "", "" },
    { "http://malformed_url_with_port.com:8080///path", false, "http",
        "malformed_url_with_port.com", 8080, "/path", "", "" },
    { "https://glpi.cloud.com/", false, "https", "glpi.cloud.com", 443,
        "/", "", "" },
    { "https://localhost:4433/", false, "https", "localhost", 4433,
        "/", "", "" },
    { "http://server:81///", false, "http", "server", 81, "/", "", "" },
    { "http://user:pass@server//", false, "http", "server", 80, "/",
        "user", "pass" },
    // IPv6 addresses
    { "http://[::1]:8080/ocs", false, "http", "::1", 8080, "/ocs", "", "" },
    { "https://[2001:db8::10]/ocsinventory", false, "https", "2001:db8::10",
        443, "/ocsinventory", "", "" },
    { "https://user:pass@[fe80::1]:8443/", false, "https", "fe80::1", 8443,
        "/", "user", "pass" },
    { "http://[::1]", false, "http", "::1", 80, "", "", "" },
    // User without password, '@' and ':' outside of the authority
    { "http://user@server:81/path", false, "http", "server", 81, "/path",
        "user", "" },
    { "http://server/path/with@at:colon", false, "http", "server", 80,
        "/path/with@at:colon", "", "" },
    { "https://user:p@ss@server/", false, "https", "server", 443, "/",
        "user", "p@ss" }
};


struct host_header_entry {
    const char* url;
    const char* hostHeader;
};


const struct host_header_entry kHostHeaderEntries[] = {
    { "http://www.test.com/test", "www.test.com" },
    { "http://www.test.com:80/test", "www.test.com" },
    { "http://www.test.com:8080/test", "www.test.com:8080" },
    { "https://www.test.com:443/", "www.test.com" },
    { "https://www.test.com:80/", "www.test.com:80" },
    { "http://[::1]/ocs", "[::1]" },
    { "http://[::1]:8080/ocs", "[::1]:8080" },
    { "/relative/path", "" }
};


int main()
{
    bool fail = false;
    URL url;
    for (size_t i = 0; i < sizeof(kTestEntries) / sizeof(kTestEntries[0]); i++) {
        char* urlString = (char*)kTestEntries[i].url;
        url.SetTo(urlString);
        std::cout << "url: " << url.URLString() << std::endl;
        std::cout << "\t" << "relative: " << (url.IsRelative() ? "yes" : "no");
        std::cout << " (should be: \"" ;
        std::cout << (kTestEntries[i].relative ? "yes" : "no");
        std::cout << "\")" << std::endl;
        std::cout << "\t" << "protocol: " << url.Protocol();
        std::cout << " (should be: \"" ;
        std::cout << kTestEntries[i].protocol;
        std::cout << "\")" << std::endl;
        std::cout << "\t" << "host: " << url.Host();
        std::cout << " (should be: \"" ;
        std::cout << kTestEntries[i].host;
        std::cout << "\")" << std::endl;
        std::cout << "\t" << "port: " << url.Port();
        std::cout << " (should be: \"" ;
        std::cout << kTestEntries[i].port;
        std::cout << "\")" << std::endl;
        std::cout << "\t" << "path: " << url.Path();
        std::cout << " (should be: \"" ;
        std::cout << kTestEntries[i].path;
        std::cout << "\")" << std::endl;
        std::cout << "\t" << "username: " << url.Username();
        std::cout << " (should be: \"" ;
        std::cout << kTestEntries[i].user;
        std::cout << "\")" << std::endl;
        std::cout << "\t" << "password: " << url.Password();
        std::cout << " (should be: \"" ;
        std::cout << kTestEntries[i].pass;
        std::cout << "\")" << std::endl;
        if (url.IsRelative() != kTestEntries[i].relative
            || url.Port() != kTestEntries[i].port
            || url.Protocol().compare(kTestEntries[i].protocol)
            || url.Host().compare(kTestEntries[i].host)
            || url.Path().compare(kTestEntries[i].path)
            || url.Username().compare(kTestEntries[i].user)
            || url.Password().compare(kTestEntries[i].pass)) {
            fail = true;
            std::cout << "Test Failed !!!" << std::endl;
        }
    }

    for (size_t i = 0; i < sizeof(kHostHeaderEntries) / sizeof(kHostHeaderEntries[0]); i++) {
        url.SetTo(kHostHeaderEntries[i].url);
        std::cout << "url: " << url.URLString() << std::endl;
        std::cout << "\t" << "host header: " << url.HostHeader();
        std::cout << " (should be: \"" << kHostHeaderEntries[i].hostHeader << "\")" << std::endl;
        if (url.HostHeader().compare(kHostHeaderEntries[i].hostHeader)) {
            fail = true;
            std::cout << "Test Failed !!!" << std::endl;
        }
    }

    if (fail) {
        ::exit(-1);
    }

    std::cout << "All tests passed!" << std::endl;
}

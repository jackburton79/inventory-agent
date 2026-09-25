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
        "user", "pass" }
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

    if (fail) {
        ::exit(-1);
    }

    std::cout << "All tests passed!" << std::endl;
}

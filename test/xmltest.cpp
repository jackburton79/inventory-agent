/*
 * xmltest.cpp
 *
 * Tests for the text getters of XML: an empty element must give an
 * empty string (tinyxml2's GetText() returns NULL for it)
 */

#include "XML.h"

#include <tinyxml2/tinyxml2.h>

#include <cstring>
#include <iostream>
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


static bool
Parse(const char* xml, tinyxml2::XMLDocument& document)
{
	return XML::Deserialize(xml, ::strlen(xml), document);
}


int main()
{
	std::cout << "GetElementText" << std::endl;
	{
		tinyxml2::XMLDocument document;
		Check(Parse("<REPLY><RESPONSE>SEND</RESPONSE></REPLY>", document), "parse");
		Check(XML::GetElementText(document, "RESPONSE") == "SEND", "element with text");
		Check(XML::GetElementText(document, "MISSING") == "", "missing element");
	}
	{
		tinyxml2::XMLDocument document;
		Check(Parse("<REPLY><RESPONSE/></REPLY>", document), "parse");
		Check(XML::GetElementText(document, "RESPONSE") == "", "self closing empty element");
	}
	{
		tinyxml2::XMLDocument document;
		Check(Parse("<REPLY><RESPONSE></RESPONSE></REPLY>", document), "parse");
		Check(XML::GetElementText(document, "RESPONSE") == "", "empty element");
	}

	std::cout << "GetFirstChildElementText" << std::endl;
	{
		tinyxml2::XMLDocument document;
		Check(Parse("<node><vendor>ACME</vendor><serial/><version></version></node>",
			document), "parse");
		const tinyxml2::XMLElement* node = document.FirstChildElement("node");
		Check(node != NULL, "node found");
		if (node != NULL) {
			Check(XML::GetFirstChildElementText(node, "vendor") == "ACME", "child with text");
			Check(XML::GetFirstChildElementText(node, "serial") == "", "self closing empty child");
			Check(XML::GetFirstChildElementText(node, "version") == "", "empty child");
			Check(XML::GetFirstChildElementText(node, "missing") == "", "missing child");
		}
	}

	if (sFailures > 0) {
		std::cout << sFailures << " check(s) failed" << std::endl;
		std::cout << "Test Failed !!!" << std::endl;
		return 1;
	}

	std::cout << "All tests passed!" << std::endl;
	return 0;
}

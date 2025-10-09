/*
 * XML.h
 *
 *  Created on: 01/sep/2014
 *      Author: Stefano Ceccherini
 */

#ifndef XML_H_
#define XML_H_

#include <string>

namespace tinyxml2 {
	class XMLDocument;
	class XMLElement;
	class XMLNode;
};

class XML {
public:
	enum match_mode {
		match_partial = 0,
		match_full = 1	
	};
	static std::string ToString(const tinyxml2::XMLDocument& document);
	static bool Serialize(const tinyxml2::XMLDocument& document, char*& destination, size_t& destLength);
	static bool Deserialize(const char* source, size_t sourceLen, tinyxml2::XMLDocument& document);

	static std::string GetElementText(const tinyxml2::XMLNode& node, const std::string& elementName);
	static std::string GetFirstChildElementText(const tinyxml2::XMLElement*, const std::string& elementName);

	static const tinyxml2::XMLElement* GetElementByName(const tinyxml2::XMLNode& node,
							const std::string& elementName,
							int matchMode = XML::match_full);
														
	static const tinyxml2::XMLElement* GetElementByAttribute(const tinyxml2::XMLNode& node,
							const std::string& attributeName,
							const std::string& attributeValue,
							int matchMode = XML::match_full);
};

#endif /* XML_H_ */

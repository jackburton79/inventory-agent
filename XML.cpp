/*
 * XML.cpp
 *
 *  Created on: 01/ago/2014
 *      Author: Stefano Ceccherini
 */


#include "Support.h"
#include "XML.h"
#include "ZLibCompressor.h"

#include <iostream>
#include <streambuf>
#include <string>
#include <string.h>

#include <tinyxml2/tinyxml2.h>


class ElementFinderByName : public tinyxml2::XMLVisitor {
public:
	ElementFinderByName(const std::string& elementName, int matchMode);
	virtual bool VisitEnter(const tinyxml2::XMLElement& element, const tinyxml2::XMLAttribute* attr);

	const tinyxml2::XMLElement* Element() const;
private:
	std::string fElementName;
	const tinyxml2::XMLElement* fElement;
	bool fFull;
};


class ElementFinderByAttribute : public tinyxml2::XMLVisitor {
public:
	ElementFinderByAttribute(const std::string& attributeName,
							const std::string& attributeValue,
							int matchMode);
	virtual bool VisitEnter(const tinyxml2::XMLElement& element, const tinyxml2::XMLAttribute* attr);

	const tinyxml2::XMLElement* Element() const;
private:
	std::string fAttributeName;
	std::string fAttributeValue;
	const tinyxml2::XMLElement* fElement;
	bool fFull;
};


// XML
std::string
XML::ToString(const tinyxml2::XMLDocument& document)
{
	tinyxml2::XMLPrinter memoryPrinter;
	document.Print(&memoryPrinter);
	std::string str = memoryPrinter.CStr();
	return str;
}


bool
XML::Serialize(const tinyxml2::XMLDocument& document, char*& destination, size_t& destLength)
{
	tinyxml2::XMLPrinter memoryPrinter;
	document.Print(&memoryPrinter);

	destination = new char[memoryPrinter.CStrSize()];
	memcpy(destination, memoryPrinter.CStr(), memoryPrinter.CStrSize() - 1);
	destLength = memoryPrinter.CStrSize() - 1;

	return true;
}


bool
XML::Deserialize(const char* source, size_t sourceLen, tinyxml2::XMLDocument& document)
{
	tinyxml2::XMLError result = document.Parse(source, sourceLen);

	tinyxml2::XMLPrinter memoryPrinter;
	document.Print(&memoryPrinter);
	return result == tinyxml2::XML_SUCCESS;
}


std::string
XML::GetElementText(const tinyxml2::XMLNode& node, const std::string& elementName)
{
	std::string result;
	const tinyxml2::XMLElement* element = GetElementByName(node, elementName);
	if (element != NULL)
		result = element->GetText();
	return result;
}


std::string
XML::GetFirstChildElementText(const tinyxml2::XMLElement* element, const std::string& elementName)
{
	std::string result;
	const tinyxml2::XMLElement* foundElement = element->FirstChildElement(elementName.c_str());
	if (foundElement != NULL)
		result = foundElement->GetText();
	return result;
}


const tinyxml2::XMLElement*
XML::GetElementByName(const tinyxml2::XMLNode& node,
						const std::string& elementName,
						int matchMode)
{
	ElementFinderByName textFinder(elementName, matchMode);
	node.Accept(&textFinder);

	return textFinder.Element();
}


const tinyxml2::XMLElement*
XML::GetElementByAttribute(const tinyxml2::XMLNode& node,
							const std::string& attributeName,
							const std::string& attributeValue,
							int matchMode)
{
	ElementFinderByAttribute attributeFinder(attributeName, attributeValue, matchMode);
	node.Accept(&attributeFinder);

	return attributeFinder.Element();
}


// ElementFinderByName
ElementFinderByName::ElementFinderByName(const std::string& elementName, int matchMode)
	:
	XMLVisitor(),
	fElementName(elementName),
	fElement(NULL),
	fFull(matchMode == XML::match_full)
{
}


/* virtual */
bool
ElementFinderByName::VisitEnter(const tinyxml2::XMLElement& element, const tinyxml2::XMLAttribute*)
{
	if (fElement != NULL)
		return false;

	if (fFull) {
		if (fElementName.compare(element.Name()) == 0) {
			fElement = &element;
			return false;
		}
	} else {
		if (fElementName.compare(0, fElementName.length(), element.Name(), fElementName.length()) == 0) {
			fElement = &element;
			return false;
		}
	}

	return true;
}


const tinyxml2::XMLElement*
ElementFinderByName::Element() const
{
	return fElement;
}


// ElementFinderByAttribute
ElementFinderByAttribute::ElementFinderByAttribute(const std::string& attributeName,
						const std::string& attributeValue,
						int matchMode)
	:
	XMLVisitor(),
	fAttributeName(attributeName),
	fAttributeValue(attributeValue),
	fElement(NULL),
	fFull(matchMode == XML::match_full)
{
}


/* virtual */
bool
ElementFinderByAttribute::VisitEnter(const tinyxml2::XMLElement& element, const tinyxml2::XMLAttribute* attr)
{
	if (fElement != NULL)
		return false;

	if (attr == NULL)
		return true;

	const tinyxml2::XMLAttribute* next = attr;
	while (next != NULL) {
		if (fFull) {
			if (fAttributeName.compare(next->Name()) == 0
					&& fAttributeValue.compare(next->Value()) == 0) {
				fElement = &element;
				return false;
			}
		} else {
			if (fAttributeName.compare(next->Name()) == 0
					&& fAttributeValue.compare(0, fAttributeValue.length(),
						next->Value(), fAttributeValue.length()) == 0) {
				fElement = &element;
				return false;
			}
		}
		next = next->Next();
	}

	return true;
}


const tinyxml2::XMLElement*
ElementFinderByAttribute::Element() const
{
	return fElement;
}

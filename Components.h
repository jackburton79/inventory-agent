/*
 * Components.h
 *
 *  Created on: 11/lug/2013
 *      Author: Stefano Ceccherini
 */

#ifndef COMPONENTS_H_
#define COMPONENTS_H_

#include <map>
#include <stdexcept>
#include <string>
#include <vector>


typedef std::map<std::string, std::string> string_map;


class Component {
public:
	string_map fields;
	void MergeWith(Component& component);
};

class components_map : public std::multimap<std::string, Component> {
public:
	void Merge(const std::string& string, Component c) {
		components_map::iterator i = find(string);
		if (i != end())
			(*i).second.MergeWith(c);
		else {
			insert(std::make_pair(string, c));
		}
	};
	Component& operator[](const std::string& string) {
		components_map::iterator i = find(string);
		if (i != end())
			return (*i).second;
		std::string errorString = "operator[]: no element for ";
		errorString.append(string);
		throw std::runtime_error(errorString);
	}
};

extern components_map gComponents;


#endif /* COMPONENTS_H_ */

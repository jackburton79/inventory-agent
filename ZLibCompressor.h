/*
 * ZLibCompressor.h
 *
 *  Created on: 03 mag 2018
 *      Author: Stefano ceccherini (stefano.ceccherini@gmail.com)
 */

#ifndef ZLIBCOMPRESSOR_H_
#define ZLIBCOMPRESSOR_H_

#include <string>
#include <sys/types.h>

class ZLibCompressor {
public:
	static bool Compress(const char* source, size_t sourceLength, std::string& destination);
	static bool Uncompress(const char* source, size_t sourceLength, std::string& destination);
};



#endif /* ZLIBCOMPRESSOR_H_ */

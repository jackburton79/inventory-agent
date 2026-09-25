/*
 * ZLibCompressor.cpp
 *
 *  Created on: 03 mag 2018
 *      Author: Stefano ceccherini (stefano.ceccherini@gmail.com)
 */

#include "ZLibCompressor.h"

#include "Logger.h"

#include <algorithm>
#include <zlib.h>

// Upper limit for the uncompressed data, to avoid exhausting memory
// with a malformed (or malicious) reply
static const size_t kMaxUncompressedLength = 64 * 1024 * 1024;


/*static */
bool
ZLibCompressor::Compress(const char* source, size_t sourceLength, std::string& destination)
{
	uLongf destLength = compressBound(sourceLength);
	destination.resize(destLength);

	int status = compress(reinterpret_cast<Bytef*>(&destination[0]), &destLength,
			reinterpret_cast<const Bytef*>(source), static_cast<uLong>(sourceLength));
	if (status != Z_OK) {
		Logger::LogFormat(LOG_ERR, "ZLibCompressor: compress failed: %s", zError(status));
		destination.clear();
		return false;
	}

	destination.resize(destLength);
	return true;
}


/* static */
bool
ZLibCompressor::Uncompress(const char* source, size_t sourceLength, std::string& destination)
{
	// The uncompressed size is not known in advance: start with a
	// reasonable buffer and grow it until the data fits
	size_t bufferLength = std::max(sourceLength * 4, static_cast<size_t>(32768));
	int status = Z_BUF_ERROR;
	while (bufferLength <= kMaxUncompressedLength) {
		destination.resize(bufferLength);
		uLongf destLength = bufferLength;
		status = uncompress(reinterpret_cast<Bytef*>(&destination[0]), &destLength,
			reinterpret_cast<const Bytef*>(source), static_cast<uLong>(sourceLength));
		if (status == Z_OK) {
			destination.resize(destLength);
			return true;
		}
		if (status != Z_BUF_ERROR)
			break;
		bufferLength *= 2;
	}

	Logger::LogFormat(LOG_ERR, "ZLibCompressor: uncompress failed: %s", zError(status));
	destination.clear();
	return false;
}

/*
 * zlibtest.cpp
 *
 * Tests for ZLibCompressor
 */

#include "ZLibCompressor.h"

#include <cstdlib>
#include <iostream>
#include <string>


static bool
RoundTrip(const std::string& data)
{
	std::string compressed;
	if (!ZLibCompressor::Compress(data.data(), data.length(), compressed)) {
		std::cout << "Compress failed for " << data.length() << " bytes" << std::endl;
		return false;
	}

	std::string uncompressed;
	if (!ZLibCompressor::Uncompress(compressed.data(), compressed.length(), uncompressed)) {
		std::cout << "Uncompress failed for " << data.length() << " bytes" << std::endl;
		return false;
	}

	if (uncompressed != data) {
		std::cout << "Data mismatch for " << data.length() << " bytes" << std::endl;
		return false;
	}

	std::cout << data.length() << " bytes -> " << compressed.length()
		<< " bytes -> " << uncompressed.length() << " bytes: OK" << std::endl;
	return true;
}


int main()
{
	bool fail = false;

	fail |= !RoundTrip("");
	fail |= !RoundTrip("<REPLY><RESPONSE>SEND</RESPONSE></REPLY>");

	// Bigger than the initial uncompress buffer, highly compressible
	std::string big;
	for (int i = 0; big.length() < 1024 * 1024; i++)
		big.append("<SOFTWARE><NAME>package-").append(std::to_string(i))
			.append("</NAME></SOFTWARE>\n");
	fail |= !RoundTrip(big);

	// Not compressible
	std::string random;
	std::srand(42);
	for (int i = 0; i < 100000; i++)
		random.push_back(static_cast<char>(std::rand()));
	fail |= !RoundTrip(random);

	// Garbage must be rejected
	std::string output;
	const char garbage[] = "this is not zlib data";
	if (ZLibCompressor::Uncompress(garbage, sizeof(garbage), output)) {
		std::cout << "Uncompress accepted garbage" << std::endl;
		fail = true;
	}

	if (fail) {
		std::cout << "Test Failed !!!" << std::endl;
		return 1;
	}

	std::cout << "All tests passed!" << std::endl;
	return 0;
}

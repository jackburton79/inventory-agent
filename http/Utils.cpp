/*
 * Utils.cpp
 *
 *  Created on: 17/07/2017
 *  Copyright 2017 Stefano Ceccherini (stefano.ceccherini@gmail.com)
 */
 
#include "Utils.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include <cstring>
#include <new>
#include <stdexcept>


std::string
Base64Encode(const std::string& string)
{
	BIO* b64f = BIO_new(BIO_f_base64());
	if (b64f == NULL)
		throw std::bad_alloc();

	BIO* buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
		throw std::bad_alloc();

	buffer = BIO_push(b64f, buffer);

	BIO_set_flags(buffer, BIO_FLAGS_BASE64_NO_NL);
	(void)BIO_set_close(buffer, BIO_CLOSE);
	BIO_write(buffer, string.c_str(), string.length());
	(void)BIO_flush(buffer);

	BUF_MEM *pointer;
	BIO_get_mem_ptr(buffer, &pointer);

	size_t encodedSize = pointer->length;
	std::string encoded(encodedSize + 1, '\0');
	::memcpy(&encoded[0], pointer->data, encodedSize);
	encoded.resize(encodedSize);

	BIO_free_all(buffer);

	return encoded;
}

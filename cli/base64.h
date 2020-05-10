/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * Modified by Frédéric Haziza <frederic.haziza@crg.eu>
 */

#ifndef __CRYPT4GH_BASE64_H_INCLUDED__
#define __CRYPT4GH_BASE64_H_INCLUDED__

#include <sys/types.h>

/* The caller is responsible to free the returned strings */

unsigned char* base64_encode(const unsigned char *src, size_t len, size_t *out_len);
unsigned char* base64_decode(const unsigned char *src, size_t len, size_t *out_len);

#endif /* !__CRYPT4GH_BASE64_H_INCLUDED__ */

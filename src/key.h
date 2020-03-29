#ifndef __CRYPT4GH_KEY_H_INCLUDED__
#define __CRYPT4GH_KEY_H_INCLUDED__

#include <stdint.h>

/* The caller is responsible to free the returned strings */

uint8_t* read_public_key(const char *filename);

#endif /* !__CRYPT4GH_BASE64_H_INCLUDED__ */

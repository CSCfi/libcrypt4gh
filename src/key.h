#ifndef __CRYPT4GH_KEY_H_INCLUDED__
#define __CRYPT4GH_KEY_H_INCLUDED__

#include <stdint.h>
#include <sodium.h>

int read_public_key(const char *filename, uint8_t output[crypto_box_PUBLICKEYBYTES]);

/* uint8_t* read_secret_key(const char *filename, (char*)(*cb)(void)); */

#endif /* !__CRYPT4GH_BASE64_H_INCLUDED__ */

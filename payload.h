#ifndef __CRYPT4GH_PAYLOAD_H_INCLUDED__
#define __CRYPT4GH_PAYLOAD_H_INCLUDED__

#include "defs.h"

int crypt4gh_payload_encrypt(int fd_in, int fd_out, const uint8_t* session_key); /* supporting only one */

int crypt4gh_payload_decrypt(int fd_in, int fd_out, const uint8_t* session_keys, unsigned int nkeys);


int crypt4gh_payload_encrypt_msg(const uint8_t *msg, size_t mlen,
				 uint8_t *out, const uint8_t* session_key); /* supporting only one */

#endif /* !__CRYPT4GH_PAYLOAD_H_INCLUDED__ */

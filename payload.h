#ifndef __CRYPT4GH_PAYLOAD_H_INCLUDED__
#define __CRYPT4GH_PAYLOAD_H_INCLUDED__

#include <sodium.h>
#include "defs.h"

#define CRYPT4GH_SESSION_KEY_SIZE crypto_aead_chacha20poly1305_IETF_KEYBYTES
#define CRYPT4GH_SEGMENT_SIZE 65536
#define CRYPT4GH_CIPHERSEGMENT_SIZE 65564 /* CRYPT4GH_SEGMENT_SIZE + 12(nonce) + 16(mac) */

int crypt4gh_encrypt_segment(const uint8_t* session_key,
			     const uint8_t *segment, size_t segment_len,
			     uint8_t *ciphersegment, size_t* cipher_len);
int crypt4gh_decrypt_segment(const uint8_t* session_key,
			     uint8_t ciphersegment[CRYPT4GH_CIPHERSEGMENT_SIZE], size_t cipher_len,
			     uint8_t segment[CRYPT4GH_SEGMENT_SIZE], size_t* segment_len);

int crypt4gh_encrypt_payload(int fd_in, int fd_out, const uint8_t* session_key); /* supporting only one */

int crypt4gh_decrypt_payload(int fd_in, int fd_out, const uint8_t* session_keys, unsigned int nkeys);


int crypt4gh_encrypt_payload_msg(const uint8_t *msg, size_t mlen,
				 uint8_t *out, const uint8_t* session_key); /* supporting only one */

#endif /* !__CRYPT4GH_PAYLOAD_H_INCLUDED__ */

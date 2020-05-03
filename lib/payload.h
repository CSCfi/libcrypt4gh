#ifndef __CRYPT4GH_PAYLOAD_H_INCLUDED__
#define __CRYPT4GH_PAYLOAD_H_INCLUDED__

#include <stdlib.h>
#include <stdint.h>
#include <sodium.h>

#define CRYPT4GH_SESSION_KEY_SIZE crypto_aead_chacha20poly1305_IETF_KEYBYTES
#define CRYPT4GH_SEGMENT_SIZE 65536
#define CRYPT4GH_CIPHERSEGMENT_SIZE 65564 /* CRYPT4GH_SEGMENT_SIZE + 12(nonce) + 16(mac) */

uint8_t* crypt4gh_session_key_new(void);
void crypt4gh_session_key_free(uint8_t* k);

int crypt4gh_encrypt_segment(const uint8_t* session_key,
			     uint8_t segment[CRYPT4GH_SEGMENT_SIZE], ssize_t segment_len,
			     uint8_t ciphersegment[CRYPT4GH_CIPHERSEGMENT_SIZE], ssize_t* cipher_len);
int crypt4gh_decrypt_segment(const uint8_t* session_key,
			     uint8_t ciphersegment[CRYPT4GH_CIPHERSEGMENT_SIZE], ssize_t cipher_len,
			     uint8_t segment[CRYPT4GH_SEGMENT_SIZE], ssize_t* segment_len);

int crypt4gh_encrypt_payload(int fd_in, int fd_out, const uint8_t* session_key); /* supporting only one */

int crypt4gh_decrypt_payload(int fd_in, int fd_out, const uint8_t* session_keys, unsigned int nkeys);

#endif /* !__CRYPT4GH_PAYLOAD_H_INCLUDED__ */

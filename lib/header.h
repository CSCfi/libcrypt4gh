#ifndef __CRYPT4GH_HEADER_H_INCLUDED__
#define __CRYPT4GH_HEADER_H_INCLUDED__

#include <sodium.h>

#include "defs.h"

typedef enum {
  X25519_chacha20_ietf_poly1305 = 0
} header_packet_encryption_method;

typedef enum {
  chacha20_ietf_poly1305 = 0
} header_data_encryption_type;

#define CRYPT4GH_SESSION_KEY_SIZE crypto_aead_chacha20poly1305_IETF_KEYBYTES

int
header_build(const uint8_t session_key[CRYPT4GH_SESSION_KEY_SIZE], /* supporting one session key only */
	     const uint8_t* seckey,
	     const uint8_t* const* recipient_pubkeys, unsigned int nb_recipients,
	     uint8_t** output, size_t* output_len);

int
header_parse(int fd,
	     const uint8_t seckey[crypto_box_SECRETKEYBYTES],
	     const uint8_t pubkey[crypto_box_PUBLICKEYBYTES],
	     uint8_t** session_keys, unsigned int* nkeys,
	     uint64_t** edit_list, unsigned int* edit_list_len);


#endif /* !__CRYPT4GH_HEADER_H_INCLUDED__ */


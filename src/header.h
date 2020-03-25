#ifndef __CRYPT4GH_HEADER_H_INCLUDED__
#define __CRYPT4GH_HEADER_H_INCLUDED__

#include <sodium.h>

#include "defs.h"

typedef enum {
  data_encryption_parameters = 0,
  data_edit_list = 1
} header_packet_type;

typedef enum {
  X25519_chacha20_ietf_poly1305 = 0
} header_packet_encryption_method;

typedef enum {
  chacha20_ietf_poly1305 = 0
} header_data_encryption_type;

#define CRYPT4GH_SESSION_KEY_SIZE crypto_aead_chacha20poly1305_IETF_KEYBYTES

int header_build(const uint8_t session_key[CRYPT4GH_SESSION_KEY_SIZE],
		 const uint8_t* seckey, const uint8_t* const* recipient_pubkeys, unsigned int nb_recipients,
		 uint8_t** output, size_t* output_len);

#endif /* !__CRYPT4GH_HEADER_H_INCLUDED__ */


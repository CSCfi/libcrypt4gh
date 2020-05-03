#ifndef __CRYPT4GH_PACKET_H_INCLUDED__
#define __CRYPT4GH_PACKET_H_INCLUDED__

#include <sodium.h>

#include "header.h"

#define CRYPT4GH_HEADER_DATA_PACKET_len (4U + 4U + crypto_aead_chacha20poly1305_IETF_KEYBYTES)
#define NONCE_LEN crypto_aead_chacha20poly1305_IETF_NPUBBYTES
#define CRYPT4GH_HEADER_ENCRYPTED_DATA_PACKET_len (4U + 4U		             \
						   + crypto_box_PUBLICKEYBYTES       \
						   + NONCE_LEN		             \
						   + CRYPT4GH_HEADER_DATA_PACKET_len \
						   + crypto_box_MACBYTES)

typedef enum {
  data_encryption_parameters = 0,
  data_edit_list = 1
} header_packet_type;

int
make_packet_data_enc(header_data_encryption_type encryption_method,
		     const uint8_t session_key[CRYPT4GH_SESSION_KEY_SIZE],
		     uint8_t** output, size_t* output_len);

int
parse_packet(uint8_t* data, unsigned int data_len,
	     uint8_t** session_keys, unsigned int* nkeys,
	     uint64_t** edit_list, unsigned int* edit_list_len);

#endif /* !__CRYPT4GH_PACKET_H_INCLUDED__ */

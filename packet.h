#ifndef __CRYPT4GH_PACKET_H_INCLUDED__
#define __CRYPT4GH_PACKET_H_INCLUDED__

#include "defs.h"

#define CRYPT4GH_HEADER_DATA_PACKET_len (4U + 4U + CRYPT4GH_SESSION_KEY_SIZE)
#define CRYPT4GH_HEADER_ENCRYPTED_DATA_PACKET_len (4U + 4U		             \
						   + crypto_box_PUBLICKEYBYTES       \
						   + CRYPT4GH_NONCE_SIZE             \
						   + CRYPT4GH_HEADER_DATA_PACKET_len \
						   + crypto_box_MACBYTES)

int
crypt4gh_packet_build_data_enc(header_data_encryption_type encryption_method,
			       const uint8_t session_key[CRYPT4GH_SESSION_KEY_SIZE],
			       uint8_t** output, size_t* output_len);

int
crypt4gh_packet_parse(uint8_t* data, unsigned int data_len,
		      uint8_t** session_keys, unsigned int* nkeys,
		      uint64_t** edit_list, unsigned int* edit_list_len);

#endif /* !__CRYPT4GH_PACKET_H_INCLUDED__ */

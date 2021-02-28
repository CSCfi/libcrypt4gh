#ifndef __CRYPT4GH_HEADER_H_INCLUDED__
#define __CRYPT4GH_HEADER_H_INCLUDED__

#include "defs.h"

int
crypt4gh_header_build(const uint8_t session_key[CRYPT4GH_SESSION_KEY_SIZE], /* supporting one session key only */
		      const uint8_t* seckey,
		      const uint8_t* recipient_pubkeys, unsigned int nrecipients,
		      uint8_t** output, size_t* output_len);

int
crypt4gh_header_parse(int fd,
		      const uint8_t seckey[crypto_kx_SECRETKEYBYTES],
		      const uint8_t pubkey[crypto_kx_PUBLICKEYBYTES],
		      uint8_t** session_keys, unsigned int* nkeys,
		      uint64_t** edit_list, unsigned int* edit_list_len);


#endif /* !__CRYPT4GH_HEADER_H_INCLUDED__ */


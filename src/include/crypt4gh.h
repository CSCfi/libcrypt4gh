#ifndef __CRYPT4GH_H_INCLUDED__
#define __CRYPT4GH_H_INCLUDED__

#include <sodium.h>

#include "crypt4gh/defs.h"

int
crypt4gh_encrypt(int fd_in, int fd_out,
		 const uint8_t seckey[crypto_box_SECRETKEYBYTES],
		 const uint8_t pubkey[crypto_box_PUBLICKEYBYTES],
		 const uint8_t* recipient_pubkeys, unsigned int nrecipients);

int
crypt4gh_decrypt(int fd_in, int fd_out,
		 const uint8_t seckey[crypto_box_SECRETKEYBYTES],
		 const uint8_t pubkey[crypto_box_PUBLICKEYBYTES]);

uint8_t*
crypt4gh_encrypt_msg(const uint8_t *msg, unsigned long long mlen,
		     size_t *clen,
		     const uint8_t seckey[crypto_kx_SECRETKEYBYTES],
		     const uint8_t pubkey[crypto_kx_PUBLICKEYBYTES],
		     const uint8_t* recipient_pubkeys, unsigned int nrecipients);


#endif /* !__CRYPT4GH_H_INCLUDED__ */


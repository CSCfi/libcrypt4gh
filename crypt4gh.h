#ifndef __CRYPT4GH_H_INCLUDED__
#define __CRYPT4GH_H_INCLUDED__

#include <stdint.h>
#include <sodium.h>

int
crypt4gh_encrypt(int fd_in, int fd_out,
		 const uint8_t seckey[crypto_box_SECRETKEYBYTES],
		 const uint8_t pubkey[crypto_box_PUBLICKEYBYTES],
		 const uint8_t* recipient_pubkeys, unsigned int nrecipients);

int
crypt4gh_decrypt(int fd_in, int fd_out,
		 const uint8_t seckey[crypto_box_SECRETKEYBYTES],
		 const uint8_t pubkey[crypto_box_PUBLICKEYBYTES]);

#endif /* !__CRYPT4GH_H_INCLUDED__ */


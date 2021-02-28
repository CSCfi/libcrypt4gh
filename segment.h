#ifndef __CRYPT4GH_SEGMENT_H_INCLUDED__
#define __CRYPT4GH_SEGMENT_H_INCLUDED__

#include "defs.h"

int crypt4gh_segment_encrypt(const uint8_t* session_key,
			     const uint8_t *segment, size_t segment_len,
			     uint8_t *ciphersegment, size_t* cipher_len);
int crypt4gh_segment_decrypt(const uint8_t* session_key,
			     uint8_t ciphersegment[CRYPT4GH_CIPHERSEGMENT_SIZE], size_t cipher_len,
			     uint8_t segment[CRYPT4GH_SEGMENT_SIZE], size_t* segment_len);


#endif /* !__CRYPT4GH_SEGMENT_H_INCLUDED__ */



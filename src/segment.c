#include <unistd.h>
#include <errno.h>
#include <sodium.h>

#include "includes.h"

#include "segment.h"


int
crypt4gh_segment_encrypt(const uint8_t* session_key,
			 const uint8_t *segment, size_t segment_len,
			 uint8_t *ciphersegment, size_t* cipher_len)
{
  /* New nonce for each segment */
  unsigned char nonce[CRYPT4GH_NONCE_SIZE];
  randombytes_buf(nonce, CRYPT4GH_NONCE_SIZE); /* CRYPT4GH_NONCE_SIZE * sizeof(char) */

  H2("Block nonce", nonce, CRYPT4GH_NONCE_SIZE);

  /* Copy the nonce at the beginning of the ciphersegment */
  memcpy(ciphersegment, nonce, CRYPT4GH_NONCE_SIZE);

  /* Encrypt */
  unsigned long long len;
  int rc = crypto_aead_chacha20poly1305_ietf_encrypt(ciphersegment + CRYPT4GH_NONCE_SIZE, &len,
						     segment, segment_len,
						     NULL, 0, /* no authenticated data */
						     NULL, nonce, session_key);
  if(!rc && cipher_len){
    *cipher_len = (size_t)len + CRYPT4GH_NONCE_SIZE;
    D2("Cipher len: %lu", *cipher_len);
  }

  sodium_memzero(nonce, CRYPT4GH_NONCE_SIZE); /* why care? */
  return rc;
}

int
crypt4gh_segment_decrypt(const uint8_t* session_key,
			 uint8_t ciphersegment[CRYPT4GH_CIPHERSEGMENT_SIZE], size_t cipher_len,
			 uint8_t segment[CRYPT4GH_SEGMENT_SIZE], size_t* segment_len)
{
  /* nonce at the beginning of the ciphersegment */

  unsigned char nonce[CRYPT4GH_NONCE_SIZE];
  memcpy(nonce, ciphersegment, CRYPT4GH_NONCE_SIZE); /* CRYPT4GH_NONCE_SIZE * sizeof(char) */

  H2("Block nonce", nonce, CRYPT4GH_NONCE_SIZE);

  /* Decrypt */
  unsigned long long len;
  int rc = crypto_aead_chacha20poly1305_ietf_decrypt(segment, &len,
						     NULL,
						     ciphersegment + CRYPT4GH_NONCE_SIZE, cipher_len - CRYPT4GH_NONCE_SIZE,
						     NULL, 0, /* no authenticated data */
						     nonce, session_key);
  if(!rc && segment_len){
    *segment_len = (size_t)len;
    D2("Segment len: %lu", *segment_len);
  }

  sodium_memzero(nonce, CRYPT4GH_NONCE_SIZE); /* why care? */
  return rc;
}

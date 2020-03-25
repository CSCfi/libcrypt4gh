#include <unistd.h>
#include <errno.h>
#include <sodium.h>

#include "debug.h"
#include "defs.h"
#include "payload.h"

#define NONCE_LEN crypto_aead_chacha20poly1305_IETF_NPUBBYTES


uint8_t*
crypt4gh_session_key_new(void){

  CRYPT4GH_INIT(NULL);

  uint8_t* key = (uint8_t*)sodium_malloc(CRYPT4GH_SESSION_KEY_SIZE * sizeof(uint8_t));

  if(key == NULL || errno == ENOMEM){
    D1("Could not allocate the key");
    return NULL;
  }

  /* Fill in with random data */
  randombytes_buf(key, CRYPT4GH_SESSION_KEY_SIZE);

  /* Mark it read-only */
  sodium_mprotect_readonly(key);

  H("Session key", key, CRYPT4GH_SESSION_KEY_SIZE);

  return key;
}

int
crypt4gh_encrypt_segment(const uint8_t* session_key,
			 uint8_t segment[CRYPT4GH_SEGMENT_SIZE], ssize_t segment_len,
			 uint8_t ciphersegment[CRYPT4GH_CIPHERSEGMENT_SIZE], ssize_t* cipher_len)
{
  /* New nonce for each segment */
  unsigned char nonce[NONCE_LEN];
  randombytes_buf(nonce, NONCE_LEN); /* NONCE_LEN * sizeof(char) */

  H("Block nonce", nonce, NONCE_LEN);

  /* Copy the nonce at the beginning of the ciphersegment */
  memcpy(ciphersegment, nonce, NONCE_LEN);

  /* Encrypt */
  unsigned long long len;
  int rc = crypto_aead_chacha20poly1305_ietf_encrypt(ciphersegment + NONCE_LEN, &len,
						     segment, segment_len,
						     NULL, 0, /* no authenticated data */
						     NULL, nonce, session_key);
  if(!rc && cipher_len){
    *cipher_len = (ssize_t)len + NONCE_LEN;
    D2("Cipher len: %lu", *cipher_len);
  }

  sodium_memzero(nonce, NONCE_LEN); /* why care? */
  return rc;
}

int
crypt4gh_decrypt_segment(const uint8_t* session_key,
			 uint8_t ciphersegment[CRYPT4GH_CIPHERSEGMENT_SIZE], ssize_t cipher_len,
			 uint8_t segment[CRYPT4GH_SEGMENT_SIZE], ssize_t* segment_len)
{
  /* nonce at the beginning of the ciphersegment */

  unsigned char nonce[NONCE_LEN];
  memcpy(nonce, ciphersegment, NONCE_LEN); /* NONCE_LEN * sizeof(char) */

  H("Block nonce", nonce, NONCE_LEN);

  /* Decrypt */
  unsigned long long len;
  int rc = crypto_aead_chacha20poly1305_ietf_decrypt(segment, &len,
						     NULL,
						     ciphersegment + NONCE_LEN, cipher_len - NONCE_LEN,
						     NULL, 0, /* no authenticated data */
						     nonce, session_key);
  if(!rc && segment_len){
    *segment_len = (ssize_t)len;
    D2("Segment len: %lu", *segment_len);
  }

  sodium_memzero(nonce, NONCE_LEN); /* why care? */
  return rc;
}


/*
 * Returns 0 if and only if success
 */
int
crypt4gh_encrypt_payload(int fd_in, int fd_out, const uint8_t* session_key)
{
  int rc = 1; /* error */

  uint8_t segment[CRYPT4GH_SEGMENT_SIZE];
  ssize_t segment_len;
  uint8_t ciphersegment[CRYPT4GH_CIPHERSEGMENT_SIZE];
  ssize_t cipher_len;
  
again:
  rc = 0; /* so far so good */

  /* Read some data */
  segment_len = read(fd_in, segment, CRYPT4GH_SEGMENT_SIZE);
  D3("read %lu bytes", segment_len);
  
  if(segment_len == -1){ /* error */
    D1("Error reading: %s", strerror(errno));
    rc = 2; goto bailout;
  }

  if(segment_len == 0){
    rc = 0; /* No more data to read: Success */
    goto bailout;
  }

  /* Otherwise, we have some data */

  D1("Encrypt a block of size %lu", segment_len);

  if( (rc = crypt4gh_encrypt_segment(session_key, segment, segment_len, ciphersegment, &cipher_len)) ||
      (rc = write(fd_out, ciphersegment, cipher_len) != cipher_len)
      )
    {
      D1("Error processing the cipher segment: [%d] %s", rc, strerror(errno));
      rc = 3;
      goto bailout;
    }

  goto again;

bailout:
  sodium_memzero(segment, CRYPT4GH_SEGMENT_SIZE);
  sodium_memzero(ciphersegment, CRYPT4GH_CIPHERSEGMENT_SIZE);
  return rc;
}

/*
 * Returns 0 if and only if success
 */
int
crypt4gh_decrypt_payload(int fd_in, int fd_out, const uint8_t* session_key)
{
  int rc = 1; /* error */

  uint8_t segment[CRYPT4GH_SEGMENT_SIZE];
  ssize_t segment_len;
  uint8_t ciphersegment[CRYPT4GH_CIPHERSEGMENT_SIZE];
  ssize_t cipher_len;

again:
  rc = 0; /* so far so good */

  /* Read some data */
  cipher_len = read(fd_in, ciphersegment, CRYPT4GH_CIPHERSEGMENT_SIZE);
  D3("read %lu bytes", cipher_len);
  
  if(cipher_len == -1){ /* error */
    D1("Error reading: %s", strerror(errno));
    rc = 2;
    goto bailout;
  }

  if(cipher_len == 0){
    rc = 0; /* No more data to read: Success */ 
    goto bailout;
  }

  /* Otherwise, we have some data */

  D1("Decrypt a block of size %lu", cipher_len);

  if( (rc = crypt4gh_decrypt_segment(session_key, ciphersegment, cipher_len, segment, &segment_len)) ||
      (rc = write(fd_out, segment, segment_len) != segment_len)
      )
    {
      D1("Error processing the cipher segment: [%d] %s", rc, strerror(errno));
      rc = 3;
      goto bailout;
    }
  goto again;

bailout:
  sodium_memzero(segment, CRYPT4GH_SEGMENT_SIZE);
  sodium_memzero(ciphersegment, CRYPT4GH_CIPHERSEGMENT_SIZE);
  return rc;
}

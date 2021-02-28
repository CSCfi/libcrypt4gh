#include <unistd.h>
#include <errno.h>
#include <sodium.h>

#include "debug.h"
#include "defs.h"
#include "segment.h"
#include "payload.h"

/*
 * Returns 0 if and only if success
 */
int
crypt4gh_payload_encrypt(int fd_in, int fd_out,
			 const uint8_t* session_key)
{
  int rc = 1; /* error */

  uint8_t segment[CRYPT4GH_SEGMENT_SIZE];
  size_t segment_len;
  uint8_t ciphersegment[CRYPT4GH_CIPHERSEGMENT_SIZE];
  size_t cipher_len;
  
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

  if( (rc = crypt4gh_segment_encrypt(session_key, segment, segment_len, ciphersegment, &cipher_len)) ||
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
crypt4gh_payload_decrypt(int fd_in, int fd_out,
			 const uint8_t* session_keys, unsigned int nkeys)
{
  int rc = 1; /* error */
  unsigned int i;
  uint8_t segment[CRYPT4GH_SEGMENT_SIZE];
  size_t segment_len;
  uint8_t ciphersegment[CRYPT4GH_CIPHERSEGMENT_SIZE];
  size_t cipher_len;

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

  uint8_t* session_key = (uint8_t*)session_keys; /* copy pointer */
  for(i = 0; i < nkeys; i++){
    rc = crypt4gh_segment_decrypt(session_key, ciphersegment, cipher_len, segment, &segment_len);
    if(rc){ /* try next session key */
      D2("Session key %d failed", i);
      session_key += CRYPT4GH_SESSION_KEY_SIZE;
      continue; 
    }
    D2("Session key %d worked", i);
    rc = write(fd_out, segment, segment_len);
    if(rc != segment_len){
      rc = 3; /* reshape */
      D1("Error processing the cipher segment: [%d] %s", rc, strerror(errno));
      goto bailout;
    }
    goto again;
  }
  /* we tried all the keys, none worked */

bailout:
  sodium_memzero(segment, CRYPT4GH_SEGMENT_SIZE);
  sodium_memzero(ciphersegment, CRYPT4GH_CIPHERSEGMENT_SIZE);
  return rc;
}

# define MIN(a,b) (((a)<(b))?(a):(b))

int
crypt4gh_payload_encrypt_msg(const uint8_t *msg, size_t mlen,
			     uint8_t *out, const uint8_t* session_key)
{
  int rc;
  size_t segment_len, cipher_len;

again:
  segment_len = MIN(mlen, CRYPT4GH_SEGMENT_SIZE);
  rc = 0; /* so far so good */
  
  if(segment_len == 0){ /* No more data to read: Success */
    goto bailout;
  }

  /* Otherwise, we have some data */
  D1("Encrypt a block of size %lu", segment_len);

  if( (rc = crypt4gh_segment_encrypt(session_key, msg, segment_len, out, &cipher_len)))
    {
      D1("Error processing the cipher segment: [%d] %s", rc, strerror(errno));
      rc = 3;
      goto bailout;
    }
  
  msg += segment_len;
  mlen -= segment_len;
  goto again;

bailout:
  return rc;
}

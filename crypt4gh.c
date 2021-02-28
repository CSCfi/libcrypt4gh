#include <sodium.h>
#include <unistd.h>
#include <errno.h>

#include "debug.h"
#include "header.h"
#include "segment.h"
#include "payload.h"
#include "crypt4gh.h"

#define CRYPT4GH_SESSION_KEY_SIZE crypto_aead_chacha20poly1305_IETF_KEYBYTES

static uint8_t*
crypt4gh_session_key_new(void){

  if (sodium_init() == -1) {
    E("Could not initialize libsodium");
    return NULL;
  }

  uint8_t* key = (uint8_t*)sodium_malloc(CRYPT4GH_SESSION_KEY_SIZE * sizeof(uint8_t));

  if(key == NULL || errno == ENOMEM){
    D1("Could not allocate the key");
    return NULL;
  }

  /* Fill in with random data */
  randombytes_buf(key, CRYPT4GH_SESSION_KEY_SIZE);

  /* Mark it read-only */
  sodium_mprotect_readonly(key);

  H1("Session key", key, CRYPT4GH_SESSION_KEY_SIZE);

  return key;
}

int
crypt4gh_encrypt(int fd_in, int fd_out,
		 const uint8_t seckey[crypto_kx_SECRETKEYBYTES],
		 const uint8_t pubkey[crypto_kx_PUBLICKEYBYTES],
		 const uint8_t* recipient_pubkeys, unsigned int nrecipients)
{
  int rc = 1;

  /* Create a new session key */
  uint8_t* k = crypt4gh_session_key_new();

  /* Create the header */
  uint8_t* h = NULL;
  size_t h_len = 0;
  rc = crypt4gh_header_build(k, seckey, recipient_pubkeys, nrecipients, &h, &h_len);
  D3("Header len: %lu", h_len);
  H3("----- Header", h, h_len);
  
  if(h){
    write(fd_out, h, h_len);
    free(h);
  } else goto bailout;

  rc = crypt4gh_payload_encrypt(fd_in, fd_out, k);

bailout:
  sodium_free(k);
  return rc;
}

int
crypt4gh_decrypt(int fd_in, int fd_out,
		 const uint8_t seckey[crypto_kx_SECRETKEYBYTES],
		 const uint8_t pubkey[crypto_kx_PUBLICKEYBYTES])
{
  int rc = 1;
  uint8_t* session_keys = NULL;
  unsigned int nkeys = 0;
  uint64_t* edit_list = NULL;
  unsigned int edit_list_len = 0;

  rc = crypt4gh_header_parse(fd_in, seckey, pubkey,
		    &session_keys, &nkeys, &edit_list, &edit_list_len);

  if(nkeys == 0){
    E("No session key found");
    return rc;
  }

  D1("Found %d session keys", nkeys);
  H1("Session keys", session_keys, nkeys * CRYPT4GH_SESSION_KEY_SIZE);

#if DEBUG
  int i = 0;
  uint8_t* session_key = session_keys;
  for(; i < nkeys; i++ ){
    D1("Session key %d", i);
    H1("=> Session keys", session_key, CRYPT4GH_SESSION_KEY_SIZE);
    session_key += CRYPT4GH_SESSION_KEY_SIZE;
  }
#endif

  if(edit_list_len > 0){
    D1("We have an edit list with %d lengths", edit_list_len);
    E("Edit list not implemented yet");
    return 2;
  }
  
  rc = crypt4gh_payload_decrypt(fd_in, fd_out,
				(const uint8_t*)(session_keys), nkeys);

  return rc;
}

/* ========================================
 *  For buffers
 * ======================================== */

/*
 * This function allocates a buffer.
 * It is the responsability of the caller to free the return buffer.
 */
uint8_t*
crypt4gh_encrypt_msg(const uint8_t *msg, unsigned long long mlen,
		     size_t *clen,
		     const uint8_t seckey[crypto_kx_SECRETKEYBYTES],
		     const uint8_t pubkey[crypto_kx_PUBLICKEYBYTES],
		     const uint8_t* recipient_pubkeys, unsigned int nrecipients)
{
  int rc = 1;
  uint8_t *buf = NULL;
  size_t buflen = 0;

  /* Create a new session key */
  uint8_t* k = crypt4gh_session_key_new();

  /* Create the header */
  uint8_t* h = NULL;
  size_t hlen = 0;
  rc = crypt4gh_header_build(k, seckey, recipient_pubkeys, nrecipients, &h, &hlen);
  D3("Header len: %lu", h_len);
  H3("----- Header", h, h_len);
  
  if(!h)
    goto bailout;

  size_t nsegments = (size_t)(mlen / CRYPT4GH_SEGMENT_SIZE) + 1; /* number of segments */
  buflen = hlen + mlen + (nsegments * (CRYPT4GH_CIPHERSEGMENT_SIZE - CRYPT4GH_SEGMENT_SIZE)); /* adding cipher diffs */
  buf = (uint8_t*)malloc(buflen * sizeof(uint8_t));
  memset(buf, '\0', buflen);

  /* copy the header */
  memcpy(buf, h, hlen);
  free(h);

  rc = crypt4gh_message_encrypt(msg, mlen, buf + hlen, k);

bailout:
  sodium_free(k);
  if(rc){ /* error */
    if(buf) free(buf);
    buflen = 0;
  }

  if(clen)
    *clen = buflen;
  return buf;
}

/* static inline unsigned long long */
/* crypt4gh_plain_len(unsigned long long clen){ */
/*   return 16; */
/* } */


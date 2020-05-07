#include <unistd.h>
#include <sys/types.h>

#include "debug.h"
#include "header.h"
#include "payload.h"

#include <sodium.h>
#define CRYPT4GH_KEY_SIZE crypto_aead_chacha20poly1305_IETF_KEYBYTES


int
crypt4gh_encrypt(int fd_in, int fd_out,
		 const uint8_t seckey[crypto_box_SECRETKEYBYTES],
		 const uint8_t pubkey[crypto_box_PUBLICKEYBYTES],
		 const uint8_t* recipient_pubkeys, unsigned int nrecipients)
{
  int rc = 1;

  /* Create a new session key */
  uint8_t* k = crypt4gh_session_key_new();

  /* Create the header */
  uint8_t* h = NULL;
  size_t h_len = 0;
  rc = header_build(k, seckey, recipient_pubkeys, nrecipients, &h, &h_len);
  D3("Header len: %lu", h_len);
  /* H("Header", h, h_len); */
  
  if(h){
    write(fd_out, h, h_len);
    free(h);
  } else goto bailout;

  rc = crypt4gh_encrypt_payload(fd_in, fd_out, k);

bailout:
  sodium_free(k);
  return rc;
}

int
crypt4gh_decrypt(int fd_in, int fd_out,
		 const uint8_t seckey[crypto_box_SECRETKEYBYTES],
		 const uint8_t pubkey[crypto_box_PUBLICKEYBYTES])
{
  int rc = 1;
  uint8_t* session_keys = NULL;
  unsigned int nkeys = 0;
  uint64_t* edit_list = NULL;
  unsigned int edit_list_len = 0;

  rc = header_parse(fd_in, seckey, pubkey,
		    &session_keys, &nkeys, &edit_list, &edit_list_len);

  if(nkeys == 0){
    E("No session key found");
    return rc;
  }

  D1("Found %d session keys", nkeys);
  H("Session keys", session_keys, nkeys * CRYPT4GH_KEY_SIZE);

  int i = 0;
  uint8_t* session_key = session_keys;
  for(; i < nkeys; i++ ){
    D1("Session key %d", i);
    H("=> Session keys", session_key, CRYPT4GH_KEY_SIZE);
    session_key += CRYPT4GH_KEY_SIZE;
  }

  if(edit_list_len > 0){
    D1("We have an edit list with %d lengths", edit_list_len);
    E("Edit list not implemented yet");
    return 2;
  }
  
  rc = crypt4gh_decrypt_payload(fd_in, fd_out,
				(const uint8_t*)(session_keys), nkeys);

  return rc;
}

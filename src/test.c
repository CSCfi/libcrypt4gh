#include <sys/types.h>
#include <stdlib.h>
#include <sodium.h>
#include <unistd.h>

#include "debug.h"
#include "defs.h"
#include "header.h"
#include "payload.h"

int
main(int argc, const char **argv)
{
  int rc = 1;

  D1("Just doing some encryption test");

  uint8_t* k = crypt4gh_session_key_new();

  const uint8_t recipient_pk[32] = {237, 240, 152, 222, 217, 78, 35, 164, 234, 174, 171, 149, 82, 34, 179, 106, 104, 81, 162, 197, 189, 248, 171, 77, 241, 95, 229, 121, 213, 81, 171, 71};

  H("Recipient pubkey", (uint8_t*)recipient_pk, 32);
   
  const uint8_t* recipient_pubkeys[1] = {(const uint8_t*) recipient_pk};

  /* uint8_t seckey[32]; */
  /* randombytes_buf(seckey, 32); */
  const uint8_t seckey[32] = { 138, 154, 233, 17, 34, 25, 137, 232, 173, 130, 56, 123, 159, 162, 203, 162, 40, 112, 149, 218, 211, 214, 145, 182, 157, 124, 143, 145, 142, 75, 232, 42};
  H("Secret key", (uint8_t*)seckey, 32);

  uint8_t* h = NULL;
  size_t h_len = 0;
    
  rc = header_build(k, seckey, (const uint8_t* const*)recipient_pubkeys, 1, &h, &h_len);

  D1("Header len: %lu", h_len);
  H("Header", h, h_len);
  
  if(h){
    write(STDOUT_FILENO, h, h_len);
    free(h);
  } else goto bailout;

  rc = crypt4gh_encrypt_payload(STDIN_FILENO, STDOUT_FILENO, k);

bailout:
  sodium_free(k);
  return rc;
}

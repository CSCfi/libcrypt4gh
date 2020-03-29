#include <sys/types.h>
#include <stdlib.h>
#include <sodium.h>
#include <unistd.h>

#include "debug.h"
#include "defs.h"
#include "header.h"
#include "payload.h"
#include "stream.h"
#include "key.h"

int
main(int argc, const char **argv)
{
  int rc = 1;
  engine_t* e = NULL;

  D1("Just doing some encryption test");
  CRYPT4GH_INIT(1);

  uint8_t* k = crypt4gh_session_key_new();

  /* const uint8_t _recipient_pk[32] = {237, 240, 152, 222, 217, 78, 35, 164, 234, 174, 171, 149, 82, 34, 179, 106, 104, 81, 162, 197, 189, 248, 171, 77, 241, 95, 229, 121, 213, 81, 171, 71}; */

  uint8_t recipient_pk[32];
  uint8_t* _pk;

  if(argc > 0){
    _pk = read_public_key(argv[1]);
    if(!_pk) goto bailout;
  }
  memcpy(recipient_pk, _pk, sizeof(recipient_pk)); /* crash and burn if */

  H("Recipient pubkey", (uint8_t*)recipient_pk, 32);
   
  const uint8_t* recipient_pubkeys[1] = {(const uint8_t*) recipient_pk};

  uint8_t seckey[32];
  randombytes_buf(seckey, 32);
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


  size_t data_len;
#define SIZE 10000
  uint8_t buf[SIZE];
  e = crypt4gh_engine_init(STDIN_FILENO, STDOUT_FILENO, k);

  if(!e) goto bailout;

  while(!rc && (data_len = read(e->fd_in, buf, SIZE)) > 0){
    D3("read %lu bytes", data_len);
    rc = crypt4gh_stream_encrypt_push(e, buf, data_len);
  }

  rc = crypt4gh_stream_encrypt_close(e);

bailout:
  if(_pk) free(_pk);
  if(e) crypt4gh_engine_free(e);
  sodium_free(k);
  return rc;
}

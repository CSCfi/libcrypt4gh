#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sodium.h>

#include "debug.h"
#include "defs.h"
/* #include "passphrase.h" */

char* pubkey_path = NULL;
char* seckey_path = NULL;

int
main(int argc, const char **argv)
{
  int rc = 1, seckey_fd = -1, pubkey_fd = -1;

  if( argc < 5 ){ rc = 1; goto bailout; }

  if( !strncmp(argv[1], "--sk", 4) )
    seckey_path = (char*)argv[2];
  if( !strncmp(argv[1], "--pk", 4) )
    pubkey_path = (char*)argv[2];

  if( !strncmp(argv[3], "--sk", 4) )
    seckey_path = (char*)argv[4];
  if( !strncmp(argv[3], "--pk", 4) )
    pubkey_path = (char*)argv[4];

  if( seckey_path == NULL || pubkey_path == NULL){ rc = 2; goto bailout; }

  seckey_fd = open(seckey_path, O_WRONLY | O_TRUNC | O_CREAT, 0600);
  pubkey_fd = open(pubkey_path, O_WRONLY | O_TRUNC | O_CREAT, 0644);

  if( seckey_fd == -1 || pubkey_fd == -1){ rc = 3; goto bailout; }
 
  /* uint8_t pubkey[crypto_kx_PUBLICKEYBYTES]; */
  /* uint8_t seckey[crypto_kx_SECRETKEYBYTES]; */
  /* crypto_kx_keypair(pubkey, seckey); */
  rc = 0;

bailout:
  if( seckey_fd != -1 ) close(seckey_fd);
  if( pubkey_fd != -1 ) close(pubkey_fd);

  if(rc){
    E("usage: crypt4gh-keygen --sk <path> --pk <path>");
  }
  return rc;
}

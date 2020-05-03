#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sodium.h>

#include "debug.h"
#include "crypt4gh.h"

int
main(int argc, const char **argv)
{
  int rc = 1;

  D1("Decrypting");

  /* get secret key - cheating */
  /* uint8_t seckey[crypto_box_SECRETKEYBYTES]; */
  /* int fd = open("_seckey", O_RDONLY, S_IRUSR | S_IWUSR); */
  /* read(fd, seckey, crypto_box_SECRETKEYBYTES); */
  /* close(fd); */

  uint8_t seckey[crypto_box_SECRETKEYBYTES] = { 245, 20, 44, 50, 96, 197, 201, 95, 10, 28, 59, 103, 171, 177, 24, 68, 174, 138, 180, 200, 182, 185, 236, 161, 211, 176, 189, 168, 77, 102, 134, 202 };
  
  H("Secret key", seckey, crypto_box_SECRETKEYBYTES);

  /* get public key from secret key */
  uint8_t pubkey[crypto_box_PUBLICKEYBYTES];
  rc = crypto_scalarmult_base(pubkey, seckey);
  if(rc){
    D1("Error retrieving the public key from the secret key");
    return 1;
  }
  H("Public key", pubkey, crypto_box_PUBLICKEYBYTES);

  /* get public key from secret key */
  rc = crypt4gh_decrypt(STDIN_FILENO, STDOUT_FILENO, seckey, pubkey);

bailout:
  return rc;
}

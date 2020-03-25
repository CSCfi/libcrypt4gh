#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "utils.h"
#include "payload.h"

#include <sodium.h>
#define CRYPT4GH_KEY_SIZE crypto_aead_chacha20poly1305_IETF_KEYBYTES

int
main(int argc, const char **argv)
{
  int rc = 1;

  if(argc < 1) return rc;
  
  if(!strcmp(*(argv + 1), "encrypt")){
    D1("Encrypting payload");

    uint8_t* k = crypt4gh_session_key_new();
    H("Session key: %.*s", CRYPT4GH_KEY_SIZE, k);

    int fd = open("_key", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    write(fd, k, CRYPT4GH_KEY_SIZE);
    close(fd);

    rc = crypt4gh_encrypt_payload(STDIN_FILENO, STDOUT_FILENO, k);

    crypt4gh_session_key_free(k);

  } else if(!strcmp(*(argv + 1), "decrypt")){

    D1("Decrypting payload");
    uint8_t k[CRYPT4GH_KEY_SIZE];
    int fd = open("_key", O_RDONLY, S_IRUSR | S_IWUSR);
    read(fd, k, CRYPT4GH_KEY_SIZE);
    close(fd);

    H("Session key: %.*s", CRYPT4GH_KEY_SIZE, k);

    rc = crypt4gh_decrypt_payload(STDIN_FILENO, STDOUT_FILENO, (uint8_t*)k);

  } else {

    D1("Unknown command: %s", *(argv + 1));
    rc = 3;

  }

  return rc;
}

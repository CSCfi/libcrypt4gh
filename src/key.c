#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>     /* isspace */
#include <sodium.h>

#include "debug.h"
#include "defs.h"
#include "key.h"
#include "base64.h"

#define PUBKEY_BUFFER_SIZE      1024 /* Large enough */
#define PUBKEY_BEGIN		"-----BEGIN CRYPT4GH PUBLIC KEY-----\n"
#define PUBKEY_END		"\n-----END CRYPT4GH PUBLIC KEY-----"
#define PUBKEY_BEGIN_LEN	36 /* (sizeof(PUBKEY_BEGIN) - 1) */
#define PUBKEY_END_LEN		34 /* (sizeof(PUBKEY_END) - 1) */


int
read_public_key(const char *filename, uint8_t output[crypto_box_PUBLICKEYBYTES])
{

  int rc = 0;
  if (!filename) { E("No filename given"); return 1; }
  if (!output) { E("No output destination"); return 2; }

  char buffer[PUBKEY_BUFFER_SIZE];
  memset(buffer, '\0', PUBKEY_BUFFER_SIZE);

  int fd = open(filename, O_RDONLY);
  if (fd == -1) {
    E("Could not open \"%s\": %s\n", filename, strerror(errno));
    rc = 3; goto bailout;
  }

  ssize_t data_len = read(fd, buffer, sizeof(buffer));
  if (data_len < PUBKEY_BEGIN_LEN + PUBKEY_END_LEN) {
    E("Invalid public key format for %s : %s\n", filename, strerror(errno));
    rc = 4; goto bailout;
  }

  char *data_start = buffer;
  char *data_end = buffer + data_len;

  /* remove newlines and white spaces */
  while(*data_start && isspace(*data_start)) data_start++;
  while(*data_end == '\0' || isspace(*data_end)){ *data_end = '\0'; data_end--;  }

  data_end = data_end - PUBKEY_END_LEN + 1;
  D3("Data start: %.*s", PUBKEY_BEGIN_LEN - 1, data_start);
  D3("  Data end: %.*s", PUBKEY_END_LEN - 1, data_end + 1); /* skip \n */

  if(strncmp(data_start, PUBKEY_BEGIN, PUBKEY_BEGIN_LEN) != 0 ||
     strncmp(data_end, PUBKEY_END, PUBKEY_END_LEN) != 0
     )
    { 
      E("Invalid public key format for %s\n", filename);
      rc = 5; goto bailout;
    }

  D3("Valid key format");
  data_start += PUBKEY_BEGIN_LEN;

  /* remove newlines and white spaces */
  while(isspace(*data_start)) data_start++;
  while(isspace(*data_end)){ *data_end = '\0'; data_end--; }
  
  D3("Base64: %.*s", (int)(data_end - data_start + 1), data_start);
  uint8_t *data = base64_decode((const unsigned char*)data_start, data_end - data_start + 1, (size_t *)&data_len);

  D3("Base64 decoded size: %zu", data_len);
  H3("Base64 decoded", data, crypto_box_PUBLICKEYBYTES);

  if(data_len != crypto_box_PUBLICKEYBYTES){
    E("Invalid public key length for %s", filename);
    rc = 6;
  } else {
    D3("copying from %p to %p", data, output);
    memcpy(output, data, (data_len > crypto_box_PUBLICKEYBYTES)?crypto_box_PUBLICKEYBYTES:data_len);
    rc = 0; /* success */
  }
  D3("Freeing data at %p", data);
  free(data);

bailout:
  if (fd != -1 && close(fd) < 0){ E("Error on closing %s : %s", filename, strerror(errno)); }
  return rc;
}

/* uint8_t* */
/* read_secret_key(const char *filename, (char*)(*cb)(void)) */
/* { */
/*   E("Not implemented yet"); */
/*   return NULL; */
/* }; */

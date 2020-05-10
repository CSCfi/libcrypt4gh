#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sodium.h>

#include "debug.h"
#include "defs.h"
#include "crypt4gh.h"
#include "key.h"
#include "cli.h"

int
main(int argc, const char **argv)
{
  int rc = 1;
  uint8_t* recipients = NULL;

  options_t* opts = docopt(argc, (char**)argv);
  
  if(!opts) return 1; /* arg parse failed */
 
  /* ----------- DECRYPT ----------- */
  if(opts->decrypt){

    /* crg.sec */
    /* uint8_t seckey[crypto_box_SECRETKEYBYTES] = { 245, 20, 44, 50, 96, 197, 201, 95, 10, 28, 59, 103, 171, 177, 24, 68, 174, 138, 180, 200, 182, 185, 236, 161, 211, 176, 189, 168, 77, 102, 134, 202 }; */

    /* fred.sec */
    uint8_t seckey[crypto_box_SECRETKEYBYTES] = { 162, 69, 254, 84, 81, 253, 182, 18, 106, 140, 139, 220, 94, 113, 27, 40, 140, 68, 237, 31, 61, 74, 80, 255, 242, 141, 122, 23, 218, 86, 140, 25 };

    H1("Secret key", seckey, crypto_box_SECRETKEYBYTES);
    
    /* get public key from secret key */
    uint8_t pubkey[crypto_box_PUBLICKEYBYTES];
    rc = crypto_scalarmult_base(pubkey, seckey);
    if(rc){
      D1("Error retrieving the public key from the secret key");
      return 1;
    }
    H1("Public key", pubkey, crypto_box_PUBLICKEYBYTES);

    
    rc = crypt4gh_decrypt(STDIN_FILENO, STDOUT_FILENO, seckey, pubkey);

    goto final;

  }

  /* ----------- ENCRYPT ----------- */
  if (opts->encrypt){
    D1("encrypt: %d", opts->encrypt);

    uint8_t pubkey[crypto_kx_PUBLICKEYBYTES];
    uint8_t seckey[crypto_kx_SECRETKEYBYTES];

    /* If no seckey supplied, we create an ephemeral key */
    if(opts->sk == NULL){
      crypto_kx_keypair(pubkey, seckey);
      D1("Creating an ephemeral keypair");
    } else {

      /* fetch from file */

      /* get public key from secret key */
      rc = crypto_scalarmult_base(pubkey, seckey);
      if(rc){
	E("Error retrieving the public key from the secret key");
	rc = 1;
	goto final;
      }
      H1("Public key", pubkey, crypto_box_PUBLICKEYBYTES);
    }

    /* fetch recipients */
    recipients = (uint8_t*)malloc(opts->nrecipients * crypto_kx_PUBLICKEYBYTES * sizeof(uint8_t));
    memset(recipients, '\0', opts->nrecipients * crypto_kx_PUBLICKEYBYTES); /* not really needed */

    int i = 0;
    for(; i < opts->nrecipients; i++){
      rc = read_public_key(opts->recipient_pubkeys[i],
			   recipients + (i * crypto_kx_PUBLICKEYBYTES));
      if(rc){
      	D1("Error loading public key \"%s\"", opts->recipient_pubkeys[i]);
      	goto final;
      }
    }

    /* Encrypting */
    D1("Encrypting");
    rc = crypt4gh_encrypt(STDIN_FILENO, STDOUT_FILENO,
    			  seckey, pubkey,
    			  (const uint8_t*)recipients, opts->nrecipients);

    D1("Encryption done");
    goto final;
  }

  /* ----------- REARRANGE ----------- */
  if (opts->rearrange){
    D1("rearrange: %d", opts->rearrange);
    goto final;
  }

  /* ----------- REENCRYPT ----------- */
  if (opts->reencrypt){
    D1("reencrypt: %d", opts->reencrypt);
    goto final;
  }


final:
  docopt_free(opts);
  if(recipients) free(recipients);
  return rc;
}

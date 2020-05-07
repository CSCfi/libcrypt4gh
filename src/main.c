#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sodium.h>

#include "debug.h"
#include "defs.h"
#include "docopt.h"
#include "crypt4gh.h"
/* #include "passphrase.h" */

int
main(int argc, const char **argv)
{
  int rc = 1;

  /* char* buf[1024]; */
  /* get_passphrase("Enter the passphrase: ", (char*)buf, sizeof(buf)); */

  /* D1("passphrase: %s", (char*)buf); */


  DocoptArgs* opts = docopt(argc, (char**)argv);
  
  if(!opts) return 1; /* arg parse failed */


    
  D1("trim: %d", opts->trim);
    
  D1("range: %s", opts->range);
  D1("recipients: %d", opts->nrecipients);
  int i=0;
  for(; i< opts->nrecipients; i++){
    D1("* recipient_pk: %s", opts->recipient_pubkeys[i]);
  }
  D1("sender_pk: %s", opts->sender_pk);
  D1("sk: %s", opts->sk);
  

  /* ----------- DECRYPT ----------- */
  if(opts->decrypt){


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
      
    } else {

      /* fetch from file */

      /* get public key from secret key */
      rc = crypto_scalarmult_base(pubkey, seckey);
      if(rc){
	E("Error retrieving the public key from the secret key");
	rc = 1;
	goto final;
      }
      H("Public key", pubkey, crypto_box_PUBLICKEYBYTES);
    }

    /* fetch recipients */
    uint8_t* recipients[opts->nrecipients * crypto_kx_PUBLICKEYBYTES];
    int i = 0;
    for(; i < opts->nrecipients; i++){
      /* rc = get_public_key(opts->recipient_pubkeys[i], recipients[i * crypto_kx_PUBLICKEYBYTES]); */
    }

    /* rc = crypt4gh_encrypt(STDIN_FILENO, STDOUT_FILENO, */
    /* 			  seckey, pubkey, */
    /* 			  (const uint8_t* const*)opts->recipient_pubkeys, opts->nrecipients); */

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
  return rc;
}

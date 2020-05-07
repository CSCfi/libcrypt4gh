
#include "debug.h"
#include "passphrase.h"
#include "docopt.h"

int
main(int argc, const char **argv)
{
  int rc = 1;

  /* char* buf[1024]; */
  /* get_passphrase("Enter the passphrase: ", (char*)buf, sizeof(buf)); */

  /* D1("passphrase: %s", (char*)buf); */


  DocoptArgs* opts = docopt(argc, (char**)argv);
  
  if(opts){
    D1("decrypt: %d", opts->decrypt);
    D1("encrypt: %d", opts->encrypt);
    D1("rearrange: %d", opts->rearrange);
    D1("reencrypt: %d", opts->reencrypt);
    
    D1("trim: %d", opts->trim);
    
    D1("range: %s", opts->range);
    D1("recipients: %d", opts->nrecipients);
    int i=0;
    for(; i< opts->nrecipients; i++){
      D1("* recipient_pk: %s", opts->recipient_pubkeys[i]);
    }
    D1("sender_pk: %s", opts->sender_pk);
    D1("sk: %s", opts->sk);
  }

  docopt_free(opts);
  return 0;
}

#ifndef __CRYPT4GH_CLI_H_INCLUDED__
#define __CRYPT4GH_CLI_H_INCLUDED__

#include <stdbool.h>

typedef struct {
    /* commands */
    int decrypt;
    int encrypt;
    int rearrange;
    int reencrypt;
    /* options without arguments */
    int trim;
    /* options with arguments */
    char* range;
    char *sender_pk;
    char *sk;
    /* options with arguments, potentially repeated */
    int nrecipients;
    char** recipient_pubkeys;
} options_t;


options_t* docopt(int argc, char** argv);

void docopt_free(options_t*);

#endif /* !__CRYPT4GH_CLI_H_INCLUDED__ */

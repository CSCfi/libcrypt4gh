#ifndef __CRYPT4GH_DOCOPT_H_INCLUDED__
#define __CRYPT4GH_DOCOPT_H_INCLUDED__

#include <stdbool.h>

typedef struct {
    /* commands */
    int decrypt;
    int encrypt;
    int rearrange;
    int reencrypt;
    /* options without arguments */
    int help;
    int trim;
    int version;
    /* options with arguments */
    char *log;
    char *range;
    char *recipient_pk;
    char *sender_pk;
    char *sk;
    /* special */
    const char *usage_pattern;
    const char *help_message;
} DocoptArgs;


DocoptArgs docopt(int argc, char** argv, bool help, const char *version);

#endif /* !__CRYPT4GH_DOCOPT_H_INCLUDED__ */

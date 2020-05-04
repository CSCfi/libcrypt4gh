#ifndef _CRYPT4GH_PASSPHRASE_H_
#define _CRYPT4GH_PASSPHRASE_H_

#include <stdint.h>

int
get_passphrase(const char* prompt, char* buf, size_t buflen);

#endif /* !_CRYPT4GH_PASSPHRASE_H_ */

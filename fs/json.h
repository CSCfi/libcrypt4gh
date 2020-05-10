#ifndef __CRYPT4GH_JSON_H_INCLUDED__
#define __CRYPT4GH_JSON_H_INCLUDED__

#include <stddef.h>

#include "permissions.h"

int json_str_array(const char* json, size_t jsonlen, iterator_t* iterator);

int json_ega_file(const char* json, size_t jsonlen,
		  char** header, size_t* header_len, char** payload_path);

#endif /* !__CRYPT4GH_JSON_H_INCLUDED__ */

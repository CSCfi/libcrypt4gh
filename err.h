#ifndef __CRYPT4GH_ERR_H_INCLUDED__
#define __CRYPT4GH_ERR_H_INCLUDED__

#define CRYPT4GH_ERR_SUCCESS             0
#define CRYPT4GH_ERR_INTERNAL_ERROR      1
#define CRYPT4GH_ERR_MEMORY_ALLOCATION   2
#define CRYPT4GH_ERR_INVALID_PARAMETERS  3
#define CRYPT4GH_ERR_PACKET_DECRYPTION   4
#define CRYPT4GH_ERR_SEGMENT_DECRYPTION  5
#define CRYPT4GH_ERR_SYSTEM_ERROR        6
#define CRYPT4GH_ERR_MAC_INVALID         7
#define CRYPT4GH_ERR_NO_CIPHER_ALG_MATCH 8
#define CRYPT4GH_ERR_INVALID_PASSPHRASE  9
#define CRYPT4GH_ERR_KEY_UNKNOWN_CIPHER  10
#define CRYPT4GH_ERR_KEY_BAD_PERMISSIONS 11
#define CRYPT4GH_ERR_KEY_NOT_FOUND       12
#define CRYPT4GH_ERR_HEADER_INVALID      13
#define CRYPT4GH_ERR_HEADER_INVALID_ENCRYPTION 14


const char* crypt4gh_err(int n);

#endif /* !__CRYPT4GH_ERR_H_INCLUDED__ */



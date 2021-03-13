#ifndef __CRYPT4GH_DEFS_H_INCLUDED__
#define __CRYPT4GH_DEFS_H_INCLUDED__

/* Crypt4GH contants */
#include <sodium.h>

#define CRYPT4GH_SESSION_KEY_SIZE   crypto_aead_chacha20poly1305_IETF_KEYBYTES
#define CRYPT4GH_NONCE_SIZE         crypto_aead_chacha20poly1305_IETF_NPUBBYTES /* 12 */
#define CRYPT4GH_MAC_SIZE           16
#define CRYPT4GH_SEGMENT_SIZE       65536
#define CRYPT4GH_CIPHERSEGMENT_SIZE 65564 /* CRYPT4GH_SEGMENT_SIZE + 12(nonce) + 16(mac) */

typedef enum {
  data_encryption_parameters = 0,
  data_edit_list = 1
} header_packet_type;

typedef enum {
  X25519_chacha20_ietf_poly1305 = 0
} header_packet_encryption_method;

typedef enum {
  chacha20_ietf_poly1305 = 0
} header_data_encryption_type;


#endif /* !__CRYPT4GH_DEFS_H_INCLUDED__ */

#ifndef __CRYPT4GH_STREAM_H_INCLUDED__
#define __CRYPT4GH_STREAM_H_INCLUDED__

#include "crypt4gh/defs.h"

typedef struct stream_s {
  int fd_in;
  int fd_out;
  const uint8_t* session_key;
  uint8_t segment[CRYPT4GH_SEGMENT_SIZE];
  size_t segment_pos;
  size_t segment_left;
  uint8_t ciphersegment[CRYPT4GH_CIPHERSEGMENT_SIZE];
  size_t cipher_pos;
  size_t cipher_left;
} stream_t;

stream_t* crypt4gh_stream_init(int fd_in, int fd_out, const uint8_t* session_key);
void crypt4gh_stream_free(stream_t* s);

int crypt4gh_stream_encrypt_push(stream_t* e, uint8_t* data, size_t data_len);
int crypt4gh_stream_encrypt_close(stream_t* e);

int crypt4gh_stream_decrypt_push(stream_t* e, uint8_t* data, size_t data_len);
int crypt4gh_stream_decrypt_close(stream_t* e);


#endif /* !__CRYPT4GH_STREAM_H_INCLUDED__ */

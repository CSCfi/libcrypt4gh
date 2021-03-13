#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "includes.h"

#include "segment.h"
#include "stream.h"

static void
crypt4gh_stream_reset(stream_t* s){
  if(!s) return;

  s->segment_pos = 0;
  s->segment_left = CRYPT4GH_SEGMENT_SIZE;
  s->cipher_pos = 0;
  s->cipher_left = CRYPT4GH_CIPHERSEGMENT_SIZE;
  sodium_memzero(s->segment, CRYPT4GH_SEGMENT_SIZE);
  sodium_memzero(s->ciphersegment, CRYPT4GH_CIPHERSEGMENT_SIZE);
}

stream_t*
crypt4gh_stream_init(int fd_in, int fd_out, const uint8_t* session_key){

  if(!session_key) return NULL;

  stream_t* s = (stream_t*)malloc(sizeof(stream_t));

  if(s == NULL || errno == ENOMEM){ D1("Could not allocate the stream engine"); return NULL; }

  s->session_key = session_key;
  s->fd_in = fd_in;
  s->fd_out = fd_out;

  crypt4gh_stream_reset(s);
  return s;
}

void
crypt4gh_stream_free(stream_t* s){
  if(!s) return;

  /* Clear the struct */
  /* sodium_free(s->session_key); */
  /* sodium_memzero(s->segment, CRYPT4GH_SEGMENT_SIZE); */
  /* sodium_memzero(s->ciphersegment, CRYPT4GH_CIPHERSEGMENT_SIZE); */
  sodium_memzero(s, sizeof(stream_t));
  free(s);
}

static int
crypt4gh_stream_encrypt_flush(stream_t* s){
  if(!s) return 1;

  int rc = 1;
  D1("Flushing segment: pos %zu | left %zu", s->segment_pos, s->segment_left);

  if( (rc = crypt4gh_segment_encrypt(s->session_key, s->segment, s->segment_pos, s->ciphersegment, &(s->cipher_pos))) ||
      (write(s->fd_out, s->ciphersegment, s->cipher_pos) != s->cipher_pos))
    {
      D1("Error while encrypting and flushing the cipher segment");
      rc = 2;
    }
  crypt4gh_stream_reset(s);
  return rc;
}

int
crypt4gh_stream_encrypt_close(stream_t* s){
  return crypt4gh_stream_encrypt_flush(s);
}


int
crypt4gh_stream_encrypt_push(stream_t* s, uint8_t* data, size_t data_len){
  if(!s) return 1;
  if(data_len == 0) return 0; /* nothing to do */

  if( data_len <= s->segment_left){ /* just add the data */
    D1("Adding %zu bytes to the segment", data_len);
    memcpy(s->segment + s->segment_pos, data, data_len);
    s->segment_left -= data_len;
    s->segment_pos += data_len;
    return 0;
  } 

  /* copy what we can, and remember what's left */
  D1("Adding %zu bytes to the segment", s->segment_left);
  memcpy(s->segment + s->segment_pos, data, s->segment_left);
  data += s->segment_left;
  data_len -= s->segment_left;
  s->segment_pos += s->segment_left; /* CRYPT4GH_SEGMENT_SIZE */
  s->segment_left = 0;

  return (/* encrypt and flush the data to disk */
	  crypt4gh_stream_encrypt_flush(s) ||
	  /* recurse with what's left */
	  crypt4gh_stream_encrypt_push(s, data, data_len));
}


static int
crypt4gh_stream_decrypt_flush(stream_t* s){
  if(!s) return 1;

  int rc = 1;
  D1("Flushing ciphersegment: pos %zu | left %zu", s->cipher_pos, s->cipher_left);

  if( (rc = crypt4gh_segment_decrypt(s->session_key, s->ciphersegment, s->cipher_pos, s->segment, &(s->segment_pos))) ||
      (write(s->fd_out, s->segment, s->segment_pos) != s->segment_pos))
    {
      D1("Error while decrypting and flushing the segment");
      rc = 2;
    }
  crypt4gh_stream_reset(s);
  return rc;
}

int
crypt4gh_stream_decrypt_close(stream_t* s){
  return crypt4gh_stream_decrypt_flush(s);
}


int
crypt4gh_stream_decrypt_push(stream_t* s, uint8_t* data, size_t data_len){
  if(!s) return 1;
  if(data_len == 0) return 0; /* nothing to do */

  if( data_len <= s->cipher_left){ /* just add the data */
    D1("Adding %zu bytes to the ciphersegment", data_len);
    memcpy(s->ciphersegment + s->cipher_pos, data, data_len);
    s->cipher_left -= data_len;
    s->cipher_pos += data_len;
    return 0;
  } 

  /* copy what we can, and remember what's left */
  D1("Adding %zu bytes to the segment", s->segment_left);
  memcpy(s->ciphersegment + s->cipher_pos, data, s->cipher_left);
  data += s->cipher_left;
  data_len -= s->cipher_left;
  s->cipher_pos += s->cipher_left; /* CRYPT4GH_CIPHERSEGMENT_SIZE */
  s->cipher_left = 0;

  return (/* encrypt and flush the data to disk */
	  crypt4gh_stream_decrypt_flush(s) ||
	  /* recurse with what's left */
	  crypt4gh_stream_decrypt_push(s, data, data_len));
}

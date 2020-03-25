#include <sys/types.h>
#include <sodium.h>
#include <errno.h>

#include "debug.h"
#include "defs.h"
#include "header.h"

#define MAGIC_NUMBER "crypt4gh"
#define VERSION 1U

#define CRYPT4GH_HEADER_DATA_PACKET_len (4U + 4U + crypto_aead_chacha20poly1305_IETF_KEYBYTES)
#define NONCE_LEN crypto_aead_chacha20poly1305_IETF_NPUBBYTES
#define CRYPT4GH_HEADER_ENCRYPTED_DATA_PACKET_len (4U + 4U		             \
						   + crypto_box_PUBLICKEYBYTES       \
						   + NONCE_LEN		             \
						   + CRYPT4GH_HEADER_DATA_PACKET_len \
						   + crypto_box_MACBYTES)


static int
make_packet_data_enc(header_data_encryption_type encryption_method,
		     const uint8_t session_key[CRYPT4GH_SESSION_KEY_SIZE],
		     uint8_t** output, size_t* output_len){
  
  CRYPT4GH_INIT(1);

  uint8_t* buf = (uint8_t*)sodium_malloc(CRYPT4GH_HEADER_DATA_PACKET_len);

  if(buf == NULL || errno == ENOMEM){
    D1("Could not allocate memory");
    return 1;
  }
  
  if(output) *output = buf;
  if(output_len) *output_len = CRYPT4GH_HEADER_DATA_PACKET_len;

  PUT_32BIT_LE(buf, data_encryption_parameters); buf+=4; /* type        */
  PUT_32BIT_LE(buf, encryption_method); buf+=4;          /* method      */
  memcpy(buf, session_key, CRYPT4GH_SESSION_KEY_SIZE);   /* session key */

  sodium_mprotect_readonly(buf);
  return 0;
}

static int
header_encrypt_X25519_Chacha20_Poly1305(const uint8_t* data, size_t data_len,
					const uint8_t pubkey[crypto_box_PUBLICKEYBYTES],
					const uint8_t seckey[crypto_box_PUBLICKEYBYTES],
					const uint8_t recipient_pubkey[crypto_box_PUBLICKEYBYTES],
					uint8_t output[CRYPT4GH_HEADER_ENCRYPTED_DATA_PACKET_len])
{
  int rc = 0;


  /* X25519 shared key */
  uint8_t* shared_key = (uint8_t*)sodium_malloc(crypto_kx_SESSIONKEYBYTES);
  if(!shared_key || errno == ENOMEM){
    D1("Unable to allocated memory for the shared key");
    return 1;
  }
  
  uint8_t ignored[crypto_kx_SESSIONKEYBYTES];
  rc = crypto_kx_server_session_keys(ignored, shared_key, pubkey, seckey, recipient_pubkey);
  sodium_memzero(ignored, crypto_kx_SESSIONKEYBYTES);

  if(rc){
    D1("Unable to derive the shared key: %d", rc);
    goto bailout;
  }

  H("Shared key", shared_key, crypto_kx_SESSIONKEYBYTES);

  /* Chacha20_Poly1305 */
  unsigned char nonce[NONCE_LEN];
  randombytes_buf(nonce, NONCE_LEN); /* NONCE_LEN * sizeof(char) */

  uint8_t* p = output; /* record the start */

  /* length */
  PUT_32BIT_LE(p, CRYPT4GH_HEADER_ENCRYPTED_DATA_PACKET_len);
  D1("Packet length: %d", CRYPT4GH_HEADER_ENCRYPTED_DATA_PACKET_len);
  H("Packet len", p, 4);
  p+=4;

  /* encryption method */
  PUT_32BIT_LE(p, X25519_chacha20_ietf_poly1305);
  D1("Encryption method: %d", X25519_chacha20_ietf_poly1305);
  H("enc method", p, 4);
  p+=4;

  /* sender's pubkey */
  memcpy(p, pubkey, crypto_box_PUBLICKEYBYTES);
  H("Sender's pubkey", p, crypto_box_PUBLICKEYBYTES);
  p+=crypto_box_PUBLICKEYBYTES;

  /* nonce */
  memcpy(p, nonce, NONCE_LEN);
  H("nonce", p, NONCE_LEN);
  p+=NONCE_LEN;

  /* encrypted session key (and mac) */
  unsigned long long len;
  rc = crypto_aead_chacha20poly1305_ietf_encrypt(p, &len,
						 data, data_len,
						 NULL, 0, /* no authenticated data */
						 NULL, nonce, shared_key);
  if(rc){
    D1("Error %d encrypting the data", rc);
    goto bailout;
  }
  H("Encrypted data", p, len);
  p+=len;
 
  if(p-output != CRYPT4GH_HEADER_ENCRYPTED_DATA_PACKET_len){
    D1("Error of size for the encrypted data packet");
    D2("packet: %p", output);
    D2("     p: %p", p);
    D2("diff: %ld", (p-output));
    D2("size: %d", CRYPT4GH_HEADER_ENCRYPTED_DATA_PACKET_len);
    rc = 4;
    goto bailout;
  }

  rc = 0; /* success */
 
bailout:
 sodium_free(shared_key);
 return rc;
}

int
header_build(const uint8_t session_key[CRYPT4GH_SESSION_KEY_SIZE],
	     const uint8_t* seckey, const uint8_t* const* recipient_pubkeys, unsigned int nb_recipients,
	     uint8_t** output, size_t* output_len)
{
  if(recipient_pubkeys == NULL || nb_recipients == 0){
    D1("No recipients");
    return 1;
  }

  /* Allocate space for n packets + magic_number and version */
  size_t buflen = (8+4+4+ nb_recipients * CRYPT4GH_HEADER_ENCRYPTED_DATA_PACKET_len);

  uint8_t* buf = (uint8_t*)malloc(buflen);

  if(buf == NULL || errno == ENOMEM){
    D1("Could not allocate memory");
    return 2;
  }

  uint8_t* data_packet = NULL;
  size_t data_packet_len;
  int rc = make_packet_data_enc(chacha20_ietf_poly1305, session_key, &data_packet, &data_packet_len);

  if(rc){
    D1("Error making data packet");
    goto bailout;
  }

  /* get public key from secret key */
  uint8_t pubkey[crypto_box_PUBLICKEYBYTES];
  rc = crypto_scalarmult_base(pubkey, seckey);
  if(rc){
    D1("Error retrieving the public key from the secret key");
    goto bailout;
  }
  H("Public key", (uint8_t*)pubkey, 32);

  if(output) *output=buf;
  if(output_len) *output_len=buflen;

  /* Magic number */
  memcpy(buf, MAGIC_NUMBER, 8);
  D1("output magic number: %.8s", MAGIC_NUMBER);
  H("Magic number", buf, 8);
  buf+=8;
  
  /* Version */
  PUT_32BIT_LE(buf, VERSION);
  D1("output version: %d", VERSION);
  H("Version", buf, 4);
  buf+=4;

  /* Number of Packets */
  PUT_32BIT_LE(buf, nb_recipients);
  D1("output nb packets: %d", nb_recipients);
  H("#packets", buf, 4);
  buf+=4;

  /* For each recipients */
  int i=0;
  for(; i<nb_recipients; i++){  

    if(header_encrypt_X25519_Chacha20_Poly1305(data_packet, data_packet_len,
					       pubkey, seckey, recipient_pubkeys[i],
					       buf))
      { D1("Error encrypting for recipient %d", i);
	rc = i+1;
	goto bailout;
      }
    buf+=CRYPT4GH_HEADER_ENCRYPTED_DATA_PACKET_len;
  }
  
  if(output && buf - *output != buflen){
    D1("Error of size for the encrypted data packets");
    D2("output: %p", *output);
    D2("buffer: %p", buf);
    D2("size: %zu", buflen);
    return i;
  }

bailout:
  if(data_packet) sodium_free(data_packet);
  if(rc){ /* error: cleanup */
    if(output) *output=NULL;
    if(output_len) *output_len=0;
    free(buf);
  }
  return rc;
}

#include <sys/types.h>
#include <sodium.h>
#include <errno.h>

#include "includes.h"

#include "packet.h"

int
crypt4gh_packet_build_data_enc(header_data_encryption_type encryption_method,
		     const uint8_t session_key[CRYPT4GH_SESSION_KEY_SIZE],
		     uint8_t** output, size_t* output_len){
  
  if (sodium_init() == -1) {
    E("Could not initialize libsodium");
    return 1;
  }

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
parse_packet_data_enc(uint8_t* data, uint8_t data_len,
		      uint8_t** session_keys, unsigned int* nkeys)
{
  D2("Data encryption packet");
  
  if(data == NULL || data_len < 4U + CRYPT4GH_SESSION_KEY_SIZE){
    D1("Not enough data to read");
    return 1;
  }
  
  uint32_t encryption_method = PEEK_U32_LE(data);
  if(encryption_method != chacha20_ietf_poly1305)
    {
      D1("Unsupported data encryption method: %u", encryption_method);
      return 2;
    }

  if(session_keys != NULL){
    memcpy(*session_keys, data+4, CRYPT4GH_SESSION_KEY_SIZE);
    *session_keys += CRYPT4GH_SESSION_KEY_SIZE;
    *nkeys += 1;
  }
  return 0;
}

static int
parse_packet_edit_list(uint8_t* data, unsigned int data_len,
		       uint64_t** edit_list, unsigned int* edit_list_len)
{
  D2("Edit list packet");

  if(edit_list == NULL)
    {
      E("Invalid interface");
      return 1;
    }

  if(*edit_list != NULL)
    {
      E("Only one edit list allowed per header");
      /* Reject header ?*/
      return 1;
    }

  if(data_len < 4)
    {
      D1("Invalid edit list of size %u", data_len);
      return 2;
    }

  uint32_t nlengths = PEEK_U32_LE(data);
  data += 4;
  data_len -= 4;

  if (data_len < 8ULL * nlengths)
    {
      D1("Edit list too small: %u, but expecting %llu", data_len, 8ULL * nlengths);
      return 3;
    }

  *edit_list = (uint64_t*)malloc(sizeof(uint64_t) * nlengths);
  if(*edit_list == NULL || errno == ENOMEM){
    D1("Could not allocate memory");
    return 4;
  }
  
  uint64_t* e = *edit_list;
  while(nlengths-- > 0)
    {
      *e = PEEK_U64_LE(data);
      data += sizeof(uint64_t);
      e++;
    }
  
  return 0;
}

int
crypt4gh_packet_parse(uint8_t* data, unsigned int data_len,
		      uint8_t** session_keys, unsigned int* nkeys,
		      uint64_t** edit_list, unsigned int* edit_list_len)
{
  int rc = 1;
  if(data_len < 4) { D1("Packet too small"); return rc; }

  uint32_t packet_type = PEEK_U32_LE(data);

  switch(packet_type){
  case data_encryption_parameters:
    rc = parse_packet_data_enc(data+4, data_len-4, session_keys, nkeys);
    break;
  case data_edit_list:
    rc = parse_packet_edit_list(data+4, data_len-4, edit_list, edit_list_len);
    break;
  default:
    D1("Unsupported packet type: %d", packet_type);
    break;
  }
  return rc;
}

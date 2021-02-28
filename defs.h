#ifndef __CRYPT4GH_DEFS_H_INCLUDED__
#define __CRYPT4GH_DEFS_H_INCLUDED__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* activate extra prototypes for glibc */
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif

/* Constants */

#ifndef STDIN_FILENO
# define STDIN_FILENO    0
#endif
#ifndef STDOUT_FILENO
# define STDOUT_FILENO   1
#endif
#ifndef STDERR_FILENO
# define STDERR_FILENO   2
#endif

/* Types */

#ifndef HAVE_STDINT_H
#    ifndef HAVE_UINTXX_T
typedef unsigned char uint8_t;
#        if (SIZEOF_INT == 4)
typedef unsigned int uint32_t;
#        else
#            error "32 bit int type not found."
#        endif
#    endif
#endif

#ifndef HAVE_SYS_TYPES_H
#    ifndef HAVE_SIZE_T
typedef unsigned int size_t;
#    define HAVE_SIZE_T
#    endif /* HAVE_SIZE_T */
#endif

/* Macros */

#ifndef MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
# define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#if !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#endif /* !defined(__GNUC__) || (__GNUC__ < 2) */

#if !defined(HAVE_ATTRIBUTE__NONNULL__) && !defined(__nonnull__)
# define __nonnull__(x)
#endif

/* Function replacement / compatibility hacks */

#if !defined(HAVE___func__) && defined(HAVE___FUNCTION__)
#  define __func__ __FUNCTION__
#elif !defined(HAVE___func__)
#  define __func__ ""
#endif


/* Endianness */

#ifdef HAVE_ENDIAN_H
# include <endian.h>
#endif

/* Set up BSD-style BYTE_ORDER definition if it isn't there already */
/* XXX: doesn't try to cope with strange byte orders (PDP_ENDIAN) */
#ifndef BYTE_ORDER
# ifndef LITTLE_ENDIAN
#  define LITTLE_ENDIAN  1234
# endif /* LITTLE_ENDIAN */
# ifndef BIG_ENDIAN
#  define BIG_ENDIAN     4321
# endif /* BIG_ENDIAN */
# ifdef WORDS_BIGENDIAN
#  define BYTE_ORDER BIG_ENDIAN
# else /* WORDS_BIGENDIAN */
#  define BYTE_ORDER LITTLE_ENDIAN
# endif /* WORDS_BIGENDIAN */
#endif /* BYTE_ORDER */


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


/*
 * Copy a value to cp in little-endian format
 */
/*
#ifdef HAVE_ENDIAN_H
# include <endian.h>
#else
#endif
*/

#define PUT_64BIT_LE(cp, value) do {					\
    (cp)[7] = (value) >> 56;						\
    (cp)[6] = (value) >> 48;						\
    (cp)[5] = (value) >> 40;						\
    (cp)[4] = (value) >> 32;						\
    (cp)[3] = (value) >> 24;						\
    (cp)[2] = (value) >> 16;						\
    (cp)[1] = (value) >> 8;						\
    (cp)[0] = (value); } while (0)

#define PUT_32BIT_LE(cp, value) do {					\
    (cp)[3] = (value) >> 24;						\
    (cp)[2] = (value) >> 16;						\
    (cp)[1] = (value) >> 8;						\
    (cp)[0] = (value); } while (0)

/*
 * Read 8 bytes from p and 
 * get its integer representation in little-endian format
 */
#define PEEK_U64_LE(p) \
	(((uint64_t)(((const uint8_t *)(p))[0])      ) | \
	 ((uint64_t)(((const uint8_t *)(p))[1]) <<  8) | \
	 ((uint64_t)(((const uint8_t *)(p))[2]) << 16) | \
	 ((uint64_t)(((const uint8_t *)(p))[3]) << 24) | \
	 ((uint64_t)(((const uint8_t *)(p))[4]) << 32) | \
	 ((uint64_t)(((const uint8_t *)(p))[5]) << 40) | \
	 ((uint64_t)(((const uint8_t *)(p))[6]) << 48) | \
	 ((uint64_t)(((const uint8_t *)(p))[7]) << 56))
/* Left shift are filled with zeros */

/*
 * Read 4 bytes from p and 
 * get its integer representation in little-endian format
 */
#define PEEK_U32_LE(p) \
	(((uint32_t)(((const uint8_t *)(p))[0])      ) | \
	 ((uint32_t)(((const uint8_t *)(p))[1]) << 8 ) | \
	 ((uint32_t)(((const uint8_t *)(p))[2]) << 16) | \
	 ((uint32_t)(((const uint8_t *)(p))[3]) << 24))


#endif /* !__CRYPT4GH_DEFS_H_INCLUDED__ */

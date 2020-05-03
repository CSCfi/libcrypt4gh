#ifndef __CRYPT4GH_UTILS_H_INCLUDED__
#define __CRYPT4GH_UTILS_H_INCLUDED__

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

#include "debug.h"

/* Abort in case of memory allocation errors */
/*
  extern char *malloc_options;
  malloc_options = "X";
*/


#define CRYPT4GH_INIT(ret) if (sodium_init() == -1) { return (ret); }

#ifdef DEBUG
  #define E(fmt,...) fprintf(stderr, "%40s | " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#else
  #define E(fmt,...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#endif

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

#endif /* !__CRYPT4GH_UTILS_H_INCLUDED__ */

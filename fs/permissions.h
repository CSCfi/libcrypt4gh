#ifndef __CRYPT4GH_PERMISSIONS_H_INCLUDED__
#define __CRYPT4GH_PERMISSIONS_H_INCLUDED__

#include <stddef.h> 
#include <sys/stat.h>
#include <fuse.h>

typedef struct iterator_s {
  char* endpoint;
  void* buf;
  struct stat* st; /* only bit 12-15 are used */
  off_t offset;
  fuse_fill_dir_t filler;
} iterator_t;

int crypt4gh_permissions_init(void);
void crypt4gh_permissions_close(void);

int crypt4gh_permissions_str_array(iterator_t* iterator);

/* int crypt4gh_permissions_ega_file(char** header, size_t* header_len, char** payload); */


#endif /* !__CRYPT4GH_PERMISSIONS_H_INCLUDED__ */

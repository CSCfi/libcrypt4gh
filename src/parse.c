#include <stdio.h>

#include "header.h"

static inline int 
is_bigendian(void){
  const int i=1;
  char *p = (char*)&i;
  return p[0] == 0;
}

int
main(int argc, const char **argv)
{
  int rc = 0;

  make_header();

  printf("My processor is %s-endian\n", (is_bigendian())?"big":"little");

  return rc;
}

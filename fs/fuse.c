/*
  FUSE for Crypt4GH

  Author: Frédéric Haziza <silverdaz@gmail.com>
*/

#define FUSE_USE_VERSION 31

#define _GNU_SOURCE

#ifdef linux
#define _XOPEN_SOURCE 700 /* For pread()/pwrite()/utimensat() */
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <libgen.h>   /* basename */
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <fuse.h>
#include <sodium.h> /* for the ephemeral key generation */

#include "debug.h"
#include "defs.h"
#include "header.h"
#include "payload.h"
#include "permissions.h"

/* Ephemeral key */
static uint8_t* pubkey;
static uint8_t* seckey;

/* mountpoint */
static char* root_prefix = NULL;
static int root_prefix_len = 0;

/* username */
static char* username = NULL;
static int username_len = 0;

/* Permissions endpoint */
extern char* endpoint_datasets;
extern size_t endpoint_datasets_len;
extern char* endpoint_file;
extern size_t endpoint_file_len;

static int
crypt4gh_getattr(const char *path, struct stat *stbuf)
{
  int res;
  
  res = lstat(path, stbuf);
  if (res == -1)
    return -errno;
  
  return 0;
}

static int
crypt4gh_access(const char *path, int mask)
{
  int res;
  
  res = access(path, mask);
  if (res == -1)
    return -errno;
  
  return 0;
}

static int
crypt4gh_readlink(const char *path, char *buf, size_t size)
{
  int res;
  
  res = readlink(path, buf, size - 1);
  if (res == -1)
    return -errno;
  
  buf[res] = '\0';
  return 0;
}



static int
crypt4gh_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		 off_t offset, struct fuse_file_info *fi)
{

  if (strncmp(path, root_prefix, root_prefix_len) != 0) /* We only recognize the root directory. */
    return -ENOENT;

  int rc = -ENOENT;

  char endpoint[endpoint_datasets_len + username_len + 128]; /* 128: large enough for dataset and file names */
  char* dataset;

  struct stat st;
  memset(&st, 0, sizeof(st));

  iterator_t iterator = {.endpoint = endpoint,
			 .buf = buf,
			 .st = &st,
			 .filler = filler };

  if (strlen(path) == root_prefix_len){ /* We want all the datasets */
    dataset = "";
    st.st_mode |= S_IFDIR; /* mark them as directories */
  } else { /* Longer => specific dataset */
    dataset = basename(path);
    st.st_mode |= S_IFREG; /* mark them as a files */
  }

  if(sprintf(endpoint, endpoint_datasets, username, dataset) < 0){
    D1("Endpoint formatting error");
    rc = -ENOENT;
    goto final;
  }

  rc = crypt4gh_permissions_str_array(&iterator);

final:
  if(endpoint) free(endpoint);
  return rc;
}

#ifdef HAVE_UTIMENSAT
static int
crypt4gh_utimens(const char *path, const struct timespec ts[2])
{
  int res;
  
  /* don't use utime/utimes since they follow symlinks */
  res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
  if (res == -1)
    return -errno;
  
  return 0;
}
#endif

static int
crypt4gh_open(const char *path, struct fuse_file_info *fi)
{
  int res;
  
  res = open(path, fi->flags);
  if (res == -1)
    return -errno;
  
  fi->fh = res;
  return 0;
}

static int
crypt4gh_read(const char *path, char *buf, size_t size, off_t offset,
	      struct fuse_file_info *fi)
{
  int fd;
  int res;
  
  if(fi == NULL)
    fd = open(path, O_RDONLY);
  else
    fd = fi->fh;
  
  if (fd == -1)
    return -errno;
  
  res = pread(fd, buf, size, offset);
  if (res == -1)
    res = -errno;
  
  if(fi == NULL)
    close(fd);
  return res;
}

static int
crypt4gh_statfs(const char *path, struct statvfs *stbuf)
{
  int res;
  
  res = statvfs(path, stbuf);
  if (res == -1)
    return -errno;
  
  return 0;
}

static int
crypt4gh_release(const char *path, struct fuse_file_info *fi)
{
  (void) path;
  close(fi->fh);
  return 0;
}

#ifdef HAVE_COPY_FILE_RANGE
static ssize_t
crypt4gh_copy_file_range(const char *path_in,
			 struct fuse_file_info *fi_in,
			 off_t offset_in, const char *path_out,
			 struct fuse_file_info *fi_out,
			 off_t offset_out, size_t len, int flags)
{
  int fd_in, fd_out;
  ssize_t res;
  
  if(fi_in == NULL)
    fd_in = open(path_in, O_RDONLY);
  else
    fd_in = fi_in->fh;
  
  if (fd_in == -1)
    return -errno;
  
  if(fi_out == NULL)
    fd_out = open(path_out, O_WRONLY);
  else
    fd_out = fi_out->fh;

  if (fd_out == -1) {
    close(fd_in);
    return -errno;
  }

  res = copy_file_range(fd_in, &offset_in, fd_out, &offset_out, len, flags);
  if (res == -1)
    res = -errno;

  close(fd_in);
  close(fd_out);

  return res;
}
#endif

static off_t
crypt4gh_lseek(const char *path, off_t off, int whence, struct fuse_file_info *fi)
{
  int fd;
  off_t res;

  if (fi == NULL)
    fd = open(path, O_RDONLY);
  else
    fd = fi->fh;

  if (fd == -1)
    return -errno;

  res = lseek(fd, off, whence);
  if (res == -1)
    res = -errno;

  if (fi == NULL)
    close(fd);
  return res;
}

static const struct fuse_operations crypt4gh_oper = {
	.getattr	= crypt4gh_getattr,
	.access		= crypt4gh_access,
	.readlink	= crypt4gh_readlink,
	.readdir	= crypt4gh_readdir,
#ifdef HAVE_UTIMENSAT
	.utimens	= crypt4gh_utimens,
#endif
	.open		= crypt4gh_open,
	.read		= crypt4gh_read,
	.statfs		= crypt4gh_statfs,
	.release	= crypt4gh_release,
#ifdef HAVE_COPY_FILE_RANGE
	.copy_file_range = crypt4gh_copy_file_range,
#endif
};

int
main(int argc, char *argv[])
{
  umask(0400);

  /* New ephemeral key on every mount */
  uint8_t* key = (uint8_t*)sodium_malloc(crypto_kx_PUBLICKEYBYTES * sizeof(uint8_t));
  pubkey = key;
  seckey = key + crypto_kx_PUBLICKEYBYTES;
  crypto_kx_keypair(pubkey, seckey);

  /* Get the username */
  struct passwd* user = getpwuid(getuid());
  if (user == NULL){
    E("Unable to determine the current username");
    return 2;
  }
  username = user->pw_name;
  username_len = strlen(username);

  /* Make the key read-only and run the fuse loop */
  int rc = (sodium_mprotect_readonly(key) ||
	    crypt4gh_permissions_init() ||
	    fuse_main(argc, argv, &crypt4gh_oper, NULL));

  /* Cleanup */
  crypt4gh_permissions_close();
  sodium_free(key);

  return rc;
}

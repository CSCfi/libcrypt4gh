#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <curl/curl.h>

#include "debug.h"
#include "defs.h"
#include "json.h"
#include "permissions.h"

#define CFGFILE "/etc/ega/permissions.conf"
#define CACHE_TTL 3600 // 1h in seconds.

#define VERIFY_PEER     1 /* false */
#define VERIFY_HOSTNAME 1

struct curl_res_s {
  char *body;
  size_t size;
};

/*
  We use a global variable to avoid:
  - the response reallocations
  - strdup the response
*/
static struct curl_res_s cres = { NULL, 0 };
static CURL* curl = NULL;

char* endpoint_datasets = NULL;   /* http://host:port/users/%s/datasets/%s */
size_t endpoint_datasets_len = 0; /* its length */
char* endpoint_files = NULL;      /* http://host:port/users/%s/files/%s */
size_t endpoint_files_len = 0;    /* its length */

/* ##################################### 
           Configuration
   ##################################### */

struct options_s {
  char* cfgfile;
  char* buffer;
  
  unsigned int cache_ttl;  /* How long a cache entry is valid (in seconds) */
  char* db_path;           /* db file path */

  /* Contacting Central EGA (vie REST call) */
  char* json_prefix;   /* Searching for the data rooted at this prefix */
  char* creds;         /* for authentication: user:password */

  char* cacertfile;    /* path to the Root certificate to contact Central EGA */
  char* certfile;      /* For client verification */
  char* keyfile;
  int verify_peer;
  int verify_hostname;
};

typedef struct options_s options_t;

static options_t* options = NULL;

static void
cleanconfig(void)
{
  if(!options) return;
  D3("Cleaning configuration [%p]", options);

  if(options->buffer){ free((char*)options->buffer); }
  free(options);
  return;
}


static int
valid_options(void)
{
  int valid = 0;
  if(!options) { D3("No config struct"); return 1; }

  D2("Checking the config struct");
  if(options->cache_ttl < 0.0 ) { D3("Invalid cache_ttl");             valid = 1; }
  if(!options->db_path        ) { D3("Invalid db_path");               valid = 1; }

  if(!options->creds          ) { D3("Invalid creds");                 valid = 1; }
  if(!endpoint_datasets       ) { D3("Invalid endpoint for datasets"); valid = 1; }
  if(!endpoint_files          ) { D3("Invalid endpoint for files");    valid = 1; }

  if(options->verify_peer &&
     !options->cacertfile){ D3("Missing cacertfile, when using verify_peer"); valid = 1; }

  if(!!options->certfile ^ !!options->keyfile){
    D3("Either certfile or keyfile is missing");
    valid = 1;
  }

  if(!valid){ D3("Invalid config struct from %s", options->cfgfile); }
  return valid;
}

static inline void
set_yes_no_option(char* key, char* val, char* name, int* loc)
{
  if(!strcmp(key, name)) {
    if(!strcasecmp(val, "yes") || !strcasecmp(val, "true") || !strcmp(val, "1") || !strcasecmp(val, "on")){
      *loc = 0;
    } else if(!strcasecmp(val, "no") || !strcasecmp(val, "false") || !strcmp(val, "0") || !strcasecmp(val, "off")){
      *loc = 1;
    } else {
      D2("Could not parse the %s option: Using %s instead.", name, ((*loc)?"yes":"no"));
    }
  }
}

/*
 * Moves a string value to a buffer (including a \0 at the end).
 * Adjusts the pointer to pointer right after the \0.
 *
 * Returns -size in case the buffer is <size> too small.
 * Otherwise, returns the <size> of the string.
 */
static inline int
copy2buffer(const char* data, char** dest, char **bufptr, size_t *buflen)
{
  size_t slen = strlen(data) + 1;

  if(*buflen < slen) {
    D3("buffer too small [currently: %zd bytes left] to copy \"%s\" [%zd bytes]", *buflen, data, slen);
    return -slen;
  }

  strncpy(*bufptr, data, slen-1);
  (*bufptr)[slen-1] = '\0';
  
  if(dest) *dest = *bufptr; /* record location */
  *bufptr += slen;
  *buflen -= slen;
  
  return slen;
}

#define INJECT_OPTION(key,ckey,val,loc) do { if(!strcmp(key, ckey) && copy2buffer(val, loc, &buffer, &buflen) < 0 ){ return -1; } } while(0)
#define COPYVAL(val,dest,b,blen) do { if( copy2buffer(val, dest, b, blen) < 0 ){ return -1; } } while(0)

static inline int
readconfig(FILE* fp, char* buffer, size_t buflen)
{
  D3("Reading configuration file");
  char* line = NULL;
  size_t len = 0;
  char *key,*eq,*val,*end;

  /* Default config values */
  options->cache_ttl = CACHE_TTL;
  
  /* TLS settings */
  options->verify_peer = VERIFY_PEER;
  options->verify_hostname = VERIFY_HOSTNAME;
  options->cacertfile = NULL;
  options->certfile = NULL;
  options->keyfile = NULL;

  COPYVAL(CFGFILE   , &(options->cfgfile), &buffer, &buflen );
  options->json_prefix = NULL; /* default */

  /* Parse line by line */
  while (getline(&line, &len, fp) > 0) {
	
    key=line;
    /* remove leading whitespace */
    while(isspace(*key)) key++;
      
    if((eq = strchr(line, '='))) {
      end = eq - 1; /* left of = */
      val = eq + 1; /* right of = */
	  
      /* find the end of the left operand */
      while(end > key && isspace(*end)) end--;
      *(end+1) = '\0';
	  
      /* find where the right operand starts */
      while(*val && isspace(*val)) val++;
	  
      /* find the end of the right operand */
      eq = val;
      while(*eq != '\0') eq++;
      eq--;
      if(*eq == '\n') { *eq = '\0'; } /* remove new line */
	  
    } else val = NULL; /* could not find the '=' sign */
	
    if(!strcmp(key, "cache_ttl"     )) { if( !sscanf(val, "%u" , &(options->cache_ttl) )) options->cache_ttl = -1; }
   
    INJECT_OPTION(key, "db_path"      , val, &(options->db_path)     );
    INJECT_OPTION(key, "datasets"     , val, &(endpoint_datasets)    );
    INJECT_OPTION(key, "files"        , val, &(endpoint_files)       );
    INJECT_OPTION(key, "creds"        , val, &(options->creds)       );
    INJECT_OPTION(key, "json_prefix"  , val, &(options->json_prefix) );
    INJECT_OPTION(key, "cacertfile"   , val, &(options->cacertfile)  );
    INJECT_OPTION(key, "certfile"     , val, &(options->certfile)    );
    INJECT_OPTION(key, "keyfile"      , val, &(options->keyfile)     );

    set_yes_no_option(key, val, "verify_peer", &(options->verify_peer));
    set_yes_no_option(key, val, "verify_hostname", &(options->verify_hostname));
  }

  D1("verify_peer: %s", ((options->verify_peer)?"yes":"no"));
  D1("verify_hostname: %s", ((options->verify_hostname)?"yes":"no"));

  if(endpoint_datasets)
    endpoint_datasets_len = strlen(endpoint_datasets) - 4 + 1; /* -2 %s + 1 null-termination */
  if(endpoint_files)
    endpoint_files_len = strlen(endpoint_files - 4 + 1); /* -2 %s + 1 null-termination */

  if(line) free(line);
  return 0;
}

static int
loadconfig(void)
{
  D2("Loading configuration %s", CFGFILE);
  if(options){ D3("Already loaded [@ %p]", options); return 0; }

  FILE* fp = NULL;
  size_t size = 1024;
  int rc = 1;
  
  /* read or re-read */
  fp = fopen(CFGFILE, "r");
  if (fp == NULL || errno == EACCES) { D2("Error accessing the config file: %s", strerror(errno)); return 1; }

  options = (options_t*)malloc(sizeof(options_t));
  if (options == NULL || errno == ENOMEM) {
    D3("Could not allocate options data structure"); 
    rc = 1;
    goto bailout;
  }
  options->buffer = NULL;

REALLOC:
  D3("Allocating buffer of size %zd", size);
  if(options->buffer)free(options->buffer);
  options->buffer = malloc(sizeof(char) * size);
  memset(options->buffer, '\0', size);
  /* *(options->buffer) = '\0'; */
  if(!options->buffer){ D3("Could not allocate buffer of size %zd", size); rc = 1; goto bailout; };

  if( readconfig(fp, options->buffer, size) < 0 ){

    /* Rewind first */
    if(fseek(fp, 0, SEEK_SET)){ D3("Could not rewind config file to start"); rc = 1; goto bailout; }

    /* Doubling the buffer size */
    size = size << 1;
    goto REALLOC;
  }

  D2("Conf loaded [@ %p]", options);

#if DEBUG
  D1("-------------");
  int i=0;
  char* c = options->buffer;
  for(;i<size;i++,c++){ fprintf(stderr, "%c", *c); }
  fprintf(stderr, "\n");
  D1("-------------");
#endif

#ifdef DEBUG
  rc = valid_options();
#else
  rc = 0; /* fallthrough */
#endif
  
bailout:
  if(fp) fclose(fp);
  return rc;
}

/* ##################################### 
           CURL
   ##################################### */

/* callback for curl fetch */
static size_t
curl_callback (void* contents, size_t size, size_t nmemb, void* userdata) {
  const size_t realsize = size * nmemb;                   /* calculate buffer size */
  struct curl_res_s *r = (struct curl_res_s*) userdata;   /* cast pointer to fetch struct */

  /* expand buffer */
  r->body = (char *) realloc(r->body, r->size + realsize + 1);

  /* check buffer */
  if (r->body == NULL) { D1("ERROR: Failed to expand buffer for cURL"); return -1; }

  /* copy contents to buffer */
  memcpy(&(r->body[r->size]), contents, realsize);
  r->size += realsize;
  r->body[r->size] = '\0';

  return realsize;
}

static int
crypt4gh_permissions_curl_init(void)
{
  int rc = 1; /* error */

  D1("Contacting %s", endpoint);

  /* Preparing cURL */
  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl = curl_easy_init();

  if(!curl) { D1("libcurl init failed"); return 1; }

  /* Preparing the request */
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION , curl_callback  );
  curl_easy_setopt(curl, CURLOPT_WRITEDATA     , (void*)&cres   );
  curl_easy_setopt(curl, CURLOPT_FAILONERROR   , 1L             ); /* when not 200 */
  curl_easy_setopt(curl, CURLOPT_HTTPAUTH      , CURLAUTH_BASIC );
  curl_easy_setopt(curl, CURLOPT_USERPWD       , options->creds );
  /* curl_easy_setopt(curl, CURLOPT_NOPROGRESS    , 0L               ); */ /* enable progress meter */

  if ( options->verify_peer && options->cacertfile ){
    D2("Verifying peer settings [CA: %s]", options->cacertfile);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_CAINFO        , options->cacertfile);
  } else {
    D2("Do not verify peer");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  }

  if ( options->verify_hostname ){
    D2("Check hostname settings");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
  } else {
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
  }

  if ( options->certfile ){
    D2("Adding certfile: %s", options->certfile);
    curl_easy_setopt(curl, CURLOPT_SSLCERT       , options->certfile);
    curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE   , "PEM"            );

  }

  if ( options->keyfile ){
    D2("Adding keyfile: %s", options->keyfile);
    curl_easy_setopt(curl, CURLOPT_SSLKEY       , options->keyfile);
    curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE   , "PEM"           );
  }

  return 0;

}

static void
crypt4gh_permissions_curl_close(void)
{
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  curl = NULL;
  if(cres.body) free(cres.body);
  cleanconfig();
}

/* ##################################### 
           Main functions
   ##################################### */

int
crypt4gh_permissions_init(void){
  return loadconfig() || crypt4gh_permissions_curl_init();
}

void
crypt4gh_permissions_close(void)
{
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  curl = NULL;
  if(cres.body) free(cres.body);
  cleanconfig();
}

int
crypt4gh_premissions_str_array(char* endpoint, iterator_t* iterator)
{
  if(!options) return 1;
  curl_easy_setopt(curl, CURLOPT_URL, endpoint);
  cres.size = 0; /* Keep the body buffer, but reset the size */
  CURLcode res = curl_easy_perform(curl);
  if(res != CURLE_OK){ D2("curl_easy_perform() failed: %s", curl_easy_strerror(res)); return 1; }
  D1("JSON string [size %zu]: %s", cres.size, cres.body);
  return json_str_array(cres.body, cres.size, iterator);
}

int
crypt4gh_curl_perform_ega_file(char* endpoint, char** header, size_t* header_len, char** payload)
{
  if(!options) return 1;
  curl_easy_setopt(curl, CURLOPT_URL, endpoint);
  cres.size = 0; /* Keep the body buffer, but reset the size */
  CURLcode res = curl_easy_perform(curl);
  if(res != CURLE_OK){ D2("curl_easy_perform() failed: %s", curl_easy_strerror(res)); return 1; }
  D1("JSON string [size %zu]: %s", cres.size, cres.body);
  return json_ega_file(cres.body, cres.size, header, header_len, payload);
}


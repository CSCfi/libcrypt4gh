#include <string.h>

#include "debug.h"
#include "defs.h"
#include "permissions.h"
#include "json.h"
#include "jsmn/jsmn.h"

#define CEGA_JSON_PREFIX_DELIM "."

/* Will search for options->cega_json_prefix first, and then those exact ones */
#define CEGA_JSON_HEADER  "header"

#ifdef DEBUG
#define TYPE2STR(t) (((t) == JSMN_OBJECT)   ? "Object":    \
                     ((t) == JSMN_ARRAY)    ? "Array":     \
                     ((t) == JSMN_STRING)   ? "String":    \
                     ((t) == JSMN_PRIMITIVE)? "Primitive": \
                                              "Undefined")
#endif

static int
get_size(jsmntok_t *t){
  int i, j;
  if (t->type == JSMN_PRIMITIVE || t->type == JSMN_STRING) {
    if(t->size > 0) return get_size(t+1)+1;
    return 1;
  } else if (t->type == JSMN_OBJECT || t->type == JSMN_ARRAY) {
    j = 0;
    for (i = 0; i < t->size; i++) { j += get_size(t+1+j); }
    return j+1;
  } else {
    D1("get_size: weird type %s", TYPE2STR(t->type));
    return 1000000;
  }
}

int
json_str_array(const char* json, size_t jsonlen, iterator_t* iterator)
{
  jsmn_parser jsonparser; /* on the stack */
  jsmntok_t *tokens = NULL; /* array of tokens */
  size_t size_guess = 11; /* 5*2 (key:value) + 1(object) */
  int r, rc=1;

REALLOC:
  /* Initialize parser (for every guess) */
  jsmn_init(&jsonparser);
  D2("Guessing with %zu tokens", size_guess);
  if(tokens)free(tokens);
  tokens = malloc(sizeof(jsmntok_t) * size_guess);
  if (tokens == NULL) { D1("memory allocation error"); goto bailout; }
  r = jsmn_parse(&jsonparser, json, jsonlen, tokens, size_guess);
  if (r < 0) { /* error */
    D2("JSON parsing error: %s", (r == JSMN_ERROR_INVAL)? "JSON string is corrupted" :
                                 (r == JSMN_ERROR_PART) ? "Incomplete JSON string":
                                 (r == JSMN_ERROR_NOMEM)? "Not enough space in token array":
                                                          "Unknown error");
    if (r == JSMN_ERROR_NOMEM) {
      size_guess = size_guess * 2; /* double it */
      goto REALLOC;
    }
    goto bailout;
  }

  /* Valid response */
  D3("%d tokens found", r);
  if( tokens->type != JSMN_ARRAY ){ D1("JSON array expected"); rc = 1; goto bailout; }

  /* walk through other tokens */
  jsmntok_t *t = tokens; /* use a sentinel and move inside the object */
  int max = t->size;
  int i;
  t++; /* move inside the root */
  rc = 0; /* assume success */
  for (i = 0; i < max; i++, t+=t->size+1) {

    if(t->type != JSMN_STRING){
      D2("Not a string token");
      rc++;
      continue;
    }
    
    t+=t->size; /* get to the value */

    char item_name[t->end - t->start + 1];
    memcpy(&item_name, json + t->start, t->end - t->start);
    item_name[t->end - t->start] = '\0';
    rc += iterator->filler(iterator->buf, (char*)item_name, iterator->st, iterator->offset);
  }

#ifdef DEBUG
  if(rc) D1("%d errors while parsing the root object", rc);
#endif

bailout:
  if(tokens){ D3("Freeing tokens at %p", tokens); free(tokens); }
  return rc;
}

int
json_ega_file(const char* json, size_t jsonlen,
	      char** header, size_t* header_len, char** payload_path)
{
  jsmn_parser jsonparser; /* on the stack */
  jsmntok_t *tokens = NULL; /* array of tokens */
  size_t size_guess = 11; /* 5*2 (key:value) + 1(object) */
  int r, rc=1;

REALLOC:
  /* Initialize parser (for every guess) */
  jsmn_init(&jsonparser);
  D2("Guessing with %zu tokens", size_guess);
  if(tokens)free(tokens);
  tokens = malloc(sizeof(jsmntok_t) * size_guess);
  if (tokens == NULL) { D1("memory allocation error"); goto bailout; }
  r = jsmn_parse(&jsonparser, json, jsonlen, tokens, size_guess);
  if (r < 0) { /* error */
    D2("JSON parsing error: %s", (r == JSMN_ERROR_INVAL)? "JSON string is corrupted" :
                                 (r == JSMN_ERROR_PART) ? "Incomplete JSON string":
                                 (r == JSMN_ERROR_NOMEM)? "Not enough space in token array":
                                                          "Unknown error");
    if (r == JSMN_ERROR_NOMEM) {
      size_guess = size_guess * 2; /* double it */
      goto REALLOC;
    }
    goto bailout;
  }

  /* Valid response */
  D3("%d tokens found", r);
  if( tokens->type != JSMN_ARRAY ){ D1("JSON array expected"); rc = 1; goto bailout; }

  /* walk through other tokens */
  jsmntok_t *t = tokens; /* use a sentinel and move inside the object */
  int max = t->size;
  int i;
  t++; /* move inside the root */
  rc = 0; /* assume success */
  for (i = 0; i < max; i++, t+=t->size+1) {

    if(t->type != JSMN_STRING){
      D2("Not a string token");
      rc++;
      continue;
    }
    
    t+=t->size; /* get to the value */
    /* rc += handle(json + t->start, t->end - t->start); */
  }

#ifdef DEBUG
  if(rc) D1("%d errors while parsing the root object", rc);
#endif

bailout:
  if(tokens){ D3("Freeing tokens at %p", tokens); free(tokens); }
  return rc;
}

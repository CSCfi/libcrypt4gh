#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sodium.h>

#include "debug.h"
#include "defs.h"
#include "cli.h"

#define PROG "crypt4gh"
#define PROG_VERSION "1.0"

static void usage(void);
static void version(void);
static options_t* docopt_new(void);


/*
 * Tokens object
 */

typedef struct {
  int argc;
  char **argv;
  int i;
  char *current;
} tokens;

static void
token_next(tokens *ts) {
  if (ts->i < ts->argc) {
    ts->current = ts->argv[++ts->i];
  }
  if (ts->i == ts->argc) {
    ts->current = NULL;
  }
}

/*
 * Argument storage
 */

enum cmd {
  DECRYPT,
  ENCRYPT,
  REARRANGE,
  REENCRYPT,
  LAST_CMD
};

enum opt {
  HELP,
  VERSION,
  TRIM,
  RANGE,
  RECIPIENT,
  SENDER,
  SECKEY,
  LAST_OPT
};

typedef struct {
  const char *name;
  enum cmd code;
  int found;
} Command;


typedef struct {
  enum opt code;
  const char *olong;  /* long flag */
  const char *oshort; /* short flag */
  int exit;           /* causes exit if > 0 */
  int narg;           /* 0, 1, or more */
  int once;           /* non repeatable */
  int count;          /* occurence found */
  char* value;        /* if once && narg = 1 */
} Option;


static Command commands[] = { {"decrypt"  , DECRYPT  , 0},
			      {"dec"      , DECRYPT  , 0},
			      {"encrypt"  , ENCRYPT  , 0},
			      {"enc"      , ENCRYPT  , 0},
			      {"rearrange", REARRANGE, 0},
			      {"reencrypt", REENCRYPT, 0},
			      {"reenc"    , REENCRYPT, 0},
			      {NULL       , LAST_CMD , 0}};

static Option options[] = {/* code   , long            ,short, exit, narg, once, count, value */
			   {HELP     , "--help"        , "-h",    1,    0,    1,     0, NULL},
			   {VERSION  , "--version"     , "-v",    2,    0,    1,     0, NULL},
			   {TRIM     , "--trim"        , "-t",    0,    0,    1,     0, NULL},
			   {RANGE    , "--range"       , NULL,    0,    1,    1,     0, NULL},
			   {RECIPIENT, "--recipient_pk", "-r",    0,    1,    0,     0, NULL}, /* can repeat */
			   {SENDER   , "--sender_pk"   , "-p",    0,    1,    1,     0, NULL},
			   {SECKEY   , "--sk"          , "-k",    0,    1,    1,     0, NULL},
			   /* final one, no --long-option */
			   {LAST_OPT , NULL            , NULL, 0, 0, 0, 0, NULL} };

static int
parse_option(tokens *ts)
{
  Option* option = &options[0];
  for (; option->code != LAST_OPT; option++) {
    if (
	!strcmp(ts->current, option->olong)
	||
	(option->oshort != NULL && !strcmp(ts->current, option->oshort))
	)
      {
	if(option->exit)
	  return option->exit;

	option->count++;
	if(option->once && option->count > 1){
	  E("%s can be used only once (found %d occurences already)", option->olong, option->count);
	  return -1;
	}
	break;
      }
  }
  if(option->code == LAST_OPT){
    E("unknown option: %s", ts->current);
    return -1; /* error */
  }
  if (option->narg) {
    token_next(ts);
    if (ts->current == NULL) {
      E("%s requires an argument", option->olong);
      return -1; /* error */
    }
    if(option->once){ /* only one arg, save the value */
      option->value = ts->current;
    }
  }
  return 0;
}

static int
parse_command(tokens *ts)
{
  Command* command = &commands[0];
  for (; command->code != LAST_CMD; command++) {
    if (!strcmp(command->name, ts->current)){
      command->found = 1;
      return 0;
    }
  }
  if(command->name == NULL){
    E("unknown command: %s", ts->current);
    return -1; /* error */
  }
  return 0;
}

static int
parse_args(tokens *ts, Command* commands, Option* options)
{
  int ret = 0;
  while (ts->current != NULL && !ret) {
    if (ts->current[0] == '-') { /* option */
      if(ts->current[1] == '\0'){
	E("Invalid option %s", ts->current);
	return -1;
      }
      ret = parse_option(ts);
    } else { /* command */
      ret = parse_command(ts);
    }
    token_next(ts);
  }
  return ret;
}

static int
collected_repeated_arguments(tokens *ts, Option* option, char** buf)
{
  int ret = 0, i = 0, j;
  while (ts->current != NULL) {
    if (!strcmp(ts->current, option->olong) ||
	!strcmp(ts->current, option->oshort))
      { /* found the option, get the value */
	if (option->narg) {
	  token_next(ts);
	  for(j=0; j<i; j++){ /* check for duplicates */
	    if(!strcmp(buf[j], ts->current))
	      break;
	  }
	  if(j < i){ /* duplicate */
	    option->count--;
	  } else {
	    buf[i++] = ts->current;
	  }
	}
      }
    token_next(ts);
  }
  return 0;
}


/*
 * Main docopt function
 */

options_t*
docopt(int argc, char** argv)
{
  
  argc--; argv++; /* skip the prog name */
  tokens ts = {argc, argv, 0, argv[0] };

  switch(parse_args(&ts, commands, options)){
  case -1: /* error */
    usage();
    exit(EXIT_FAILURE);
  case 1: /* help */
    usage();
    exit(EXIT_SUCCESS);
  case 2: /* version */
    version();
    exit(EXIT_SUCCESS);
  default:
    break; /* fallthrough*/
  } 

  options_t* args = docopt_new();

  /* commands */
  Command* command = &commands[0];
  int found = 0;
  for (; command->code != LAST_CMD; command++) {
    switch(command->code){
    case DECRYPT:
      args->decrypt += command->found;
      if(command->found) found++;
      break;
    case ENCRYPT:
      args->encrypt += command->found;
      if(command->found) found++;
      break;
    case REARRANGE:
      args->rearrange += command->found;
      if(command->found) found++;
      break;
    case REENCRYPT:
      args->reencrypt += command->found;
      if(command->found) found++;
      break;
    default:
      E("Invalid configuration of %s", command->name);
      docopt_free(args);
      exit(EXIT_FAILURE);
      break;
    }
  }

  /* We didn't exit yet for help, or version, so we should found one and only one command */
  if(found != 1){
    D1("%d command found", found);
    usage();
    docopt_free(args);
    exit(EXIT_FAILURE);
  }

  /* For the option with argument */
  Option* option = &options[0];
  for (; option->code != LAST_OPT; option++) {
    
    switch(option->code){
    case TRIM:
      args->trim = option->count;
      break;
    case RANGE:
      args->range = option->value;
      break;
    case SENDER:
      args->sender_pk = option->value;
      break;
    case SECKEY:
      args->sk = option->value;
      break;
    case RECIPIENT: /* can repeat */

      /* start again */
      ts.argc = argc;
      ts.argv = argv;
      ts.i = 0;
      ts.current = argv[0];

      /* loop again, and collect */
      char** buf = (char**)malloc(option->count * sizeof(char*));
      if(!collected_repeated_arguments(&ts, option, buf)){
      	args->nrecipients = option->count; /* adjusted for duplicates */
      	args->recipient_pubkeys = buf;
      }
      break;
    default: /* not needed */
      break;
    }

  }

  /* Final rule: encrypt must have a recipient */
  if(args->encrypt == 1 && args->nrecipients == 0){
    E("The encrypt command must be provided a recipient public key");
    usage();
    docopt_free(args);
    exit(EXIT_FAILURE);
  }


#ifdef DEBUG
  D1("trim: %d", args->trim);    
  D1("range: %s", args->range);
  D1("recipients: %d", args->nrecipients);
  int i=0;
  for(; i< args->nrecipients; i++){
    D1("* recipient_pk: %s", args->recipient_pubkeys[i]);
  }
  D1("sender_pk: %s", args->sender_pk);
  D1("sk: %s", args->sk);
#endif
  return args;
}


static options_t*
docopt_new(void){

  options_t* args = (options_t*)malloc(sizeof(options_t));

  if(args == NULL || errno == ENOMEM){
    E("Unable to allocate memory");
    return NULL;
  }

  args->decrypt = 0;
  args->encrypt = 0;
  args->rearrange = 0;
  args->reencrypt = 0;
  args->trim = 0;
  args->range = NULL;
  args->sender_pk = NULL;
  args->sk = NULL;
  args->nrecipients = 0;
  args->recipient_pubkeys = NULL;

  return args;
}

void
docopt_free(options_t* args){
  if(args){
    if(args->recipient_pubkeys) free(args->recipient_pubkeys);
    free(args);
  }
}


#define P(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)

static void
usage(void){
  P("Utility for the cryptographic GA4GH standard, reading from stdin and outputting to stdout.");
  P("Usage:");
  P("   %s [-hv] encrypt [--sk <path>] --recipient_pk <path> [--recipient_pk <path>]... [--range <start-end>]", PROG);
  P("   %s [-hv] decrypt [--sk <path>] [--sender_pk <path>] [--range <start-end>]", PROG);
  P("   %s [-hv] rearrange [--sk <path>] --range <start-end>", PROG);
  P("   %s [-hv] reencrypt [--sk <path>] --recipient_pk <path> [--recipient_pk <path>]... [--trim]", PROG);
  P("");
  P("Options:");
  P("   -h, --help             Prints this help and exit");
  P("   -v, --version          Prints the version and exits");
  P("   -k <path>,");
  P("   --sk <keyfile>         Curve25519-based Private key");
  P("                          When encrypting, if neither the private key nor C4GH_SECRET_KEY are specified, we generate a new key");
  P("   -r <path>,");
  P("   --recipient_pk <path>  Recipient's Curve25519-based Public key");
  P("   -p <path>,");
  P("   --sender_pk <path>     Peer's Curve25519-based Public key to verify provenance (akin to signature)");
  P("   --range <start-end>    Byte-range either as  <start-end> or just <start> (Start included, End excluded)");
  P("   -t, --trim             Keep only header packets that you can decrypt");
  P("");
  P("Environment variables:");
  P("   C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${C4GH_SECRET_KEY})");
  P("   C4GH_PASSPHRASE  If defined, it will be used as the passphrase");
  P("                    for decoding the secret key, replacing the callback.");
  P("                    Note: this is insecure. Only used for testing");
}

static void
version(void){
  P("GA4GH cryptographic utility (version %s)", PROG_VERSION);
  P("Based on libsodium %s (https://libsodium.org)", sodium_version_string());
}
#undef P

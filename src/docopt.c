#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "docopt.h"


const char help_message[] =
"Utility for the cryptographic GA4GH standard, reading from stdin and outputting to stdout.\n"
"\n"
"Usage:\n"
"   crypt4gh [-hv] [--log <file>] encrypt [--sk <path>] --recipient_pk <path> [--recipient_pk <path>]... [--range <start-end>]\n"
"   crypt4gh [-hv] [--log <file>] decrypt [--sk <path>] [--sender_pk <path>] [--range <start-end>]\n"
"   crypt4gh [-hv] [--log <file>] rearrange [--sk <path>] --range <start-end>\n"
"   crypt4gh [-hv] [--log <file>] reencrypt [--sk <path>] --recipient_pk <path> [--recipient_pk <path>]... [--trim]\n"
"\n"
"Options:\n"
"   -h, --help             Prints this help and exit\n"
"   -v, --version          Prints the version and exits\n"
"   --log <file>           Path to the logger file (in YML format)\n"
"   --sk <keyfile>         Curve25519-based Private key\n"
"                          When encrypting, if neither the private key nor C4GH_SECRET_KEY are specified, we generate a new key \n"
"   --recipient_pk <path>  Recipient's Curve25519-based Public key\n"
"   --sender_pk <path>     Peer's Curve25519-based Public key to verify provenance (akin to signature)\n"
"   --range <start-end>    Byte-range either as  <start-end> or just <start> (Start included, End excluded)\n"
"   -t, --trim             Keep only header packets that you can decrypt\n"
"\n"
"\n"
"Environment variables:\n"
"   C4GH_LOG         If defined, it will be used as the default logger\n"
"   C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${C4GH_SECRET_KEY})\n"
"   C4GH_PASSPHRASE  If defined, it will be used as the passphrase\n"
"                    for decoding the secret key, replacing the callback.\n"
"                    Note: this is insecure. Only used for testing\n"
"   C4GH_DEBUG       If True, it will print (a lot of) debug information.\n"
"                    (Watch out: the output contains secrets)\n"
"";

const char usage_pattern[] =
"Usage:\n"
"   crypt4gh [-hv] [--log <file>] encrypt [--sk <path>] --recipient_pk <path> [--recipient_pk <path>]... [--range <start-end>]\n"
"   crypt4gh [-hv] [--log <file>] decrypt [--sk <path>] [--sender_pk <path>] [--range <start-end>]\n"
"   crypt4gh [-hv] [--log <file>] rearrange [--sk <path>] --range <start-end>\n"
"   crypt4gh [-hv] [--log <file>] reencrypt [--sk <path>] --recipient_pk <path> [--recipient_pk <path>]... [--trim]";

typedef struct {
    const char *name;
    bool value;
} Command;

typedef struct {
    const char *name;
    char *value;
    char **array;
} Argument;

typedef struct {
    const char *oshort;
    const char *olong;
    bool argcount;
    bool value;
    char *argument;
} Option;

typedef struct {
    int n_commands;
    int n_arguments;
    int n_options;
    Command *commands;
    Argument *arguments;
    Option *options;
} Elements;


/*
 * Tokens object
 */

typedef struct Tokens {
    int argc;
    char **argv;
    int i;
    char *current;
} Tokens;

Tokens tokens_new(int argc, char **argv) {
    Tokens ts = {argc, argv, 0, argv[0]};
    return ts;
}

Tokens* tokens_move(Tokens *ts) {
    if (ts->i < ts->argc) {
        ts->current = ts->argv[++ts->i];
    }
    if (ts->i == ts->argc) {
        ts->current = NULL;
    }
    return ts;
}


/*
 * ARGV parsing functions
 */

int parse_doubledash(Tokens *ts, Elements *elements) {
    //int n_commands = elements->n_commands;
    //int n_arguments = elements->n_arguments;
    //Command *commands = elements->commands;
    //Argument *arguments = elements->arguments;

    // not implemented yet
    // return parsed + [Argument(None, v) for v in tokens]
    return 0;
}

int parse_long(Tokens *ts, Elements *elements) {
    int i;
    int len_prefix;
    int n_options = elements->n_options;
    char *eq = strchr(ts->current, '=');
    Option *option;
    Option *options = elements->options;

    len_prefix = (eq-(ts->current))/sizeof(char);
    for (i=0; i < n_options; i++) {
        option = &options[i];
        if (!strncmp(ts->current, option->olong, len_prefix))
            break;
    }
    if (i == n_options) {
        // TODO '%s is not a unique prefix
        fprintf(stderr, "%s is not recognized\n", ts->current);
        return 1;
    }
    tokens_move(ts);
    if (option->argcount) {
        if (eq == NULL) {
            if (ts->current == NULL) {
                fprintf(stderr, "%s requires argument\n", option->olong);
                return 1;
            }
            option->argument = ts->current;
            tokens_move(ts);
        } else {
            option->argument = eq + 1;
        }
    } else {
        if (eq != NULL) {
            fprintf(stderr, "%s must not have an argument\n", option->olong);
            return 1;
        }
        option->value = true;
    }
    return 0;
}

int parse_shorts(Tokens *ts, Elements *elements) {
    char *raw;
    int i;
    int n_options = elements->n_options;
    Option *option;
    Option *options = elements->options;

    raw = &ts->current[1];
    tokens_move(ts);
    while (raw[0] != '\0') {
        for (i=0; i < n_options; i++) {
            option = &options[i];
            if (option->oshort != NULL && option->oshort[1] == raw[0])
                break;
        }
        if (i == n_options) {
            // TODO -%s is specified ambiguously %d times
            fprintf(stderr, "-%c is not recognized\n", raw[0]);
            return 1;
        }
        raw++;
        if (!option->argcount) {
            option->value = true;
        } else {
            if (raw[0] == '\0') {
                if (ts->current == NULL) {
                    fprintf(stderr, "%s requires argument\n", option->oshort);
                    return 1;
                }
                raw = ts->current;
                tokens_move(ts);
            }
            option->argument = raw;
            break;
        }
    }
    return 0;
}

int parse_argcmd(Tokens *ts, Elements *elements) {
    int i;
    int n_commands = elements->n_commands;
    //int n_arguments = elements->n_arguments;
    Command *command;
    Command *commands = elements->commands;
    //Argument *arguments = elements->arguments;

    for (i=0; i < n_commands; i++) {
        command = &commands[i];
        if (!strcmp(command->name, ts->current)){
            command->value = true;
            tokens_move(ts);
            return 0;
        }
    }
    // not implemented yet, just skip for now
    // parsed.append(Argument(None, tokens.move()))
    /*fprintf(stderr, "! argument '%s' has been ignored\n", ts->current);
    fprintf(stderr, "  '");
    for (i=0; i<ts->argc ; i++)
        fprintf(stderr, "%s ", ts->argv[i]);
    fprintf(stderr, "'\n");*/
    tokens_move(ts);
    return 0;
}

int parse_args(Tokens *ts, Elements *elements) {
    int ret;

    while (ts->current != NULL) {
        if (strcmp(ts->current, "--") == 0) {
            ret = parse_doubledash(ts, elements);
            if (!ret) break;
        } else if (ts->current[0] == '-' && ts->current[1] == '-') {
            ret = parse_long(ts, elements);
        } else if (ts->current[0] == '-' && ts->current[1] != '\0') {
            ret = parse_shorts(ts, elements);
        } else
            ret = parse_argcmd(ts, elements);
        if (ret) return ret;
    }
    return 0;
}

int elems_to_args(Elements *elements, DocoptArgs *args, bool help,
                  const char *version){
    Command *command;
    Argument *argument;
    Option *option;
    int i;

    // fix gcc-related compiler warnings (unused)
    (void)command;
    (void)argument;

    /* options */
    for (i=0; i < elements->n_options; i++) {
        option = &elements->options[i];
        if (help && option->value && !strcmp(option->olong, "--help")) {
            printf("%s", args->help_message);
            return 1;
        } else if (version && option->value &&
                   !strcmp(option->olong, "--version")) {
            printf("%s\n", version);
            return 1;
        } else if (!strcmp(option->olong, "--help")) {
            args->help = option->value;
        } else if (!strcmp(option->olong, "--trim")) {
            args->trim = option->value;
        } else if (!strcmp(option->olong, "--version")) {
            args->version = option->value;
        } else if (!strcmp(option->olong, "--log")) {
            if (option->argument)
                args->log = option->argument;
        } else if (!strcmp(option->olong, "--range")) {
            if (option->argument)
                args->range = option->argument;
        } else if (!strcmp(option->olong, "--recipient_pk")) {
            if (option->argument)
                args->recipient_pk = option->argument;
        } else if (!strcmp(option->olong, "--sender_pk")) {
            if (option->argument)
                args->sender_pk = option->argument;
        } else if (!strcmp(option->olong, "--sk")) {
            if (option->argument)
                args->sk = option->argument;
        }
    }
    /* commands */
    for (i=0; i < elements->n_commands; i++) {
        command = &elements->commands[i];
        if (!strcmp(command->name, "decrypt")) {
            args->decrypt = command->value;
        } else if (!strcmp(command->name, "encrypt")) {
            args->encrypt = command->value;
        } else if (!strcmp(command->name, "rearrange")) {
            args->rearrange = command->value;
        } else if (!strcmp(command->name, "reencrypt")) {
            args->reencrypt = command->value;
        }
    }
    /* arguments */
    for (i=0; i < elements->n_arguments; i++) {
        argument = &elements->arguments[i];
    }
    return 0;
}


/*
 * Main docopt function
 */

DocoptArgs docopt(int argc, char** argv, bool help, const char *version) {
    DocoptArgs args = {
        0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL,
        usage_pattern, help_message
    };
    Tokens ts;
    Command commands[] = {
        {"decrypt", 0},
        {"encrypt", 0},
        {"rearrange", 0},
        {"reencrypt", 0}
    };
    Argument arguments[] = {
    };
    Option options[] = {
        {"-h", "--help", 0, 0, NULL},
        {"-t", "--trim", 0, 0, NULL},
        {"-v", "--version", 0, 0, NULL},
        {NULL, "--log", 1, 0, NULL},
        {NULL, "--range", 1, 0, NULL},
        {NULL, "--recipient_pk", 1, 0, NULL},
        {NULL, "--sender_pk", 1, 0, NULL},
        {NULL, "--sk", 1, 0, NULL}
    };
    Elements elements = {4, 0, 8, commands, arguments, options};

    ts = tokens_new(argc, argv);
    if (parse_args(&ts, &elements))
        exit(EXIT_FAILURE);
    if (elems_to_args(&elements, &args, help, version))
        exit(EXIT_SUCCESS);
    return args;
}


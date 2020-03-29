#
# Makefile for the NSS and PAM modules used at EGA
#
# Blowfish code from http://www.openwall.com/crypt/
#

C4GH_LD_SONAME = -Wl,-soname,libcrypt4gh.so.2
C4GH_LIBRARY = libcrypt4gh.so.2.0
C4GH_EXEC = crypt4gh

CC=gcc
LD=ld
AS=gcc -c
CFLAGS=-O2 -Wall -Wstrict-prototypes -Werror \
	-fPIC \
	-I. 
#	-I. $(shell pkg-config --cflags libsodium)
#LIBS=$(shell pkg-config --libs libsodium)
LIBS=-lsodium

ifdef SYSLOG
CFLAGS += -DHAS_SYSLOG
endif

ifdef DEBUG
CFLAGS += -DDEBUG=$(DEBUG) -g
endif

C4GH_BINDIR = /usr/local/bin

HEADERS = debug.h defs.h payload.h header.h stream.h base64.h key.h

C4GH_SOURCES = payload.c header.c stream.c base64.c key.c
C4GH_OBJECTS = $(C4GH_SOURCES:%.c=%.o)

.PHONY: all clean install
.SUFFIXES: .c .o

all: $(C4GH_EXEC)

$(C4GH_BINDIR):
	@echo "Creating bin dir: $(C4GH_BINDIR)"
	@install -d $(C4GH_BINDIR)

$(C4GH_EXEC): main.c $(HEADERS) $(C4GH_OBJECTS) 
	@echo "Creating $@"
	@$(CC) -o $@ $< $(C4GH_OBJECTS) $(LIBS)

%.o: %.c $(HEADERS)
ifdef DEBUG
	@echo "Compiling $< (debug: $(DEBUG))"
else
	@echo "Compiling $<"
endif
	@$(CC) $(CFLAGS) -c -o $@ $<

install: $(C4GH_EXEC) | $(C4GH_BINDIR)
	@echo "Installing $< into $(C4GH_BINDIR)"
	@install -m 700 $< $(C4GH_BINDIR)

clean:
	-rm -f $(C4GH_EXEC) {parse,test,stream,teststream}{,-debug} $(C4GH_OBJECTS)
	-rm -rf _output _key {_input,_output}.*
	-rm -rf teststream.o test.o


parse: parse.o $(HEADERS) $(C4GH_OBJECTS) 
	@echo "Creating $@"
	$(CC) -o $@ $< $(C4GH_OBJECTS) $(LIBS)


test: test.o $(HEADERS) $(C4GH_OBJECTS)
	@echo "Creating $@"
	$(CC) $(CFLAGS) -o $@ $< $(C4GH_OBJECTS) $(LIBS)

stream: teststream.o $(HEADERS) $(C4GH_OBJECTS)
	@echo "Creating $@"
	$(CC) $(CFLAGS) -o $@ $< $(C4GH_OBJECTS) $(LIBS)

run%: %
	./$* ~/Desktop/fred.pub < _input > _output.$*
ifdef DEBUG
	C4GH_LOG=~/_cryptor/tmp/logger.yml crypt4gh decrypt --sk ~/Desktop/fred.sec < _output.$* > _input.$*
else
	crypt4gh decrypt --sk ~/Desktop/fred.sec < _output.$* > _input.$*
endif
	diff _input _input.$*

encrypt-decrypt: $(C4GH_EXEC)
	@echo "Encrypting _input into _output"
	./$(C4GH_EXEC) encrypt < _input > _output
	@echo "Decrypting _output into _input.again"
	./$(C4GH_EXEC) decrypt < _output > _input.again
	@echo "Comparing"
	diff _input _input.again

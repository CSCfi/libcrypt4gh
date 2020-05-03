
CC     = gcc
CFLAGS = -g -O2 -I../lib 
LIBS   = -lsodium -L/Users/daz/_libc4gh/lib -lcrypt4gh

ifdef DEBUG
CFLAGS += -DDEBUG=$(DEBUG) -g
endif

.PHONY: all clean
.SUFFIXES: .c .o

all: decrypt

../lib/libcrypt4gh.so:
	make -C ../lib libcrypt4gh.so

decrypt: decrypt.c ../lib/libcrypt4gh.so
	@echo "Creating $@"
	@$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	-rm -f decrypt


CC     = gcc
CFLAGS = -g -O2 -I../lib 
LIBS   = -L../lib -lcrypt4gh -lsodium

ifdef DEBUG
CFLAGS += -DDEBUG=$(DEBUG) -g
endif

.PHONY: all clean
.SUFFIXES: .c .o

all: decrypt

../lib/libcrypt4gh.a:
	make -C ../lib libcrypt4gh.a

decrypt: decrypt.c ../lib/libcrypt4gh.a
	@echo "Creating $@"
	@$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	-rm -f decrypt

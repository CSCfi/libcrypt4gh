
AR     = ar
RANLIB = ranlib
CC     = gcc
CFLAGS = -g -O2 -fPIC -I. # -I./lib -I./cli
LIBS   = -lsodium

ifdef DEBUG
CFLAGS += -DDEBUG=$(DEBUG) -g
endif

LIBDIR = .

C4GH_LD_SONAME = -Wl #,-soname,libcrypt4gh.so.2
C4GH_LIBRARY =  #.2.0
C4GH_HEADERS = debug.h defs.h payload.h header.h packet.h stream.h crypt4gh.h
C4GH_SOURCES = payload.c header.c packet.c stream.c crypt4gh.c
C4GH_OBJECTS = $(C4GH_SOURCES:%.c=%.o)

.PHONY: all clean install
.SUFFIXES: .c .o

all: libcrypt4gh.so

$(LIBDIR):
	@echo "Creating lib dir: $(LIBDIR)"
	@install -d $(LIBDIR)

libcrypt4gh.so: $(C4GH_HEADERS) $(C4GH_OBJECTS)
	@echo "Linking objects into $@"
	@$(CC) -shared $(C4GH_LD_SONAME) -o $@ $(LIBS) $(C4GH_OBJECTS)

libcrypt4gh.a: $(C4GH_HEADERS) $(C4GH_OBJECTS)
	$(AR) rv $@ $(C4GH_OBJECTS)
	$(RANLIB) $@

%.o: %.c
ifdef DEBUG
	@echo "Compiling $< (debug: $(DEBUG))"
else
	@echo "Compiling $<"
endif
	@$(CC) $(CFLAGS) -c -o $@ $<

install: libcrypt4gh.so | $(LIBDIR)
	@echo "Installing $< into $(C4GH_LIBDIR)"
	@install -m 700 $< $(C4GH_LIBDIR)

clean:
	-rm -f libcrypt4gh.so libcrypt4gh.a $(C4GH_OBJECTS)

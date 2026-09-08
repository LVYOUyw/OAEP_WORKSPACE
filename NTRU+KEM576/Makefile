CC =gcc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -O3 -fomit-frame-pointer
NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
RM = /bin/rm

LDFLAGS=-lcrypto

SOURCES= kem.c poly.c ntt.c sha2.c symmetric.c reduce.c verify.c fips202.c aes128gcm.c hybrid.c
HEADERS= api.h params.h poly.h ntt.h sha2.h symmetric.h reduce.h verify.h fips202.h aes128gcm.h hybrid.h

.PHONY: all PQCgenKAT_kem test clean

all: \
	hybridtest \
	PQCgenKAT_kem

PQCgenKAT_kem: $(HEADERS) rng.h $(SOURCES) PQCgenKAT_kem.c rng.c
	$(CC) $(NISTFLAGS) -o $@ PQCgenKAT_kem.c rng.c $(SOURCES) $(LDFLAGS)


hybridtest: $(HEADERS) randombytes.h $(SOURCES) randombytes.c hybridtest.c 
	$(CC) $(CFLAGS) -o $@ randombytes.c hybridtest.c $(SOURCES) $(LDFLAGS)

clean:
	-$(RM) PQCgenKAT_kem
	-$(RM) test
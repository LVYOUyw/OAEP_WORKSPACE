CC=/usr/bin/gcc
CFLAGS += -O3 -march=native -fomit-frame-pointer
LDFLAGS=-lcrypto

SOURCES= cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c reduce.c rng.c verify.c symmetric-shake.c aes128gcm.c hybrid.c 
HEADERS= api.h cbd.h fips202.h indcpa.h ntt.h params.h poly.h polyvec.h reduce.h rng.h verify.h symmetric.h aes128gcm.h hybrid.h 

all: PQCgenKAT_kem hybridtest

PQCgenKAT_kem: $(HEADERS) $(SOURCES) PQCgenKAT_kem.c
	$(CC) $(CFLAGS) -o $@ $(SOURCES) PQCgenKAT_kem.c $(LDFLAGS)

hybridtest: $(HEADERS) $(SOURCES)  hybridtest.c
	$(CC) $(CFLAGS) -o $@ $(SOURCES) hybridtest.c $(LDFLAGS)

.PHONY: clean

clean:
	-rm PQCgenKAT_kem
	-rm hybridtest


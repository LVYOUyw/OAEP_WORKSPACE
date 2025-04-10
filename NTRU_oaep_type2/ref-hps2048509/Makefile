NTRU_NAMESPACE ?= ntru_

CC ?= /usr/bin/cc
CFLAGS = -O3 -fomit-frame-pointer -march=native -fPIC -fPIE -pie
CFLAGS += -Wall -Wextra -Wpedantic
CFLAGS += -DCRYPTO_NAMESPACE\(s\)=${NTRU_NAMESPACE}\#\#s
LDFLAGS=-lcrypto

SRC = cmov.c \
      crypto_sort_int32.c \
      fips202.c \
      kem.c \
      owcpa.c \
      pack3.c \
      packq.c \
      poly.c \
      poly_lift.c \
      poly_mod.c \
      poly_r2_inv.c \
      poly_rq_mul.c \
      poly_s3_inv.c \
      aes128gcm.c \
      oaephybrid.c \
      sample.c \
      sample_iid.c

HDR = cmov.h \
      crypto_hash_sha3256.h \
      crypto_sort_int32.h \
      kem.h \
      owcpa.h \
      params.h \
      poly.h \
      aes128gcm.h \
      oaephybrid.h \
      sample.h

SRC_URAND = $(SRC) randombytes.c
HDR_URAND = $(HDR) randombytes.h

all: test/oaep test/oaephyb

test/oaep: $(SRC_URAND) $(HDR_URAND) test/oaep.c
	$(CC) $(CFLAGS) -o $@ $(SRC_URAND) test/oaep.c $(LDFLAGS)

test/oaephyb: $(SRC_URAND) $(HDR_URAND) test/oaephyb.c
	$(CC) $(CFLAGS) -o $@ $(SRC_URAND) test/oaephyb.c $(LDFLAGS)

.PHONY: clean test

test: all
	./test/speed
	./test/test_gp_compat | gp -q
	./test/test_ntru
	./test/test_pack

clean::
	-$(RM) *.o
	-$(RM) -r test/oaep
	-$(RM) -r test/oaephyb      
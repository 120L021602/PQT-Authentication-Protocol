#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "../randombytes.h"
#include "../sign.h"

#define MLEN 59
#define NTESTS 10000

int main(void)
{
  size_t i, j;
  int ret;
  size_t mlen, smlen;
  uint8_t b;
  uint8_t m[MLEN + CRYPTO_BYTES_SIG];
  uint8_t m2[MLEN + CRYPTO_BYTES_SIG];
  uint8_t sm[MLEN + CRYPTO_BYTES_SIG];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES_SIG];
  uint8_t sk[CRYPTO_SECRETKEYBYTES_SIG];

  for(i = 0; i < NTESTS; ++i) {
    randombytes(m, MLEN);

    crypto_sign_keypair(pk, sk);
    crypto_sign(sm, &smlen, m, MLEN, sk);
    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);

    if(ret) {
      fprintf(stderr, "Verification failed\n");
      return -1;
    }
    if(smlen != MLEN + CRYPTO_BYTES_SIG) {
      fprintf(stderr, "Signed message lengths wrong\n");
      return -1;
    }
    if(mlen != MLEN) {
      fprintf(stderr, "Message lengths wrong\n");
      return -1;
    }
    for(j = 0; j < MLEN; ++j) {
      if(m2[j] != m[j]) {
        fprintf(stderr, "Messages don't match\n");
        return -1;
      }
    }

    randombytes((uint8_t *)&j, sizeof(j));
    do {
      randombytes(&b, 1);
    } while(!b);
    sm[j % (MLEN + CRYPTO_BYTES_SIG)] += b;
    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);
    if(!ret) {
      fprintf(stderr, "Trivial forgeries possible\n");
      return -1;
    }
  }

  printf("CRYPTO_PUBLICKEYBYTES_SIG = %d\n", CRYPTO_PUBLICKEYBYTES_SIG);
  printf("CRYPTO_SECRETKEYBYTES_SIG = %d\n", CRYPTO_SECRETKEYBYTES_SIG);
  printf("CRYPTO_BYTES_SIG = %d\n", CRYPTO_BYTES_SIG);

  return 0;
}

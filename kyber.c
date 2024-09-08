#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "header/param.h"
#include "header/api.h"
#include "header/fips202.h"
#include "header/randomBytes"
#include "header/reduce.h"
#include "header/verify.h"
#include "header/symmetric.h"
#include "header/ntt.h"
#include "header/poly.h"
#include "header/polyvec.h"
#include "header/indcpa.h"
#include "header/kem.h"

int main(void)
{
  unsigned int i,j, n=1;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];

  for(i=0;i<n;i++) {

    // Key-pair generation
    int start, end;
    start = clock();
    crypto_kem_keypair(pk, sk);
    end = clock();

    printf("Public Key char:\n");
    for(j=0;pk[j] || pk[j+1] || pk[j+2];j++)
      printf("%c",pk[j]);
    printf("\nlen pk char= %u\n\n",CRYPTO_PUBLICKEYBYTES);

    printf("Public Key:\n");
    for(j=0;j<CRYPTO_PUBLICKEYBYTES;j++)
      printf("%02x",pk[j]);
    printf("\nlen pk= %u\n\n",j);
    
    printf("Secret Key:\n");
    for(j=0;j<CRYPTO_SECRETKEYBYTES;j++)
      printf("%02x",sk[j]);
    printf("\nlen sk= %u\n\n",j);

    printf("*** Duration of Public and Private keys generation: %d milli second\n\n",(end-start));
    
    // Encapsulation
    start = clock();
    crypto_kem_enc(ct, key_a, pk);
    end = clock();

    printf("Ciphertext:\n");
    for(j=0;j<CRYPTO_CIPHERTEXTBYTES;j++)
      printf("%02x",ct[j]);
    printf("\nlen ct= %u\n\n",j);

    printf("Shared Secret A:\n");
    for(j=0;j<CRYPTO_BYTES;j++)
      printf("%02x",key_a[j]);
    printf("\nlen ssa= %u\n\n",j);

    printf("*** Duration of Ciphertext and Shared Secret A generation: %d milli second\n\n",(end-start));

    // Decapsulation
    start = clock();
    crypto_kem_dec(key_b, ct, sk);
    end = clock();

    printf("Shared Secret B:\n");
    for(j=0;j<CRYPTO_BYTES;j++)
      printf("%02x",key_b[j]);
    printf("\nlen ssb= %u\n\n",j);

    printf("*** Duration of Shared Secret B generation: %d milli second\n\n",(end-start));

    for(j=0;j<CRYPTO_BYTES;j++) {
      if(key_a[j] != key_b[j]) {
        fprintf(stderr, "ERROR\n");
        return -1;
      }
    }

    // Decapsulation of invalid (random) ciphertexts
    randombytes(ct, KYBER_CIPHERTEXTBYTES); 
    crypto_kem_dec(key_a, ct, sk);
    
    printf("Pseudorandom Shared Secret A:\n");
    for(j=0;j<CRYPTO_BYTES;j++)
      printf("%02x",key_a[j]);
    printf("\nlen pssa= %u\n\n",j);
  }
  
  time_t current_time;
  time(&current_time);
  char* time_string = ctime(&current_time);
    
  printf("finish at: %s", time_string);

  return 0;
}
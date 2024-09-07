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
  unsigned int i,j;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];

  int start, end;

  for(i=0;i<1;i++) {

    // Key-pair generation
    start = clock();
    crypto_kem_keypair(pk, sk);
    end = clock();

    printf("Public Key char: ");
    for(j=0;pk[j] || pk[j+1] || pk[j+2];j++)
      printf("%c",pk[j]);
    printf("\nlen pk char= %u\n\n",j-1);

    printf("Public Key: ");
    for(j=0;j<CRYPTO_PUBLICKEYBYTES;j++)
      printf("%02x",pk[j]);
    printf("\nlen pk= %u\n\n",j);
    
    printf("Secret Key: ");
    for(j=0;j<CRYPTO_SECRETKEYBYTES;j++)
      printf("%02x",sk[j]);
    printf("\nlen sk= %u\n\n",j);

    printf("***   time pk and sk= %d milli second\n\n",(end-start));
    
    // Encapsulation
    crypto_kem_enc(ct, key_b, pk);

    printf("Ciphertext: ");
    for(j=0;j<CRYPTO_CIPHERTEXTBYTES;j++)
      printf("%02x",ct[j]);
    printf("\nlen ct= %u\n\n",j);
    printf("Shared Secret B: ");
    for(j=0;j<CRYPTO_BYTES;j++)
      printf("%02x",key_b[j]);
    printf("\nlen ssb= %u\n\n",j);

    // Decapsulation
    crypto_kem_dec(key_a, ct, sk);
    printf("Shared Secret A: ");
    for(j=0;j<CRYPTO_BYTES;j++)
      printf("%02x",key_a[j]);
    printf("\nlen ssa= %u\n\n",j);

    for(j=0;j<CRYPTO_BYTES;j++) {
      if(key_a[j] != key_b[j]) {
        fprintf(stderr, "ERROR\n");
        return -1;
      }
    }

    // Decapsulation of invalid (random) ciphertexts
    int start1, end1;
    start1 = clock();

    randombytes(ct, KYBER_CIPHERTEXTBYTES); 
    crypto_kem_dec(key_a, ct, sk);
    end1 = clock();
    printf("***   time pssa= %d milli second\n\n",(end1-start1));
    printf("Pseudorandom shared Secret A: ");
    for(j=0;j<CRYPTO_BYTES;j++)
      printf("%02x",key_a[j]);
    printf("\nlen pssa= %u\n\n",j);
  }
  
  time_t current_time;
  time(&current_time);
  char* time_string = ctime(&current_time);
    
  printf("finish at: %s", time_string);
  printf("end\n");

  return 0;
}
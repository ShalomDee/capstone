/* Median timings for ML-KEM-768 and ML-DSA-65 straight from liboqs, plus a tamper check.
 * Source of the Preliminary Results table in Progress Report 2.
 * Build and run inside the dev container:
 *   make bench          (or: ./build/time_pqc [runs], default 1000)
 * Owner: Shalom. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>
static uint64_t now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000ull+t.tv_nsec;}
static int c(const void*a,const void*b){uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b;return (x>y)-(x<y);}
static void rep(const char*l,uint64_t*v,int n){qsort(v,n,8,c);printf("%-22s median %8.4f ms   p10 %8.4f   p90 %8.4f\n",l,v[n/2]/1e6,v[n/10]/1e6,v[n*9/10]/1e6);}
int main(int argc,char**argv){int n=argc>1?atoi(argv[1]):1000;
 uint64_t *a=malloc(8*n),*b=malloc(8*n),*d=malloc(8*n);
 OQS_KEM*k=OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
 uint8_t*pk=malloc(k->length_public_key),*sk=malloc(k->length_secret_key),*ct=malloc(k->length_ciphertext),s1[32],s2[32];
 for(int i=0;i<n;i++){uint64_t t0=now();OQS_KEM_keypair(k,pk,sk);uint64_t t1=now();OQS_KEM_encaps(k,ct,s1,pk);uint64_t t2=now();OQS_KEM_decaps(k,s2,ct,sk);uint64_t t3=now();
  if(memcmp(s1,s2,32)){puts("MISMATCH");return 1;} a[i]=t1-t0;b[i]=t2-t1;d[i]=t3-t2;}
 printf("ML-KEM-768, %d runs\n",n);rep("keypair",a,n);rep("encapsulate",b,n);rep("decapsulate",d,n);
 OQS_SIG*s=OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
 uint8_t*spk=malloc(s->length_public_key),*ssk=malloc(s->length_secret_key),*sig=malloc(s->length_signature);size_t sl;uint8_t m[]="s1,0,20.0,40";int bad=0;
 for(int i=0;i<n;i++){uint64_t t0=now();OQS_SIG_keypair(s,spk,ssk);uint64_t t1=now();OQS_SIG_sign(s,sig,&sl,m,12,ssk);uint64_t t2=now();if(OQS_SIG_verify(s,m,12,sig,sl,spk)!=OQS_SUCCESS)bad++;uint64_t t3=now();a[i]=t1-t0;b[i]=t2-t1;d[i]=t3-t2;}
 printf("ML-DSA-65, %d runs (%d verify failures)\n",n,bad);rep("keypair",a,n);rep("sign",b,n);rep("verify",d,n);
 int caught=0;for(int i=0;i<n;i++){OQS_SIG_sign(s,sig,&sl,m,12,ssk);m[i%12]^=1;if(OQS_SIG_verify(s,m,12,sig,sl,spk)!=OQS_SUCCESS)caught++;m[i%12]^=1;}
 printf("tampered readings rejected: %d of %d\n",caught,n);return 0;}

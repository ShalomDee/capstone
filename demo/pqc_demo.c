/* demo/pqc_demo.c
 * First proof that the toolchain works: a quantum-safe key exchange (ML-KEM-768)
 * and a digital signature (ML-DSA-65), using liboqs. Take your screenshot of this output.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>

static double ms_since(struct timespec start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start.tv_sec) * 1000.0 + (now.tv_nsec - start.tv_nsec) / 1e6;
}

static int key_exchange_demo(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) { fprintf(stderr, "ML-KEM-768 is not in this liboqs build\n"); return 1; }

    uint8_t *pk = malloc(kem->length_public_key);       /* server's public lock   */
    uint8_t *sk = malloc(kem->length_secret_key);       /* server's private key   */
    uint8_t *ct = malloc(kem->length_ciphertext);       /* the "locked box"       */
    uint8_t *ss_client = malloc(kem->length_shared_secret);
    uint8_t *ss_server = malloc(kem->length_shared_secret);
    struct timespec t;

    printf("== Key exchange: %s ==\n", kem->method_name);

    clock_gettime(CLOCK_MONOTONIC, &t);
    int ok = OQS_KEM_keypair(kem, pk, sk) == OQS_SUCCESS;                /* server */
    printf("server makes key pair      %8.3f ms\n", ms_since(t));

    clock_gettime(CLOCK_MONOTONIC, &t);
    ok = ok && OQS_KEM_encaps(kem, ct, ss_client, pk) == OQS_SUCCESS;    /* client */
    printf("client makes locked box    %8.3f ms\n", ms_since(t));

    clock_gettime(CLOCK_MONOTONIC, &t);
    ok = ok && OQS_KEM_decaps(kem, ss_server, ct, sk) == OQS_SUCCESS;    /* server */
    printf("server opens locked box    %8.3f ms\n", ms_since(t));

    int match = ok && memcmp(ss_client, ss_server, kem->length_shared_secret) == 0;
    printf("public key %zu bytes | locked box %zu bytes | secret %zu bytes\n",
           kem->length_public_key, kem->length_ciphertext, kem->length_shared_secret);
    printf("shared secrets match: %s\n\n", match ? "YES" : "NO");

    OQS_MEM_secure_free(sk, kem->length_secret_key);
    OQS_MEM_secure_free(ss_client, kem->length_shared_secret);
    OQS_MEM_secure_free(ss_server, kem->length_shared_secret);
    free(pk); free(ct);
    OQS_KEM_free(kem);
    return match ? 0 : 1;
}

static int signature_demo(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (sig == NULL) { fprintf(stderr, "ML-DSA-65 is not in this liboqs build\n"); return 1; }

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t signature_len = 0;
    uint8_t message[] = "soil_moisture=0.31;temp_c=24.5";   /* a pretend sensor reading */
    struct timespec t;

    printf("== Signature: %s ==\n", sig->method_name);
    int ok = OQS_SIG_keypair(sig, pk, sk) == OQS_SUCCESS;

    clock_gettime(CLOCK_MONOTONIC, &t);
    ok = ok && OQS_SIG_sign(sig, signature, &signature_len, message, sizeof message, sk) == OQS_SUCCESS;
    printf("sign                       %8.3f ms\n", ms_since(t));

    clock_gettime(CLOCK_MONOTONIC, &t);
    int valid = ok && OQS_SIG_verify(sig, message, sizeof message, signature, signature_len, pk) == OQS_SUCCESS;
    printf("verify                     %8.3f ms\n", ms_since(t));

    message[0] ^= 1;                                         /* change one bit of the reading */
    int tampered_ok = ok && OQS_SIG_verify(sig, message, sizeof message, signature, signature_len, pk) == OQS_SUCCESS;

    printf("message %zu bytes | signature %zu bytes | public key %zu bytes\n",
           sizeof message, signature_len, sig->length_public_key);
    printf("original message verifies: %s\n", valid ? "YES" : "NO");
    printf("tampered message verifies: %s (should be NO)\n", tampered_ok ? "YES" : "NO");

    OQS_MEM_secure_free(sk, sig->length_secret_key);
    free(pk); free(signature);
    OQS_SIG_free(sig);
    return (valid && !tampered_ok) ? 0 : 1;
}

int main(void) {
    int bad = key_exchange_demo();
    bad |= signature_demo();
    return bad;
}

/* Times id_sign and id_verify many times and reports the median.
 * Cloud machines are noisy, so single runs are not results (CLAUDE.md section 5).
 * Uses Chris's real ML-DSA-65 code with a fresh key pair in a temporary folder.
 * id_sign reads the private key file each call, so its time includes that file read.
 * Usage: time_sign [runs]        (default: 1000)
 * Owner: Shalom. */
#include "bench.h"
#include "identity.h"
#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static uint64_t median(uint64_t *v, int n)
{
    qsort(v, (size_t)n, sizeof *v, cmp_u64);
    return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2;
}

int main(int argc, char **argv)
{
    int runs = argc > 1 ? atoi(argv[1]) : 1000;
    if (runs < 1) runs = 1;
    uint64_t *sign_ns = malloc(sizeof(uint64_t) * (size_t)runs);
    uint64_t *verify_ns = malloc(sizeof(uint64_t) * (size_t)runs);
    if (!sign_ns || !verify_ns) return 1;

    const uint8_t msg[] = "sample message to sign";
    uint8_t pk[QD_SIG_PK_BYTES];
    uint8_t sig[QD_SIG_BYTES];
    size_t sig_len;

    /* Fresh key pair in a temporary folder, removed at the end. */
    char dir[] = "/tmp/qd-time-sign-XXXXXX", key[64], pub[64];
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    snprintf(key, sizeof key, "%s/bench.key", dir);
    snprintf(pub, sizeof pub, "%s/bench.pub", dir);
    FILE *f = NULL;
    int ok = id_generate_keys("bench", dir) == QD_OK && (f = fopen(pub, "rb")) &&
             fread(pk, 1, sizeof pk, f) == sizeof pk;
    if (f) fclose(f);
    if (!ok) { fprintf(stderr, "cannot make bench keys\n"); return 1; }

    for (int i = 0; i < runs; i++) {
        uint64_t t0 = bench_now_ns();
        if (id_sign(key, msg, sizeof msg, sig, &sig_len) != QD_OK) {
            fprintf(stderr, "sign failed\n");
            return 1;
        }
        uint64_t t1 = bench_now_ns();
        if (id_verify(pk, msg, sizeof msg, sig, sig_len) != QD_OK) {
            fprintf(stderr, "verify failed\n");
            return 1;
        }
        uint64_t t2 = bench_now_ns();
        sign_ns[i] = t1 - t0;
        verify_ns[i] = t2 - t1;
    }

    printf("%d runs (medians):\n", runs);
    bench_log("sign_median", median(sign_ns, runs), "ns");
    bench_log("verify_median", median(verify_ns, runs), "ns");
    bench_log("signature_bytes", sig_len, "B");
    unlink(key);
    unlink(pub);
    rmdir(dir);
    free(sign_ns);
    free(verify_ns);
    return 0;
}

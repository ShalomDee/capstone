/* STUB farm sensor simulator. Makes fake readings and prints how big each one
 * is next to the signature that would travel with it.
 * The reading format below is a PLACEHOLDER until the format is agreed (task step 7).
 * Usage: sensor <id> [count]        (default count: 5)
 * Owner: Shalom. */
#include "bench.h"
#include "identity.h"
#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <id> [count]\n", argv[0]);
        return 1;
    }
    const char *id = argv[1];
    int count = argc > 2 ? atoi(argv[2]) : 5;

    for (int seq = 0; seq < count; seq++) {
        char reading[128];
        double temp = 20.0 + (seq % 10) * 0.5;      /* fake values */
        int humidity = 40 + seq % 20;
        int n = snprintf(reading, sizeof reading, "%s,%d,%.1f,%d", id, seq, temp, humidity);

        uint8_t sig[QD_SIG_BYTES];
        size_t sig_len = 0;
        int rc = id_sign("keys/unused", (const uint8_t *)reading, (size_t)n, sig, &sig_len);
        if (rc != QD_OK) {
            fprintf(stderr, "sign failed: %s\n", qd_strerror(rc));
            return 1;
        }
        printf("reading \"%s\": %d bytes, signature %zu bytes\n", reading, n, sig_len);
        bench_log("reading_bytes", (uint64_t)n, "B");
        bench_log("signature_bytes", sig_len, "B");
    }
    return 0;
}

/* Farm sensor simulator (topic 5). Makes fake readings in the agreed v1 format
 * (sensor/reading.h), groups them into files of `batch` readings, signs each file,
 * and reports how many bytes each upload puts on the wire.
 *
 * Today: signing uses Chris's identity stubs (fake signature of the real length)
 * and byte counts are computed from PROTOCOL.md (sensor/wire_cost.h), because the
 * secure pipe is still a stub. The files themselves are real.
 *
 * Usage: sensor <id> [count] [batch] [outdir]
 *   count   readings to make (default 10)
 *   batch   readings per file, one signature per file (default 1)
 *   outdir  folder for the files (default sensor-data)
 * Owner: Shalom. */
#include "bench.h"
#include "identity.h"
#include "protocol.h"
#include "reading.h"
#include "wire_cost.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define READING_INTERVAL_S 60   /* one simulated reading per minute */
#define BATCH_MAX          10000
#define SHOW_FILES_MAX     10   /* print one line per file only for small runs */

/* Whole number from text, refusing junk like "10x" or "-3". */
static int parse_count(const char *s, long max, long *out)
{
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end || v < 1 || v > max) return 0;
    *out = v;
    return 1;
}

/* Write readings first..first+n-1 to one file, read it back and check it,
 * then build the signed record. Fills in the sizes the caller reports. */
static int make_file(const char *id, uint32_t first, size_t n, int64_t start_time,
                     const char *key_path, reading *batch, reading *check,
                     char *name, size_t name_cap, uint64_t *file_size,
                     size_t *rec_len, size_t *sig_len)
{
    int rc = reading_filename(id, first, first + (uint32_t)n - 1, name, name_cap);
    if (rc != QD_OK) return rc;

    FILE *fp = fopen(name, "wb");
    if (!fp) {
        fprintf(stderr, "cannot write %s: %s\n", name, strerror(errno));
        return QD_ERR_FILE;
    }
    *file_size = 0;
    for (size_t i = 0; i < n; i++) {
        uint32_t seq = first + (uint32_t)i;
        char line[READING_LINE_MAX];
        size_t len;
        rc = reading_simulate(id, seq, start_time + (int64_t)seq * READING_INTERVAL_S, &batch[i]);
        if (rc == QD_OK) rc = reading_format(&batch[i], line, sizeof line, &len);
        if (rc == QD_OK && fwrite(line, 1, len, fp) != len) rc = QD_ERR_FILE;
        if (rc != QD_OK) { fclose(fp); return rc; }
        *file_size += len;
    }
    if (fclose(fp) != 0) return QD_ERR_FILE;

    /* Read the file back so a broken file is caught here, not by the server. */
    size_t got;
    const char *why;
    rc = reading_read_file(name, check, n, &got, &why);
    if (rc != QD_OK || got != n || check[0].seq != first) {
        fprintf(stderr, "%s failed its own check: %s\n", name, rc != QD_OK ? why : "wrong readings");
        return rc != QD_OK ? rc : QD_ERR_FORMAT;
    }

    uint8_t rec[QD_RECORD_MAX], sig[QD_SIG_BYTES];
    rc = id_make_record(id, name, rec, rec_len);
    if (rc == QD_OK) rc = id_sign(key_path, rec, *rec_len, sig, sig_len);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 5) {
        fprintf(stderr, "usage: %s <id> [count] [batch] [outdir]\n", argv[0]);
        return 1;
    }
    const char *id = argv[1];
    long count = 10, batch = 1;
    const char *outdir = argc > 4 ? argv[4] : "sensor-data";
    if (!reading_id_ok(id)) {
        fprintf(stderr, "sensor id must be 1 to %d letters, digits, '-' or '_'\n", QD_ID_MAX);
        return 1;
    }
    if (argc > 2 && !parse_count(argv[2], (long)READING_SEQ_MAX + 1, &count)) {
        fprintf(stderr, "count must be 1 to %u\n", READING_SEQ_MAX + 1);
        return 1;
    }
    if (argc > 3 && !parse_count(argv[3], BATCH_MAX, &batch)) {
        fprintf(stderr, "batch must be 1 to %d\n", BATCH_MAX);
        return 1;
    }

    /* Key path is fixed before moving into outdir. File name to match Chris's id_generate_keys. */
    char cwd[PATH_MAX], key_path[PATH_MAX + QD_ID_MAX + 8];
    if (!getcwd(cwd, sizeof cwd)) { perror("getcwd"); return 1; }
    snprintf(key_path, sizeof key_path, "%s/keys/%s", cwd, id);

    /* Work inside outdir so the signed record holds only the file name, never a
     * folder path (PROTOCOL.md 6.1 forbids '/' in file names). */
    if (mkdir(outdir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "cannot make %s: %s\n", outdir, strerror(errno));
        return 1;
    }
    if (chdir(outdir) != 0) {
        fprintf(stderr, "cannot enter %s: %s\n", outdir, strerror(errno));
        return 1;
    }

    reading *buf = malloc(sizeof *buf * (size_t)batch);
    reading *check = malloc(sizeof *check * (size_t)batch);
    if (!buf || !check) { fprintf(stderr, "out of memory\n"); return 1; }

    int64_t start_time = (int64_t)time(NULL);
    long files = (count + batch - 1) / batch;
    uint64_t data = 0, c2s = 0, s2c = 0;
    size_t sig_total = 0;

    for (long done = 0; done < count; done += batch) {
        size_t n = (size_t)(count - done < batch ? count - done : batch);
        char name[QD_NAME_MAX + 1];
        uint64_t file_size;
        size_t rec_len, sig_len;
        int rc = make_file(id, (uint32_t)done, n, start_time, key_path, buf, check,
                           name, sizeof name, &file_size, &rec_len, &sig_len);
        if (rc != QD_OK) {
            fprintf(stderr, "file starting at reading %ld failed: %s\n", done, qd_strerror(rc));
            return 1;
        }
        uint64_t up = wire_upload_c2s(rec_len, sig_len, file_size);
        data += file_size;
        c2s += up;
        s2c += wire_upload_s2c();
        sig_total += sig_len;
        if (files <= SHOW_FILES_MAX)
            printf("%s: %zu readings, %llu B data, record %zu B, signature %zu B, sends %llu B\n",
                   name, n, (unsigned long long)file_size, rec_len, sig_len, (unsigned long long)up);
    }

    uint64_t setup_c2s = wire_handshake_c2s() + wire_register_c2s(strlen(id));
    uint64_t setup_s2c = wire_handshake_s2c() + wire_register_s2c();
    printf("sensor %s: %ld readings in %ld file%s of up to %ld (in %s/)\n",
           id, count, files, files == 1 ? "" : "s", batch, outdir);
    printf("  reading data                  %10llu B   %8.1f B per reading\n",
           (unsigned long long)data, (double)data / count);
    printf("  uploads, sensor to server     %10llu B   %8.1f B per reading\n",
           (unsigned long long)c2s, (double)c2s / count);
    printf("    of which signatures         %10zu B   %8.1f%% of upload bytes\n",
           sig_total, 100.0 * (double)sig_total / (double)c2s);
    printf("  replies, server to sensor     %10llu B\n", (unsigned long long)s2c);
    printf("  connection setup, once        %10llu B to server, %llu B back (handshake + register)\n",
           (unsigned long long)setup_c2s, (unsigned long long)setup_s2c);
    printf("  (byte counts computed from PROTOCOL.md; securenet and identity are stubs)\n");

    bench_log("batch_size", (uint64_t)batch, "readings");
    bench_log("readings", (uint64_t)count, "readings");
    bench_log("files", (uint64_t)files, "files");
    bench_log("data_bytes", data, "B");
    bench_log("upload_c2s_bytes", c2s, "B");
    bench_log("upload_s2c_bytes", s2c, "B");
    bench_log("signature_bytes", sig_total, "B");
    bench_log("setup_c2s_bytes", setup_c2s, "B");
    bench_log("setup_s2c_bytes", setup_s2c, "B");

    free(buf);
    free(check);
    return 0;
}

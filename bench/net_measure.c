/* End-to-end measurements over the real encrypted connection (topics 5 and 7).
 *
 * Needs a running server:   ./build/server <port> <storage_dir>
 * Usage:  net_measure <host> <port> <out.csv> <id> [sensor_dir ...]
 *
 * What it measures, one CSV row per run:
 *   handshake   connect + ML-KEM-768 handshake, 1000 times, and its bytes
 *   register    one REGISTER of <id>'s key (made in keys/ if missing)
 *   upload      cmd_upload of 1 KiB, 100 KiB, 1 MiB and 10 MiB files, many times each
 *   sensorfile  every .csv file in each sensor_dir, uploaded once
 * Each row also holds the bytes worked out from PROTOCOL.md (sensor/wire_cost.h)
 * so the measured and computed counts can be compared.
 *
 * Bytes are counted with link-time wrappers around send() and recv()
 * (-Wl,--wrap=send,--wrap=recv in the Makefile), so no shared code changes.
 * Only this client's side is counted: c2s = bytes sent, s2c = bytes received.
 * TCP/IP headers are not included.
 * Owner: Shalom. */
#include "bench.h"
#include "commands.h"
#include "identity.h"
#include "protocol.h"
#include "securenet.h"
#include "wire_cost.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* ---------------------------------------------------------- byte counting */

static uint64_t sent_bytes, recv_bytes;

ssize_t __real_send(int fd, const void *buf, size_t n, int flags);
ssize_t __real_recv(int fd, void *buf, size_t n, int flags);

ssize_t __wrap_send(int fd, const void *buf, size_t n, int flags)
{
    ssize_t r = __real_send(fd, buf, n, flags);
    if (r > 0) sent_bytes += (uint64_t)r;
    return r;
}

ssize_t __wrap_recv(int fd, void *buf, size_t n, int flags)
{
    ssize_t r = __real_recv(fd, buf, n, flags);
    if (r > 0) recv_bytes += (uint64_t)r;
    return r;
}

/* Same as client/main.c, which cannot be linked here because it has main(). */
int client_open(const client_ctx *c, sec_session *s)
{
    int fd = net_connect(c->host, c->port);
    if (fd < 0) return fd;
    s->fd = fd;
    int rc = sec_handshake_client(fd, s);
    if (rc != QD_OK) sec_close(s);
    return rc;
}

/* ------------------------------------------------------------------ output */

static FILE *csv;

static void row(const char *kind, const char *param, long run, uint64_t ns,
                uint64_t c2s, uint64_t s2c, uint64_t comp_c2s, uint64_t comp_s2c,
                long readings, uint64_t data_bytes)
{
    fprintf(csv, "%s,%s,%ld,%llu,%llu,%llu,%llu,%llu,%ld,%llu\n", kind, param, run,
            (unsigned long long)ns, (unsigned long long)c2s, (unsigned long long)s2c,
            (unsigned long long)comp_c2s, (unsigned long long)comp_s2c, readings,
            (unsigned long long)data_bytes);
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* Prints median, p10 and p90 (in ms) of v[0..n-1]; sorts v. */
static void summary(const char *label, uint64_t *v, int n)
{
    qsort(v, (size_t)n, sizeof *v, cmp_u64);
    fprintf(stderr, "%-28s median %9.3f ms   p10 %9.3f   p90 %9.3f   (%d runs)\n",
            label, v[n / 2] / 1e6, v[n / 10] / 1e6, v[n * 9 / 10] / 1e6, n);
}

/* Upload cost worked out from PROTOCOL.md for one file on a fresh connection. */
static int computed_upload(const char *id, const char *path, uint64_t size,
                           uint64_t *c2s, uint64_t *s2c)
{
    uint8_t rec[QD_RECORD_MAX];
    size_t rec_len;
    int rc = id_make_record(id, path, rec, &rec_len);
    if (rc != QD_OK) return rc;
    *c2s = wire_handshake_c2s() + wire_upload_c2s(rec_len, QD_SIG_BYTES, size);
    *s2c = wire_handshake_s2c() + wire_upload_s2c();
    return QD_OK;
}

/* ------------------------------------------------------------- the runs */

static int run_handshakes(const client_ctx *c, int runs)
{
    uint64_t *t = malloc(sizeof *t * (size_t)runs);
    if (!t) return QD_ERR_IO;
    for (int i = 0; i < runs; i++) {
        uint64_t s0 = sent_bytes, r0 = recv_bytes;
        uint64_t t0 = bench_now_ns();
        sec_session s;
        int rc = client_open(c, &s);
        uint64_t t1 = bench_now_ns();
        if (rc != QD_OK) { free(t); return rc; }
        sec_close(&s);
        t[i] = t1 - t0;
        row("handshake", "-", i, t[i], sent_bytes - s0, recv_bytes - r0,
            wire_handshake_c2s(), wire_handshake_s2c(), 0, 0);
    }
    summary("connect + handshake", t, runs);
    free(t);
    return QD_OK;
}

static int run_register(const client_ctx *c)
{
    uint64_t s0 = sent_bytes, r0 = recv_bytes, t0 = bench_now_ns();
    int rc = cmd_register(c);
    uint64_t t1 = bench_now_ns();
    if (rc != QD_OK && rc != QD_ERR_PEER) return rc;   /* PEER: already registered */
    row("register", "-", 0, t1 - t0, sent_bytes - s0, recv_bytes - r0,
        wire_handshake_c2s() + wire_register_c2s(strlen(c->id)),
        wire_handshake_s2c() + wire_register_s2c(), 0, 0);
    return QD_OK;
}

static int make_random_file(const char *path, uint64_t size)
{
    FILE *f = fopen(path, "wb");
    if (!f) return QD_ERR_FILE;
    uint8_t buf[65536];
    for (uint64_t left = size; left > 0;) {
        size_t n = left < sizeof buf ? (size_t)left : sizeof buf;
        for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)rand();
        if (fwrite(buf, 1, n, f) != n) { fclose(f); return QD_ERR_FILE; }
        left -= n;
    }
    return fclose(f) == 0 ? QD_OK : QD_ERR_FILE;
}

static int run_uploads(const client_ctx *c)
{
    static const struct { const char *name; uint64_t size; int runs; } sizes[] = {
        { "1KiB", 1024ull, 200 },
        { "100KiB", 100ull * 1024, 200 },
        { "1MiB", 1024ull * 1024, 100 },
        { "10MiB", 10ull * 1024 * 1024, 30 },
    };
    for (size_t k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        char path[64];
        snprintf(path, sizeof path, "upload-%s.bin", sizes[k].name);
        int rc = make_random_file(path, sizes[k].size);
        uint64_t comp_c2s, comp_s2c;
        if (rc == QD_OK) rc = computed_upload(c->id, path, sizes[k].size, &comp_c2s, &comp_s2c);
        if (rc != QD_OK) return rc;

        int runs = sizes[k].runs;
        uint64_t *t = malloc(sizeof *t * (size_t)runs);
        if (!t) return QD_ERR_IO;
        for (int i = 0; i < runs; i++) {
            uint64_t s0 = sent_bytes, r0 = recv_bytes, t0 = bench_now_ns();
            rc = cmd_upload(c, path);
            uint64_t t1 = bench_now_ns();
            if (rc != QD_OK) { free(t); return rc; }
            t[i] = t1 - t0;
            row("upload", sizes[k].name, i, t[i], sent_bytes - s0, recv_bytes - r0,
                comp_c2s, comp_s2c, 0, sizes[k].size);
        }
        char label[64];
        snprintf(label, sizeof label, "upload %s", sizes[k].name);
        summary(label, t, runs);
        free(t);
    }
    return QD_OK;
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static long count_lines(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    long n = 0;
    for (int ch; (ch = fgetc(f)) != EOF;) n += ch == '\n';
    fclose(f);
    return n;
}

/* Uploads every .csv in dir, in name order. param is the folder's name. */
static int run_sensor_dir(const client_ctx *c, const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return QD_ERR_FILE;
    char *names[20000];
    size_t n = 0;
    for (struct dirent *e; (e = readdir(d)) && n < 20000;) {
        size_t len = strlen(e->d_name);
        if (len > 4 && !strcmp(e->d_name + len - 4, ".csv")) names[n++] = strdup(e->d_name);
    }
    closedir(d);
    qsort(names, n, sizeof *names, cmp_str);

    const char *param = strrchr(dir, '/') ? strrchr(dir, '/') + 1 : dir;
    uint64_t total_ns = 0, total_c2s = 0, total_data = 0;
    long total_readings = 0;
    int rc = QD_OK;
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof cwd) || chdir(dir) != 0) rc = QD_ERR_FILE;
    for (size_t i = 0; rc == QD_OK && i < n; i++) {
        /* Upload from inside the folder so the record holds only the file name. */
        long readings = count_lines(names[i]);
        FILE *f = fopen(names[i], "rb");
        uint64_t size = 0;
        if (f) { fseek(f, 0, SEEK_END); size = (uint64_t)ftell(f); fclose(f); }
        uint64_t comp_c2s, comp_s2c;
        rc = readings > 0 ? computed_upload(c->id, names[i], size, &comp_c2s, &comp_s2c) : QD_ERR_FILE;
        if (rc != QD_OK) break;
        client_ctx inside = *c;
        char keys[PATH_MAX + 8];
        snprintf(keys, sizeof keys, "%s/%s", cwd, c->key_dir);
        inside.key_dir = keys;
        uint64_t s0 = sent_bytes, r0 = recv_bytes, t0 = bench_now_ns();
        rc = cmd_upload(&inside, names[i]);
        uint64_t t1 = bench_now_ns();
        if (rc != QD_OK) break;
        row("sensorfile", param, (long)i, t1 - t0, sent_bytes - s0, recv_bytes - r0,
            comp_c2s, comp_s2c, readings, size);
        total_ns += t1 - t0;
        total_c2s += sent_bytes - s0;
        total_data += size;
        total_readings += readings;
    }
    if (chdir(cwd) != 0 && rc == QD_OK) rc = QD_ERR_FILE;
    for (size_t i = 0; i < n; i++) free(names[i]);
    if (rc == QD_OK)
        fprintf(stderr, "sensor %-20s %4zu files, %5ld readings, %8.1f B sent per reading, %.3f ms per reading\n",
                param, n, total_readings, (double)total_c2s / total_readings,
                total_ns / 1e6 / total_readings);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "usage: %s <host> <port> <out.csv> <id> [sensor_dir ...]\n", argv[0]);
        return 1;
    }
    client_ctx c = {
        .id = argv[4], .host = argv[1], .port = atoi(argv[2]),
        .key_dir = "keys", .data_dir = "client-data",
    };
    csv = fopen(argv[3], "w");
    if (!csv) { perror(argv[3]); return 1; }
    fprintf(csv, "kind,param,run,ns,c2s,s2c,computed_c2s,computed_s2c,readings,data_bytes\n");

    /* The commands print a line per success; keep stdout quiet, results go to stderr and the CSV. */
    if (!freopen("/dev/null", "w", stdout)) return 1;
    srand(1);

    int rc = run_register(&c);
    if (rc == QD_OK) rc = run_handshakes(&c, 1000);
    if (rc == QD_OK) rc = run_uploads(&c);
    for (int i = 5; rc == QD_OK && i < argc; i++) rc = run_sensor_dir(&c, argv[i]);

    fclose(csv);
    if (rc != QD_OK) {
        fprintf(stderr, "measurement failed: %s\n", qd_strerror(rc));
        return 1;
    }
    return 0;
}

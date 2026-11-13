/* make test: checks the parts that are real today (framing, byte order,
 * constants, bench clock) and that the stubs keep the contract's sizes.
 * Add tests here as real code lands. Owner: Shalom. */
#include "bench.h"
#include "framing.h"
#include "identity.h"
#include "protocol.h"
#include "reading.h"
#include "securenet.h"
#include "wire_cost.h"
#include <stdlib.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <errno.h>
#include <oqs/oqs.h>
#include <pthread.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures, checks;

#define CHECK(cond) do { \
    checks++; \
    if (!(cond)) { failures++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

static uint8_t buf[QD_FRAME_MAX];

static void test_byte_order(void)
{
    uint8_t b[8];
    put_u16(b, 0x1234);
    CHECK(b[0] == 0x12 && b[1] == 0x34);
    CHECK(get_u16(b) == 0x1234);
    put_u32(b, 0x01020304);
    CHECK(b[0] == 1 && b[3] == 4);
    CHECK(get_u32(b) == 0x01020304);
    put_u64(b, 0x0102030405060708ULL);
    CHECK(b[0] == 1 && b[7] == 8);
    CHECK(get_u64(b) == 0x0102030405060708ULL);
}

static void test_frame_round_trip(void)
{
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    const uint8_t msg[] = { 0x01 };
    CHECK(frame_write(sv[0], QD_F_HELLO, msg, sizeof msg) == QD_OK);
    uint8_t type = 0;
    size_t len = 0;
    CHECK(frame_read(sv[1], &type, buf, sizeof buf, &len) == QD_OK);
    CHECK(type == QD_F_HELLO && len == 1 && buf[0] == 0x01);

    /* empty payload */
    CHECK(frame_write(sv[0], QD_T_OK, NULL, 0) == QD_OK);
    CHECK(frame_read(sv[1], &type, buf, sizeof buf, &len) == QD_OK);
    CHECK(type == QD_T_OK && len == 0);

    /* largest allowed payload (socketpair buffer is too small to write it all at once,
     * so the writer runs in a child process) */
    pid_t pid = fork();
    if (pid == 0) {
        static uint8_t big[QD_FRAME_MAX - 1];
        memset(big, 0x5A, sizeof big);
        _exit(frame_write(sv[0], QD_F_SECURE, big, sizeof big) == QD_OK ? 0 : 1);
    }
    CHECK(frame_read(sv[1], &type, buf, sizeof buf, &len) == QD_OK);
    CHECK(type == QD_F_SECURE && len == QD_FRAME_MAX - 1);
    CHECK(buf[0] == 0x5A && buf[len - 1] == 0x5A);

    /* writer refuses a payload over the limit */
    CHECK(frame_write(sv[0], QD_F_SECURE, buf, QD_FRAME_MAX) == QD_ERR_TOO_LARGE);

    /* clean close between frames */
    close(sv[0]);
    CHECK(frame_read(sv[1], &type, buf, sizeof buf, &len) == QD_ERR_CLOSED);
    close(sv[1]);
}

static void test_frame_rejects_bad_headers(void)
{
    int sv[2];
    uint8_t hdr[4], type;
    size_t len;
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    put_u32(hdr, QD_FRAME_MAX + 1);              /* too large */
    CHECK(write_all(sv[0], hdr, 4) == QD_OK);
    CHECK(frame_read(sv[1], &type, buf, sizeof buf, &len) == QD_ERR_TOO_LARGE);

    put_u32(hdr, 0);                             /* zero length: no type byte */
    CHECK(write_all(sv[0], hdr, 4) == QD_OK);
    CHECK(frame_read(sv[1], &type, buf, sizeof buf, &len) == QD_ERR_FORMAT);

    put_u32(hdr, 11);                            /* 10-byte payload into a 4-byte buffer */
    CHECK(write_all(sv[0], hdr, 4) == QD_OK);
    uint8_t small[4];
    CHECK(frame_read(sv[1], &type, small, sizeof small, &len) == QD_ERR_BUFFER);

    close(sv[0]);
    close(sv[1]);

    /* connection dropped in the middle of a frame */
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    put_u32(hdr, 100);
    CHECK(write_all(sv[0], hdr, 4) == QD_OK);
    close(sv[0]);
    CHECK(frame_read(sv[1], &type, buf, sizeof buf, &len) == QD_ERR_IO);
    close(sv[1]);
}

static void test_constants_match_liboqs(void)
{
    CHECK(QD_KEM_PK_BYTES == OQS_KEM_ml_kem_768_length_public_key);
    CHECK(QD_KEM_CT_BYTES == OQS_KEM_ml_kem_768_length_ciphertext);
    CHECK(QD_SECRET_BYTES == OQS_KEM_ml_kem_768_length_shared_secret);
    CHECK(QD_SIG_PK_BYTES == OQS_SIG_ml_dsa_65_length_public_key);
    CHECK(QD_SIG_BYTES == OQS_SIG_ml_dsa_65_length_signature);
    CHECK(QD_RECORD_MAX == 371);
    CHECK(QD_BODY_MAX == 131054);
}

static void test_bench_clock(void)
{
    uint64_t a = bench_now_ns(), b = bench_now_ns();
    CHECK(b >= a);
}

static void test_identity_contract_sizes(void)
{
    /* Make a temporary folder for the test files. */
    char dir[] = "/tmp/qd_identity_XXXXXX";
    CHECK(mkdtemp(dir) != NULL);

    char key[256];
    char pub[256];
    char data[256];

    snprintf(key,  sizeof(key),  "%s/alice.key", dir);
    snprintf(pub,  sizeof(pub),  "%s/alice.pub", dir);
    snprintf(data, sizeof(data), "%s/notes.txt", dir);

    /* Test key generation and invalid usernames. */
    CHECK(id_generate_keys("alice", dir) == QD_OK);
    CHECK(id_generate_keys("alice", dir) == QD_ERR_FILE);
    CHECK(id_generate_keys("../bad", dir) == QD_ERR_ARG);
    CHECK(id_generate_keys(".", dir) == QD_ERR_ARG);
    CHECK(id_generate_keys("", dir) == QD_ERR_ARG);

    /* Check the private-key file permissions. */
    struct stat st;
    CHECK(stat(key, &st) == 0 && (st.st_mode & 0777) == 0600);

    uint8_t pk[QD_SIG_PK_BYTES];
    uint8_t sig[QD_SIG_BYTES];
    uint8_t hash[QD_SHA256_BYTES];
    uint8_t rec[QD_RECORD_MAX];

    /* Read the public key. */
    FILE *f = fopen(pub, "rb");
    CHECK(f != NULL);

    if (f == NULL) {
        return;
    }

    CHECK(fread(pk, 1, sizeof(pk), f) == sizeof(pk));
    CHECK(fclose(f) == 0);

    /* Sign and verify a message. */
    uint8_t msg[] = "hello";
    size_t sig_len = 0;
    size_t rec_len = 0;

    CHECK(id_sign(key, msg, sizeof(msg), sig, &sig_len) == QD_OK);
    CHECK(sig_len == QD_SIG_BYTES);
    CHECK(id_verify(pk, msg, sizeof(msg), sig, sig_len) == QD_OK);

    /* Change the message: verification should fail. */
    msg[0] ^= 1;
    CHECK(id_verify(pk, msg, sizeof(msg), sig, sig_len) == QD_ERR_CRYPTO);

    /* Restore the message, then change the signature. */
    msg[0] ^= 1;
    sig[0] ^= 1;
    CHECK(id_verify(pk, msg, sizeof(msg), sig, sig_len) == QD_ERR_CRYPTO);
    sig[0] ^= 1;

    /* The wrong public key should also fail. */
    uint8_t wrong[QD_SIG_PK_BYTES] = {0};
    CHECK(id_verify(wrong, msg, sizeof(msg), sig, sig_len) == QD_ERR_CRYPTO);

    /* A missing private-key file should return an error. */
    CHECK(id_sign("/no/such/key", msg, sizeof(msg), sig, &sig_len)
          == QD_ERR_FILE);

    /* Create a real file for the hash and record tests. */
    f = fopen(data, "wb");
    CHECK(f != NULL);

    if (f == NULL) {
        return;
    }

    CHECK(fwrite("abc", 1, 3, f) == 3);
    CHECK(fclose(f) == 0);

    /* Known SHA-256 fingerprint for the text "abc". */
    static const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    CHECK(id_hash_file(data, hash) == QD_OK);
    CHECK(memcmp(hash, expected, sizeof(expected)) == 0);

    /* Build the upload record and check its information. */
    CHECK(id_make_record("alice", data, rec, &rec_len) == QD_OK);
    CHECK(rec_len == 1 + 1 + 5 + 2 + 9 + 8 + 32 + 8);

    CHECK(rec[0] == QD_RECORD_VERSION && rec[1] == 5);
    CHECK(memcmp(rec + 2, "alice", 5) == 0);
    CHECK(get_u16(rec + 7) == 9);
    CHECK(memcmp(rec + 9, "notes.txt", 9) == 0);
    CHECK(get_u64(rec + 18) == 3);
    CHECK(memcmp(rec + 26, expected, 32) == 0);

    /* Sign the record, then check that changing it is caught. */
    CHECK(id_sign(key, rec, rec_len, sig, &sig_len) == QD_OK);
    CHECK(id_verify(pk, rec, rec_len, sig, sig_len) == QD_OK);

    rec[26] ^= 1;
    CHECK(id_verify(pk, rec, rec_len, sig, sig_len) == QD_ERR_CRYPTO);

    /* Change the file and check that its fingerprint changes. */
    f = fopen(data, "wb");
    CHECK(f != NULL);

    if (f != NULL) {
        CHECK(fwrite("abd", 1, 3, f) == 3);
        CHECK(fclose(f) == 0);
    }

    CHECK(id_hash_file(data, hash) == QD_OK);
    CHECK(memcmp(hash, expected, 32) != 0);
    CHECK(id_hash_file("/no/such/file", hash) == QD_ERR_FILE);
    CHECK(id_make_record("../alice", data, rec, &rec_len) == QD_ERR_ARG);

    /* Remove the temporary test files. */
    unlink(key);
    unlink(pub);
    unlink(data);
    rmdir(dir);
}

static int parse_str(const char *s, reading *r)
{
    return reading_parse(s, strlen(s), r);
}

static void test_reading_format_and_parse(void)
{
    reading r, back;
    char line[READING_LINE_MAX];
    size_t len;

    CHECK(parse_str("v1,field-a-01,42,1792345678,21.5,43,31\n", &r) == QD_OK);
    CHECK(strcmp(r.id, "field-a-01") == 0 && r.seq == 42 && r.time == 1792345678);
    CHECK(r.temp_tenths == 215 && r.humidity == 43 && r.soil == 31);
    CHECK(reading_format(&r, line, sizeof line, &len) == QD_OK);
    CHECK(len == 39 && strcmp(line, "v1,field-a-01,42,1792345678,21.5,43,31\n") == 0);

    r.temp_tenths = -5;                                   /* below zero keeps its sign */
    CHECK(reading_format(&r, line, sizeof line, &len) == QD_OK);
    CHECK(strstr(line, ",-0.5,") != NULL);
    CHECK(reading_parse(line, len, &back) == QD_OK && back.temp_tenths == -5);

    for (uint32_t seq = 0; seq < 200; seq++) {            /* simulated readings round-trip */
        CHECK(reading_simulate("s1", seq, 1792345678 + seq * 60, &r) == QD_OK);
        CHECK(reading_format(&r, line, sizeof line, &len) == QD_OK);
        CHECK(reading_parse(line, len, &back) == QD_OK && memcmp(&r, &back, sizeof r) == 0);
    }

    /* Each of these must be refused */
    const char *bad[] = {
        "v1,field-a-01,42,1792345678,21.5,43,31",         /* no newline */
        "v1,field-a-01,42,1792345678,21.5,43,31\r\n",     /* Windows line ending */
        "v2,field-a-01,42,1792345678,21.5,43,31\n",       /* unknown version */
        "v1,field a,42,1792345678,21.5,43,31\n",          /* space in ID */
        "v1,,42,1792345678,21.5,43,31\n",                 /* empty ID */
        "v1,field-a-01,042,1792345678,21.5,43,31\n",      /* leading zero */
        "v1,field-a-01,-1,1792345678,21.5,43,31\n",       /* negative seq */
        "v1,field-a-01,1000000,1792345678,21.5,43,31\n",  /* seq too big */
        "v1,field-a-01,42,0,21.5,43,31\n",                /* clock not set */
        "v1,field-a-01,42,1792345678,21,43,31\n",         /* no decimal */
        "v1,field-a-01,42,1792345678,21.55,43,31\n",      /* two decimals */
        "v1,field-a-01,42,1792345678,-0.0,43,31\n",       /* negative zero */
        "v1,field-a-01,42,1792345678,90.0,43,31\n",       /* temperature out of range */
        "v1,field-a-01,42,1792345678,21.5,101,31\n",      /* humidity over 100 */
        "v1,field-a-01,42,1792345678,21.5,43\n",          /* field missing */
        "v1,field-a-01,42,1792345678,21.5,43,31,7\n",     /* extra field */
        "v1,field-a-01,42,1792345678,21.5, 43,31\n",      /* space */
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        CHECK(parse_str(bad[i], &r) == QD_ERR_FORMAT);
}

static void test_reading_batch_checks(void)
{
    reading b[4];
    const char *why;
    for (uint32_t i = 0; i < 4; i++)
        CHECK(reading_simulate("s1", 10 + i, 1792345678 + i * 60, &b[i]) == QD_OK);
    CHECK(reading_check_batch(b, 4, &why) == QD_OK);

    b[2].seq = 13;                                        /* 10, 11, 13: gap */
    CHECK(reading_check_batch(b, 3, &why) == QD_ERR_FORMAT && strstr(why, "gap"));
    b[2].seq = 11;                                        /* 10, 11, 11: duplicate */
    CHECK(reading_check_batch(b, 3, &why) == QD_ERR_FORMAT && strstr(why, "duplicate"));
    b[2].seq = 9;                                         /* 10, 11, 9: out of order */
    CHECK(reading_check_batch(b, 3, &why) == QD_ERR_FORMAT && strstr(why, "order"));
    b[2].seq = 12;
    b[2].time = b[1].time - 1;                            /* clock went backwards */
    CHECK(reading_check_batch(b, 3, &why) == QD_ERR_FORMAT && strstr(why, "backwards"));
    b[2].time = b[1].time;                                /* same second is allowed */
    CHECK(reading_check_batch(b, 3, &why) == QD_OK);
    strcpy(b[3].id, "s2");                                /* two sensors in one file */
    CHECK(reading_check_batch(b, 4, &why) == QD_ERR_FORMAT && strstr(why, "sensor"));
    CHECK(reading_check_batch(b, 0, &why) == QD_ERR_ARG);
}

static void test_reading_filenames(void)
{
    char name[QD_NAME_MAX + 1];
    CHECK(reading_filename("field-a-01", 42, 42, name, sizeof name) == QD_OK);
    CHECK(strcmp(name, "field-a-01-000042.csv") == 0);
    CHECK(reading_filename("field-a-01", 40, 49, name, sizeof name) == QD_OK);
    CHECK(strcmp(name, "field-a-01-000040-000049.csv") == 0);
    CHECK(reading_filename("field-a-01", 49, 40, name, sizeof name) == QD_ERR_ARG);
    CHECK(reading_filename("../etc", 1, 1, name, sizeof name) == QD_ERR_ARG);
    CHECK(reading_filename("field-a-01", 1, 2, name, 8) == QD_ERR_BUFFER);
}

static void test_reading_file(void)
{
    char path[] = "/tmp/qd_reading_XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    const char good[] = "v1,s1,0,1792345678,21.5,43,31\nv1,s1,1,1792345738,21.6,44,31\n";
    CHECK(write(fd, good, sizeof good - 1) == (ssize_t)(sizeof good - 1));
    reading r[4];
    size_t n = 0;
    const char *why;
    CHECK(reading_read_file(path, r, 4, &n, &why) == QD_OK && n == 2);
    CHECK(reading_read_file(path, r, 1, &n, &why) == QD_ERR_BUFFER);

    const char gap[] = "v1,s1,3,1792345858,21.5,43,31\n";   /* appended: 0, 1, 3 */
    CHECK(write(fd, gap, sizeof gap - 1) == (ssize_t)(sizeof gap - 1));
    CHECK(reading_read_file(path, r, 4, &n, &why) == QD_ERR_FORMAT && strstr(why, "gap"));
    close(fd);
    unlink(path);
}

static void test_wire_cost(void)
{
    /* One 39-byte reading, 83-byte record: worked out by hand from PROTOCOL.md */
    CHECK(wire_upload_c2s(83, QD_SIG_BYTES, 39) == 3418 + 69 + 22);
    CHECK(wire_upload_c2s(83, QD_SIG_BYTES, 0) == 3418 + 22);              /* no chunks */
    CHECK(wire_upload_c2s(83, QD_SIG_BYTES, QD_CHUNK_MAX + 1) ==
          3418 + 2 * 30 + QD_CHUNK_MAX + 1 + 22);                          /* two chunks */
    CHECK(wire_upload_s2c() == 22);
    CHECK(wire_handshake_c2s() == 6 + 1093);
    CHECK(wire_handshake_s2c() == 1189);
    CHECK(wire_register_c2s(10) == 22 + 1 + 10 + 2 + 1952);
}

/* Exercise the real handlers with a scripted transport. Include the handler
 * source so the existing test target can substitute only sec_send/sec_recv. */
static int upload_test_send(sec_session *, uint8_t, const uint8_t *, size_t);
static int upload_test_recv(sec_session *, uint8_t *, uint8_t *, size_t, size_t *);
#define sec_send upload_test_send
#define sec_recv upload_test_recv
#include "../server/handlers.c"
#undef sec_send
#undef sec_recv

typedef struct {
    uint8_t type;
    size_t len;
    uint8_t body[32];
} upload_test_frame;
static upload_test_frame upload_input[3], upload_output[4];
static size_t upload_read, upload_sent;

static int upload_test_send(sec_session *s, uint8_t type, const uint8_t *body, size_t len)
{
    (void)s;
    if (upload_sent >= 4) return QD_ERR_BUFFER;
    upload_test_frame *out = &upload_output[upload_sent++];
    out->type = type;
    out->len = len;
    size_t copy = len < sizeof out->body ? len : sizeof out->body;
    if (copy) memcpy(out->body, body, copy);
    return QD_OK;
}

static int upload_test_recv(sec_session *s, uint8_t *type, uint8_t *body,
                            size_t cap, size_t *len)
{
    (void)s;
    if (upload_read == 3) return QD_ERR_CLOSED;
    const upload_test_frame *in = &upload_input[upload_read++];
    if (in->len > cap) return QD_ERR_BUFFER;
    *type = in->type;
    *len = in->len;
    if (*len) memcpy(body, in->body, *len);
    return QD_OK;
}

static void test_upload_replacement_and_single_error(void)
{
    char dir[] = "/tmp/qd-upload-XXXXXX";
    if (!mkdtemp(dir)) { CHECK(0); return; }
    char source[128], key[128], pub[128];
    snprintf(source, sizeof source, "%s/report.txt", dir);
    snprintf(key, sizeof key, "%s/chris.key", dir);
    snprintf(pub, sizeof pub, "%s/chris.pub", dir);
    int rc = id_generate_keys("chris", dir);
    CHECK(rc == QD_OK);
    if (rc != QD_OK) goto cleanup;

    server_conn conn = {.storage_dir = dir};
    uint8_t meta[META_MAX];
    char target[PATH_MAX] = "";
    const char *versions[] = {"old!", "new!", "bad!", "bad!"};
    for (size_t i = 0; i < 4; ++i) {
        FILE *f = fopen(source, "wb");
        CHECK(f != NULL);
        if (!f) break;
        CHECK(fwrite(versions[i], 1, 4, f) == 4);
        CHECK(fclose(f) == 0);
        size_t rlen, slen;
        rc = id_make_record("chris", source, meta + 2, &rlen);
        CHECK(rc == QD_OK);
        if (rc != QD_OK) break;
        rc = id_sign(key, meta + 2, rlen, meta + 4 + rlen, &slen);
        CHECK(rc == QD_OK);
        if (rc != QD_OK) break;
        put_u16(meta, rlen);
        put_u16(meta + 2 + rlen, slen);
        file_record r;
        if (!parse_meta(meta, 4 + rlen + slen, &r) ||
            !object_path(&conn, &r, target)) { CHECK(0); break; }

        upload_input[0] = (upload_test_frame){.type = QD_T_CHUNK, .len = i == 3 ? 13 : 10};
        upload_input[1] = (upload_test_frame){.type = QD_T_CHUNK, .len = 10};
        upload_input[2] = (upload_test_frame){.type = QD_T_UPLOAD_END};
        put_u64(upload_input[0].body, i == 2 ? 1 : 0);
        put_u64(upload_input[1].body, 2);
        memcpy(upload_input[0].body + 8, versions[i], 2);
        memcpy(upload_input[1].body + 8, versions[i] + 2, 2);
        upload_read = upload_sent = 0;
        CHECK(server_handle(&conn, QD_T_UPLOAD_BEGIN, meta, 4 + rlen + slen) == QD_OK);
        CHECK(upload_read == 3);
        CHECK(upload_sent == 1);
        CHECK(upload_output[0].type == (i < 2 ? QD_T_OK : QD_T_ERROR));
        if (i >= 2)
            CHECK(upload_output[0].body[0] == (i == 2 ? QD_E_BAD_FORMAT : QD_E_SIZE_MISMATCH));

        /* Download immediately: the only next replies should belong to it. */
        uint8_t request[] = {5, 'c','h','r','i','s', 0, 10, 'r','e','p','o','r','t','.','t','x','t'};
        upload_sent = 0;
        CHECK(server_handle(&conn, QD_T_DOWNLOAD_REQUEST, request, sizeof request) == QD_OK);
        CHECK(upload_sent == 3);
        CHECK(upload_output[0].type == QD_T_UPLOAD_BEGIN);
        CHECK(upload_output[1].type == QD_T_CHUNK && upload_output[1].len == 12);
        CHECK(!memcmp(upload_output[1].body + 8, i == 0 ? "old!" : "new!", 4));
        CHECK(upload_output[2].type == QD_T_UPLOAD_END);
    }
    if (target[0]) {
        char path[PATH_MAX + 6];
        snprintf(path, sizeof path, "%s/data", target); unlink(path);
        snprintf(path, sizeof path, "%s/meta", target); unlink(path);
        rmdir(target);
    }
cleanup:
    unlink(source); unlink(key); unlink(pub);
    CHECK(rmdir(dir) == 0); /* also catches leaked staging/backup directories */
}

static void test_secure_handshake_and_messages(void)
{
    int sv[2];
    int socket_rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    CHECK(socket_rc == 0);
    if (socket_rc != 0) return;

    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid < 0) {
        close(sv[0]);
        close(sv[1]);
        return;
    }
    if (pid == 0) {
        close(sv[0]);
        sec_session server = { .fd = sv[1] };
        int rc = sec_handshake_server(sv[1], &server);
        uint8_t type = 0, body[3] = {0};
        size_t len = 0;
        if (rc == QD_OK)
            rc = sec_recv(&server, &type, body, sizeof body, &len);
        int valid = rc == QD_OK && type == 0x55 && len == 3 &&
            memcmp(body, "hey", 3) == 0;
        if (valid)
            rc = sec_send(&server, 0x56, (const uint8_t *)"yes", 3);
        sec_close(&server);
        _exit(valid && rc == QD_OK ? 0 : 1);
    }
    close(sv[1]);

    sec_session client = { .fd = sv[0] };
    int rc = sec_handshake_client(sv[0], &client);
    CHECK(rc == QD_OK);
    if (rc == QD_OK) {
        uint8_t type = 0, body[3] = {0};
        size_t len = 0;
        CHECK(sec_send(&client, 0x55, (const uint8_t *)"hey", 3) == QD_OK);
        CHECK(sec_recv(&client, &type, body, sizeof body, &len) == QD_OK);
        CHECK(type == 0x56 && len == 3 && memcmp(body, "yes", 3) == 0);
    }
    sec_close(&client);
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_secure_rejects_modified_ciphertext(void)
{
    int handshake_fds[2];
    int socket_rc = socketpair(AF_UNIX, SOCK_STREAM, 0, handshake_fds);
    CHECK(socket_rc == 0);
    if (socket_rc != 0) return;

    int client_route[2] = {-1, -1}, server_route[2] = {-1, -1};
    int client_pair_rc = socketpair(AF_UNIX, SOCK_STREAM, 0, client_route);
    int server_pair_rc = socketpair(AF_UNIX, SOCK_STREAM, 0, server_route);
    CHECK(client_pair_rc == 0 && server_pair_rc == 0);
    if (client_pair_rc != 0 || server_pair_rc != 0) {
        close(handshake_fds[0]);
        close(handshake_fds[1]);
        if (client_pair_rc == 0) {
            close(client_route[0]);
            close(client_route[1]);
        }
        if (server_pair_rc == 0) {
            close(server_route[0]);
            close(server_route[1]);
        }
        return;
    }

    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid < 0) {
        close(handshake_fds[0]);
        close(handshake_fds[1]);
        close(client_route[0]);
        close(client_route[1]);
        close(server_route[0]);
        close(server_route[1]);
        return;
    }
    if (pid == 0) {
        close(handshake_fds[0]);
        close(client_route[0]);
        close(client_route[1]);
        close(server_route[0]);
        sec_session server = { .fd = handshake_fds[1] };
        int rc = sec_handshake_server(handshake_fds[1], &server);
        close(handshake_fds[1]);
        server.fd = server_route[1];
        if (rc == QD_OK) {
            uint8_t type = 0, body[16];
            size_t len = 0;
            rc = sec_recv(&server, &type, body, sizeof body, &len);
            /* a bad tag must also close the connection (PROTOCOL.md 5) */
            int closed = server.fd == -1;
            sec_close(&server);
            _exit(rc == QD_ERR_CRYPTO && closed ? 0 : 1);
        }
        sec_close(&server);
        _exit(1);
    }

    close(handshake_fds[1]);
    close(server_route[1]);
    sec_session client = { .fd = handshake_fds[0] };
    int client_rc = sec_handshake_client(client.fd, &client);
    CHECK(client_rc == QD_OK);
    if (client_rc != QD_OK) {
        sec_close(&client);
        close(client_route[0]);
        close(client_route[1]);
        close(server_route[0]);
        int status = 0;
        CHECK(waitpid(pid, &status, 0) == pid);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        return;
    }
    close(client.fd);
    client.fd = client_route[0];

    int send_rc = sec_send(&client, 0x57, (const uint8_t *)"tamper", 6);
    CHECK(send_rc == QD_OK);
    if (send_rc == QD_OK) {
        uint8_t frame_type = 0;
        size_t frame_len = 0;
        int rc = frame_read(client_route[1], &frame_type, buf, sizeof buf, &frame_len);
        CHECK(rc == QD_OK && frame_type == QD_F_SECURE);
        if (rc == QD_OK && frame_type == QD_F_SECURE &&
            frame_len > QD_GCM_TAG_BYTES) {
            buf[0] ^= 0x01;
            int relay_rc = frame_write(server_route[0], frame_type, buf, frame_len);
            CHECK(relay_rc == QD_OK);
        } else {
            CHECK(0 && "could not relay ciphertext for tamper test");
        }
    } else {
        CHECK(0 && "could not send ciphertext for tamper test");
    }

    sec_close(&client);
    close(client_route[1]);
    close(server_route[0]);
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

typedef struct {
    int listen_fd;
    int handshake_rc;
} tcp_handshake_peer;

static void *tcp_handshake_server(void *arg)
{
    tcp_handshake_peer *peer = arg;
    int fd = net_accept(peer->listen_fd);
    close(peer->listen_fd);
    if (fd < 0) {
        peer->handshake_rc = fd;
        return NULL;
    }

    sec_session s = { .fd = fd };
    peer->handshake_rc = sec_handshake_server(fd, &s);
    sec_close(&s);
    return NULL;
}

static void test_handshake_bad_version(void)
{
    int sv[2];
    int socket_rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    CHECK(socket_rc == 0);
    if (socket_rc != 0) return;

    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid < 0) {
        close(sv[0]);
        close(sv[1]);
        return;
    }
    if (pid == 0) {
        close(sv[0]);
        sec_session server = { .fd = sv[1] };
        int rc = sec_handshake_server(sv[1], &server);
        sec_close(&server);
        _exit(rc == QD_ERR_FORMAT ? 0 : 1);
    }
    close(sv[1]);

    uint8_t wrong_version = QD_PROTOCOL_VERSION + 1;
    CHECK(frame_write(sv[0], QD_F_HELLO, &wrong_version, 1) == QD_OK);
    uint8_t type = 0, body[1] = {0};
    size_t len = 0;
    CHECK(frame_read(sv[0], &type, body, sizeof body, &len) == QD_OK);
    CHECK(QD_E_BAD_VERSION == 0x09);
    CHECK(type == QD_F_ERROR && len == 1 && body[0] == 0x09);

    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(sv[0]);
}

static int compare_u64(const void *a, const void *b)
{
    uint64_t left = *(const uint64_t *)a;
    uint64_t right = *(const uint64_t *)b;
    return (left > right) - (left < right);
}

static int measure_handshakes(size_t runs)
{
    uint64_t *samples = calloc(runs, sizeof *samples);
    if (!samples) return 1;

    for (size_t i = 0; i < runs; i++) {
        int listen_fd = net_listen(0);
        if (listen_fd < 0) {
            fprintf(stderr, "net_listen: %s\n", qd_strerror(listen_fd));
            free(samples);
            return 1;
        }

        struct sockaddr_storage address;
        socklen_t address_len = sizeof address;
        if (getsockname(listen_fd, (struct sockaddr *)&address, &address_len) != 0) {
            perror("getsockname");
            close(listen_fd);
            free(samples);
            return 1;
        }
        char host[INET6_ADDRSTRLEN];
        int port;
        if (address.ss_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)&address;
            strcpy(host, "127.0.0.1");
            port = ntohs(addr->sin_port);
        } else if (address.ss_family == AF_INET6) {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&address;
            strcpy(host, "::1");
            port = ntohs(addr->sin6_port);
        } else {
            fprintf(stderr, "unexpected listener address family\n");
            close(listen_fd);
            free(samples);
            return 1;
        }

        int client_fd = net_connect(host, port);
        if (client_fd < 0) {
            fprintf(stderr, "net_connect: %s\n", qd_strerror(client_fd));
            close(listen_fd);
            free(samples);
            return 1;
        }

        tcp_handshake_peer peer = { .listen_fd = listen_fd };
        pthread_t thread;
        int thread_rc = pthread_create(&thread, NULL, tcp_handshake_server, &peer);
        if (thread_rc != 0) {
            fprintf(stderr, "pthread_create: %s\n", strerror(thread_rc));
            close(client_fd);
            close(listen_fd);
            free(samples);
            return 1;
        }

        sec_session client = { .fd = client_fd };
        uint64_t start = bench_now_ns();
        int rc = sec_handshake_client(client_fd, &client);
        uint64_t end = bench_now_ns();
        int join_rc = pthread_join(thread, NULL);
        sec_close(&client);
        if (rc != QD_OK || join_rc != 0 || peer.handshake_rc != QD_OK) {
            fprintf(stderr, "handshake measurement failed: client=%s, server=%s\n",
                    qd_strerror(rc), qd_strerror(peer.handshake_rc));
            free(samples);
            return 1;
        }
        samples[i] = end - start;
    }

    qsort(samples, runs, sizeof *samples, compare_u64);
    uint64_t median = runs % 2
        ? samples[runs / 2]
        : samples[runs / 2 - 1] + (samples[runs / 2] - samples[runs / 2 - 1]) / 2;
    bench_log("handshake_runs", runs, "runs");
    bench_log("handshake_median", median, "ns");
    bench_log("handshake_c2s_bytes", wire_handshake_c2s(), "B");
    bench_log("handshake_s2c_bytes", wire_handshake_s2c(), "B");
    bench_log("handshake_total_bytes",
              wire_handshake_c2s() + wire_handshake_s2c(), "B");
    free(samples);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--measure-handshake") == 0) {
        size_t runs = 1000;
        if (argc > 3) {
            fprintf(stderr, "usage: %s [--measure-handshake [runs]]\n", argv[0]);
            return 2;
        }
        if (argc == 3) {
            char *end = NULL;
            errno = 0;
            unsigned long value = strtoul(argv[2], &end, 10);
            if (errno || end == argv[2] || *end || value == 0 ||
                value > 100000 || value > SIZE_MAX) {
                fprintf(stderr, "runs must be between 1 and 100000\n");
                return 2;
            }
            runs = (size_t)value;
        }
        return measure_handshakes(runs);
    }
    if (argc != 1) {
        fprintf(stderr, "usage: %s [--measure-handshake [runs]]\n", argv[0]);
        return 2;
    }

    test_byte_order();
    test_frame_round_trip();
    test_frame_rejects_bad_headers();
    test_constants_match_liboqs();
    test_bench_clock();
    test_identity_contract_sizes();
    test_reading_format_and_parse();
    test_reading_batch_checks();
    test_reading_filenames();
    test_reading_file();
    test_wire_cost();
    test_secure_handshake_and_messages();
    test_secure_rejects_modified_ciphertext();
    test_handshake_bad_version();
    test_upload_replacement_and_single_error();

    printf("%d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}

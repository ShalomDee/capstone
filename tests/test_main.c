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

#include <oqs/oqs.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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
    uint8_t sig[QD_SIG_BYTES], rec[QD_RECORD_MAX], pk[QD_SIG_PK_BYTES] = {0};
    size_t sig_len = 0, rec_len = 0;
    const uint8_t msg[] = "hello";

    CHECK(id_sign("keys/test.key", msg, sizeof msg, sig, &sig_len) == QD_OK);
    CHECK(sig_len == QD_SIG_BYTES);
    CHECK(id_verify(pk, msg, sizeof msg, sig, sig_len) == QD_OK);

    CHECK(id_make_record("alice", "notes.txt", rec, &rec_len) == QD_OK);
    CHECK(rec_len == 1 + 1 + 5 + 2 + 9 + 8 + 32 + 8);
    CHECK(rec[0] == QD_RECORD_VERSION && rec[1] == 5);
    CHECK(memcmp(rec + 2, "alice", 5) == 0);
    CHECK(get_u16(rec + 7) == 9);
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

int main(void)
{
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

    printf("%d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}

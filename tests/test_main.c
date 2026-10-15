/* make test: checks the parts that are real today (framing, byte order,
 * constants, bench clock) and that the stubs keep the contract's sizes.
 * Add tests here as real code lands. Owner: Shalom. */
#include "bench.h"
#include "framing.h"
#include "identity.h"
#include "protocol.h"
#include "securenet.h"

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

int main(void)
{
    test_byte_order();
    test_frame_round_trip();
    test_frame_rejects_bad_headers();
    test_constants_match_liboqs();
    test_bench_clock();
    test_identity_contract_sizes();

    printf("%d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}

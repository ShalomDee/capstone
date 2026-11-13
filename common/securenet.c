#include "securenet.h"
#include "framing.h"
#include "protocol.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int set_nodelay(int fd)
{
    int enabled = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof enabled) == 0
        ? QD_OK : QD_ERR_IO;
}

int net_listen(int port)
{
    if (port < 0 || port > 65535) return QD_ERR_ARG;

    char service[6];
    snprintf(service, sizeof service, "%d", port);
    struct addrinfo hints = {0}, *addresses = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, service, &hints, &addresses) != 0) return QD_ERR_IO;

    int fd = -1;
    for (struct addrinfo *addr = addresses; addr; addr = addr->ai_next) {
        fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (fd < 0) continue;

        int enabled = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof enabled) != 0 ||
            bind(fd, addr->ai_addr, addr->ai_addrlen) != 0 ||
            listen(fd, SOMAXCONN) != 0) {
            close(fd);
            fd = -1;
            continue;
        }
        break;
    }

    freeaddrinfo(addresses);
    return fd < 0 ? QD_ERR_IO : fd;
}

int net_accept(int listen_fd)
{
    if (listen_fd < 0) return QD_ERR_ARG;

    int fd;
    do {
        fd = accept(listen_fd, NULL, NULL);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) return QD_ERR_IO;

    if (set_nodelay(fd) != QD_OK) {
        close(fd);
        return QD_ERR_IO;
    }
    return fd;
}

int net_connect(const char *host, int port)
{
    if (!host || !host[0] || port < 1 || port > 65535) return QD_ERR_ARG;

    char service[6];
    snprintf(service, sizeof service, "%d", port);
    struct addrinfo hints = {0}, *addresses = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, service, &hints, &addresses) != 0) return QD_ERR_IO;

    int fd = -1;
    for (struct addrinfo *addr = addresses; addr; addr = addr->ai_next) {
        fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, addr->ai_addr, addr->ai_addrlen) == 0 &&
            set_nodelay(fd) == QD_OK) {
            break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(addresses);
    return fd < 0 ? QD_ERR_IO : fd;
}

static int derive_hkdf_key(const uint8_t secret[QD_SECRET_BYTES],
                           const uint8_t salt[QD_SHA256_BYTES],
                           const char *info, uint8_t key[QD_AES_KEY_BYTES])
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return QD_ERR_CRYPTO;
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) return QD_ERR_CRYPTO;

    char digest[] = "SHA256";
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                          (void *)secret, QD_SECRET_BYTES),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                          (void *)salt, QD_SHA256_BYTES),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                          (void *)info, strlen(info)),
        OSSL_PARAM_construct_end()
    };
    int ok = EVP_KDF_derive(ctx, key, QD_AES_KEY_BYTES, params);
    EVP_KDF_CTX_free(ctx);
    return ok == 1 ? QD_OK : QD_ERR_CRYPTO;
}

static int install_keys(sec_session *s,
                        const uint8_t secret[QD_SECRET_BYTES],
                        const uint8_t public_key[QD_KEM_PK_BYTES],
                        const uint8_t ciphertext[QD_KEM_CT_BYTES],
                        int is_client)
{
    uint8_t transcript[QD_KEM_PK_BYTES + QD_KEM_CT_BYTES];
    uint8_t salt[QD_SHA256_BYTES];
    uint8_t c2s[QD_AES_KEY_BYTES], s2c[QD_AES_KEY_BYTES];
    unsigned int salt_len = 0;
    memcpy(transcript, public_key, QD_KEM_PK_BYTES);
    memcpy(transcript + QD_KEM_PK_BYTES, ciphertext, QD_KEM_CT_BYTES);

    int rc = QD_ERR_CRYPTO;
    if (EVP_Digest(transcript, sizeof transcript, salt, &salt_len,
                   EVP_sha256(), NULL) != 1 || salt_len != QD_SHA256_BYTES)
        goto done;
    if (derive_hkdf_key(secret, salt, "quantumdrive v1 c2s", c2s) != QD_OK ||
        derive_hkdf_key(secret, salt, "quantumdrive v1 s2c", s2c) != QD_OK)
        goto done;

    memcpy(s->send_key, is_client ? c2s : s2c, QD_AES_KEY_BYTES);
    memcpy(s->recv_key, is_client ? s2c : c2s, QD_AES_KEY_BYTES);
    s->send_ctr = 0;
    s->recv_ctr = 0;
    rc = QD_OK;

done:
    OPENSSL_cleanse(transcript, sizeof transcript);
    OPENSSL_cleanse(salt, sizeof salt);
    OPENSSL_cleanse(c2s, sizeof c2s);
    OPENSSL_cleanse(s2c, sizeof s2c);
    return rc;
}

static void reset_session(sec_session *s, int fd)
{
    OPENSSL_cleanse(s, sizeof *s);
    s->fd = fd;
}

int sec_handshake_client(int fd, sec_session *s)
{
    if (fd < 0 || !s) return QD_ERR_ARG;
    reset_session(s, fd);

    uint8_t version = QD_PROTOCOL_VERSION;
    int rc = frame_write(fd, QD_F_HELLO, &version, sizeof version);
    if (rc != QD_OK) return rc;

    uint8_t type, payload[QD_KEM_PK_BYTES];
    size_t len = 0;
    rc = frame_read(fd, &type, payload, sizeof payload, &len);
    if (rc != QD_OK) return rc;
    if (type == QD_F_ERROR && len == 1 && payload[0] == QD_E_BAD_VERSION)
        return QD_ERR_PEER;
    if (type != QD_F_KEM_PUBKEY || len != QD_KEM_PK_BYTES)
        return QD_ERR_FORMAT;

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return QD_ERR_CRYPTO;
    if (kem->length_public_key != QD_KEM_PK_BYTES ||
        kem->length_ciphertext != QD_KEM_CT_BYTES ||
        kem->length_shared_secret != QD_SECRET_BYTES) {
        OQS_KEM_free(kem);
        return QD_ERR_CRYPTO;
    }

    uint8_t ciphertext[QD_KEM_CT_BYTES], secret[QD_SECRET_BYTES];
    rc = OQS_KEM_encaps(kem, ciphertext, secret, payload) == OQS_SUCCESS
        ? QD_OK : QD_ERR_CRYPTO;
    OQS_KEM_free(kem);
    if (rc == QD_OK) rc = frame_write(fd, QD_F_KEM_CIPHERTEXT,
                                       ciphertext, sizeof ciphertext);
    if (rc == QD_OK)
        rc = install_keys(s, secret, payload, ciphertext, 1);
    OPENSSL_cleanse(secret, sizeof secret);
    OPENSSL_cleanse(ciphertext, sizeof ciphertext);
    return rc;
}

int sec_handshake_server(int fd, sec_session *s)
{
    if (fd < 0 || !s) return QD_ERR_ARG;
    reset_session(s, fd);

    uint8_t type, payload[QD_KEM_CT_BYTES];
    size_t len = 0;
    int rc = frame_read(fd, &type, payload, sizeof payload, &len);
    if (rc != QD_OK) return rc;
    if (type != QD_F_HELLO || len != 1) return QD_ERR_FORMAT;
    if (payload[0] != QD_PROTOCOL_VERSION) {
        uint8_t error = QD_E_BAD_VERSION;
        rc = frame_write(fd, QD_F_ERROR, &error, sizeof error);
        return rc == QD_OK ? QD_ERR_FORMAT : rc;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return QD_ERR_CRYPTO;
    if (kem->length_public_key != QD_KEM_PK_BYTES ||
        kem->length_ciphertext != QD_KEM_CT_BYTES ||
        kem->length_shared_secret != QD_SECRET_BYTES) {
        OQS_KEM_free(kem);
        return QD_ERR_CRYPTO;
    }

    uint8_t public_key[QD_KEM_PK_BYTES];
    uint8_t secret_key[OQS_KEM_ml_kem_768_length_secret_key];
    uint8_t secret[QD_SECRET_BYTES];
    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        rc = QD_ERR_CRYPTO;
        goto done;
    }
    rc = frame_write(fd, QD_F_KEM_PUBKEY, public_key, sizeof public_key);
    if (rc != QD_OK) goto done;

    rc = frame_read(fd, &type, payload, sizeof payload, &len);
    if (rc != QD_OK) goto done;
    if (type != QD_F_KEM_CIPHERTEXT || len != QD_KEM_CT_BYTES) {
        rc = QD_ERR_FORMAT;
        goto done;
    }
    if (OQS_KEM_decaps(kem, secret, payload, secret_key) != OQS_SUCCESS) {
        rc = QD_ERR_CRYPTO;
        goto done;
    }
    rc = install_keys(s, secret, public_key, payload, 0);

done:
    OPENSSL_cleanse(secret_key, sizeof secret_key);
    OPENSSL_cleanse(secret, sizeof secret);
    OPENSSL_cleanse(public_key, sizeof public_key);
    OQS_KEM_free(kem);
    return rc;
}

static void make_nonce(uint64_t counter, uint8_t nonce[QD_GCM_NONCE_BYTES])
{
    memset(nonce, 0, 4);
    put_u64(nonce + 4, counter);
}

int sec_send(sec_session *s, uint8_t type, const uint8_t *body, size_t len)
{
    if (!s || s->fd < 0 || (len && !body)) return QD_ERR_ARG;
    if (len > QD_BODY_MAX) return QD_ERR_TOO_LARGE;
    if (s->send_ctr == UINT64_MAX) return QD_ERR_CRYPTO;

    size_t plain_len = len + 1;
    size_t frame_len = plain_len + QD_GCM_TAG_BYTES;
    uint8_t *plain = malloc(plain_len);
    uint8_t *encrypted = malloc(frame_len);
    if (!plain || !encrypted) {
        free(plain);
        free(encrypted);
        return QD_ERR_IO;
    }
    plain[0] = type;
    if (len) memcpy(plain + 1, body, len);

    uint8_t nonce[QD_GCM_NONCE_BYTES];
    make_nonce(s->send_ctr, nonce);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len = 0, final_len = 0;
    int ok = ctx &&
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof nonce, NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, s->send_key, nonce) == 1 &&
        EVP_EncryptUpdate(ctx, encrypted, &out_len, plain, (int)plain_len) == 1 &&
        EVP_EncryptFinal_ex(ctx, encrypted + out_len, &final_len) == 1 &&
        (size_t)(out_len + final_len) == plain_len &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, QD_GCM_TAG_BYTES,
                            encrypted + plain_len) == 1;
    EVP_CIPHER_CTX_free(ctx);

    int rc = ok ? frame_write(s->fd, QD_F_SECURE, encrypted, frame_len)
                : QD_ERR_CRYPTO;
    if (rc == QD_OK) s->send_ctr++;
    OPENSSL_cleanse(plain, plain_len);
    OPENSSL_cleanse(encrypted, frame_len);
    OPENSSL_cleanse(nonce, sizeof nonce);
    free(plain);
    free(encrypted);
    return rc;
}

int sec_recv(sec_session *s, uint8_t *type, uint8_t *buf, size_t cap, size_t *len)
{
    if (!s || s->fd < 0 || !type || !len || (cap && !buf)) return QD_ERR_ARG;
    if (s->recv_ctr == UINT64_MAX) return QD_ERR_CRYPTO;

    uint8_t encrypted[QD_FRAME_MAX - 1];
    uint8_t frame_type;
    size_t frame_len = 0;
    int rc = frame_read(s->fd, &frame_type, encrypted, sizeof encrypted, &frame_len);
    if (rc != QD_OK) return rc;
    if (frame_type != QD_F_SECURE || frame_len < QD_GCM_TAG_BYTES + 1)
        return QD_ERR_FORMAT;

    size_t plain_len = frame_len - QD_GCM_TAG_BYTES;
    size_t body_len = plain_len - 1;
    if (body_len > cap) return QD_ERR_BUFFER;
    uint8_t *plain = malloc(plain_len);
    if (!plain) return QD_ERR_IO;

    uint8_t nonce[QD_GCM_NONCE_BYTES];
    make_nonce(s->recv_ctr, nonce);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len = 0, final_len = 0;
    int ok = ctx &&
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof nonce, NULL) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, s->recv_key, nonce) == 1 &&
        EVP_DecryptUpdate(ctx, plain, &out_len, encrypted, (int)plain_len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, QD_GCM_TAG_BYTES,
                            encrypted + plain_len) == 1 &&
        EVP_DecryptFinal_ex(ctx, plain + out_len, &final_len) == 1 &&
        (size_t)(out_len + final_len) == plain_len;
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(nonce, sizeof nonce);

    if (!ok) {
        OPENSSL_cleanse(plain, plain_len);
        free(plain);
        return QD_ERR_CRYPTO;
    }

    *type = plain[0];
    if (body_len) memcpy(buf, plain + 1, body_len);
    *len = body_len;
    s->recv_ctr++;
    OPENSSL_cleanse(plain, plain_len);
    free(plain);
    return QD_OK;
}

void sec_close(sec_session *s)
{
    if (!s) return;
    if (s->fd >= 0) close(s->fd);
    OPENSSL_cleanse(s, sizeof *s);
    s->fd = -1;
}

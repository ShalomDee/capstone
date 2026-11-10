/*
 * securenet.c — QuantumDrive secure pipe (docs/PROTOCOL.md v1, sections 2-5)
 *
 * Stack: liboqs ML-KEM-768 for the handshake, OpenSSL for SHA-256,
 * HKDF-SHA256 and AES-256-GCM.
 *
 * Frame:      length (4, BE) | type (1) | payload (length - 1)
 *             1 <= length <= 131,072; anything else closes without reading on.
 *
 * Handshake:  1. C -> S  HELLO          [0x01]
 *             2. S -> C  KEM_PUBKEY     pk (1184), fresh per connection
 *             3. C -> S  KEM_CIPHERTEXT ct (1088)
 *             Bad version: server sends ERROR [0x09] unencrypted, then closes.
 *             Any other handshake problem: close with no reply.
 *
 * Keys:       th      = SHA-256(pk || ct)
 *             key_c2s = HKDF-SHA256(ss, salt = th, info = "quantumdrive v1 c2s", 32)
 *             key_s2c = HKDF-SHA256(ss, salt = th, info = "quantumdrive v1 s2c", 32)
 *
 * SECURE:     payload = AES-256-GCM(app type (1) | body) || tag (16), no AAD
 *             nonce   = 00 00 00 00 | 8-byte BE counter, one counter per direction
 *             Tag failure or counter overflow closes the connection.
 *
 * Connection closing: whenever the spec says to close, this file closes the
 * socket itself and sets s->fd = -1, so a later sec_close() is still safe.
 * The caller must not close the fd it passed in after a failed handshake.
 *
 * Link with: -loqs -lcrypto
 *
 */
#include "securenet.h"
#include "protocol.h"
#include "framing.h"

#include <oqs/oqs.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* PROTOCOL.md section 2 */
#define ERR_UNSUPPORTED_VER 0x09

/* sections 3-5 */
#define KEM_PK_LEN          QD_KEM_PK_BYTES
#define KEM_CT_LEN          QD_KEM_CT_BYTES
#define KEM_SS_LEN          QD_SECRET_BYTES
#define TH_LEN              QD_SHA256_BYTES
#define KEY_LEN             QD_AES_KEY_BYTES
#define NONCE_LEN           QD_GCM_NONCE_BYTES
#define TAG_LEN             QD_GCM_TAG_BYTES
#define MAX_BODY_LEN        QD_BODY_MAX
#define INFO_C2S            "quantumdrive v1 c2s"
#define INFO_S2C            "quantumdrive v1 s2c"

#define QD_KEM_ALG OQS_KEM_alg_ml_kem_768

static void make_nonce(uint8_t nonce[NONCE_LEN], uint64_t counter)
{
    memset(nonce, 0, 4);
    put_u64(nonce + 4, counter);
}

/* handshake frames have one exact type and payload size */
static int read_exact_frame(int fd, uint8_t want_type, uint8_t *buf, size_t want_len)
{
    uint8_t type;
    size_t plen;
    int rc = frame_read(fd, &type, buf, want_len, &plen);
    if (rc != QD_OK) return rc;
    if (type != want_type || plen != want_len) return QD_ERR_FORMAT;
    return QD_OK;
}

/* ------------------------------------------------------------ session state */

static void wipe_keys(sec_session *s)
{
    OPENSSL_cleanse(s->send_key, sizeof s->send_key);
    OPENSSL_cleanse(s->recv_key, sizeof s->recv_key);
    s->send_ctr = s->recv_ctr = 0;
}

/* the spec's "close the connection": drop keys, close the socket */
static void kill_session(sec_session *s)
{
    wipe_keys(s);
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
}

/* ---------------------------------------------------- key derivation (sec 4) */

static int hkdf_sha256(uint8_t *out, size_t out_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *ikm, size_t ikm_len,
                       const char *info)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    int ok = pctx != NULL &&
        EVP_PKEY_derive_init(pctx) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char *)info,
                                    (int)strlen(info)) > 0 &&   /* no trailing 0 */
        EVP_PKEY_derive(pctx, out, &out_len) > 0;
    EVP_PKEY_CTX_free(pctx);
    return ok ? QD_OK : QD_ERR_CRYPTO;
}

static int derive_keys(sec_session *s, const uint8_t ss[KEM_SS_LEN],
                       const uint8_t pk[KEM_PK_LEN], const uint8_t ct[KEM_CT_LEN],
                       int is_client)
{
    uint8_t th[TH_LEN], c2s[KEY_LEN], s2c[KEY_LEN];
    unsigned int th_len = 0;
    int rc = QD_ERR_CRYPTO;

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md ||
        EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md, pk, KEM_PK_LEN) != 1 ||
        EVP_DigestUpdate(md, ct, KEM_CT_LEN) != 1 ||
        EVP_DigestFinal_ex(md, th, &th_len) != 1 || th_len != TH_LEN)
        goto out;

    if (hkdf_sha256(c2s, KEY_LEN, th, TH_LEN, ss, KEM_SS_LEN, INFO_C2S) != QD_OK ||
        hkdf_sha256(s2c, KEY_LEN, th, TH_LEN, ss, KEM_SS_LEN, INFO_S2C) != QD_OK)
        goto out;

    memcpy(s->send_key, is_client ? c2s : s2c, KEY_LEN);
    memcpy(s->recv_key, is_client ? s2c : c2s, KEY_LEN);
    s->send_ctr = s->recv_ctr = 0;
    rc = QD_OK;

out:
    EVP_MD_CTX_free(md);
    OPENSSL_cleanse(c2s, sizeof c2s);
    OPENSSL_cleanse(s2c, sizeof s2c);
    return rc;
}

/* ------------------------------------------------------------- networking */

int net_listen(int port)
{
    if (port < 0 || port > 65535) return QD_ERR_ARG;

    char portstr[8];
    snprintf(portstr, sizeof portstr, "%d", port);

    struct addrinfo hints, *res = NULL, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    if (getaddrinfo(NULL, portstr, &hints, &res) != 0) return QD_ERR_IO;

    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        int one = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) < 0) {
            close(fd);
            fd = -1;
            continue;
        }

        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 &&
            listen(fd, SOMAXCONN) == 0)
            break;

        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd >= 0 ? fd : QD_ERR_IO;
}

int net_accept(int listen_fd)
{
    if (listen_fd < 0) return QD_ERR_ARG;

    int fd;
    do {
        fd = accept(listen_fd, NULL, NULL);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) return QD_ERR_IO;

    int one = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) < 0) {
        close(fd);
        return QD_ERR_IO;
    }
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    return fd;
}

int net_connect(const char *host, int port)
{
    if (!host || port <= 0 || port > 65535) return QD_ERR_ARG;

    char portstr[8];
    snprintf(portstr, sizeof portstr, "%d", port);

    struct addrinfo hints, *res = NULL, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, portstr, &hints, &res) != 0) return QD_ERR_IO;

    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        int r;
        do {
            r = connect(fd, ai->ai_addr, ai->ai_addrlen);
        } while (r < 0 && errno == EINTR);
        if (r == 0) break;

        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return QD_ERR_IO;

    int one = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) < 0) {
        close(fd);
        return QD_ERR_IO;
    }
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    return fd;
}

/* ---------------------------------------------------------- handshake (sec 3) */

static OQS_KEM *new_kem(void)
{
    OQS_KEM *kem = OQS_KEM_new(QD_KEM_ALG);
    if (kem && (kem->length_public_key != KEM_PK_LEN ||
                kem->length_ciphertext != KEM_CT_LEN ||
                kem->length_shared_secret != KEM_SS_LEN)) {
        OQS_KEM_free(kem);
        return NULL;
    }
    return kem;
}

int sec_handshake_client(int fd, sec_session *s)
{
    if (fd < 0 || !s) return QD_ERR_ARG;

    memset(s, 0, sizeof *s);
    s->fd = fd;

    uint8_t pk[KEM_PK_LEN], ct[KEM_CT_LEN], ss[KEM_SS_LEN];
    int rc;

    OQS_KEM *kem = new_kem();
    if (!kem) { rc = QD_ERR_CRYPTO; goto fail; }

    /* 1. HELLO */
    uint8_t ver = QD_PROTOCOL_VERSION;
    if ((rc = frame_write(fd, QD_F_HELLO, &ver, 1)) != QD_OK) goto fail;

    /* 2. KEM_PUBKEY, or ERROR [0x09] if the server rejects our version */
    uint8_t type, response[KEM_PK_LEN];
    size_t plen;
    if ((rc = frame_read(fd, &type, response, sizeof response, &plen)) != QD_OK) goto fail;
    if (type == QD_F_ERROR && plen == 1) {
        rc = (response[0] == ERR_UNSUPPORTED_VER) ? QD_ERR_PEER : QD_ERR_FORMAT;
        goto fail;
    }
    if (type != QD_F_KEM_PUBKEY || plen != KEM_PK_LEN) { rc = QD_ERR_FORMAT; goto fail; }
    memcpy(pk, response, KEM_PK_LEN);

    /* 3. encapsulate to the server's key, send the ciphertext */
    if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) { rc = QD_ERR_CRYPTO; goto fail; }
    if ((rc = frame_write(fd, QD_F_KEM_CIPHERTEXT, ct, KEM_CT_LEN)) != QD_OK) goto fail;

    if ((rc = derive_keys(s, ss, pk, ct, 1)) != QD_OK) goto fail;

    rc = QD_OK;
    goto done;

fail:
    kill_session(s);
done:
    OPENSSL_cleanse(ss, sizeof ss);
    OQS_KEM_free(kem);
    return rc;
}

int sec_handshake_server(int fd, sec_session *s)
{
    if (fd < 0 || !s) return QD_ERR_ARG;

    memset(s, 0, sizeof *s);
    s->fd = fd;

    uint8_t pk[KEM_PK_LEN], ct[KEM_CT_LEN], ss[KEM_SS_LEN];
    uint8_t *sk = NULL;
    int rc;

    OQS_KEM *kem = new_kem();
    if (!kem) { rc = QD_ERR_CRYPTO; goto fail; }

    /* 1. HELLO: exactly one version byte */
    uint8_t ver;
    if ((rc = read_exact_frame(fd, QD_F_HELLO, &ver, 1)) != QD_OK) goto fail;
    if (ver != QD_PROTOCOL_VERSION) {
        uint8_t code = ERR_UNSUPPORTED_VER;
        frame_write(fd, QD_F_ERROR, &code, 1);    /* best effort, then close */
        rc = QD_ERR_PEER;
        goto fail;
    }

    /* 2. fresh keypair for this connection, send the public key */
    sk = malloc(kem->length_secret_key);
    if (!sk) { rc = QD_ERR_IO; goto fail; }
    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) { rc = QD_ERR_CRYPTO; goto fail; }
    if ((rc = frame_write(fd, QD_F_KEM_PUBKEY, pk, KEM_PK_LEN)) != QD_OK) goto fail;

    /* 3. ciphertext in, open it, then throw the private key away */
    if ((rc = read_exact_frame(fd, QD_F_KEM_CIPHERTEXT, ct, KEM_CT_LEN)) != QD_OK) goto fail;
    int dec = OQS_KEM_decaps(kem, ss, ct, sk);
    OQS_MEM_secure_free(sk, kem->length_secret_key);
    sk = NULL;
    if (dec != OQS_SUCCESS) { rc = QD_ERR_CRYPTO; goto fail; }

    if ((rc = derive_keys(s, ss, pk, ct, 0)) != QD_OK) goto fail;

    rc = QD_OK;
    goto done;

fail:
    kill_session(s);
done:
    if (sk) OQS_MEM_secure_free(sk, kem->length_secret_key);
    OPENSSL_cleanse(ss, sizeof ss);
    OQS_KEM_free(kem);
    return rc;
}

/* ------------------------------------------------------ SECURE frames (sec 5) */

int sec_send(sec_session *s, uint8_t type, const uint8_t *body, size_t len)
{
    if (!s || s->fd < 0) return QD_ERR_ARG;
    if (len > MAX_BODY_LEN) return QD_ERR_TOO_LARGE;
    if (len > 0 && !body)   return QD_ERR_ARG;

    /* counter would pass 2^64 - 1: sender closes */
    if (s->send_ctr == UINT64_MAX) { kill_session(s); return QD_ERR_FORMAT; }

    size_t pt_len = 1 + len;
    size_t payload_len = pt_len + TAG_LEN;
    uint8_t *buf = malloc(payload_len);
    if (!buf) return QD_ERR_IO;
    buf[0] = type;
    if (len) memcpy(buf + 1, body, len);

    uint8_t nonce[NONCE_LEN];
    make_nonce(nonce, s->send_ctr);

    int rc = QD_ERR_CRYPTO, outl = 0, finl = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx &&
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, s->send_key, nonce) == 1 &&
        EVP_EncryptUpdate(ctx, buf, &outl, buf, (int)pt_len) == 1 &&
        EVP_EncryptFinal_ex(ctx, buf + outl, &finl) == 1 &&
        (size_t)(outl + finl) == pt_len &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, buf + pt_len) == 1) {
        s->send_ctr++;
        rc = frame_write(s->fd, QD_F_SECURE, buf, payload_len);
    }

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(buf, payload_len);
    free(buf);
    return rc;
}

int sec_recv(sec_session *s, uint8_t *type, uint8_t *buf, size_t cap, size_t *len)
{
    if (!s || s->fd < 0 || !type || !len) return QD_ERR_ARG;
    if (cap > 0 && !buf) return QD_ERR_ARG;

    size_t frame_cap = QD_FRAME_MAX - 1;
    uint8_t *tmp = malloc(frame_cap);
    if (!tmp) { kill_session(s); return QD_ERR_IO; }

    uint8_t ftype;
    size_t plen;
    int rc = frame_read(s->fd, &ftype, tmp, frame_cap, &plen);
    if (rc != QD_OK) {
        kill_session(s);
        OPENSSL_cleanse(tmp, frame_cap);
        free(tmp);
        return rc;
    }

    /* after the handshake every frame must be SECURE with room for app type + tag */
    if (ftype != QD_F_SECURE || plen < 1 + TAG_LEN) {
        kill_session(s);
        rc = QD_ERR_FORMAT;
        goto out;
    }

    size_t ct_len = plen - TAG_LEN;
    uint8_t nonce[NONCE_LEN];
    make_nonce(nonce, s->recv_ctr);

    int outl = 0, finl = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok = ctx &&
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, s->recv_key, nonce) == 1 &&
        EVP_DecryptUpdate(ctx, tmp, &outl, tmp, (int)ct_len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tmp + ct_len) == 1 &&
        EVP_DecryptFinal_ex(ctx, tmp + outl, &finl) > 0 &&             /* tag check */
        (size_t)(outl + finl) == ct_len;
    EVP_CIPHER_CTX_free(ctx);

    /* wrong tag: counters can't be trusted, no recovery on this connection */
    if (!ok) { kill_session(s); rc = QD_ERR_CRYPTO; goto out; }
    s->recv_ctr++;

    size_t body_len = ct_len - 1;
    *type = tmp[0];
    *len  = body_len;                       /* set even when the caller's buffer is small */
    if (body_len > cap) { rc = QD_ERR_BUFFER; goto out; }
    if (body_len) memcpy(buf, tmp + 1, body_len);
    rc = QD_OK;

out:
    OPENSSL_cleanse(tmp, frame_cap);
    free(tmp);
    return rc;
}

void sec_close(sec_session *s)
{
    if (!s) return;
    if (s->fd >= 0) close(s->fd);
    OPENSSL_cleanse(s, sizeof *s);
    s->fd = -1;
}

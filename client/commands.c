/* QuantumDrive client commands. Message layouts: docs/PROTOCOL.md section 6. */
#include "commands.h"
#include "identity.h"
#include "framing.h"
#include "protocol.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

/* Decode the signed record without reading past the message. */
typedef struct {
    const uint8_t *id, *name, *hash;
    size_t id_len, name_len;
    uint64_t size;
} file_record;

static int valid_name(const uint8_t *name, size_t len, size_t max)
{
    return len && len <= max && !memchr(name, 0, len) &&
           !memchr(name, '/', len) && !memchr(name, '\\', len) &&
           !(len == 1 && name[0] == '.') &&
           !(len == 2 && !memcmp(name, "..", 2));
}

static int parse_record(const uint8_t *p, size_t len, file_record *r)
{
    if (len < 4 || p[0] != QD_RECORD_VERSION) return 0;
    r->id_len = p[1];
    r->id = p + 2;
    if (r->id_len > len - 4 || !valid_name(r->id, r->id_len, QD_ID_MAX))
        return 0;
    size_t pos = 2 + r->id_len;
    r->name_len = get_u16(p + pos);
    pos += 2;
    if (len - pos != r->name_len + 16 + QD_SHA256_BYTES) return 0;
    r->name = p + pos;
    if (!valid_name(r->name, r->name_len, QD_NAME_MAX)) return 0;
    pos += r->name_len;
    r->size = get_u64(p + pos);
    r->hash = p + pos + 8;
    return 1;
}

#define META_MAX (4 + QD_RECORD_MAX + QD_SIG_BYTES)

static int parse_meta(const uint8_t *p, size_t len, file_record *r)
{
    if (len < 4) return 0;
    size_t record_len = get_u16(p);
    return len == 4 + record_len + QD_SIG_BYTES &&
           get_u16(p + 2 + record_len) == QD_SIG_BYTES &&
           parse_record(p + 2, record_len, r);
}

static size_t read_meta(const char *path, uint8_t meta[META_MAX])
{
    FILE *file = fopen(path, "rb");
    if (!file) return 0;
    size_t n = fread(meta, 1, META_MAX, file);
    int complete = fgetc(file) == EOF && !ferror(file);
    fclose(file);
    return complete ? n : 0;
}

int cmd_register(const client_ctx *c)
{
    size_t n = strlen(c->id);
    if (!n || n > QD_ID_MAX || strpbrk(c->id, "/\\") ||
        !strcmp(c->id, ".") || !strcmp(c->id, ".."))
        return QD_ERR_ARG;

    char path[PATH_MAX];
    int count = snprintf(path, sizeof path, "%s/%s.pub", c->key_dir, c->id);
    if (count < 0 || (size_t)count >= sizeof path) return QD_ERR_FILE;

    FILE *key = fopen(path, "rb");
    if (!key && errno == ENOENT) {
        int rc = id_generate_keys(c->id, c->key_dir);
        if (rc != QD_OK) return rc;
        key = fopen(path, "rb");
    }
    if (!key) return QD_ERR_FILE;

    /* Send the ID and public key. The private key stays on this machine. */
    uint8_t body[1 + QD_ID_MAX + 2 + QD_SIG_PK_BYTES];
    body[0] = (uint8_t)n;
    memcpy(body + 1, c->id, n);
    put_u16(body + 1 + n, QD_SIG_PK_BYTES);
    int valid = fread(body + 3 + n, 1, QD_SIG_PK_BYTES, key) == QD_SIG_PK_BYTES
                && fgetc(key) == EOF && !ferror(key);
    if (fclose(key) != 0 || !valid) return QD_ERR_FILE;

    sec_session session;
    int rc = client_open(c, &session);
    if (rc != QD_OK) return rc;
    rc = sec_send(&session, QD_T_REGISTER, body, 3 + n + QD_SIG_PK_BYTES);
    if (rc == QD_OK) {
        uint8_t type;
        size_t len;
        rc = sec_recv(&session, &type, body, sizeof body, &len);
        if (rc == QD_OK) {
            if (type == QD_T_OK && len == 0) {
                printf("Registered %s.\n", c->id);
            } else if (type == QD_T_ERROR && len > 0) {
                fprintf(stderr, "Registration rejected (server error 0x%02x).\n", body[0]);
                rc = QD_ERR_PEER;
            } else {
                rc = QD_ERR_FORMAT;
            }
        }
    }
    sec_close(&session);
    return rc;
}

static int receive(sec_session *s, uint8_t expected, uint8_t *body,
                   size_t cap, size_t *len)
{
    uint8_t type;
    int rc = sec_recv(s, &type, body, cap, len);
    if (rc != QD_OK) return rc;
    if (type == QD_T_ERROR && *len) {
        fprintf(stderr, "Server rejected the request (0x%02x).\n", body[0]);
        return QD_ERR_PEER;
    }
    return type == expected ? QD_OK : QD_ERR_FORMAT;
}

int cmd_upload(const client_ctx *c, const char *path)
{
    uint8_t meta[META_MAX];
    size_t record_len, sig_len;
    int rc = id_make_record(c->id, path, meta + 2, &record_len);
    if (rc != QD_OK) return rc;
    char key[PATH_MAX];
    int written = snprintf(key, sizeof key, "%s/%s.key", c->key_dir, c->id);
    if (written < 0 || (size_t)written >= sizeof key) return QD_ERR_FILE;
    rc = id_sign(key, meta + 2, record_len, meta + 4 + record_len, &sig_len);
    if (rc != QD_OK) return rc;
    put_u16(meta, record_len);
    put_u16(meta + 2 + record_len, sig_len);

    FILE *file = fopen(path, "rb");
    if (!file) return QD_ERR_FILE;
    sec_session session;
    rc = client_open(c, &session);
    if (rc != QD_OK) {
        fclose(file);
        return rc;
    }
    rc = sec_send(&session, QD_T_UPLOAD_BEGIN, meta, 4 + record_len + sig_len);
    uint8_t chunk[8 + QD_CHUNK_MAX];
    uint64_t offset = 0;
    size_t n;
    while (rc == QD_OK && (n = fread(chunk + 8, 1, QD_CHUNK_MAX, file))) {
        put_u64(chunk, offset);
        rc = sec_send(&session, QD_T_CHUNK, chunk, 8 + n);
        offset += n;
    }
    if (ferror(file) && rc == QD_OK) rc = QD_ERR_FILE;
    fclose(file);
    if (rc == QD_OK) rc = sec_send(&session, QD_T_UPLOAD_END, NULL, 0);
    if (rc == QD_OK) {
        rc = receive(&session, QD_T_OK, chunk, sizeof chunk, &n);
        if (rc == QD_OK && n) rc = QD_ERR_FORMAT;
    }
    sec_close(&session);
    if (rc == QD_OK) printf("Uploaded %s.\n", path);
    return rc;
}

int cmd_list(const client_ctx *c)
{
    sec_session session;
    int rc = client_open(c, &session);
    if (rc != QD_OK) return rc;
    uint8_t reply[QD_BODY_MAX];
    size_t len = 0;
    rc = sec_send(&session, QD_T_LIST_REQUEST, NULL, 0);
    if (rc == QD_OK)
        rc = receive(&session, QD_T_LIST_REPLY, reply, sizeof reply, &len);
    sec_close(&session);
    if (rc != QD_OK) return rc;
    if (len < 2) return QD_ERR_FORMAT;
    size_t pos = 2;
    uint16_t count = get_u16(reply);
    for (uint16_t i = 0; i < count; i++) {
        if (len - pos < 2) return QD_ERR_FORMAT;
        size_t n = get_u16(reply + pos);
        pos += 2;
        file_record r;
        if (n > len - pos || !parse_record(reply + pos, n, &r))
            return QD_ERR_FORMAT;
        printf("%.*s/%.*s (%llu bytes)\n", (int)r.id_len, (const char *)r.id,
               (int)r.name_len, (const char *)r.name, (unsigned long long)r.size);
        pos += n;
    }
    if (pos != len) return QD_ERR_FORMAT;
    if (!count) puts("No files stored.");
    return QD_OK;
}

/* Check size and hash before asking the server for the uploader's key. */
static int verify_file(sec_session *s, const char *path,
                       const uint8_t *meta, const file_record *r)
{
    struct stat info;
    uint8_t hash[QD_SHA256_BYTES];
    if (stat(path, &info) != 0 || !S_ISREG(info.st_mode)) return QD_ERR_FILE;
    if ((uint64_t)info.st_size != r->size) return QD_ERR_CRYPTO;
    int rc = id_hash_file(path, hash);
    if (rc != QD_OK) return rc;
    if (memcmp(hash, r->hash, sizeof hash)) return QD_ERR_CRYPTO;
    uint8_t request[1 + QD_ID_MAX], reply[2 + QD_SIG_PK_BYTES];
    request[0] = (uint8_t)r->id_len;
    memcpy(request + 1, r->id, r->id_len);
    rc = sec_send(s, QD_T_KEY_REQUEST, request, 1 + r->id_len);
    if (rc != QD_OK) return rc;
    size_t len;
    rc = receive(s, QD_T_KEY_REPLY, reply, sizeof reply, &len);
    if (rc != QD_OK) return rc;
    if (len != sizeof reply || get_u16(reply) != QD_SIG_PK_BYTES) return QD_ERR_FORMAT;
    size_t record_len = get_u16(meta);
    return id_verify(reply + 2, meta + 2, record_len, meta + 4 + record_len,
                     QD_SIG_BYTES);
}

int cmd_download(const client_ctx *c, const char *owner_id, const char *filename)
{
    size_t id_len = strlen(owner_id), name_len = strlen(filename);
    if (!valid_name((const uint8_t *)owner_id, id_len, QD_ID_MAX) ||
        !valid_name((const uint8_t *)filename, name_len, QD_NAME_MAX))
        return QD_ERR_ARG;

    char path[PATH_MAX], sidecar[PATH_MAX], temp[PATH_MAX];
    int n = snprintf(path, sizeof path, "%s/%s", c->data_dir, filename);
    if (n < 0 || n >= PATH_MAX - 5 || name_len > QD_NAME_MAX - 5)
        return QD_ERR_FILE;
    snprintf(sidecar, sizeof sidecar, "%s/%s.meta", c->data_dir, filename);
    n = snprintf(temp, sizeof temp, "%s/.download-XXXXXX", c->data_dir);
    if (n < 0 || (size_t)n >= sizeof temp) return QD_ERR_FILE;
    if (mkdir(c->data_dir, 0700) != 0 && errno != EEXIST) return QD_ERR_FILE;

    sec_session session;
    int rc = client_open(c, &session);
    if (rc != QD_OK) return rc;
    uint8_t request[3 + QD_ID_MAX + QD_NAME_MAX], meta[META_MAX];
    request[0] = (uint8_t)id_len;
    memcpy(request + 1, owner_id, id_len);
    put_u16(request + 1 + id_len, name_len);
    memcpy(request + 3 + id_len, filename, name_len);
    rc = sec_send(&session, QD_T_DOWNLOAD_REQUEST, request, 3 + id_len + name_len);
    size_t meta_len;
    if (rc == QD_OK)
        rc = receive(&session, QD_T_UPLOAD_BEGIN, meta, sizeof meta, &meta_len);
    file_record r;
    if (rc == QD_OK && (!parse_meta(meta, meta_len, &r) ||
        r.id_len != id_len || r.name_len != name_len ||
        memcmp(r.id, owner_id, id_len) || memcmp(r.name, filename, name_len)))
        rc = QD_ERR_FORMAT;
    if (rc != QD_OK) {
        sec_close(&session);
        return rc;
    }

    int fd = mkstemp(temp);
    FILE *file = fd >= 0 ? fdopen(fd, "wb") : NULL;
    if (!file) {
        if (fd >= 0) { close(fd); unlink(temp); }
        sec_close(&session);
        return QD_ERR_FILE;
    }
    uint8_t chunk[8 + QD_CHUNK_MAX];
    uint64_t offset = 0;
    while (rc == QD_OK) {
        uint8_t type;
        size_t len;
        rc = sec_recv(&session, &type, chunk, sizeof chunk, &len);
        if (rc != QD_OK) break;
        if (type == QD_T_UPLOAD_END && !len) break;
        if (type != QD_T_CHUNK || len <= 8 || get_u64(chunk) != offset ||
            len - 8 > r.size - offset) {
            rc = QD_ERR_FORMAT;
        } else if (fwrite(chunk + 8, 1, len - 8, file) != len - 8) {
            rc = QD_ERR_FILE;
        } else {
            offset += len - 8;
        }
    }
    if (fclose(file) != 0 && rc == QD_OK) rc = QD_ERR_FILE;
    if (rc == QD_OK) rc = verify_file(&session, temp, meta, &r);
    sec_close(&session);

    /* Publish only a verified download and never overwrite local files. */
    if (rc == QD_OK) {
        file = fopen(sidecar, "wbx");
        if (!file) rc = QD_ERR_FILE;
        else {
            int saved = fwrite(meta, 1, meta_len, file) == meta_len;
            if (fclose(file) != 0 || !saved || link(temp, path) != 0) {
                unlink(sidecar);
                rc = QD_ERR_FILE;
            }
        }
    }
    unlink(temp);
    if (rc == QD_OK) printf("Downloaded and verified %s.\n", path);
    return rc;
}

int cmd_verify(const client_ctx *c, const char *path)
{
    char sidecar[PATH_MAX];
    int n = snprintf(sidecar, sizeof sidecar, "%s.meta", path);
    if (n < 0 || (size_t)n >= sizeof sidecar) return QD_ERR_FILE;
    uint8_t meta[META_MAX];
    file_record r;
    if (!parse_meta(meta, read_meta(sidecar, meta), &r)) return QD_ERR_FILE;
    sec_session session;
    int rc = client_open(c, &session);
    if (rc != QD_OK) return rc;
    rc = verify_file(&session, path, meta, &r);
    sec_close(&session);
    if (rc == QD_OK) printf("Verified %s.\n", path);
    return rc;
}

/* QuantumDrive server handlers. Message layouts: docs/PROTOCOL.md section 6. */
#include "handlers.h"
#include "identity.h"
#include "framing.h"
#include "protocol.h"

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>
#include <openssl/sha.h>

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

/* Send ERROR with a code and a short text (PROTOCOL.md section 5.3). */
static int send_error(server_conn *c, uint8_t code, const char *text)
{
    uint8_t body[128];
    size_t n = strlen(text);
    if (n > sizeof body - 1) n = sizeof body - 1;
    body[0] = code;
    memcpy(body + 1, text, n);
    return sec_send(c->s, QD_T_ERROR, body, 1 + n);
}

/* Check the ID before using it as part of a filename. */
static int key_path(server_conn *c, const uint8_t *id, size_t n, char path[PATH_MAX])
{
    if (!n || n > QD_ID_MAX || memchr(id, 0, n) ||
        memchr(id, '/', n) || memchr(id, '\\', n) ||
        (n == 1 && id[0] == '.') ||
        (n == 2 && id[0] == '.' && id[1] == '.'))
        return QD_E_BAD_FORMAT;
    int written = snprintf(path, PATH_MAX, "%s/%.*s.pub", c->storage_dir, (int)n, (const char *)id);
    return written < 0 || written >= PATH_MAX ? QD_E_STORAGE : 0;
}

static int read_public_key(const char *path, uint8_t *key)
{
    FILE *file = fopen(path, "rb");
    if (!file) return errno == ENOENT ? QD_E_UNKNOWN_ID : QD_E_STORAGE;
    int valid = fread(key, 1, QD_SIG_PK_BYTES, file) == QD_SIG_PK_BYTES &&
                fgetc(file) == EOF && !ferror(file);
    return fclose(file) == 0 && valid ? 0 : QD_E_STORAGE;
}

static int handle_register(server_conn *c, const uint8_t *body, size_t len)
{
    if (len < 3 || len != 3u + body[0] + QD_SIG_PK_BYTES ||
        get_u16(body + 1 + body[0]) != QD_SIG_PK_BYTES)
        return send_error(c, QD_E_BAD_FORMAT, "invalid registration");

    char path[PATH_MAX];
    int code = key_path(c, body + 1, body[0], path);
    if (code) return send_error(c, code, "invalid key path");
    const uint8_t *key = body + 3 + body[0];

    /* Exclusive creation keeps the first key registered to this ID. */
    FILE *file = fopen(path, "wbx");
    if (!file) {
        if (errno != EEXIST) return send_error(c, QD_E_STORAGE, "cannot save key");
        uint8_t existing[QD_SIG_PK_BYTES];
        code = read_public_key(path, existing);
        if (code) return send_error(c, QD_E_STORAGE, "cannot read saved key");
        if (memcmp(key, existing, sizeof existing) != 0)
            return send_error(c, QD_E_ID_KEY_CONFLICT, "ID has a different key");
    } else {
        int saved = fwrite(key, 1, QD_SIG_PK_BYTES, file) == QD_SIG_PK_BYTES;
        if (fclose(file) != 0 || !saved) {
            unlink(path);
            return send_error(c, QD_E_STORAGE, "cannot save key");
        }
    }
    return sec_send(c->s, QD_T_OK, NULL, 0);
}

/* Use a fixed-size storage name derived from the owner and filename.
 * Each directory holds a file and its signed metadata. */
static int object_path(server_conn *c, const file_record *r, char out[PATH_MAX])
{
    uint8_t names[1 + QD_ID_MAX + QD_NAME_MAX];
    uint8_t hash[QD_SHA256_BYTES];
    names[0] = (uint8_t)r->id_len;
    memcpy(names + 1, r->id, r->id_len);
    memcpy(names + 1 + r->id_len, r->name, r->name_len);
    if (!SHA256(names, 1 + r->id_len + r->name_len, hash)) return 0;
    char hex[2 * QD_SHA256_BYTES + 1];
    for (size_t i = 0; i < sizeof hash; i++)
        snprintf(hex + 2 * i, 3, "%02x", hash[i]);
    int n = snprintf(out, PATH_MAX, "%s/qd-%s", c->storage_dir, hex);
    return n >= 0 && n < PATH_MAX - 6;
}

/* Publish only a fully checked upload. Preserve the old pair until
 * the new directory has been installed. The server handles one client at a time. */
static int publish_upload(const char *dir, const char *target)
{
    struct stat info;
    if (lstat(target, &info) != 0)
        return errno == ENOENT ? rename(dir, target) : -1;
    if (!S_ISDIR(info.st_mode)) return -1;

    char backup[PATH_MAX];
    int n = snprintf(backup, sizeof backup, "%s.old-XXXXXX", dir);
    if (n < 0 || (size_t)n >= sizeof backup || !mkdtemp(backup)) return -1;
    if (rename(target, backup) != 0) {
        rmdir(backup);
        return -1;
    }
    if (rename(dir, target) != 0) {
        if (rename(backup, target) != 0)
            fprintf(stderr, "Could not restore previous upload; retained at %s\n", backup);
        return -1;
    }

    char path[PATH_MAX + 6];
    snprintf(path, sizeof path, "%s/data", backup);
    unlink(path);
    snprintf(path, sizeof path, "%s/meta", backup);
    unlink(path);
    rmdir(backup);
    return 0;
}

static int handle_upload_begin(server_conn *c, const uint8_t *body, size_t len)
{
    file_record r;
    char key_file[PATH_MAX], target[PATH_MAX];
    uint8_t key[QD_SIG_PK_BYTES];
    char dir[PATH_MAX], data[PATH_MAX + 6], meta[PATH_MAX + 6];
    FILE *file = NULL;
    int staged = 0;
    int code = 0;

    if (!parse_meta(body, len, &r)) {
        code = QD_E_BAD_FORMAT;
    } else {
        code = key_path(c, r.id, r.id_len, key_file);
        if (!code) code = read_public_key(key_file, key);
        if (!code && !object_path(c, &r, target)) code = QD_E_STORAGE;
    }
    if (!code) {
        int n = snprintf(dir, sizeof dir, "%s/.incoming-XXXXXX", c->storage_dir);
        if (n < 0 || (size_t)n >= sizeof dir || !mkdtemp(dir)) {
            code = QD_E_STORAGE;
        } else {
            staged = 1;
            snprintf(data, sizeof data, "%s/data", dir);
            snprintf(meta, sizeof meta, "%s/meta", dir);
            file = fopen(data, "wb");
            if (!file) code = QD_E_STORAGE;
        }
    }

    uint64_t total = 0;
    int rc;
    /* Keep the first error and consume this upload before replying. */
    uint8_t chunk[QD_BODY_MAX];
    for (;;) {
        uint8_t type;
        size_t bytes;
        rc = sec_recv(c->s, &type, chunk, sizeof chunk, &bytes);
        if (rc != QD_OK) break;
        if (type == QD_T_UPLOAD_END && !bytes) break;
        if (code) continue;
        if (type != QD_T_CHUNK || bytes <= 8 ||
            bytes > 8 + QD_CHUNK_MAX || get_u64(chunk) != total) {
            code = QD_E_BAD_FORMAT;
        } else if (bytes - 8 > r.size - total) {
            code = QD_E_SIZE_MISMATCH;
        } else if (fwrite(chunk + 8, 1, bytes - 8, file) != bytes - 8) {
            code = QD_E_STORAGE;
        } else {
            total += bytes - 8;
        }
    }
    if (file && fclose(file) != 0 && !code) code = QD_E_STORAGE;
    if (rc == QD_OK && !code) {
        uint8_t hash[QD_SHA256_BYTES];
        size_t record_len = get_u16(body);
        if (total != r.size) code = QD_E_SIZE_MISMATCH;
        else if (id_hash_file(data, hash) != QD_OK) code = QD_E_STORAGE;
        else if (memcmp(hash, r.hash, sizeof hash)) code = QD_E_HASH_MISMATCH;
        else if (id_verify(key, body + 2, record_len, body + 4 + record_len,
                           QD_SIG_BYTES) != QD_OK) code = QD_E_BAD_SIGNATURE;
    }
    if (rc == QD_OK && !code) {
        file = fopen(meta, "wb");
        if (!file) code = QD_E_STORAGE;
        else {
            int saved = fwrite(body, 1, len, file) == len;
            if (fclose(file) != 0 || !saved || publish_upload(dir, target) != 0)
                code = QD_E_STORAGE;
        }
    }
    if (staged && (code || rc != QD_OK)) {
        unlink(data);
        unlink(meta);
        rmdir(dir);
    }
    if (rc != QD_OK) return rc;
    if (code) return send_error(c, code, "upload rejected");
    return sec_send(c->s, QD_T_OK, NULL, 0);
}

static int handle_list(server_conn *c, const uint8_t *body, size_t len)
{
    (void)body;
    if (len) return send_error(c, QD_E_BAD_FORMAT, "list needs no body");
    DIR *dir = opendir(c->storage_dir);
    if (!dir) return send_error(c, QD_E_STORAGE, "cannot list files");
    uint8_t reply[QD_BODY_MAX], meta[META_MAX];
    size_t used = 2;
    uint16_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "qd-", 3)) continue;
        char path[PATH_MAX];
        int n = snprintf(path, sizeof path, "%s/%s/meta", c->storage_dir, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof path) continue;
        file_record r;
        if (!parse_meta(meta, read_meta(path, meta), &r)) continue;
        size_t record_bytes = 2 + get_u16(meta);
        if (record_bytes > sizeof reply - used) {
            closedir(dir);
            return send_error(c, QD_E_TOO_LARGE, "file list is too large");
        }
        memcpy(reply + used, meta, record_bytes);
        used += record_bytes;
        count++;
    }
    closedir(dir);
    put_u16(reply, count);
    return sec_send(c->s, QD_T_LIST_REPLY, reply, used);
}

static int handle_download(server_conn *c, const uint8_t *body, size_t len)
{
    file_record r;
    if (len < 3 || body[0] > len - 3)
        return send_error(c, QD_E_BAD_FORMAT, "invalid download request");
    r.id_len = body[0];
    r.id = body + 1;
    r.name_len = get_u16(body + 1 + r.id_len);
    r.name = body + 3 + r.id_len;
    if (len != 3 + r.id_len + r.name_len ||
        !valid_name(r.id, r.id_len, QD_ID_MAX) ||
        !valid_name(r.name, r.name_len, QD_NAME_MAX))
        return send_error(c, QD_E_BAD_FORMAT, "invalid file name");

    char dir[PATH_MAX], path[PATH_MAX + 6];
    if (!object_path(c, &r, dir))
        return send_error(c, QD_E_STORAGE, "invalid storage path");
    uint8_t meta[META_MAX];
    snprintf(path, sizeof path, "%s/meta", dir);
    size_t n = read_meta(path, meta);
    if (!parse_meta(meta, n, &r))
        return send_error(c, QD_E_NOT_FOUND, "file unavailable");
    snprintf(path, sizeof path, "%s/data", dir);
    FILE *file = fopen(path, "rb");
    if (!file) return send_error(c, QD_E_NOT_FOUND, "file unavailable");

    int rc = sec_send(c->s, QD_T_UPLOAD_BEGIN, meta, n);
    uint8_t chunk[8 + QD_CHUNK_MAX];
    uint64_t offset = 0;
    while (rc == QD_OK && (n = fread(chunk + 8, 1, QD_CHUNK_MAX, file))) {
        put_u64(chunk, offset);
        rc = sec_send(c->s, QD_T_CHUNK, chunk, 8 + n);
        offset += n;
    }
    if (ferror(file) && rc == QD_OK) rc = QD_ERR_FILE;
    fclose(file);
    if (rc != QD_OK) return rc;
    return sec_send(c->s, QD_T_UPLOAD_END, NULL, 0);
}

static int handle_key_request(server_conn *c, const uint8_t *body, size_t len)
{
    if (!len || len != 1u + body[0])
        return send_error(c, QD_E_BAD_FORMAT, "invalid key request");
    char path[PATH_MAX];
    int code = key_path(c, body + 1, body[0], path);
    if (code) return send_error(c, code, "invalid key path");
    uint8_t reply[2 + QD_SIG_PK_BYTES];
    code = read_public_key(path, reply + 2);
    if (code) return send_error(c, code, "key unavailable");
    put_u16(reply, QD_SIG_PK_BYTES);
    return sec_send(c->s, QD_T_KEY_REPLY, reply, sizeof reply);
}

int server_handle(server_conn *c, uint8_t type, const uint8_t *body, size_t len)
{
    switch (type) {
    case QD_T_REGISTER:         return handle_register(c, body, len);
    case QD_T_UPLOAD_BEGIN:     return handle_upload_begin(c, body, len);
    case QD_T_LIST_REQUEST:     return handle_list(c, body, len);
    case QD_T_DOWNLOAD_REQUEST: return handle_download(c, body, len);
    case QD_T_KEY_REQUEST:      return handle_key_request(c, body, len);
    default:                    return send_error(c, QD_E_BAD_FORMAT, "unknown message type");
    }
}

/* STUB. Chris replaces the body of every function with the real code.
 * The stubs return fake values of the correct SIZE, so size measurements and
 * the command loop can be built before the real crypto lands.
 * WARNING: the id_verify stub accepts any signature of the right length. */
#include "identity.h"
#include "framing.h"
#include "protocol.h"

#include <string.h>

int id_generate_keys(const char *id, const char *dir)
{
    (void)id; (void)dir;
    return QD_OK;                                   /* fake: writes nothing */
}

int id_sign(const char *key_path, const uint8_t *msg, size_t n, uint8_t *sig, size_t *sig_len)
{
    (void)key_path; (void)msg; (void)n;
    if (!sig || !sig_len) return QD_ERR_ARG;
    memset(sig, 0xAB, QD_SIG_BYTES);                /* fake signature, real length */
    *sig_len = QD_SIG_BYTES;
    return QD_OK;
}

int id_verify(const uint8_t *pk, const uint8_t *msg, size_t n, const uint8_t *sig, size_t sig_len)
{
    (void)pk; (void)msg; (void)n; (void)sig;
    return sig_len == QD_SIG_BYTES ? QD_OK : QD_ERR_CRYPTO;   /* fake: length check only */
}

int id_hash_file(const char *path, uint8_t out[32])
{
    (void)path;
    memset(out, 0, QD_SHA256_BYTES);                /* fake hash */
    return QD_OK;
}

int id_make_record(const char *id, const char *file, uint8_t *rec, size_t *rec_len)
{
    /* Real layout, fake contents: file_size, hash and timestamp are all zero. */
    if (!id || !file || !rec || !rec_len) return QD_ERR_ARG;
    size_t id_len = strlen(id), name_len = strlen(file);
    if (id_len < 1 || id_len > QD_ID_MAX || name_len < 1 || name_len > QD_NAME_MAX) return QD_ERR_ARG;

    uint8_t *p = rec;
    *p++ = QD_RECORD_VERSION;
    *p++ = (uint8_t)id_len;
    memcpy(p, id, id_len);       p += id_len;
    put_u16(p, (uint16_t)name_len); p += 2;
    memcpy(p, file, name_len);   p += name_len;
    put_u64(p, 0);               p += 8;            /* file_size */
    memset(p, 0, QD_SHA256_BYTES); p += QD_SHA256_BYTES;
    put_u64(p, 0);               p += 8;            /* timestamp */
    *rec_len = (size_t)(p - rec);
    return QD_OK;
}

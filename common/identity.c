/* STUB. Chris replaces the body of every function with the real code.
 * The stubs return fake values of the correct SIZE, so size measurements and
 * the command loop can be built before the real crypto lands.
 * WARNING: the id_verify stub accepts any signature of the right length. */
#include "identity.h"
#include "framing.h"
#include "protocol.h"

/*Adding these in to be able to call for these things*/
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <oqs/oqs.h>




#include <string.h>

/* Save one key without replacing an existing file. */
static int save_key(const char *name,
                    const unsigned char *key,
                    size_t size,
                    mode_t permissions)
{
    int file = open(name, O_WRONLY | O_CREAT | O_EXCL, permissions);

    if (file == -1) {
        return QD_ERR_FILE;
    }

    int result = QD_OK;

    /* Set the file permissions. */
    if (fchmod(file, permissions) == -1) {
        result = QD_ERR_FILE;
    }

    /* Keep writing until the entire key is saved. */
    size_t saved = 0;

    while (result == QD_OK && saved < size) {
        ssize_t amount = write(file, key + saved, size - saved);

        if (amount == -1 && errno == EINTR) {
            continue;
        }

        if (amount <= 0) {
            result = QD_ERR_FILE;
        } else {
            saved += (size_t)amount;
        }
    }

    /* Close the file and remove it if saving failed. */
    if (close(file) == -1) {
        result = QD_ERR_FILE;
    }

    if (result != QD_OK) {
        unlink(name);
    }

    return result;
}


/* Create and save a user's public and private keys. */
int id_generate_keys(const char *id, const char *dir)
{
    /* STEP 1: Check the username and folder. */
    if (id == NULL || dir == NULL) {
        return QD_ERR_ARG;
    }

    if (strlen(id) < 1 ||
        strlen(id) > QD_ID_MAX ||
        strlen(dir) == 0) {
        return QD_ERR_ARG;
    }

    /* Block usernames that could change the file path. */
    if (strchr(id, '/')  != NULL ||
        strchr(id, '\\') != NULL ||
        strcmp(id, ".")  == 0    ||
        strcmp(id, "..") == 0) {
        return QD_ERR_ARG;
    }

    /* STEP 2: Prepare the filenames. */
    char private_name[PATH_MAX];
    char public_name[PATH_MAX];

    int a = snprintf(private_name, sizeof(private_name), "%s/%s.key", dir, id);
    int b = snprintf(public_name,  sizeof(public_name),  "%s/%s.pub", dir, id);

    /* Make sure the complete filenames fit. */
    if (a < 0 || b < 0) {
        return QD_ERR_ARG;
    }

    if ((size_t)a >= sizeof(private_name) ||
        (size_t)b >= sizeof(public_name)) {
        return QD_ERR_ARG;
    }

    /* STEP 3: Create the folder if needed. */
    if (mkdir(dir, 0700) == -1 && errno != EEXIST) {
        return QD_ERR_FILE;
    }

    /* Confirm the path really is a folder. */
    struct stat folder;

    if (stat(dir, &folder) == -1 || !S_ISDIR(folder.st_mode)) {
        return QD_ERR_FILE;
    }

    /* STEP 4: Prepare the cryptography tool. */
    OQS_SIG *algorithm = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

    if (algorithm == NULL) {
        return QD_ERR_CRYPTO;
    }

    /* Prepare temporary containers for the keys. */
    unsigned char public_key[OQS_SIG_ml_dsa_65_length_public_key];
    unsigned char private_key[OQS_SIG_ml_dsa_65_length_secret_key];

    /* STEP 5: Generate the keys. */
    int result = QD_ERR_CRYPTO;

    if (OQS_SIG_keypair(algorithm, public_key, private_key) == OQS_SUCCESS) {

        /* STEP 6: Save the private key with owner-only access. */
        result = save_key(private_name, private_key, sizeof(private_key), 0600);

        if (result == QD_OK) {

            /* STEP 7: Save the public key. */
            result = save_key(public_name, public_key, sizeof(public_key), 0644);

            /* Remove the new private file if the public key could not save. */
            if (result != QD_OK) {
                unlink(private_name);
            }
        }
    }

    /* STEP 8: Clear the temporary secret and release the tool. */
    OQS_MEM_cleanse(private_key, sizeof(private_key));
    OQS_SIG_free(algorithm);

    return result;
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

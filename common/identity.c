/* User keys, signatures, file hashes, and upload records. */

#include "identity.h"
#include "framing.h"
#include "protocol.h"

/* Libraries needed for files, text, keys, hashes, and time. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <time.h>


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


/* Sign a message using the user's saved private key. */
int id_sign(const char *key_path, const uint8_t *msg, size_t n,
            uint8_t *sig, size_t *sig_len)
{
    /* STEP 1: Check the inputs and open the private-key file. */
    if (key_path == NULL || (msg == NULL && n != 0) ||
        sig == NULL || sig_len == NULL) {
        return QD_ERR_ARG;
    }

    *sig_len = 0;

    FILE *key_file = fopen(key_path, "rb");

    if (key_file == NULL) {
        return QD_ERR_FILE;
    }

    /* STEP 2: Read the key and make sure the file is the right size. */
    uint8_t private_key[OQS_SIG_ml_dsa_65_length_secret_key];

    size_t bytes_read = fread(private_key, 1, sizeof(private_key), key_file);

    int extra_byte = fgetc(key_file);
    int read_failed = ferror(key_file);
    int close_failed = fclose(key_file);

    if (bytes_read != sizeof(private_key) ||
        extra_byte != EOF ||
        read_failed != 0 ||
        close_failed != 0) {
        OQS_MEM_cleanse(private_key, sizeof(private_key));
        return QD_ERR_FILE;
    }

    /* STEP 3: Prepare the signature tool. */
    OQS_SIG *algorithm = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

    if (algorithm == NULL) {
        OQS_MEM_cleanse(private_key, sizeof(private_key));
        return QD_ERR_CRYPTO;
    }

    /* An empty message is allowed when no message pointer was given. */
    static const uint8_t empty_message = 0;

    if (msg == NULL) {
        msg = &empty_message;
    }

    /* STEP 4: Sign, then clear the temporary private key from memory. */
    int sign_result = OQS_SIG_sign(
        algorithm,
        sig,
        sig_len,
        msg,
        n,
        private_key
    );

    OQS_MEM_cleanse(private_key, sizeof(private_key));
    OQS_SIG_free(algorithm);

    if (sign_result != OQS_SUCCESS || *sig_len != QD_SIG_BYTES) {
        *sig_len = 0;
        return QD_ERR_CRYPTO;
    }

    return QD_OK;
}


/* Check a signature using the user's public key. */
int id_verify(const uint8_t *pk, const uint8_t *msg, size_t n,
              const uint8_t *sig, size_t sig_len)
{
    /* STEP 1: Check the inputs and signature size. */
    if (pk == NULL || (msg == NULL && n != 0) || sig == NULL) {
        return QD_ERR_ARG;
    }

    if (sig_len != QD_SIG_BYTES) {
        return QD_ERR_CRYPTO;
    }

    /* STEP 2: Prepare the same signature tool used to sign. */
    OQS_SIG *algorithm = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

    if (algorithm == NULL) {
        return QD_ERR_CRYPTO;
    }

    static const uint8_t empty_message = 0;

    if (msg == NULL) {
        msg = &empty_message;
    }

    /* STEP 3: Check the signature using the public key. */
    int check_result = OQS_SIG_verify(
        algorithm,
        msg,
        n,
        sig,
        sig_len,
        pk
    );

    OQS_SIG_free(algorithm);

    if (check_result != OQS_SUCCESS) {
        return QD_ERR_CRYPTO;
    }

    return QD_OK;
}


/* Create a SHA-256 fingerprint for a file. */
int id_hash_file(const char *path, uint8_t out[32])
{
    /* STEP 1: Check the inputs and open the file. */
    if (path == NULL || out == NULL) {
        return QD_ERR_ARG;
    }

    FILE *file = fopen(path, "rb");

    if (file == NULL) {
        return QD_ERR_FILE;
    }

    /* STEP 2: Prepare OpenSSL's SHA-256 fingerprint tool. */
    EVP_MD_CTX *hash_tool = EVP_MD_CTX_new();

    if (hash_tool == NULL) {
        fclose(file);
        return QD_ERR_CRYPTO;
    }

    int result = QD_OK;

    uint8_t file_piece[16384];
    size_t bytes_read = 0;
    unsigned int hash_size = 0;

    if (EVP_DigestInit_ex(hash_tool, EVP_sha256(), NULL) != 1) {
        result = QD_ERR_CRYPTO;
    }

    /* STEP 3: Feed the file to the tool one piece at a time. */
    while (result == QD_OK &&
           (bytes_read = fread(
               file_piece,
               1,
               sizeof(file_piece),
               file
           )) != 0) {

        if (EVP_DigestUpdate(hash_tool, file_piece, bytes_read) != 1) {
            result = QD_ERR_CRYPTO;
        }
    }

    if (result == QD_OK && ferror(file)) {
        result = QD_ERR_FILE;
    }

    /* STEP 4: Finish the fingerprint and clean up. */
    if (result == QD_OK) {
        if (EVP_DigestFinal_ex(hash_tool, out, &hash_size) != 1 ||
            hash_size != QD_SHA256_BYTES) {
            result = QD_ERR_CRYPTO;
        }
    }

    EVP_MD_CTX_free(hash_tool);

    if (fclose(file) != 0) {
        result = QD_ERR_FILE;
    }

    return result;
}


/* Create the record that will be signed for an upload. */
int id_make_record(const char *id, const char *file,
                   uint8_t *rec, size_t *rec_len)
{
    /* STEP 1: Check the inputs and find the file's name. */
    if (id == NULL || file == NULL || rec == NULL || rec_len == NULL) {
        return QD_ERR_ARG;
    }

    const char *name = strrchr(file, '/');

    if (name == NULL) {
        name = file;
    } else {
        name = name + 1;
    }

    size_t id_len = strlen(id);
    size_t name_len = strlen(name);

    if (id_len == 0 || id_len > QD_ID_MAX ||
        name_len == 0 || name_len > QD_NAME_MAX ||
        strchr(id, '/') != NULL ||
        strchr(id, '\\') != NULL ||
        strcmp(id, ".") == 0 ||
        strcmp(id, "..") == 0 ||
        strchr(name, '\\') != NULL ||
        strcmp(name, ".") == 0 ||
        strcmp(name, "..") == 0) {
        return QD_ERR_ARG;
    }

    /* STEP 2: Get the file size, fingerprint, and current time. */
    struct stat file_info;

    if (stat(file, &file_info) != 0 ||
        !S_ISREG(file_info.st_mode) ||
        file_info.st_size < 0) {
        return QD_ERR_FILE;
    }

    uint8_t fingerprint[QD_SHA256_BYTES];

    int result = id_hash_file(file, fingerprint);

    if (result != QD_OK) {
        return result;
    }

    time_t current_time = time(NULL);

    if (current_time == (time_t)-1) {
        return QD_ERR_FILE;
    }

    /* STEP 3: Put each part into the record in the agreed order. */
    uint8_t *position = rec;

    *position = QD_RECORD_VERSION;
    position = position + 1;

    *position = (uint8_t)id_len;
    position = position + 1;

    memcpy(position, id, id_len);
    position = position + id_len;

    put_u16(position, (uint16_t)name_len);
    position = position + 2;

    memcpy(position, name, name_len);
    position = position + name_len;

    put_u64(position, (uint64_t)file_info.st_size);
    position = position + 8;

    memcpy(position, fingerprint, sizeof(fingerprint));
    position = position + sizeof(fingerprint);

    put_u64(position, (uint64_t)current_time);
    position = position + 8;

    /* Report how many bytes the completed record uses. */
    *rec_len = (size_t)(position - rec);

    return QD_OK;
}
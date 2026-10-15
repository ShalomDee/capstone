/* Proof of who sent what: ML-DSA-65 key pairs, signing, verifying, file hashes,
 * and the signed record. Owner: Chris. The function list is the shared contract
 * (CLAUDE.md section 8); do not change it without Shalom's approval.
 * Record layout: docs/PROTOCOL.md section 5.2. */
#ifndef QD_IDENTITY_H
#define QD_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

/* Make a new ML-DSA-65 key pair for id and save both keys in folder dir. */
int id_generate_keys(const char *id, const char *dir);

/* Sign msg with the private key stored at key_path.
 * sig must hold at least QD_SIG_BYTES; *sig_len is set to the signature length. */
int id_sign(const char *key_path, const uint8_t *msg, size_t n, uint8_t *sig, size_t *sig_len);

/* Check sig over msg with public key pk (QD_SIG_PK_BYTES long).
 * Returns 0 only if the signature is valid. */
int id_verify(const uint8_t *pk, const uint8_t *msg, size_t n, const uint8_t *sig, size_t sig_len);

/* SHA-256 fingerprint of a whole file. */
int id_hash_file(const char *path, uint8_t out[32]);

/* Build the signed record for file, uploaded by id.
 * rec must hold at least QD_RECORD_MAX bytes; *rec_len is set to the length used. */
int id_make_record(const char *id, const char *file, uint8_t *rec, size_t *rec_len);

#endif

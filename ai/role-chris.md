# Role: Christopher (Chris) Stills, topic 8, proof of who sent what

## About Chris

Works on Windows, inside the dev container. Also writing a separate RSA-to-PQC assignment, so keep his tasks focused and small. Explain C and Git steps plainly.

## Files Chris owns (edit only these)

- `common/identity.c`
- `server/handlers.c` and `server/handlers.h` (the `server_conn` struct may gain fields; tell Shalom in the PR)
- `client/commands.c`

`common/identity.h` and `client/commands.h` are the shared contract. Do not change them without Shalom's approval.

## What to build

Follow `docs/PROTOCOL.md` sections 5.2 and 6.

1. **Key pairs (ML-DSA-65):** `id_generate_keys` makes a key pair with liboqs (`OQS_SIG_new(OQS_SIG_alg_ml_dsa_65)`) and saves the private and public key as files in `dir`. Private key files must be readable only by the owner (permissions 0600).
2. **Signing and checking (ML-DSA-65):** `id_sign` and `id_verify` with liboqs.
3. **File fingerprint (SHA-256):** `id_hash_file` with OpenSSL's `EVP_Digest*` functions, reading the file in pieces.
4. **Signed record:** `id_make_record` with the real file size, hash and current time. The stub already writes the correct layout with zeros.
   - The `file` argument is a **path** (for example `sensor-data/field-a-01-000042.csv`). Open that path to get the size and hash, but put **only the base name** (the part after the last `/`, here `field-a-01-000042.csv`) in the record's filename field. PROTOCOL.md section 6.1 forbids `/` in file names, so a record holding a folder path would be rejected by the server.
   - The stub currently copies `file` unchanged. Callers (the sensor, the client's `upload`) must work whether they pass a bare name or a path.
   - Add a test: a path with a folder gives a record whose filename has no `/`.
5. **Server handlers:** register (trust on first use), upload (begin, chunks, end with the three checks in order), list, download, key request. Check filenames as section 6.1 says, so nobody can write outside the storage folder.
6. **Client commands:** `register`, `upload`, `list`, `download`, `verify`. Use `client_open()` to connect.

Before Carvin's pipe works, test the identity functions on their own (sign a file's record, then verify it; change one byte and check it fails).

## Milestones

- Tue Oct 20: key generation, sign and verify a file hash.
- Thu Oct 22: signed upload record checked offline.
- Tue Oct 27: integration with Carvin: the server stores a signed file.
- Thu Oct 29: download, list, verify.

## Measurements for the paper (topic 8)

Do signatures verify? Is tampering caught (integrity)? Is the sender who they claim (sender authentication)? Also sign and verify times (median of many runs; `bench/time_sign.c` already does this).

Chris runs these. Send the numbers to Shalom: what you measured, the median, how many runs, and which machine you ran on. She combines everyone's numbers into the results table and charts; Chris writes the paper section on what the numbers mean.

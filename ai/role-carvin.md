# Role: Carvin Young, topic 7, the secure pipe

## About Carvin

New to Git, C toolchains and VS Code (has used Python and PyCharm). Works on a Mac. Use Codespaces: the local container on a Mac is untested. Explain each command before running it, and what it does. Prefer small steps that can be checked one at a time.

## Files Carvin owns (edit only these)

- `common/securenet.c`
- Tests for the pipe: add your own test functions to `tests/test_main.c` (see "Tests" in `ai/rules-common.md`). Don't change other people's tests.

`common/securenet.h` is the shared contract. Do not change it without Shalom's approval.

## What to build

Replace the stubs in `common/securenet.c`, following `docs/PROTOCOL.md` sections 2 to 5:

1. **Plain connection (TCP):** `net_listen`, `net_accept`, `net_connect`. Use `frame_write` / `frame_read` from `common/framing.h` for every message. Set `TCP_NODELAY` on sockets so small messages are not delayed (this matters for timing).
2. **Agreeing on a secret (ML-KEM-768 key exchange):** `sec_handshake_client` and `sec_handshake_server`. HELLO, then the server sends a fresh public key, then the client sends the ciphertext. Use liboqs (`OQS_KEM_new(OQS_KEM_alg_ml_kem_768)` or the `OQS_KEM_ml_kem_768_*` functions).
3. **Making the two AES keys (HKDF-SHA256):** with OpenSSL's `EVP_KDF` "HKDF". Salt is SHA-256 of public key followed by ciphertext. Info strings `"quantumdrive v1 c2s"` and `"quantumdrive v1 s2c"`. On the client, `send_key` is the c2s key; on the server, `send_key` is the s2c key.
4. **Encrypting messages (AES-256-GCM):** `sec_send` and `sec_recv` with OpenSSL's `EVP_aes_256_gcm`. Nonce is 4 zero bytes plus the 8-byte counter. Tag goes after the ciphertext. If decryption fails, return an error; the caller closes the connection.
5. `sec_close`: close the socket and wipe the keys (already done in the stub).

## Milestones

- Tue Oct 20: TCP hello works (client and server exchange a frame).
- Thu Oct 22: ML-KEM handshake gives both sides the same secret.
- Tue Oct 27: encrypted messages carry a signed file (integration with Chris).
- Tue Nov 3: chunked transfer; resume after a dropped connection if time allows.

**Revised Oct 31 (these dates were missed):** Shalom is away Mon Nov 2 to Fri Nov 6 and cannot answer questions that week. By **Fri Nov 6, 23:59**: all of `common/securenet.c` (steps 1 to 5 above) working, with tests in `tests/test_main.c`, pushed to your branch with a PR open to `main`. Push as you go so the work is visible. In the same PR, put your topic 7 measurements that need only the pipe: handshake time (median of many runs) and bytes sent during the handshake.

## Measurements for the paper (topic 7)

Transfer time, recovery time after a dropped connection, and the extra cost (overhead) of PQC compared with plain transfer: handshake time and extra bytes.

Carvin runs these. Send the numbers to Shalom: what you measured, the median, how many runs, and which machine you ran on. She combines everyone's numbers into the results table and charts; Carvin writes the paper section on what the numbers mean.

# QuantumDrive protocol, version 1

This file is the single source of truth for what goes over the network. Changes need Shalom's approval. Propose them in a pull request description first.

Status: approved by Shalom on Oct 15, 2026.

## 1. General rules

- All multi-byte numbers are **big-endian** (most significant byte first). The C helpers in `common/framing.h` handle this. Do not write the bytes by hand.
- Text fields (IDs, filenames) are UTF-8 bytes with a length prefix. They are not zero-terminated on the wire.
- Lengths written as "N bytes" below are exact.

## 2. Frames

Every message on the wire is a frame:

```
length   4 bytes   number of bytes that follow (type + payload)
type     1 byte
payload  length - 1 bytes
```

- **Maximum frame size:** `length` must be at most 131,072 (128 KiB). A receiver that sees a larger value closes the connection without reading the rest. This stops a broken or hostile peer from making the other side reserve huge amounts of memory.
- `length` must be at least 1 (the type byte).

Frame types:

| Code | Name | Encrypted? |
|---|---|---|
| 0x01 | HELLO | no |
| 0x02 | KEM_PUBKEY | no |
| 0x03 | KEM_CIPHERTEXT | no |
| 0x10 | SECURE | yes |
| 0x31 | ERROR | only unencrypted during the handshake (see 3.2) |

## 3. Handshake (agreeing on a shared secret, ML-KEM-768)

### 3.1 Steps

| Step | Frame | Direction | Payload |
|---|---|---|---|
| 1 | HELLO (0x01) | client to server | 1 byte: protocol version, `0x01` |
| 2 | KEM_PUBKEY (0x02) | server to client | 1184 bytes: a fresh ML-KEM-768 public key, made new for every connection |
| 3 | KEM_CIPHERTEXT (0x03) | client to server | 1088 bytes: the ML-KEM-768 ciphertext (the "locked box") |

After step 3 both sides hold the same 32-byte shared secret. The server throws away its ML-KEM private key once the box is opened.

### 3.2 Handshake errors

- If the server does not support the version in HELLO, it sends one unencrypted frame of type ERROR (0x31) with payload `[0x09]` and closes the connection.
- Any other problem during the handshake (wrong frame type, wrong payload size) closes the connection with no reply.

## 4. Key derivation (turning the secret into AES keys, HKDF-SHA256)

Both sides compute the same values with OpenSSL's HKDF.

```
transcript_hash = SHA-256( KEM public key (1184 bytes) || KEM ciphertext (1088 bytes) )

key_c2s = HKDF-SHA256( input = shared secret (32 bytes),
                       salt  = transcript_hash (32 bytes),
                       info  = "quantumdrive v1 c2s",
                       output length = 32 bytes )

key_s2c = HKDF-SHA256( same input and salt,
                       info  = "quantumdrive v1 s2c",
                       output length = 32 bytes )
```

- `||` means "joined end to end".
- The info strings are the ASCII bytes shown, with no trailing zero byte.
- `key_c2s` encrypts everything the client sends. `key_s2c` encrypts everything the server sends. Two keys means the same key and nonce are never used in both directions.
- **Why the salt is the transcript hash:** it ties the keys to the exact public key and ciphertext that were exchanged. If anyone altered either one in transit, the two sides end up with different keys and the first encrypted message fails to decrypt. This does not replace server authentication (see section 7).

## 5. Encrypted messages (AES-256-GCM)

After the handshake, every frame is type SECURE (0x10).

```
SECURE payload = ciphertext || tag (16 bytes)
plaintext      = app type (1 byte) || body
```

- **Nonce** (the number that must never repeat under one key), 12 bytes: `00 00 00 00` followed by the 8-byte big-endian message counter.
- Each direction has its own counter. Both start at 0 and go up by 1 after every message sent in that direction. The counter is never sent; each side tracks it.
- No additional authenticated data (AAD) is used.
- If decryption fails (wrong tag), the receiver closes the connection. The counters can no longer be trusted, so there is no recovery on that connection.
- If a counter would pass 2^64 - 1, the sender closes the connection. In practice this never happens.
- Largest possible body: 131,072 - 1 (frame type) - 16 (tag) - 1 (app type) = 131,054 bytes.

### 5.1 App types

| Code | Name | Direction |
|---|---|---|
| 0x20 | REGISTER | client to server |
| 0x21 | UPLOAD_BEGIN | client to server, and server to client in a download |
| 0x22 | CHUNK | both |
| 0x23 | UPLOAD_END | both |
| 0x24 | LIST_REQUEST | client to server |
| 0x25 | DOWNLOAD_REQUEST | client to server |
| 0x26 | KEY_REQUEST | client to server |
| 0x27 | STATUS_REQUEST | client to server (stretch goal) |
| 0x30 | OK | server to client |
| 0x31 | ERROR | server to client |
| 0x32 | LIST_REPLY | server to client |
| 0x35 | KEY_REPLY | server to client |

### 5.2 The signed record (proof of who sent what, ML-DSA-65)

The uploader signs this exact byte string with their ML-DSA-65 private key.

```
version      1 byte    0x01
id_len       1 byte    1 to 64
id           id_len bytes
name_len     2 bytes   1 to 255
filename     name_len bytes
file_size    8 bytes
sha256       32 bytes  SHA-256 of the whole file
timestamp    8 bytes   Unix time in seconds, UTC
```

- Largest record: 1 + 1 + 64 + 2 + 255 + 8 + 32 + 8 = 371 bytes.
- The signature covers every byte of the record above, nothing more.
- An ML-DSA-65 signature is 3,309 bytes.

### 5.3 ERROR body

```
code   1 byte
text   0 or more bytes, optional short human-readable detail (UTF-8)
```

| Code | Meaning |
|---|---|
| 0x01 | Bad message format |
| 0x02 | Unknown ID |
| 0x03 | ID already registered with a different key |
| 0x04 | Bad signature |
| 0x05 | Hash mismatch |
| 0x06 | Size mismatch |
| 0x07 | File not found |
| 0x08 | Server storage failure |
| 0x09 | Unsupported protocol version |
| 0x0A | Too large |

## 6. Message bodies

| App type | Body |
|---|---|
| REGISTER (0x20) | `id_len` (1) + `id` + `pk_len` (2) + ML-DSA-65 public key. `pk_len` must be exactly 1952. Server replies OK, or ERROR 0x03 if the ID already exists with a different key. Registering the same ID with the same key again is OK. |
| UPLOAD_BEGIN (0x21) | `rec_len` (2) + record (5.2) + `sig_len` (2) + signature. `sig_len` must be exactly 3309. The record's ID must already be registered, otherwise ERROR 0x02. |
| CHUNK (0x22) | `offset` (8) + data (1 to 65,536 bytes) |
| UPLOAD_END (0x23) | empty. After an upload the server checks size, hash and signature and replies OK or ERROR (0x04, 0x05 or 0x06). |
| LIST_REQUEST (0x24) | empty |
| LIST_REPLY (0x32) | `count` (2), then for each file: `rec_len` (2) + record |
| DOWNLOAD_REQUEST (0x25) | `id_len` (1) + `id` + `name_len` (2) + `filename`. Server replies with UPLOAD_BEGIN (record and signature), then CHUNKs, then UPLOAD_END; or ERROR 0x07. |
| KEY_REQUEST (0x26) | `id_len` (1) + `id` |
| KEY_REPLY (0x35) | `pk_len` (2) + ML-DSA-65 public key (1952 bytes). Unknown ID gives ERROR 0x02. |
| STATUS_REQUEST (0x27) | reserved for the resume stretch goal. Not defined or implemented in v1. A server that receives it replies ERROR 0x01. |
| OK (0x30) | empty |

### 6.1 Rules for these messages

- **Chunks are sent in order.** The first CHUNK has offset 0. Each later CHUNK's offset equals the previous offset plus the previous chunk's data length. Anything else gives ERROR 0x01. A file of size 0 has no CHUNKs, only UPLOAD_BEGIN then UPLOAD_END.
- **Total size.** The chunk lengths must add up to `file_size` in the record. Otherwise ERROR 0x06.
- **What the server checks at UPLOAD_END, in this order:** total size matches `file_size` (else 0x06), SHA-256 of the received bytes matches `sha256` in the record (else 0x05), the signature verifies over the record with the uploader's registered public key (else 0x04).
- **Filenames.** Besides the length limits in 5.2, a filename must not contain `/`, `\` or a zero byte, and must not be `.` or `..`. This stops an uploader from writing outside the server's storage folder (a path traversal attack). Breaking this rule gives ERROR 0x01.
- **IDs** follow the same character rules as filenames.
- **Downloads.** The client checks the download itself: total size, SHA-256, and the signature using the uploader's key from KEY_REQUEST. It does not send OK or anything else back to the server. If a check fails, the client reports it to the user and deletes the partial file.

Note: a LIST_REPLY entry is at most 2 + 371 = 373 bytes. A body can be up to 131,054 bytes (section 5), so one LIST_REPLY holds up to (131,054 - 2) / 373 = 351 records. That is enough for this project; a longer list would need paging.

## 7. Known limitations (for the paper)

- **The server is not authenticated.** The client cannot tell whether the KEM public key really came from our server. An attacker in the middle could run one handshake with the client and another with the server. Fix for later: the server signs its KEM public key with a long-term ML-DSA key, as a new message type, without changing the existing ones.
- **Raw TCP instead of TLS.** Building the secure channel ourselves is the research. Real systems would use TLS 1.3 with PQC key exchange.
- **liboqs is for prototyping and evaluation,** not production use.
- **Trust on first use for REGISTER.** The first key the server sees for an ID is trusted.

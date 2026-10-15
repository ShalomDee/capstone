# Glossary

Plain meaning first, technical term after.

| Term | Plain meaning |
|---|---|
| **Post-quantum cryptography (PQC)** | Cryptography designed to stay safe even against future quantum computers. |
| **Key exchange / KEM** | Two sides agreeing on a shared secret over an open network. KEM stands for key encapsulation mechanism. |
| **ML-KEM-768** | The post-quantum key exchange we use (standard FIPS 203, middle security level). |
| **Public key / private key** | A pair: the public key can be shared with anyone; the private key stays with its owner and must never be shared or committed. |
| **Ciphertext ("locked box")** | Encrypted data. In ML-KEM, the client's locked box holds the shared secret and only the server's private key opens it. |
| **Shared secret** | The 32 bytes both sides end up with after the key exchange. |
| **Symmetric encryption** | Both sides use the same key to lock and unlock. Much faster than public-key methods. |
| **AES-256-GCM** | The symmetric encryption we use. It also detects tampering (authenticated encryption). |
| **Tag** | The 16-byte tamper check AES-GCM adds to every message. If any byte changes, the check fails. |
| **Nonce** | A number used once per key. Reusing one with the same key breaks AES-GCM's security. We use a message counter. |
| **HKDF** | A key derivation function: turns one shared secret into several separate keys. |
| **Salt / info** | Extra inputs to HKDF. The salt ties keys to this handshake; the info labels make the two direction keys different. |
| **Hash / fingerprint (SHA-256)** | A 32-byte summary of data. Changing any byte gives a completely different hash. |
| **Digital signature** | Proof that the holder of a private key approved some data. Anyone with the public key can check it. |
| **ML-DSA-65** | The post-quantum signature scheme we use (standard FIPS 204). A signature is 3,309 bytes. |
| **Signed record** | The small block (ID, filename, size, hash, time) that the uploader signs. See `docs/PROTOCOL.md` 5.2. |
| **Integrity** | The data was not changed on the way. |
| **Sender authentication** | The data really came from who it claims to come from. |
| **Trust on first use (TOFU)** | The server accepts the first public key it sees for an ID and rejects different keys later. |
| **Man-in-the-middle (MITM)** | An attacker sitting between client and server, pretending to be each to the other. v1 does not stop this (see `docs/PROTOCOL.md` section 7). |
| **Path traversal** | Using a filename like `../../x` to write outside the intended folder. |
| **Frame** | One message on the wire: `[4-byte length][1-byte type][payload]`. |
| **Big-endian** | Writing numbers with the most significant byte first ("network byte order"). |
| **TCP / socket** | The basic reliable connection between two programs over a network, and the handle a program uses for it. |
| **Stub** | A placeholder function that compiles and returns a fake result until the real code is written. |
| **liboqs** | The C library that provides ML-KEM and ML-DSA. For prototyping and research, not production. |
| **OpenSSL** | The C library we use for AES-GCM, HKDF and SHA-256. |
| **Dev container** | A ready-made Linux environment (Docker) with all tools installed, so everyone's setup is identical. |
| **Branch / pull request (PR)** | A branch is your own copy of the code to work on. A PR asks Shalom to review and merge it into `main`. |
| **Median** | The middle value when results are sorted. Less affected by one slow run than the average. |

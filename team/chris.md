# Chris: proof of who sent what (topic 8)

Read [README.md](README.md) in this folder first.

## Your job in one paragraph

You make sure that every file in QuantumDrive carries **proof of who uploaded it**, and that any change to the file is caught. You do this with digital signatures (ML-DSA-65). You also write what the server and client actually **do** for each command: register, upload, list, download, verify. Carvin's pipe carries your messages, so you never deal with encryption yourself. You call `sec_send` and `sec_recv`.

## Your files

You edit **only** these:
- `common/identity.c`: keys, signing, checking, file fingerprints, the signed record
- `server/handlers.c` (and `server/handlers.h` if you need to add fields to `server_conn`; mention it in your PR)
- `client/commands.c`

Useful to read, but don't change:
- `common/identity.h`, `client/commands.h`: the functions you fill in.
- `common/protocol.h`: names for every number (`QD_SIG_BYTES`, `QD_T_REGISTER`, ...).
- `common/framing.h`: `put_u16`, `get_u64` and friends, for writing numbers into bytes.
- `docs/PROTOCOL.md` **sections 5.2, 5.3 and 6**: the signed record, error codes, and what each message contains.

## How signing works here

1. Each user has a **key pair**: a private key (kept secret, never committed) and a public key (shared with the server).
2. To upload a file, the client builds a small **record**: who, file name, size, the file's **fingerprint** (SHA-256 hash) and the time. Then it signs the record. Because the fingerprint is inside, signing the record also covers the file's contents.
3. The server checks three things, in order: the size matches, the fingerprint matches, and the signature is valid for that user's public key.
4. Anyone who downloads the file can check the same signature themselves.

The first time a user registers, the server remembers their public key. After that it refuses a different key for the same name. This is called **trust on first use**.

## The steps, in order

1. **Keys, sign, check** (by Tue Oct 20). Fill in `id_generate_keys`, `id_sign`, `id_verify`, `id_hash_file`. Test them on their own: sign something, check it passes, change one byte, check it fails.
2. **Signed record offline** (by Thu Oct 22). Fill in `id_make_record` with real values. Sign a record and check it, still without the network.
3. **Integration** (Tue Oct 27). Fill in register and upload on both client and server, using Carvin's pipe.
4. **List, download, verify** (Thu Oct 29).

**Important for upload:** the server must reject file names containing `/`, `\` or `..`. Otherwise someone could save a file outside the server's folder. The rule is in `docs/PROTOCOL.md` section 6.1.

`ai/role-chris.md` has the technical hints (which liboqs and OpenSSL functions to use). It's written for AI tools, but you can read it too.

## Terms you'll meet

| Term | What it means for you |
|---|---|
| **ML-DSA-65** | The quantum-safe signature method. Signature 3,309 bytes, public key 1,952 bytes. |
| **Key pair** | Private key (signs) and public key (checks). |
| **SHA-256 hash / fingerprint** | A 32-byte summary of a file. Any change gives a totally different hash. |
| **Signed record** | The small block of upload facts that gets signed. |
| **Integrity** | Nothing was changed. |
| **Sender authentication** | It really came from who it says. |
| **Trust on first use** | The first key seen for a name is trusted from then on. |
| **Path traversal** | A sneaky file name like `../../x` that escapes the storage folder. |
| **Handler** | The server code that runs for one type of message. |

More in `ai/glossary.md`.

## What you measure for the paper

- Do valid signatures always pass?
- Is tampering always caught? Change one byte of a file or record and show the check fails.
- Is a wrong sender caught? For example, a file signed by Alice but claimed as Bob's.
- How long signing and checking take. `bench/time_sign.c` already measures this; it starts giving real numbers once your code is in.

Send your numbers to Shalom: what you measured, the median, how many runs, and which machine you ran on. She combines everyone's numbers into the results table and charts; you write the paper section on what yours mean.

## Tips for you

- This lines up with your RSA-to-PQC assignment: same idea of a signature, but a quantum-safe one, with much bigger signatures than RSA.
- Build after every small change (`make`) and run `make test`.
- Never commit your key files. They live in `keys/`, which Git ignores.

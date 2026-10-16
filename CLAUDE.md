# QuantumDrive: project brief for Claude Code

**If the person you are working with is not Shalom** (for example Chris or Carvin), read `AGENTS.md` and follow it instead: ask which teammate they are and load their file in `ai/`. The rest of this file is Shalom's brief, and its task list is hers.

Read this whole file before doing anything in this repo. It records every decision made so far, why it was made, what is finished, and what is left. If something here conflicts with what Shalom tells you in chat, what she says in chat wins.

## 1. Who you are working with

- **Shalom Donga** is the repo owner and integrator. She is a computer science major, not a security specialist, and has no prior cryptography background. Explain every security concept in plain words first, with the technical term in brackets, e.g. "agreeing on a shared secret (key exchange)". Never assume she knows what a term means.
- She reviews and merges every teammate's pull request, so anything you produce must be easy for her to check: small changes, clear file boundaries, and a short plain-language summary of what changed and why.
- Writing preferences for any prose you write (docs, reports, PR descriptions): plain and factual, no em dashes, no filler, no invented specifics. If you are unsure of a fact, say so instead of guessing.

## 2. Course context

- Group project for a post-quantum cryptography course taught by Dr. Rawal at Grambling State University.
- The project plan was graded 47/50, so the scope below is accepted. It is a command-line program. There is no frontend in scope.
- Deliverables and dates:
  - Progress Report 1 (two pages): Thu Oct 15, 2026, 23:59.
  - Progress Report 2 (three pages): Sun Oct 18, 2026.
  - Final presentation in person and final paper (8 to 10 pages): Tue Nov 17, 2026, paper due 23:59.
- Code is submitted as a **zip file**. Dr. Rawal rejected a GitHub link on an earlier assignment. The zip must include the `.devcontainer/` folder so he can reproduce the environment.
- Grade weight sits in the paper, the measurements, and the demo. Code polish matters less than correct, measured, explainable results.

## 3. Team and ownership

| Person | Topic | Owns (folders/files) | Builds |
|---|---|---|---|
| Carvin Young | 7: the secure pipe | `common/securenet.*` | TCP connection, ML-KEM handshake, AES-GCM encryption, chunked transfer |
| Christopher (Chris) Stills | 8: proof of who sent what | `common/identity.*`, command handlers in `server/` and `client/` | Key pairs, ML-DSA signing and verifying, register, list, download |
| Shalom Donga | 5: farm devices | `sensor/`, `bench/`, `docs/`, the skeleton, integration | Sensor simulator, topic 5 measurements, combined results table and charts, repo setup, merging |

Notes:
- Shalom builds the skeleton first (empty server and client programs with a command loop, headers, stubs, Makefile). Chris fills in the handlers. Carvin supplies the secure pipe.
- Measurements: each person measures their own topic (research questions in section 4) and sends Shalom the numbers; she builds the combined results table and charts. Decided Oct 16; the teammate guides say this. Chris and Carvin still need to confirm it.
- Chris is also writing the separate RSA-to-PQC proof-of-concept assignment, so his load is kept lighter.
- Carvin did not have a GitHub account and has used PyCharm. Assume he is new to Git, C toolchains and VS Code. Shalom and Chris are on Windows, Carvin is on a Mac. Shalom has Docker installed.
- Shalom wants to get everything working herself first, then hand teammates a working setup. Do not design steps that require the three of them to troubleshoot together.

## 4. What the system does (plain version)

Three building blocks:

1. **Agreeing on a secret (key exchange, ML-KEM-768).** The server publishes a public key. The client uses it to create a secret plus a locked box holding that secret (ciphertext). Only the server's private key opens the box. Both sides end up with the same 32-byte secret even if someone watched the whole exchange. This is the step quantum computers would break in today's systems.
2. **Locking the files (symmetric authenticated encryption, AES-256-GCM).** The shared secret is turned into AES keys (with HKDF-SHA256, a key-derivation function). AES encrypts the data and also detects tampering. ML-KEM is not used on the files because it only makes keys and AES is far faster on large data.
3. **Proving who sent something (digital signature, ML-DSA-65).** The sender signs the file's fingerprint (SHA-256 hash) with their private key. Anyone with the public key can check it. Changing one byte breaks the signature.

A farm sensor (topic 5) is just a client running the same flow, where each reading is a tiny file.

Research questions the measurements answer:
- Topic 7: transfer time, recovery time after a dropped connection, and the extra cost (overhead) of PQC.
- Topic 8: do signatures verify, is tampering caught (integrity), is the sender who they claim (sender authentication).
- Topic 5: message size, CPU time and memory per reading. Key finding to explore: one ML-DSA-65 signature is 3,309 bytes, far larger than a small sensor reading.

## 5. Toolchain (decided, do not change without Shalom)

| Need | Choice | Reason |
|---|---|---|
| PQC library | **liboqs 0.16.0** (pinned) | Has both ML-KEM and ML-DSA, written in C. Version 0.15.0 removed the old "Dilithium" names, so use ML-DSA names. Older tutorials using Dilithium/Kyber names will fail. liboqs is for prototyping and evaluation, not production: state this as a limitation in the paper. |
| Algorithms | ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204) | Middle security level |
| File encryption | AES-256-GCM via OpenSSL, keys from HKDF-SHA256 (OpenSSL) | Standard, detects tampering |
| Connection | Raw TCP sockets | Built into C and Linux. Building the secure channel is the research. Paper limitation: real systems would use TLS with PQC. |
| Language | C core; small Python scripts only for charts and test scripts | Proposal says C; liboqs is C; exact timing and byte counts; close to embedded devices. Fallback if someone is stuck on a non-core piece: liboqs-python. |
| Build | Makefile for our code; CMake only to build liboqs | liboqs needs CMake; our code is small |
| Environment | **Dev container** (`.devcontainer/`), run in GitHub Codespaces or locally with Docker + VS Code Dev Containers | Same Linux for all three; removes the Windows/Mac problem |
| Never | Hand-written cryptography | Crypto bugs are subtle; the course is about using and evaluating PQC |

### Environment details

- Base image `mcr.microsoft.com/devcontainers/base:ubuntu-24.04` (if that tag fails to pull, try `noble`).
- The Dockerfile installs build-essential, cmake, ninja-build, libssl-dev, git, curl, gdb and valgrind. It then downloads the liboqs 0.16.0 release tarball and builds it with CMake/Ninja as a static library (`BUILD_SHARED_LIBS=OFF`), library only, with `OQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65"`, installed to `/usr/local`. Only those two algorithms exist in this build; adding any other algorithm means editing that line and rebuilding the container.
- `python3` and `python3-matplotlib` were added to the Dockerfile on Oct 15 for the chart scripts. They take effect after a container rebuild.
- `devcontainer.json` points at that Dockerfile, adds the `ms-vscode.cpptools` and `ms-vscode.makefile-tools` extensions, and runs as user `vscode`.
- `Makefile` currently has only `all`, `demo` and `clean`; it links `-loqs -lcrypto -lpthread`. `.gitignore` currently ignores only `build/`, `*.key` and `*.o`; extend it (keys folders, `*.pem`, generated data, server storage).
- Codespaces allowance: Shalom's verified student account gets 180 core-hours/month; free accounts get 120 (about 60 hours on a 2-core machine). Each person's usage bills to whoever creates the codespace. Codespaces needs internet, so demo-day fallback is the same container run locally with Docker.
- Cloud machines are shared, so timings are noisy. Repeat every measurement many times and report the median. Note in the paper that all measurements ran on the same machine type.

### What has been verified

A previous session built liboqs 0.16.0 on Ubuntu 24.04 with the Dockerfile commands, and `make demo` ran `demo/pqc_demo.c` with this output:

```
== Key exchange: ML-KEM-768 ==
server makes key pair         1.384 ms
client makes locked box       0.014 ms
server opens locked box       0.012 ms
public key 1184 bytes | locked box 1088 bytes | secret 32 bytes
shared secrets match: YES

== Signature: ML-DSA-65 ==
sign                          0.130 ms
verify                        0.029 ms
message 31 bytes | signature 3309 bytes | public key 1952 bytes
original message verifies: YES
tampered message verifies: NO (should be NO)
```

The 1.4 ms first key pair is mostly start-up cost; single runs are not results.

Verified Oct 15: the Docker image builds and `make demo` runs in the local dev container on Shalom's Windows machine (Docker Desktop, WSL2).

Oct 16: Shalom opened a codespace and it appeared to work. `make demo`, `make test` and the hook setting were not individually checked there, so treat Codespaces as lightly tested.

Not verified: the Mac path (Carvin has not brought his laptop yet). Carvin is told to use Codespaces until someone tests a Mac.

## 6. Repo layout

```
quantumdrive/
  README.md          how to build and run (keep current)
  CLAUDE.md          this file
  AGENTS.md          rules for any AI assistant (to be written)
  .devcontainer/     Dockerfile, devcontainer.json
  .github/           CODEOWNERS, copilot-instructions.md pointer, optional Actions
  .claude/           settings.json (attribution off)
  ai/                rules-common.md, role-carvin.md, role-chris.md, role-shalom.md, glossary.md
  docs/              PROTOCOL.md, diagram, setup guides, reports
  common/            shared code: protocol constants, framing, securenet (Carvin), identity (Chris), bench (Shalom)
  server/            server program (skeleton by Shalom, handlers by Chris)
  client/            client program (skeleton by Shalom, handlers by Chris)
  sensor/            sensor simulator (Shalom)
  bench/             measurement programs and Python chart scripts (Shalom)
  demo/              pqc_demo.c toolchain check
  tests/             make test (Shalom)
  scripts/           helper scripts
  Makefile
  .gitignore         build output, keys, local data
```

## 7. Protocol v1 (message format)

Every message on the wire is a frame: `[4-byte length, big-endian][1-byte type][payload]`.

Handshake (unencrypted):

| Code | Name | Direction | Payload |
|---|---|---|---|
| 0x01 | HELLO | client to server | protocol version |
| 0x02 | KEM_PUBKEY | server to client | fresh ML-KEM-768 public key, new per connection |
| 0x03 | KEM_CIPHERTEXT | client to server | ML-KEM ciphertext (the locked box) |

After the handshake both sides hold the same 32-byte secret. HKDF-SHA256 derives **two** AES-256 keys, one per direction (client-to-server and server-to-client), so the same key and nonce are never reused in both directions. Each direction keeps a message counter used as the 12-byte GCM nonce; the counter is not sent.

After that every message is type `0x10 SECURE`, whose payload is AES-GCM ciphertext (with tag) of `[1-byte app type][body]`.

| Code | Name | Meaning |
|---|---|---|
| 0x20 | REGISTER | client sends its ID and ML-DSA public key; server stores it on first sight (trust on first use) |
| 0x21 | UPLOAD_BEGIN | signed record (ID, filename, size, SHA-256, timestamp) plus signature |
| 0x22 | CHUNK | offset and data, max 64 KiB, both directions |
| 0x23 | UPLOAD_END | server checks hash and signature, replies OK or ERROR |
| 0x24 | LIST_REQUEST | |
| 0x25 | DOWNLOAD_REQUEST | server replies with record, chunks, then an end message |
| 0x26 | KEY_REQUEST | client fetches uploader's public key to verify locally |
| 0x27 | STATUS_REQUEST | stretch: bytes received so far, for resuming |
| 0x30 | OK | |
| 0x31 | ERROR | |
| 0x32 | LIST_REPLY | file records |
| 0x35 | KEY_REPLY | |

Known limitation for the paper: v1 does not authenticate the server, so a man-in-the-middle could attack the handshake. A signed server key can be added later as a new message type without changing the others.

Open details (signed record layout, HKDF salt and info strings, maximum frame size, error codes) were settled with Shalom on Oct 15. See `docs/PROTOCOL.md`, which is now the authority on byte layouts.

## 8. Shared function contract

All functions return 0 on success and a negative code on error. Teammates code against these headers using stubs until the real code lands.

```c
/* common/securenet.h  (Carvin) */
int  net_listen(int port);
int  net_accept(int listen_fd);
int  net_connect(const char *host, int port);
int  sec_handshake_client(int fd, sec_session *s);
int  sec_handshake_server(int fd, sec_session *s);
int  sec_send(sec_session *s, uint8_t type, const uint8_t *body, size_t len);
int  sec_recv(sec_session *s, uint8_t *type, uint8_t *buf, size_t cap, size_t *len);
void sec_close(sec_session *s);

/* common/identity.h  (Chris) */
int id_generate_keys(const char *id, const char *dir);
int id_sign(const char *key_path, const uint8_t *msg, size_t n, uint8_t *sig, size_t *sig_len);
int id_verify(const uint8_t *pk, const uint8_t *msg, size_t n, const uint8_t *sig, size_t sig_len);
int id_hash_file(const char *path, uint8_t out[32]);
int id_make_record(const char *id, const char *file, uint8_t *rec, size_t *rec_len);

/* common/bench.h  (Shalom) */
uint64_t bench_now_ns(void);
void     bench_log(const char *label, uint64_t value, const char *unit);
```

`sec_session` is defined in `securenet.h` and holds the socket, both direction keys, and both counters. Its fields are named send/recv from each program's own point of view, so the same code works on client and server.

`common/protocol.h` (Shalom, approved Oct 15) holds every message code, size and return code from `docs/PROTOCOL.md`. Use its names instead of typing numbers. It has the same change rule as the other headers.

## 9. Git workflow

- One branch per person: `carvin/secure-pipe`, `chris/identity`, `shalom/sensor`. Nobody pushes to `main` except Shalom.
- Teammates open a pull request to `main`; Shalom reviews the "Files changed" tab and merges.
- Shalom's GitHub student account should include GitHub Pro, which allows branch protection with required reviewers on a private repo. Set it on `main`, keep admin bypass on so Shalom can push her own work. Confirm in repo settings; if unavailable, the rule is enforced by review.
- `CODEOWNERS` maps each folder to its owner so GitHub requests the right review.
- Optional later: a GitHub Action that builds on push, and one that fails a PR if the author changed folders they don't own.
- **No AI attribution anywhere.** No `Co-Authored-By` trailers, no "Generated with" lines in commits or PR descriptions, from any tool. For Claude Code this is set in `.claude/settings.json`:

```json
{
  "attribution": { "commit": "", "pr": "" }
}
```

(The older key `includeCoAuthoredBy` is deprecated.) Other assistants must be told the same rule in `AGENTS.md`.

Backup enforcement, since teammates may use any tool: a `commit-msg` git hook stored in the repo (for example `scripts/hooks/commit-msg`, enabled with `git config core.hooksPath scripts/hooks`, which the setup guide and the dev container's post-create step should run) that deletes `Co-Authored-By:` lines and "Generated with" lines naming an AI tool. Optionally, a GitHub Action that fails a PR whose commits still contain them. Test the hook before relying on it.

## 10. AI instruction files (to build)

Instruction files guide an assistant; they cannot verify identity. Real enforcement is PR review, CODEOWNERS and branch protection. Build:

- `AGENTS.md` at the root: the shared rules. Many assistants (including OpenAI Codex) read it.
- Pointer files that say "read AGENTS.md and the ai/ folder": `CLAUDE.md` section for teammates or a short note, `.github/copilot-instructions.md`.
- `ai/rules-common.md`, `ai/role-carvin.md`, `ai/role-chris.md`, `ai/role-shalom.md`, `ai/glossary.md`.

Rules every assistant must follow:
1. First ask "Which teammate are you?", load that role file, and edit only that person's folders.
2. Use liboqs for all PQC. Never write cryptography by hand.
3. Never change `docs/PROTOCOL.md` or any header in `common/*.h` without Shalom's approval; propose the change in the PR description instead.
4. Never commit keys, secrets, or generated data. Never push to `main`.
5. No AI attribution in commits or PRs (see section 9).
6. Explain in plain words with the technical term in brackets. Assume the teammate is new to C and Git.
7. Run `make` and `make test` before suggesting a push. Report honestly what was and wasn't tested.
8. Keep changes small and inside the owner's folder.

## 11. Status as of Oct 15, 2026

Done (decided or verified):
- Roles and topic ownership agreed.
- Toolchain chosen, liboqs 0.16.0 pinned.
- Dev container files drafted (Dockerfile, devcontainer.json, Makefile, demo/pqc_demo.c, .gitignore) and the liboqs build plus demo verified on Ubuntu 24.04.
- Protocol v1 and the function contract agreed.
- Git workflow and AI-guidance approach agreed.

- Progress Report 1 filled in on the course template (not yet submitted as of Oct 15).

Files Shalom has right now (all from the earlier session), and where they go:

| File | Repo path |
|---|---|
| Dockerfile | `.devcontainer/Dockerfile` |
| devcontainer.json | `.devcontainer/devcontainer.json` |
| Makefile | `Makefile` |
| pqc_demo.c | `demo/pqc_demo.c` |
| gitignore | `.gitignore` (note the leading dot) |
| this file | `CLAUDE.md` |
| CHATGPT_BRIEF.md | not in the repo; for teammates who use ChatGPT |

An earlier chat session wrote and tested a code skeleton, tests, a commit-message hook and draft docs, but it ran out of usage before delivering any of them. None of that work exists. Rebuild it from this file.

Not done or not confirmed (check the repo before assuming):
- Whether the GitHub repo exists and the files above are committed at those paths.
- Teammates invited, Carvin's GitHub account created.
- The skeleton (headers, stubs, server/client command loop, `make test`). A previous session started it but never delivered it.
- `README.md`, `docs/PROTOCOL.md`, `docs/SETUP.md`, `docs/log/`, `AGENTS.md`, `ai/` files, `.github/CODEOWNERS`, `.github/copilot-instructions.md`, `.claude/settings.json`, the commit-msg hook.
- Docker build and Codespaces launch tested end to end.

## 12. Your task list, in order

Stop after each step, summarise in plain words, and let Shalom confirm before moving on.

1. Inspect the repo. Report what exists versus section 6.
2. Make sure the dev container files exist and are correct. Help Shalom build and open it (locally with Docker + Dev Containers extension, or Codespaces) and run `make demo`. She needs a screenshot of the output for Progress Report 1.
3. Write `docs/PROTOCOL.md` from section 7, settling the open details with Shalom.
4. Build the skeleton: `common/framing.*`, the three headers exactly as in section 8, stub implementations that compile and return fixed fake values, `server/` and `client/` programs with a command loop (`register`, `upload`, `list`, `download`, `verify`), `sensor/` stub, `bench/` helpers, Makefile targets (`all`, `demo`, `test`, `clean`), and a minimal `make test`.
5. Write `.claude/settings.json`, `CODEOWNERS`, `AGENTS.md`, `.github/copilot-instructions.md`, the `ai/` files, and the commit-msg hook (section 9). Write `README.md`.
6. Write `docs/SETUP.md`: one short guide per person (create GitHub account, accept invite, open codespace or local container, run `make demo`, create branch, commit, open PR). Plain steps, one action per step, what each command does.
7. Then Shalom's own topic 5 work: sensor reading generator in an agreed format, size measurements against stubs, later real signing via Chris's code.

## 13. Milestones

| Date | Goal |
|---|---|
| Thu Oct 15 | Toolchain running, demo screenshot, protocol doc, Report 1 submitted |
| Sun Oct 18 | Report 2 (three pages) |
| Tue Oct 20 | Carvin: TCP hello. Chris: keygen, sign/verify a file hash. Shalom: sensor readings in agreed format |
| Thu Oct 22 | Carvin: ML-KEM handshake. Chris: signed upload record checked offline. Shalom: signed readings via Chris's code |
| Tue Oct 27 | Integration: encrypted channel carries a signed file, server stores it |
| Thu Oct 29 | Download, list, verify. Sensor auto-uploads |
| Tue Nov 3 | Basic chunking, resume if time. First measurements |
| Thu Nov 5 | Each person's measurements done and sent to Shalom; she builds the results table and charts. Decide cuts |
| Tue Nov 10 | Paper writing, each on own topic |
| Thu Nov 12 | Edit paper, slides, rehearse demo, freeze code, zip |
| Tue Nov 17 | Presentation; paper due 23:59 |

Must-have: ML-KEM handshake, AES-encrypted upload, signed upload and verify, sensor simulator, three measurements (transfer time, message size, signature check).
Stretch, cut in this order if short on time: share links, version history, resume after drop, front end.

Habit: at the end of every work session, each person writes 3 to 4 sentences on what they built and found, in their own file in `docs/log/` (`shalom.md`, `chris.md`, `carvin.md`). One file each, so log entries never cause merge conflicts. These become the paper.

## 14. Risks

- liboqs install failure: solved by the dev container; local Docker is the fallback.
- Pieces not fitting together: contract first, stubs, fixed integration sessions Oct 27 and 29.
- Too much for about 10 team hours: must-have first, cut list above, protect benchmarks and paper.
- Teammates' AI tools ignoring the rules: PR review is the real check.

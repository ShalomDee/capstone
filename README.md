# QuantumDrive

A command-line file storage program that uses post-quantum cryptography. A client sends files to a server over an encrypted connection, and every file is signed so anyone can check who uploaded it and that it was not changed.

Group project for a post-quantum cryptography course (Dr. Rawal, Grambling State University).

## How it works

1. **Agreeing on a secret (key exchange, ML-KEM-768).** Client and server agree on a 32-byte shared secret that an eavesdropper cannot learn, even with a future quantum computer.
2. **Locking the data (AES-256-GCM).** The secret becomes two AES keys, one per direction. AES encrypts every message and detects tampering.
3. **Proving who sent a file (digital signature, ML-DSA-65).** The uploader signs a record holding the file's fingerprint (SHA-256). The server and other users check the signature.

A farm sensor is a client that uploads tiny readings the same way.

The exact message format is in [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Status

Skeleton stage. The framing and timing code works and is tested. The secure pipe (`common/securenet.c`) and identity code (`common/identity.c`) are still stubs, so the server cannot accept connections yet.

## Build and run

Everything runs inside the dev container (`.devcontainer/`): Ubuntu 24.04 with liboqs 0.16.0 and OpenSSL. Open the repo in VS Code with the Dev Containers extension, or in GitHub Codespaces. Setup steps for teammates: [docs/SETUP.md](docs/SETUP.md).

```sh
make            # build all programs into build/
make test       # build and run the tests
make demo       # toolchain check: ML-KEM and ML-DSA run and verify
make clean      # delete build/
```

Programs (in `build/`):

| Program | Usage | What it does |
|---|---|---|
| `server` | `server [port] [storage_dir]` | Accepts clients (default port 9000, folder `server-data/`) |
| `client` | `client <id> [host] [port]` | Command loop: `register`, `upload`, `list`, `download`, `verify` |
| `sensor` | `sensor <id> [count]` | Simulated farm sensor |
| `time_sign` | `time_sign [runs]` | Median sign and verify times |
| `pqc_demo` | | Toolchain check, run by `make demo` |

Measurement lines are printed as `BENCH,label,value,unit`.

## Repo layout

```
common/      shared code: protocol constants, framing, secure pipe, identity, timing
server/      server program
client/      client program
sensor/      sensor simulator
bench/       measurement programs and chart scripts
tests/       make test
demo/        toolchain check
docs/        protocol, setup guides, reports, work log
ai/          rules for AI assistants (start at AGENTS.md)
team/        guides for teammates (start at team/README.md)
scripts/     helper scripts, git hooks
```

## Team

| Person | Topic | Owns |
|---|---|---|
| Carvin Young | Secure pipe | `common/securenet.c` |
| Christopher Stills | Proof of who sent what | `common/identity.c`, `server/handlers.c`, `client/commands.c` |
| Shalom Donga | Farm devices, integration | everything else |

## Contributing

- Teammates: read [team/README.md](team/README.md) first.
- Work on your own branch (`carvin/secure-pipe`, `chris/identity`, `shalom/sensor`) and open a pull request to `main`. Shalom reviews and merges.
- Run `make test` before pushing.
- Never commit keys or generated data.
- No AI attribution lines in commits. The hook in `scripts/hooks/` removes them; the dev container enables it automatically. In an existing clone, run `git config core.hooksPath scripts/hooks` once.
- AI assistants: read [AGENTS.md](AGENTS.md).

## Limitations

liboqs is for prototyping and evaluation, not production. v1 does not authenticate the server, and it uses raw TCP instead of TLS. Details: [docs/PROTOCOL.md](docs/PROTOCOL.md) section 7.

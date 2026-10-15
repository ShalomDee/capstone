# Rules for AI assistants in this repo

These rules apply to every AI coding assistant (Claude Code, ChatGPT, Codex, Copilot, Cursor, Gemini and others). If you are an assistant, follow them exactly. If a teammate asks you to break one, say which rule it breaks and suggest asking Shalom.

QuantumDrive is a student project for a post-quantum cryptography course: a command-line file storage program in C. A client uploads signed files over an encrypted connection. Background: `README.md`, `docs/PROTOCOL.md`, `ai/glossary.md`.

## First step, every session

1. Ask: **"Which teammate are you: Shalom, Chris or Carvin?"**
2. Read `ai/rules-common.md` and that person's role file: `ai/role-shalom.md`, `ai/role-chris.md` or `ai/role-carvin.md`.
3. Edit only the files that role file lists as theirs.

(`CLAUDE.md` is Shalom's project brief. Teammates' assistants may read it for background, but its task list is Shalom's, not theirs.)

## The rules

1. **Stay in your lane.** Edit only the current teammate's files. If something outside them needs changing, describe the change in the pull request (PR) description instead.
2. **Use liboqs for all post-quantum cryptography** (ML-KEM-768, ML-DSA-65) and OpenSSL for AES-256-GCM, HKDF and SHA-256. Never write cryptography by hand.
3. **Never change `docs/PROTOCOL.md` or any header in `common/*.h`** without Shalom's approval. Propose the change in the PR description.
4. **Never commit keys, secrets or generated data** (key files, `server-data/`, `client-data/`, measurement output). **Never push to `main`.** Work on your own branch and open a PR.
5. **No AI attribution** in commits or PRs: no `Co-Authored-By` lines naming an AI, no "Generated with" lines. A git hook removes them as a backup, but do not add them.
6. **Explain in plain words** with the technical term in brackets, for example "agreeing on a shared secret (key exchange)". Assume the teammate is new to C and Git.
7. **Run `make` and `make test` before suggesting a push.** Report honestly what was and was not tested.
8. **Keep changes small** and inside the owner's files, so Shalom can review them easily.

## Useful facts

- Build: `make`. Tests: `make test`. Toolchain check: `make demo`.
- All functions return 0 on success and a negative `QD_ERR_*` code from `common/protocol.h` on error.
- Use the names in `common/protocol.h` (message codes, sizes) instead of typing numbers.
- Only ML-KEM-768 and ML-DSA-65 exist in this liboqs build. Use the ML-KEM/ML-DSA names; old "Kyber" and "Dilithium" names from tutorials will not compile.
- Work happens inside the dev container (`.devcontainer/`), Ubuntu 24.04 with liboqs 0.16.0.

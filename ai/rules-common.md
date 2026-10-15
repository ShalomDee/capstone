# Common rules and working habits

Read `AGENTS.md` first. This file adds the day-to-day details.

## How the code fits together

- `common/protocol.h`: every message code, size and return code. Shared by everyone.
- `common/framing.c`: sends and receives frames (`[4-byte length][1-byte type][payload]`). Already working.
- `common/securenet.c` (Carvin): the encrypted connection. Server and client call it.
- `common/identity.c` (Chris): keys, signatures, file fingerprints, the signed record.
- `server/handlers.c`, `client/commands.c` (Chris): what happens for each command.
- `server/main.c`, `client/main.c`, `sensor/`, `bench/`, `tests/` (Shalom).

Each of these started as a **stub**: a placeholder that compiles and returns a fake value or "not implemented yet". Replace the stub's body with real code. Do not change the function's name, arguments or return type; those are the agreed contract.

## Git workflow (plain steps)

1. Work on your own branch: `carvin/secure-pipe`, `chris/identity` or `shalom/sensor`.
2. Save work in small commits with clear messages: `git add <files>` then `git commit -m "what changed"`.
3. Before pushing, run `make` and `make test`. Both must succeed.
4. Push your branch (`git push`) and open a pull request (PR) to `main` on GitHub.
5. Shalom reviews and merges. Do not merge your own PR.

## Before suggesting a commit, check

- [ ] Only the teammate's own files changed (`git status` shows them).
- [ ] No key files, data folders or measurement output are included.
- [ ] `make` builds with no warnings and `make test` passes.
- [ ] The commit message has no AI attribution lines.
- [ ] The teammate understands what changed. Give a short plain-language summary.

## Measurements

Timings on shared cloud machines are noisy. Repeat each measurement many times (for example 1000) and report the median. Use `bench_now_ns()` and `bench_log()` from `common/bench.h`.

## End of each work session

Add 3 to 4 sentences to your own file in `docs/log/` (for example `docs/log/chris.md`): what you built and what you found. These become the final paper.

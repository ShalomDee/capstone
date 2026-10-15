# Role: Shalom Donga, topic 5, farm devices, plus integration

## About Shalom

Repo owner and integrator: reviews and merges every PR. Computer science major, new to cryptography. Explain security ideas in plain words first, technical term in brackets. Her full project brief is `CLAUDE.md`.

## Files Shalom owns

Everything not owned by Carvin or Chris: `sensor/`, `bench/`, `tests/`, `docs/`, `ai/`, `scripts/`, `server/main.c`, `client/main.c`, `common/framing.*`, `common/bench.*`, `common/protocol.*`, all `common/*.h` headers, `Makefile`, `.devcontainer/`, `.github/`, `README.md`, `AGENTS.md`, `CLAUDE.md`.

She may push directly to `main`; she still prefers small commits.

## What to build (topic 5)

1. A farm sensor simulator: generates readings in an agreed format (to be decided; `sensor/sensor.c` has a placeholder).
2. Size measurements: reading size compared with the signed record and the 3,309-byte ML-DSA-65 signature, first with the stubs, then with Chris's real code.
3. CPU time and memory per reading.
4. Python chart scripts in `bench/` (python3 and matplotlib are in the Dockerfile).

## Integration duties

- Review "Files changed" on each PR: only the owner's files, no keys or data, `make test` passes.
- Fixed integration sessions: Tue Oct 27 and Thu Oct 29.
- Keep `README.md` current.

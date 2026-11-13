# Work log: Carvin

At the end of each work session, add 3 to 4 sentences: what you built and what you found. Newest at the bottom. These become the paper.

Format:

## YYYY-MM-DD
What I built. What I found or measured. What's next or what's blocking me.

---

## 2026-11-12
I added tests for the ML-KEM handshake, matching directional keys, encrypted message round trips, tamper rejection, and wrong protocol versions. I measured 1,000 handshakes: median 175,981 ns, 1,099 bytes client-to-server and 1,189 bytes server-to-client, on the Codespaces Linux x86_64 machine. `make` and `make test` passed with 829 checks and no failures. The next step is Shalom's review and my explanation of the handshake and key derivation in the PR.

> **Correction added by Shalom (integrator), 2026-11-12, after merging PR #5.** The 829 checks above were counted at commit `b79731c`. Carvin's last commit in the PR, `b548448` ("Use separate processes in secure pipe tests"), changed only `tests/test_main.c` and brought the count to **822 checks, 0 failed**. That is what the merged code gives; Shalom ran it on both commits in WSL. The handshake timing and byte counts above still apply: `b548448` did not change `common/securenet.c` or the timing code (`./build/test_main --measure-handshake`), and the later fix `c3b14d0` (close the connection on a bad tag or counter overflow) changes only failure paths and keeps 822 checks. A separate PDF report on Topic 7 dated Nov 12 gives 733 checks and medians of 0.164 and 0.172 ms. Those figures do not match any pushed commit, so use the numbers in this log and in `docs/results/`, not the PDF.

# Work log: Carvin

At the end of each work session, add 3 to 4 sentences: what you built and what you found. Newest at the bottom. These become the paper.

Format:

## YYYY-MM-DD
What I built. What I found or measured. What's next or what's blocking me.

---

## 2026-11-12
I added tests for the ML-KEM handshake, matching directional keys, encrypted message round trips, tamper rejection, and wrong protocol versions. I measured 1,000 handshakes: median 175,981 ns, 1,099 bytes client-to-server and 1,189 bytes server-to-client, on the Codespaces Linux x86_64 machine. `make` and `make test` passed with 829 checks and no failures. The next step is Shalom's review and my explanation of the handshake and key derivation in the PR.

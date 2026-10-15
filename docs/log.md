# Work log

At the end of each work session, add 3 to 4 sentences: what you built and what you found. Newest at the bottom. These become the paper.

Format:

## YYYY-MM-DD, Name
What I built. What I found or measured. What's next or what's blocking me.

---

## 2026-10-15, Shalom
Verified the dev container: liboqs 0.16.0 builds and `make demo` shows ML-KEM-768 secrets matching and ML-DSA-65 rejecting a tampered message. Settled protocol v1 in docs/PROTOCOL.md (frame size, HKDF salt bound to the handshake, signed record layout, error codes). Built the code skeleton with stubs so everyone can start in parallel; make test passes 44 checks. The sensor stub already shows the topic 5 question: a 15-byte reading carries a 3,309-byte signature.

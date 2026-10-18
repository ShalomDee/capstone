# Work log: Shalom

At the end of each work session, add 3 to 4 sentences: what you built and what you found. Newest at the bottom. These become the paper.

Format:

## YYYY-MM-DD
What I built. What I found or measured. What's next or what's blocking me.

---

## 2026-10-15
Verified the dev container: liboqs 0.16.0 builds and `make demo` shows ML-KEM-768 secrets matching and ML-DSA-65 rejecting a tampered message. Settled protocol v1 in docs/PROTOCOL.md (frame size, HKDF salt bound to the handshake, signed record layout, error codes). Built the code skeleton with stubs so everyone can start in parallel; make test passes 44 checks. The sensor stub already shows the topic 5 question: a 15-byte reading carries a 3,309-byte signature.

## 2026-10-18
Added bench/time_pqc.c and a `make bench` target: it times ML-KEM-768 and ML-DSA-65 directly through liboqs, 1000 runs each, and reports the median with the 10th and 90th percentiles. Ran it in the local dev container (Docker Desktop on Windows, 11th Gen Intel Core i5-1155G7, 8 cores visible); medians were ML-KEM-768 keypair 0.0104 ms, encapsulate 0.0111 ms, decapsulate 0.0128 ms, and ML-DSA-65 keypair 0.0346 ms, sign 0.0920 ms, verify 0.0331 ms. Signing varies the most (p10 0.047 ms, p90 0.234 ms), which fits ML-DSA retrying internally until a signature passes its checks. All 1000 signatures verified and all 1000 tampered 12-byte readings were rejected; next is agreeing the sensor reading format.

Raw output:
```
ML-KEM-768, 1000 runs
keypair                median   0.0104 ms   p10   0.0094   p90   0.0153
encapsulate            median   0.0111 ms   p10   0.0100   p90   0.0161
decapsulate            median   0.0128 ms   p10   0.0116   p90   0.0182
ML-DSA-65, 1000 runs (0 verify failures)
keypair                median   0.0346 ms   p10   0.0315   p90   0.0552
sign                   median   0.0920 ms   p10   0.0472   p90   0.2335
verify                 median   0.0331 ms   p10   0.0302   p90   0.0526
tampered readings rejected: 1000 of 1000
```

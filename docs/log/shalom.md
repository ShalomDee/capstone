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

Later on 2026-10-18: Built the sensor reading format agreed today (v1 CSV, one newline-terminated line per reading, 39 bytes for the example) in sensor/reading.c, with strict parsing and batch checks that refuse gaps, duplicates, reordering, mixed sensors and clocks going backwards; `make test` now runs 701 checks. `make sensor-sizes` sends 100 simulated readings in files of 1, 10 and 100, one signature per file, using real file and record sizes but the identity stub and byte counts computed from PROTOCOL.md, since the secure pipe is still a stub. Sensor-to-server bytes per reading were 3,508.9 (batch 1), 386.6 (batch 10) and 73.7 (batch 100); the signature is 94.3% of upload bytes at batch 1 and 44.9% at batch 100. Connection setup adds 3,086 bytes to the server and 1,211 back, once per connection; next is CPU time and memory per reading once Chris's real signing lands, and checking these byte counts against Carvin's real sec_send.

## 2026-10-31
Reviewed Chris's PR #2 (ML-DSA-65 key generation) on Oct 27 and merged it: it builds with no warnings, `make test` passes 701 of 701, and a separate run confirmed the private key is saved owner-only (0600) even with the loosest umask, the public key is 1,952 bytes, existing keys are never overwritten, and IDs that could escape the keys folder are rejected. Merged `main` into `shalom/sensor` and set the rule that each teammate writes tests for their own functions in `tests/test_main.c`, which I review. Dr. Rawal replied that teams cannot change and that individual contributions will count in grading, so the original split stays and this log is my record. As of today `common/securenet.c` is still my stub and `id_sign` is not written, so my CPU and memory per signed reading and real socket byte counts are still blocked; Chris and Carvin have until Fri Nov 6, 23:59 to push code and tests, since I am away Nov 2 to 6.

## 2026-11-11
Reviewed and merged Chris's PR #4 (signing, file checks, server and client commands) after his fixes for same-name re-uploads and single error replies; it builds with no warnings and `make test` passes 797 of 797. Reviewed Carvin's PR #5 (secure pipe) and requested changes: the code matches PROTOCOL.md but adds no tests, so it is not merged yet. With both branches merged in a test copy, the real client and server ran end to end over the encrypted connection for the first time: register, a 200 KB multi-chunk upload, a 39-byte sensor reading upload, list, and a download that verified and matched the original byte for byte (one run, not a measurement). Local Docker stopped working, so I now build and test in WSL (Ubuntu 24.04, liboqs 0.16.0); I added a wrong-key check to `make bench`, where 1000 of 1000 signatures were rejected under a different real key pair. WSL timings on the same laptop were about 35% faster than the Oct 18 Docker run, so results from different environments must be reported separately.

Raw output (WSL, 11th Gen Intel Core i5-1155G7):
```
ML-KEM-768, 1000 runs
keypair                median   0.0065 ms   p10   0.0064   p90   0.0071
encapsulate            median   0.0069 ms   p10   0.0069   p90   0.0074
decapsulate            median   0.0080 ms   p10   0.0080   p90   0.0084
ML-DSA-65, 1000 runs (0 verify failures)
keypair                median   0.0212 ms   p10   0.0209   p90   0.0239
sign                   median   0.0598 ms   p10   0.0305   p90   0.1364
verify                 median   0.0211 ms   p10   0.0209   p90   0.0229
tampered readings rejected: 1000 of 1000
signatures rejected under a different real key: 1000 of 1000
```

## 2026-11-12
Added `make measure`, which runs every timing and byte measurement three times in one sitting and writes a summary with charts to docs/results/results-wsl.md; it measured over the real encrypted connection by merging Carvin's PR #5 into a test copy, since that PR is not merged yet. All 1,642 connections sent and received exactly the bytes computed from PROTOCOL.md, so the Progress Report 2 byte counts are now confirmed on a real socket. Because the client opens a new connection per file, each file also pays a 1,099-byte handshake, so one reading per file costs 4,608 bytes sent per 38.9-byte reading (3,509 without the handshake), and 100 per file costs 85. Medians in WSL on the i5-1155G7: connect plus handshake 0.22 ms, upload 1 MiB 3.9 ms and 10 MiB 26.9 ms, sensor CPU 125 µs per reading at one per file and 3.4 µs at 100 per file, peak memory about 5.5 MiB; medians moved up to about 30% between the three runs, and a first run without a warm-up showed ML-KEM about twice as slow, so the script now warms up first. Also added scripts/demo.sh (sensor upload, list, download, tamper, rejection) and scripts/sensor_upload.sh; both run end to end.

Later on 2026-11-12: Carvin pushed a second version of PR #5 with three tests (handshake plus an encrypted message each way, one changed byte rejected, wrong-version HELLO answered with ERROR 0x09), a 1,000-handshake timing mode, and a rewritten `common/securenet.c`; I checked the new file against PROTOCOL.md, built it in WSL with no warnings, ran `make test` (822 of 822, five runs) and the full demo, and merged it. His log said 829 checks, which I traced to his earlier commit `b79731c` (his last commit changed only the tests and gives 822), so I added a marked correction under his entry; a separate PDF report on Topic 7 dated Nov 12 gives 733 checks and medians of 0.164 and 0.172 ms, which match no pushed commit. After the merge I changed `securenet.c` (commit `c3b14d0`) so it closes the connection itself after a bad tag or a counter overflow, as PROTOCOL.md section 5 requires, instead of relying on every caller, and restored the comment block that describes the frame, handshake and key layout; the tamper test now also checks the connection is closed, and I confirmed it fails without the change. A first `make measure` rerun in WSL was too noisy to use (code that had not changed ran 28 to 64% slower and runs differed up to 3x), so I did not keep it.

Later on 2026-11-12 (Codespaces, AMD EPYC 7763, 2 vCPUs): On the merged code (`c3b14d0`), `make test` passed 822 of 822 with no warnings, `scripts/demo.sh` ran end to end and rejected the tampered file, and Carvin's `--measure-handshake` gave a median of 0.157 ms and 2,288 bytes (his own Codespaces run gave 0.176 ms). `make measure` there is now the results of record (docs/results/results-codespaces.md): ML-KEM-768 keypair 0.0156 ms, encapsulate 0.0161 ms, decapsulate 0.0184 ms; ML-DSA-65 sign 0.1197 ms, verify 0.0519 ms; connect plus handshake 0.214 ms; upload 1 MiB 5.65 ms and 10 MiB 51.0 ms; sensor CPU 261 µs per reading at one per file and 6.0 µs at 100 per file, peak memory 5,888 KiB. All 1,642 connections sent and received exactly the bytes computed from PROTOCOL.md, 1,000 of 1,000 tampered readings and 1,000 of 1,000 signatures under a different real key were rejected, and the post-quantum medians moved less than 3% across the three runs while network times moved more (handshake 0.214 to 0.329 ms, 10 MiB upload 48.5 to 74.9 ms). The two handshake figures measure different things: 0.157 ms is the client's handshake call on an open connection, 0.214 ms includes opening the connection, so the paper must say which one it quotes. I removed the earlier WSL results (they predate the merge and used an older version of the secure pipe; still in git history at `d4bf763`), and kept the paper drafts out of the repo; next is the final pull request from `shalom/sensor` to `main`, the zip built from `main`, and the paper.

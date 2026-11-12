# QuantumDrive benchmark results

## Test setup

| Field | Value |
| --- | --- |
| Test environment | GitHub Codespaces (cloud workspace) |
| CPU model | AMD EPYC 7763 |
| CPU architecture | x86_64 (64-bit x86) |
| Logical CPUs | 2 visible to the workspace |
| Trials | 1,000 per algorithm |
| What was timed | Individual cryptographic operations using liboqs |
| Outside the timed operations | File reads, file writes, and network transfers |

The setup identifies what ran and where so readers can compare results fairly.

## Timing results

All values are in milliseconds. P10 and P90 are the 10th and 90th percentiles.

| Algorithm | Operation | Median (ms) | P10 (ms) | P90 (ms) |
| --- | --- | ---: | ---: | ---: |
| ML-DSA-65 | Key generation | 0.0565 | 0.0562 | 0.0900 |
| ML-DSA-65 | Sign | 0.1276 | 0.0662 | 0.2865 |
| ML-DSA-65 | Verify | 0.0529 | 0.0528 | 0.0789 |
| ML-KEM-768 | Key generation | 0.0232 | 0.0156 | 0.0266 |
| ML-KEM-768 | Encapsulate | 0.0239 | 0.0162 | 0.0273 |
| ML-KEM-768 | Decapsulate | 0.0256 | 0.0187 | 0.0287 |

## Verification outcomes

- Valid signatures verified: 1,000/1,000.
- Tampered readings rejected: 1,000/1,000.
- Earlier project test suite: 797 checks, 0 failures.

The test suite count is separate from the benchmark trials. These timings describe individual operations, not full file transfer latency.

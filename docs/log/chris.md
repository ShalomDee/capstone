# Work log: Chris

At the end of each work session, add 3 to 4 sentences: what you built and what you found. Newest at the bottom. These become the paper.

Format:

## YYYY-MM-DD
What I built. What I found or measured. What's next or what's blocking me.

---

Added registration, public key lookup, and the upload, list, download, and verify commands. The server validates size, SHA-256, and signature before storing an upload, and the client checks downloads before saving them. The branch passed 733 checks and a local client/server test using a simulated connection, including a multi-chunk transfer, an empty file, and tampered upload and download rejection. In 1,000 trials on Linux x86-64 (AMD EPYC 9V74), all valid signatures passed and all modified signed records failed; median signing (including reading the key file) was 75,819 ns and median verification was 25,097 ns.

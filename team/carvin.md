# Carvin: the secure pipe (topic 7)

Read [README.md](README.md) in this folder first.

## Your job in one paragraph

You build the **pipe** between client and server. First a plain network connection. Then the two sides agree on a secret using the padlock-and-box trick (ML-KEM-768). Then every message going through the pipe is locked (encrypted) and protected against tampering (AES-256-GCM). Chris's code will put files into your pipe without caring how it works inside. That's why the function names must stay exactly as agreed.

## Your files

You edit **only** `common/securenet.c`.

You may read everything else. These are the most useful:
- `common/securenet.h`: the functions you must fill in, and the `sec_session` box that holds one connection's keys and counters. Don't change this file.
- `common/framing.h`: already working. `frame_write` and `frame_read` send and receive one message. Use them; don't write your own.
- `common/protocol.h`: names for every number (`QD_KEM_PK_BYTES`, `QD_F_HELLO`, ...). Use the names instead of typing numbers.
- `docs/PROTOCOL.md` **sections 2 to 5**: the exact steps of the handshake and encryption.

## The steps, in order

Do them one at a time, and get each working before the next.

1. **Say hello** (by Tue Oct 20). Fill in `net_listen`, `net_accept`, `net_connect`. Goal: the server waits, the client connects, they swap one message.
2. **Agree on the secret** (by Thu Oct 22). Fill in `sec_handshake_client` and `sec_handshake_server`. Goal: both sides print the same 32 bytes.
3. **Make the two keys.** Turn the secret into two keys, one per direction, so the two sides never lock messages with the same key and number. This uses HKDF from OpenSSL.
4. **Lock every message.** Fill in `sec_send` and `sec_recv` with AES-256-GCM. Each message gets a fresh number (the counter) so no two messages are locked the same way.
5. **Integration** (Tue Oct 27). Chris's code sends a signed file through your pipe.
6. **Big files and dropped connections** (Tue Nov 3). Files go in pieces of at most 64 KiB. If time allows: continuing after the connection drops.

`ai/role-carvin.md` has the technical hints (which liboqs and OpenSSL functions to use). It's written for AI tools, but you can read it too.

## Terms you'll meet

| Term | What it means for you |
|---|---|
| **TCP / socket** | The basic connection between two programs. A socket is a number your program uses to refer to the connection. |
| **Port** | Like an apartment number on a computer. Our server uses 9000. |
| **Frame** | One message: its length, a type byte, then the content. |
| **Handshake** | The first three messages, where the secret gets agreed. |
| **ML-KEM-768** | The quantum-safe padlock-and-box method for agreeing on a secret. |
| **Public key / ciphertext** | The open padlock (1,184 bytes) and the locked box (1,088 bytes). |
| **AES-256-GCM** | Fast locking for all the actual data, with a built-in tamper check (the 16-byte "tag"). |
| **Nonce** | A number that must never be used twice with the same key. We use a counter: 0, 1, 2, ... |
| **HKDF** | Turns one secret into several separate keys. |
| **Overhead** | The extra time and bytes that the security adds. You will measure it. |

More in `ai/glossary.md`.

## What you measure for the paper

- How long a transfer takes, with and without the quantum-safe parts. The difference is the **overhead**.
- How long the handshake takes and how many extra bytes it sends.
- If you build resuming: how long it takes to recover after a dropped connection.

Shalom has timing helpers in `common/bench.h`. Always repeat a measurement many times and use the middle value (median), because shared machines are noisy.

Send your numbers to Shalom: what you measured, the median, how many runs, and which machine you ran on. She combines everyone's numbers into the results table and charts; you write the paper section on what yours mean.

## Tips for you

- You're on a Mac, but **everything runs inside the dev container** (Linux), so Mac-specific tutorials don't apply. Use the VS Code terminal that opens inside the container.
- **Use Codespaces (option A in `docs/SETUP.md`).** Running the container locally on a Mac has not been tested yet. If you try it and anything fails, tell Shalom.
- Coming from Python, the big C differences are: you manage memory yourself, strings are byte arrays ending in a zero byte, and the compiler is strict. Read the compiler's first error, not the last.
- Build after every small change (`make`). Many small working steps beat one big broken one.

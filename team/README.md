# Start here: guide for teammates

This folder is for **people**, not AI tools. Read this page first, then your own page:

- Carvin: [carvin.md](carvin.md)
- Chris: [chris.md](chris.md)

Setting up your computer (GitHub account, dev container, first branch) is in `docs/SETUP.md`.

---

## 1. What we are building, in plain words

**QuantumDrive** is a small program that stores files on a server, like a very basic Google Drive that runs in the terminal. What makes it special is the security, which is designed to survive future **quantum computers**. Those could one day break the security most of the internet uses today.

Three things happen when you upload a file:

1. **The client and server agree on a secret** (key exchange, ML-KEM-768). Think of it like this: the server hands out an open padlock. The client puts a random secret in a box, snaps the padlock shut and sends it back. Only the server has the key to that padlock. Now both know the secret, and anyone who watched only saw a locked box.
2. **Everything after that is locked with the secret** (encryption, AES-256-GCM). The file travels scrambled, and if anyone changes even one byte on the way, the receiver notices.
3. **The uploader signs the file** (digital signature, ML-DSA-65). Like a wax seal only you can make. Anyone can check the seal, and if the file is changed the seal breaks.

A **farm sensor** (Shalom's part) is just a tiny client that uploads small readings, like temperature, the same way. Part of our research is how much these protections cost on small devices: one signature is 3,309 bytes, while a reading might be 15 bytes.

### Who builds what

```
   client program                                         server program
  ┌──────────────┐                                       ┌──────────────┐
  │ commands     │  register / upload / list / download  │ handlers     │   <- Chris
  │ (Chris)      │                                       │ (Chris)      │
  ├──────────────┤                                       ├──────────────┤
  │ signatures   │  sign files, check signatures         │ signatures   │   <- Chris
  │ (Chris)      │                                       │ (Chris)      │
  ├──────────────┤        encrypted connection           ├──────────────┤
  │ secure pipe  │ <===================================> │ secure pipe  │   <- Carvin
  │ (Carvin)     │                                       │ (Carvin)     │
  └──────────────┘                                       └──────────────┘
   sensor simulator, setup, merging, results table: Shalom
```

Carvin builds the **pipe**: the connection and the encryption. Chris builds **what travels through it** and the **proof of who sent it**. Shalom builds the sensor and puts the pieces together.

**Measurements:** each of us measures our own topic and sends Shalom the numbers. Shalom combines them into one results table and the charts.

The pieces talk to each other through agreed **function names** in the `.h` files in `common/` (the "contract"). Right now each function is a **stub**: a placeholder that returns a fake answer. Your job is to replace your stubs with real code without changing the names. Then the pieces fit together on integration day.

## 2. What Dr. Rawal wants from us

| What | When |
|---|---|
| Progress Report 1 (2 pages) | Thu Oct 15, 23:59 (done) |
| Progress Report 2 (3 pages) | Sun Oct 18 |
| Final presentation, in person, with a live demo | Tue Nov 17 |
| Final paper, 8 to 10 pages | Tue Nov 17, 23:59 |
| Code, as a **zip file** (not a GitHub link) including `.devcontainer/` | with the final submission |

Most of the grade is in the **paper, the measurements and the demo**. Pretty code matters less than code that works, numbers we measured properly, and results we can explain. Each of us writes the paper section on our own topic.

### Team dates

| Date | Goal |
|---|---|
| Tue Oct 20 | Carvin: client and server say hello over TCP. Chris: make keys, sign and check a file. |
| Thu Oct 22 | Carvin: the key exchange works. Chris: a signed upload record checks out offline. |
| Tue Oct 27 | **Integration session:** an encrypted connection carries a signed file. |
| Thu Oct 29 | **Integration session:** download, list, verify. |
| Tue Nov 3 | Sending big files in pieces. First measurements. |
| Thu Nov 5 | Measurements done, results tables and charts. |
| Tue Nov 10 | Paper writing, each on own topic. |
| Thu Nov 12 | Edit paper, slides, rehearse demo, code freeze. |

## 3. Rules we agreed on

1. **Only edit your own files.** Your page lists them. If something else needs to change, say so in your pull request description and Shalom decides.
2. **Never write cryptography yourself.** Use the libraries: liboqs for ML-KEM and ML-DSA, OpenSSL for AES, HKDF and SHA-256.
3. **Don't change the contract** (`common/*.h` files and `docs/PROTOCOL.md`) without asking Shalom. Everyone's code depends on them.
4. **Never commit keys, passwords or generated data.** `.gitignore` already blocks the usual ones; still check `git status` before committing.
5. **Never push to `main`.** Work on your branch, open a pull request, Shalom merges.
6. **No AI attribution** in commits or pull requests (no "Co-Authored-By: Claude", no "Generated with ChatGPT"). A git hook removes these automatically inside the dev container, but don't add them.
7. **Run `make` and `make test` before you push.** Both must succeed.
8. **Small pull requests.** One feature or fix at a time. Small is easy to review; huge gets sent back.
9. **Write in the work log.** At the end of each session, add 3 or 4 sentences to your own log file, `docs/log/<your name>.md`: what you built and what you noticed. This becomes the paper, so it saves you work later.

The exact message format is in `docs/PROTOCOL.md`. You don't need to read it all; your page tells you which sections matter for you.

## 4. Using AI tools on this project

AI tools are allowed. These rules make sure they help instead of creating messes Shalom has to clean up.

### How the AI instruction files work

We wrote rule files for AI tools:

| File | What it is |
|---|---|
| `AGENTS.md` | The main rule list for any AI |
| `ai/rules-common.md` | Day-to-day habits (Git steps, checklist) |
| `ai/role-carvin.md`, `ai/role-chris.md` | What each person owns and builds, with technical hints |
| `ai/glossary.md` | Terms explained simply |
| `CLAUDE.md` | Shalom's own brief. Tells other people's Claude to read `AGENTS.md` instead |
| `.github/copilot-instructions.md` | Points Copilot to `AGENTS.md` |

**AI tools that run inside the project** read these files by themselves. This includes Claude Code, GitHub Copilot in VS Code and OpenAI Codex. The AI should start by asking "Which teammate are you?". Answer with your name.

**These files are instructions, not locks.** An AI can still ignore them or make mistakes. You are responsible for everything in your pull request, so read what the AI wrote and make sure you can explain it.

### Using a web chat (ChatGPT, Claude.ai, Gemini in the browser)

A web chat **cannot see our repo**. It only knows what you paste in. If you skip this, it will guess, and its guesses (old "Kyber" or "Dilithium" names, a different message format, changing headers) will not fit our code.

**Step 1: make one file with everything it needs.** In the VS Code terminal, run your line:

```sh
scripts/ai-context.sh carvin     # Carvin
scripts/ai-context.sh chris      # Chris
```

It writes `build/ai-context-<name>.txt` containing the rules, your role file, the glossary, the protocol and your code files.

**Step 2: paste it as your first message.** Open that file in VS Code, select all (`Ctrl+A`, or `Cmd+A` on a Mac), copy, and paste it into a **new chat**. If your chat tool lets you attach files or set "project instructions", you can attach the file there instead.

**Step 3: when you ask about a specific file, paste its current version too.** The chat doesn't see your edits since step 1.

**Step 4: bring answers back carefully.**
- Paste AI code **only into your own files**.
- If the AI says to change a `.h` file, `docs/PROTOCOL.md`, the Makefile or someone else's file, **don't**. Write the suggestion in your pull request description instead.
- Run `make` and `make test`. If they fail, paste the error back into the chat.
- Start a fresh chat (repeat steps 1 and 2) when a chat gets long or confused, or after your branch has new changes from `main`.

## 5. Before you open a pull request

Shalom reviews every pull request. Make it easy:

- [ ] `git status` shows only your files changed.
- [ ] No key files, no `server-data/` or `client-data/`, no measurement output.
- [ ] `make` shows no warnings and `make test` passes.
- [ ] You can explain every line in plain words.
- [ ] You filled in the pull request description (GitHub shows a template): what changed, why, how you tested it, and anything you'd like changed outside your files.

If you're stuck for more than about 30 minutes, message Shalom with what you tried and the exact error text. A screenshot of the terminal is fine.

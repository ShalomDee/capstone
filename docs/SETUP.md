# Setup guide

For Carvin and Chris. You already have a GitHub account and access to the repo. This guide gets you from there to your first pull request.

Each step is one action. Commands go in the terminal; the text after `#` explains what the command does (don't type that part).

**Your details:**

| | Carvin | Chris |
|---|---|---|
| Your branch | `carvin/secure-pipe` | `chris/identity` |
| Your files | `common/securenet.c` | `common/identity.c`, `server/handlers.c`, `client/commands.c` |
| Your computer | Mac | Windows |

---

## Part 1: Open the project

You work inside a **dev container**: a ready-made Linux machine with every tool installed, so all three of us have the same setup. There are two ways to open it. **Use option A (Codespaces) unless you have a reason not to.**

### Option A: GitHub Codespaces (runs in the cloud, nothing to install)

1. Go to the repo page on github.com.
2. Click the green **Code** button.
3. Click the **Codespaces** tab.
4. Click **Create codespace on main**.
5. Wait. The first time takes several minutes because it builds the tools (liboqs). A VS Code window opens in your browser when it's ready.

Good to know:
- Codespaces usage is billed to **your** GitHub account, which has free monthly hours (120 core-hours on a free account, about 60 hours on the default machine).
- It stops by itself after about 30 minutes of no activity. To stop it sooner: github.com/codespaces, then **...** next to it, then **Stop codespace**.
- To come back later, use github.com/codespaces and open the same one. **Don't create a new one each time.**
- A codespace unused for about 30 days is deleted along with anything you didn't push. **Push often.**

### Option B: on your own computer with Docker (works offline, e.g. demo day)

Not yet tested on a Mac. Tell Shalom if anything fails.

1. Install **Docker Desktop** and start it.
2. Install **VS Code**.
3. In VS Code, open Extensions (`Ctrl+Shift+X`, or `Cmd+Shift+X` on a Mac), search **Dev Containers** (by Microsoft), and click Install.
4. Open the Command Palette (`Ctrl+Shift+P`, or `Cmd+Shift+P` on a Mac).
5. Type **Dev Containers: Clone Repository in Container Volume** and press Enter.
6. Paste the repo URL and press Enter. Sign in to GitHub if VS Code asks.
7. Wait several minutes for the first build.
8. In the terminal, tell Git who you are (only needed once, and only in option B; Codespaces does it for you):
   ```sh
   git config --global user.name "Your Name"            # name shown on your commits
   git config --global user.email "you@example.com"     # use the email on your GitHub account
   ```

## Part 2: Check that it works

1. Open a terminal: menu **Terminal**, then **New Terminal**.
2. Run:
   ```sh
   make demo        # builds and runs a small test of the quantum-safe tools
   ```
   You should see `shared secrets match: YES`, `original message verifies: YES` and `tampered message verifies: NO (should be NO)`. The timings will differ; that's normal.
3. Run:
   ```sh
   make test        # builds everything and runs our tests
   ```
   The last line should say `0 failed`.
4. Run:
   ```sh
   git config core.hooksPath     # checks that the commit-message hook is switched on
   ```
   It should print `scripts/hooks`. If it prints nothing, run `git config core.hooksPath scripts/hooks`.

If any of these fail, send Shalom a screenshot of the terminal.

## Part 3: Make your branch

A **branch** is your own copy of the code. Your changes stay there until Shalom merges them.

1. Create your branch and switch to it (use your branch name from the table at the top):
   ```sh
   git switch -c chris/identity        # Chris
   git switch -c carvin/secure-pipe    # Carvin
   ```
2. Publish it to GitHub so it's backed up:
   ```sh
   git push -u origin chris/identity       # Chris; Carvin uses carvin/secure-pipe
   ```
   `-u` links your local branch to the one on GitHub, so from now on plain `git push` is enough.

## Part 4: Practice pull request

This is a harmless first run of the whole process.

1. Open your log file, `docs/log/chris.md` or `docs/log/carvin.md`, and add an entry at the bottom, in the format shown at the top of the file. For example: "Set up the dev container, `make demo` and `make test` pass."
2. Check what changed:
   ```sh
   git status          # lists changed files; should show only your log file
   ```
3. Mark the file to be saved in the next commit:
   ```sh
   git add docs/log/chris.md        # Carvin: docs/log/carvin.md
   ```
4. Save it as a commit with a short message:
   ```sh
   git commit -m "Add first log entry"
   ```
5. Send it to GitHub:
   ```sh
   git push
   ```
6. Go to the repo on github.com. A yellow bar says your branch had recent pushes. Click **Compare & pull request**.
7. Check that it says **base: main** and **compare: your branch**.
8. Fill in the template (what changed, why, how you tested it) and click **Create pull request**.
9. Shalom reviews and merges it. Done.

## Part 5: Your normal routine

**Start of a session:**
1. Open your codespace (or local container).
2. Make sure you're on your branch:
   ```sh
   git branch          # the line with * is your current branch
   ```
3. Pick up anything Shalom merged into `main` since last time:
   ```sh
   git fetch origin            # downloads the latest from GitHub, changes nothing yet
   git merge origin/main       # adds main's new changes into your branch
   ```

**While working:**
1. Edit only your own files.
2. Build often:
   ```sh
   make
   ```
3. Save progress whenever something works:
   ```sh
   git status
   git add <your file>
   git commit -m "short description of what changed"
   git push
   ```

**When a piece is finished:**
1. Run `make test`. It must pass.
2. Push and open a pull request (Part 4, steps 6 to 8). Keep it small: one feature per pull request.
3. Add your 3 to 4 sentences to your log file in `docs/log/`.

## If something goes wrong

| Problem | What to do |
|---|---|
| `git push` says "rejected" or "fetch first" | Run `git fetch origin` then `git merge origin/main`, then push again. |
| `git merge` says "CONFLICT" | Two people changed the same lines. Don't guess: run `git merge --abort` and message Shalom. |
| `git commit` says "Please tell me who you are" | Do Part 1, option B, step 8. |
| You committed to `main` by mistake | Don't push. Message Shalom. |
| `make` shows an error | Read the **first** error line. Paste it into your AI chat or send it to Shalom. |
| You accidentally committed a key file | Don't push. Message Shalom. |

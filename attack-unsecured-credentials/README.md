# jFTP saved-login leak -> FTP exam deletion (spike demo)

Simulates recovering a real FTP password from a leaked jFTP saved-login
file, then using that password with an ordinary FTP client to find and
delete a "sensitive" exam from an **already-running** pyftpdlib server.
`attack.sh` does not start a server and does not create any jFTP config
file of its own — it only reads real files jFTP already wrote, and only
talks to the real, already-running server over FTP.

jFTP keeps all of its saved-login state in the same directory,
`${user.home}/.jftp/`, across two different files, and `attack.sh` tries
both, in this order:

1. **`bookmarks.txt`** (primary) — written by the "Add Bookmark" dialog
   (`AddBookmarks`/`BookmarkManager`). Its password field is **plain
   text** — `AddBookmarks.getData()` never calls any encryption routine
   — so if a bookmark with real credentials exists, this is the fastest,
   most direct leak: just read the file, no decryption needed.
2. **`.login_default`** (fallback) — written by `HostChooser`/`SaveSet`
   on every successful connect. Its password field is "encrypted" with
   jFTP's `Crypto` class (hardcoded key/salt, trivially reversible). Used
   only if `bookmarks.txt` is missing, or has no FTP entry with a real,
   non-anonymous, non-placeholder password.

## Process this demo assumes

1. **You** start the real pyftpdlib server yourself, from the `pyftpdlib/`
   directory, in your own terminal (e.g. `cmd` on Windows). For example:

   ```sh
   cd pyftpdlib
   python3 -m pyftpdlib -i 127.0.0.1 -p 2121 -d . -u ta_exams -P 'some-password' -w
   ```

   Put the exam file (or an exam directory) somewhere under that document
   root (`.` above) first.

2. **You** start jFTP yourself (e.g. run it from VS Code / however you
   normally build/launch it) and get a real credential leak saved to
   disk, by doing EITHER (or both) of:
   - **Bookmarks:** use jFTP's "Add Bookmark" dialog to save a bookmark
     for the server above with the real password filled in. This writes
     `~/.jftp/bookmarks.txt` immediately, in plain text.
   - **Saved login:** connect to the server via the normal connect
     dialog with **Options → Security → "Store passwords (encrypted
     using internal password)"** checked. On a successful connect,
     jFTP's `HostChooser` writes `~/.jftp/.login_default` via `SaveSet`,
     with the password field encrypted by `Crypto.Encrypt()`.

3. **Run `./attack.sh`** on the same machine. It:
   - looks for `~/.jftp/bookmarks.txt` first (plain text — just read it);
     only if that's missing or has no usable FTP credential, falls back
     to `~/.jftp/.login_default` and decrypts it with jFTP's own
     `Crypto` class,
   - connects to the host/port/user it recovered using a plain FTP
     client (`curl` — not jFTP),
   - recursively searches the server for anything named like an exam, and
     deletes it (file or whole directory).

The server and jFTP are both already-running, independent processes that
`attack.sh` never starts, stops, or writes into — it only ever talks to
the server over the FTP protocol, and only ever reads jFTP's existing
config files off disk.

## Vulnerability

### Primary: `bookmarks.txt` — plaintext password storage

`Settings.bookmarks` = `${user.home}/.jftp/bookmarks.txt`. It's written
by `AddBookmarks.getData()` (the "Add Bookmark" dialog) in the format

```
protocol#host#user#password#port#dir/domain#local
```

one line per bookmark, appended to the file (`FileOutputStream(..., true)`).
**The password field is written exactly as typed — there is no call to
any encryption routine anywhere in that code path.** Anyone who can read
this file has the real FTP password immediately: no decryption, no brute
force, no sniffing. This is CWE-256 / CWE-312 (plaintext storage of a
password).

(jFTP also ships a *default* `bookmarks.txt` template, written by
`BookmarkManager.setDefaultText()`, containing a couple of harmless
`anonymous` entries pointed at public mirrors like
`upload.sourceforge.net`. `attack.sh` ignores those — see "Credential
selection" below — since they aren't a real leaked login.)

### Fallback: `.login_default` — hardcoded-key "encryption"

`jftp/src/java/net/sf/jftp/config/Crypto.java` "encrypts" saved passwords
with `PBEWithMD5AndDES` using a password and salt that are **hardcoded
constants**, identical for every install:

```java
private static final char[] PASSWORD = "(l_[m^5][:]FQ8D* ;zoG,7".toCharArray();
private static final byte[] SALT = { 0x56, 0x40, 0x77, 0x32, 0x10, 0x63, 0x25, 0x3C };
```

`.login_default` (`Settings.login_def` = `${user.home}/.jftp/.login_default`)
is written by `SaveSet.savePW()` every time `HostChooser` completes a
successful FTP connection with "Store passwords" enabled, with the
password field run through `Crypto.Encrypt()`. Anyone who can read that
file can decrypt the password with the exact same (public, open-source)
class — no brute force, no sniffing, no interaction with the server
required. This is CWE-321 / CWE-798 (use of a hardcoded cryptographic
key / hardcoded credentials): storing a password this way is only
cosmetically different from plaintext — which is exactly why `attack.sh`
treats it as a fallback, not the primary target: it's marginally more
work to exploit than just reading `bookmarks.txt` in the same directory,
but ends in the same place.

### Credential selection logic (why `bookmarks.txt` is tried first)

`attack.sh` reads every `FTP#...` line in `bookmarks.txt`, discards any
with an empty password field or the literal placeholder
`Settings.hiddenPassword` (`<%hidden%>`, which jFTP writes back into a
bookmark it couldn't reconnect with), and then:
- picks the **last** remaining non-`anonymous` entry (bookmarks.txt is
  append-only, so the last matching line is the most recently saved
  bookmark), or
- if every remaining entry is `anonymous` (i.e. only jFTP's seeded
  default-template bookmarks are present, not a real saved login), treats
  the file as having no usable credential and falls through to
  `.login_default` instead.

## Layout

```
crypto_helper/   CryptoCli.java, a thin wrapper around jFTP's real,
                 unmodified Crypto class (compiled, then used by
                 attack.sh ONLY if it needs to fall back to decrypting
                 .login_default)
attack.sh        runs the attack against the already-running server
setup.sh         one-time environment check (JDK, curl) + compiles
                 crypto_helper
```

## Prerequisites

- `curl` on `PATH` (ships with Git Bash and most modern OSes). Always
  required.
- A JDK (`javac`/`java`) on `PATH` — only needed if you want the
  `.login_default` fallback to work (i.e. if you might not have a real
  bookmark saved). `setup.sh` checks for this and tells you how to
  install one if it's missing (Windows/macOS/Linux hints included). It
  installs nothing itself — no admin/sudo required. If you only ever plan
  to exercise the `bookmarks.txt` path, you can skip the JDK and just
  skip/ignore `setup.sh`'s JDK check failing (`attack.sh` only needs
  `crypto_helper` compiled when it actually falls back).
- Run from a shell that understands bash scripts: Git Bash or WSL on
  Windows, or a regular terminal on macOS/Linux.
- The pyftpdlib server already running, and jFTP already used to produce
  at least one of `bookmarks.txt` / `.login_default` with a real
  credential (see Process above).

## Running it

```sh
./setup.sh     # one-time: checks for a JDK + curl, compiles crypto_helper
./attack.sh    # runs the attack against your already-running server
```

By default, `setup.sh`/`attack.sh` find `jftp/` automatically as a sibling
of this `attack/` folder (i.e. directly under the repo root). Override
with `JFTP_SRC` if you've moved things, e.g.:

```sh
JFTP_SRC=/path/to/jftp ./setup.sh
JFTP_SRC=/path/to/jftp ./attack.sh
```

`attack.sh` also reads these (all optional):

| Variable         | Default                    | Meaning |
|------------------|-----------------------------|---------|
| `JFTP_HOME_DIR`  | `${HOME}/.jftp`             | where to look for jFTP's config dir |
| `BOOKMARKS_FILE` | `${JFTP_HOME_DIR}/bookmarks.txt` | the plaintext bookmarks file to try first |
| `LOGIN_DEFAULT`  | `${JFTP_HOME_DIR}/.login_default` | the encrypted saved-login file to try as a fallback |
| `EXAM_NAME`      | `exam`                      | case-insensitive substring to search for (file or directory name) |
| `MAX_DEPTH`      | `6`                         | how many directory levels deep to search on the server |

e.g. if your exam file is named `midterm.pdf`:

```sh
EXAM_NAME=midterm ./attack.sh
```

## What `attack.sh` does

1. **Locate the leak:**
   - Try `bookmarks.txt` first — read it off disk (real file, written by
     jFTP itself; this script never creates or edits it), parse every
     `FTP#host#user#password#port#dir#local` line, discard entries with
     an empty or `<%hidden%>` password, and pick the most recently
     appended non-`anonymous` entry. No decryption needed — the field is
     already plaintext.
   - If that fails (file missing, or only `anonymous`/placeholder
     entries present), fall back to `.login_default`: read it off disk,
     parse out host/user/encrypted-password/port, and call jFTP's own
     `Crypto.Decrypt()` (via the compiled `CryptoCli` wrapper) on the
     encrypted password field.
2. **Connect** — logs in to the real host/port/user with `curl` as a
   plain FTP client (not jFTP) and lists the root directory to confirm
   the credentials work.
3. **Search** — recursively walks the server's directory tree (via
   `LIST`) looking for a file or directory whose name contains
   `EXAM_NAME` (case-insensitive), up to `MAX_DEPTH` levels deep.
4. **Delete** — if a file: `DELE`s it directly. If a directory: recursively
   `DELE`s every file inside it, then `RMD`s every subdirectory from the
   deepest level up (FTP's `RMD` only removes empty directories, so
   contents have to go first).
5. **Verify** — attempts to list the deleted path again and confirms it's
   gone, then prints a root-cause/remediation summary (covering whichever
   of the two files the credentials actually came from).

Nothing in this script starts, stops, or configures the FTP server or
jFTP — both are expected to already be running when you invoke it.

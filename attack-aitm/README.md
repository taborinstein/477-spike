# 477-spike
# FTP / FTPS adversary-in-the-middle demos

A self-contained teaching harness for the CSSE477 FTP exercise. It walks the
security progression in four attacks: **plaintext FTP → FTPS → active MITM with
a forged cert → active MITM with a stolen key.** Everything runs on
`127.0.0.1` against servers you start yourself, using a dummy `exam.txt`.

> **Lab use only.** Don't point any of this at a machine you don't own.

Make sure that in `jftp\src\java\net\sf\jftp\config\Settings.java`, the variable
`useFtps = true` to run JFTP in FTPS mode. 

---

## Files

| file | role |
|------|------|
| `attack_1_ftp.ps1` | **Attack 1** — passive sniff of plaintext FTP (recovers creds + exam) |
| `attack_2_ftps.ps1` | **Attack 2** — same sniff vs FTPS (recovers nothing) |
| `attack_3_mitm.py` | **Attack 3** — active MITM with a **forged** cert |
| `attack_4_mitm_validCreds.py` | **Attack 4** — active MITM that can present the **genuine cert + stolen key** |
| `ftp_server.py` | plaintext pyftpdlib server (serves `server_root\`) |
| `ftps_server.py` | FTPS server, TLS required (serves `root\`) |
| `make_cert.py` | generates `cert.pem` + `key.pem` for the FTPS server |
| `extract_secrets.py` | pcap analyzer used by `attack_1_ftp.ps1` |
| `exam.txt` | the sensitive file (copy into `root\` and/or `server_root\`) |

---

## Prerequisites

Install once:

```powershell
python -m pip install pyftpdlib pyopenssl cryptography
```

- **Python** on PATH (`python`, or `py`).
- **Wireshark** installed **with Npcap's "Support loopback traffic capture"** —
  provides `dumpcap`, `tshark`, and the loopback adapter the `.ps1` demos need.
- **`curl.exe`** and **`ftp.exe`** ship with Windows 10/11.
- Run the capture demos (Attacks 1 & 2) in an **elevated (Administrator)
  PowerShell** — Npcap capture needs it.

> In PowerShell always call **`curl.exe`**, never `curl` (that's an alias for
> `Invoke-WebRequest`, which can't speak FTPS).

---

## Attack 1 — Plaintext FTP is wide open

A passive eavesdropper recovers the login *and* the exam from cleartext FTP.

```powershell
powershell -ExecutionPolicy Bypass -File .\attack_1_ftp.ps1
```

It creates `server_root\exam.txt` if needed, starts `ftp_server.py`, sniffs
loopback with `dumpcap`, runs an `ftp.exe` download, reconstructs everything via
`extract_secrets.py`, and replays the stolen login. Loot lands in `loot\`
(`credentials.txt`, `stolen_exam.txt`, `replayed_exam.txt`).

Capture a **JFTP** session instead of `ftp.exe`:

```powershell
powershell -ExecutionPolicy Bypass -File .\attack_1_ftp.ps1 -Manual
```
Connect JFTP to `127.0.0.1:2121` (`student` / `RHITspr26!exam`), download
`exam.txt`, then press Enter in the console.

---

## Attack 2 — FTPS defeats the passive sniff

Same attack, now against the TLS server. The capture is ciphertext.

```powershell
powershell -ExecutionPolicy Bypass -File .\attack_2_ftps.ps1
```

It auto-generates `cert.pem`/`key.pem` (via `make_cert.py`) and
`root\exam.txt` if missing, starts `ftps_server.py`, sniffs while `curl.exe`
does an FTPS download, then scans the pcap. Expect **`NO LEAK`** — only the
pre-TLS `AUTH TLS` handshake is readable.

---

## Attacks 3 & 4 — Active MITM vs FTPS

Here the attacker sits *between* client and server. These are run by hand in
**three terminals**; the real server moves to **2122** so the proxy can own
**2121**.

**One-time setup** (the proxy and server share one cert/key, and the FTPS
server serves `root\`):

```powershell
python make_cert.py            # creates cert.pem + key.pem
mkdir root 2>$null
copy exam.txt root\exam.txt    # so the FTPS server has a file to serve
```

**Terminal 1 — the real FTPS server on 2122:**
```powershell
python ftps_server.py 2122
```

**Terminal 3 — the victim client, pointed at the proxy (2121):**

trust-all client (`curl.exe -k`):
```powershell
curl.exe --ssl-reqd -k --user student:"RHITspr26!exam" ftp://127.0.0.1:2121/exam.txt -O
```
or **JFTP**: connect to `127.0.0.1` port **2121**, `student` / `RHITspr26!exam`.

### Attack 3 — forged certificate

**Terminal 2:**
```powershell
python attack_3_mitm.py 2121 2122
```
The proxy answers the client's `AUTH TLS` with its own **forged** cert.

- A **trust-all** client (curl `-k`, or JFTP with `ftpsTrustAllCerts=true`)
  accepts it → Terminal 2 prints the stolen credentials.
- A **cert-pinning** client (JFTP with `ftpsTrustAllCerts=false`) rejects it →
  the handshake aborts. *Pinning defeats the forged cert.*

### Attack 4 — stolen private key

**Terminal 2:**
```powershell
python attack_4_mitm_validCreds.py 2121 2122 cert.pem key.pem
```
Given the server's real `cert.pem` **and** `key.pem`, the proxy presents the
**genuine** cert and proves it with the leaked key — so even a **pinning**
client validates it and the credentials are stolen. (Run without the
`cert.pem key.pem` args and it falls back to Attack 3's forged behavior.)

### What each combination shows

| client | proxy | result |
|--------|-------|--------|
| trust-all | `attack_3` (forged) | **creds stolen** — TLS without validation isn't enough |
| pinning   | `attack_3` (forged) | **rejected** — pinning defeats the forged cert |
| pinning   | `attack_4` (stolen key) | **creds stolen** — pinning fails once the key leaks |

The last row is the real lesson: once the server's **private key** is stolen,
no client-side check restores security. The defense is protecting the key
(file permissions, never commit it, an HSM in production) plus rotation to
shrink the stolen-key window.

---

## Notes & troubleshooting

- **Ports:** Attacks 1 & 2 use `2121`. Attacks 3 & 4 use `2121` (proxy) +
  `2122` (real server). Stop anything already on those ports first
  (`netstat -ano | findstr :2121`).
- **One `cert.pem` everywhere:** in Attacks 3 & 4 the server, the proxy, and a
  pinning client must all use the *same* `cert.pem`. If the client pins a
  different or stale copy you'll see `certificate_unknown` /
  `signature check failed`. Point the JFTP client's `Settings.ftpsTrustedCert`
  at *this* folder's `cert.pem` (or copy it to where the client resolves it).
- **After regenerating the cert** (`make_cert.py`), restart the server and proxy
  and reconnect the client so everyone loads the new cert.
- **`exam.txt` placement:** `ftp_server.py` serves `server_root\`,
  `ftps_server.py` serves `root\`. The `.ps1` demos create those automatically;
  for the manual MITM demos, copy `exam.txt` into `root\` yourself.
- **Don't commit secrets:** keep `*.pem` out of git (a `.gitignore` with
  `*.pem`, plus the `capture/`, `loot/`, `download/` output folders).
- **Cleanup:** `Remove-Item -Recurse -Force capture, loot` removes demo output.

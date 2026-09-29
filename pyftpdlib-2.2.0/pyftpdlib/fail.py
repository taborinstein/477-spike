# =================================== Implementation of JFTP M1 ============================================================================
import os
import socket
import struct
import threading
import time

from .handlers import FTPHandler

MARK = b'KBM1'                    # must match client readReason()
FRAME_CONTROL_LOST = 1
# wire: MARK(4) + type(1) + committed_bytes(8, big-endian) = 13 bytes

# Need to make a registry of what handlers are active
_active_handlers = set()
_registry_lock = threading.Lock()

def _register(handler):
    with _registry_lock:
        _active_handlers.add(handler)

def _deregister(handler):
    with _registry_lock:
        _active_handlers.discard(handler)

def list_active_handlers():
    with _registry_lock:
        return list(_active_handlers)

#Button hit, kill upload
def kill_active_upload():
    """Button A entry point: find the handler with a current upload and close its data channel. Returns True if one was killed."""
    handlers = list_active_handlers()
    print(f"[M1] kill_active_upload called; {len(handlers)} registered handler(s)", flush=True)
    for h in handlers:
        dtp = h.data_channel
        print(f"[M1]   {h.remote_ip}:{h.remote_port} dtp={dtp!r} "
              f"receive={getattr(dtp, 'receive', None)} "
              f"finished={getattr(dtp, 'transfer_finished', None)}", flush=True)
        if dtp is not None \
                and getattr(dtp, "receive", False) \
                and not getattr(dtp, "transfer_finished", True):
            h.kill_data_channel()
            return True
    print("[M1] no in-progress upload found", flush=True)
    return False

def kill_active_control():
    for h in list_active_handlers():
        dtp = h.data_channel
        if dtp is not None and getattr(dtp, "receive", False) \
                and not getattr(dtp, "transfer_finished", True):
            h.close()      # runs _notify_data_channel_control_lost first
            return True
    print("[M1] no in-progress upload found", flush=True)
    return False

def _drain_then_close(sock, secs=5.0):
    """Keep reading (and discarding) until the client closes its side or time out.
    Keeps the connection open so pyftpdlib closing its own
    handle doesn't trigger a race that would wipe out the frame."""
    try:
        sock.settimeout(secs)
        deadline = time.monotonic() + secs
        while time.monotonic() < deadline:
            if not sock.recv(65536):
                break          # client closed after reading the frame
    except OSError:
        pass
    finally:
        sock.close()

#Class to actually handle failures in both lines
class FailHandler(FTPHandler):

    # Register
    def on_connect(self):
        _register(self)

    def close(self):
        # Send the fail message before data socket is torn down by superclass
        self._notify_data_channel_control_lost()
        _deregister(self)
        super().close()

    # Server-side kill command
    def kill_data_channel(self):
        self.log("[M1] kill_data_channel called;")
        dtp = self.data_channel
        if dtp is None:
            self.log("Cannot KILL data channel that does not exist")
            return False
        self.log("MANUAL KILL: closing data channel mid-transfer")
        # dtp.close() does three things:
        #   - closes the data socket
        #   - transfer_finished is still False - partial retained for REST/STOR resume
        #   - calls _on_dtp_close(), so self.data_channel = None, idle timer restart
        dtp.close()
        self.respond("426 Connection closed; transfer aborted by server.")
        return True

    def _notify_data_channel_control_lost(self):
        dtp = self.data_channel
        # receive == True  -> this is a STOR (client->server); return is idle
        # transfer_finished -> nothing to warn about.
        if dtp is None:
            return
        if not getattr(dtp, "receive", False):
            return
        if getattr(dtp, "transfer_finished", True):
            return

        committed = getattr(dtp, "tot_bytes_received", 0)
        frame = MARK + struct.pack("!BQ", FRAME_CONTROL_LOST, int(committed))

        try:
            dup = dtp.socket.dup()
            dup.setblocking(True)
            dup.settimeout(2.0)
            dup.sendall(frame)
            dup.shutdown(socket.SHUT_WR)   # FIN after the frame
        except Exception as ex:
            self.log(f"DataFail notice failed: {ex}")
            return
        threading.Thread(target=_drain_then_close, args=(dup,), daemon=True).start() #Open new thread to drain the socket before closing

    def on_incomplete_file_received(self, file):
        """Keep the partial file so a later REST+STOR can resume the upload.
        Ovveride the log so the intent is explicit."""
        self.log(f"partial retained for resume: {file}")
        # intentionally do NOT remove(file)
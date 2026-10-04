# ================================================== M2: New File ===========================================================================
" This file is responsible for setting up a new testing directory, registering it"
"as the home directory for a test user, calling serve_forever, and shutting down the"
"server and cleaning up the test directory"
""
" The server will stop when a file named .stop is uploaded to it "

#M2 NOTE: For simplicity, I put TestFTPHandler in here as well to make fewer new files required

import os
import tempfile

from authorizers import DummyAuthorizer
from handlers import FTPHandler
from servers import FTPServer

# Print a report to stdout
def report(line):
    print(line, flush=True)

" Class that implements the FTPHandler responsible for the current client-server connection"
"so that additional assertions can be run from the server side"
class TestFTPHandler(FTPHandler):
    root = None # main will set up a root, so the handler shouldn't have one

    #Run some assertion
    def check(self, condition, message):
        try:
            assert condition, message
            report(f"PASS {message}")
        except AssertionError:
            report(f"FAIL {message}")

    #Assert that the STOR command is being handled as it should (mimics the test added in FTPConnection)
    def ftp_STOR(self, file, mode="w"):
        pending = self._dtp_acceptor is not None or self._dtp_connector is not None
        self.check(self.data_channel is not None or pending, f"{os.path.basename(file)} : data connection open or pending when STOR is received")
        return super().ftp_STOR(file, mode)

    #Run assertions to verify a file has been received
    def on_file_received(self, file):
        dtp = self.data_channel
        filename = os.path.basename(file)
        received = dtp.get_transmitted_bytes()

        #ASSERT: Check that the transfer finished
        self.check(dtp.transfer_finished, f"{filename} : transfer finished")

        #ASSERT: Check the file is in the test directory, which is the correct directory for all tests in M2
        self.check(os.path.realpath(filename).startswith(self.root + os.sep), f"{filename} : stored inside test directory")

        #ASSERT: Check the file exists on the disk
        self.check(os.path.isfile(filename), f"{filename} : exists on disk")

        #ASSERT: If it is an ASCII file, check that it is the right size
        if self.current_type == "i":
            self.check(os.path.getsize(filename) == received, f"{filename} : size on disk equals bytes received")

        report(f"RECEIVED {filename} {received}")

    # Run assertions on a 0-byte upload
    def on_incomplete_file_received(self, file):
        dtp = self.data_channel
        filename = os.path.basename(file)
        received = dtp.get_transmitted_bytes()

        #ASSERT: The transfer is marked as not finished
        self.check(not dtp.transfer_finished, f"{filename} : transfer marked incomplete")

        report(f"INCOMPLETE {filename} {dtp.get_transmitted_bytes()}")

def main():
    #Set up temporary test directory
    with tempfile.TemporaryDirectory(prefix="JFTP-M2-test-") as root:
        root = os.path.realpath(root)
        authorizer = DummyAuthorizer
        authorizer.add_user("test", "test", root, perm="elradfmw")
        authorizer.add_user("reader", "reader", root, perm="elr")

        TestFTPHandler.authorizer = authorizer
        TestFTPHandler.root = root
        server = FTPServer(("127.0.0.1", 12346), TestFTPHandler)
        stop_file = os.path.join(root, ".stop")

        report(f"ROOT {root}")
        report(f"READY {server.address[1]}")

        try:
            while not os.path.exists(stop_file):
                server.serve_forever(timeout=FTPHandler.timeout, blocking=False)
        finally:
            server.close_all()

if __name__ =="__main__":
    main()
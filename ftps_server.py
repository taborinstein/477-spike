# Starts the pyftpdlib server in FTPS mode and gives it the user that will be used to download the exam
import os, sys
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import TLS_FTPHandler
from pyftpdlib.servers import FTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 2121
auth = DummyAuthorizer()
auth.add_user("student", "RHITspr26!exam", os.path.join(HERE, "root"), perm="elr")
h = TLS_FTPHandler
h.certfile = os.path.join(HERE, "cert.pem")
h.keyfile = os.path.join(HERE, "key.pem")
h.authorizer = auth
h.tls_control_required = True
h.tls_data_required = True
h.passive_ports = range(60000, 60011)
h.masquerade_address = "127.0.0.1"
srv = FTPServer(("127.0.0.1", PORT), h)
print(f"FTPS server listening on 127.0.0.1:{PORT}", flush=True)
srv.serve_forever()

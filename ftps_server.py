import os
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import TLS_FTPHandler
from pyftpdlib.servers import FTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
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
srv = FTPServer(("127.0.0.1", 2121), h)
print("FTPS server listening on 127.0.0.1:2121", flush=True)
srv.serve_forever()

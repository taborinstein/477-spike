# Chmod Attack Lab

Edit `lab_config.json` to change the lab FTP accounts. Each entry under
`users` maps an FTP username to its password and pyftpdlib permission string.
The lab script uses `student`, `chmodonly`, and `unlisted` for its built-in
scenarios; all configured accounts are loaded by the server.

`site_chmod_users` is the username allowlist for `SITE CHMOD`. A user must be
listed there and have the `M` permission in `users` to change file modes. Other
FTP operations use their own permissions: `r` retrieves files, `w` stores
files, and `d` deletes files. The full permission list is documented in
`pyftpdlib/authorizers.py`.

The server runs on loopback and operates on a temporary copy of
`server_root/exam.txt`; the fixture is not changed by the simulation. It starts
the server through `python -m pyftpdlib --config lab_config.json`, so the
simulation exercises the standalone CLI configuration path.
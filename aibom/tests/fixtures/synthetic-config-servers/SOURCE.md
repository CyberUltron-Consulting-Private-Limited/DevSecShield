# synthetic-config-servers

Hand-derived 2026-10-27. Values come from reading the three configuration files
and applying the server extractor rules in `extract_servers.py` (same shapes
exercised in `test_cbom_posture_settings_servers.py`), not from running
`scan_crypto`.

## nginx.conf

- One `server` block with `listen 443 ssl` and `ssl_protocols TLSv1.2 TLSv1.3`.
- Address `nginx.server[1]`, line 2 (`listen`), verdict `ENCRYPTED_DECLARED`.
- Posture finding set empty; protocol floor TLS 1.2 is not weak.

## httpd/ssl.conf

- Path uses the `httpd/` segment so classification picks Apache (`ssl.conf`).
- Apache `VirtualHost *:443` with `SSLEngine on` and `SSLProtocol TLSv1`.
- Address `apache.virtualhost[1]`, line 2 (`SSLEngine`), verdict
  `ENCRYPTED_DECLARED`.
- Posture finding set empty; the weak TLS 1.0 floor is inventory on the linked
  TLS protocol asset (`WEAK_PROTOCOL`), not a posture verdict code.

## sshd_config

- `Protocol 2` and `Port 22` only.
- Address `sshd_config[1]`, line 1, kind `ssh_service`, verdict
  `ENCRYPTED_DECLARED` with transport basis only.

No secrets are planted in this tree.

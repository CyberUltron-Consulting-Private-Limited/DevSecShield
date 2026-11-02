"""TLS client contexts for collectors that authenticate with a client certificate (KMIP, EJBCA).

``client_context`` loads the stored PEM certificate and key into an ``ssl.SSLContext``.  ssl can only load a key from
a file, so the key is written to a 0600 file in a private 0700 directory and removed as soon as it is loaded (before
any connection is made).  The server is verified against the uploaded CA certificate, or the system trust store, or
(``verify=False``, only where the protocol never reveals a secret to an impostor) not at all.
"""
from __future__ import annotations

import os
import shutil
import ssl
import tempfile

from zs_scan_node.collectors import ConfigError


def client_context(ca_pem: str | None, cert_pem: str | None, key_pem: str | None, verify: bool = True,
                   what: str = "client") -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_pem:
        ctx.load_verify_locations(cadata=ca_pem)
        ctx.verify_mode = ssl.CERT_REQUIRED
    elif verify:
        ctx.load_default_certs()
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if not cert_pem or not key_pem:
        raise ConfigError(f"the {what} certificate and key are not stored for this source")
    folder = tempfile.mkdtemp(prefix="zstls-")
    try:
        cert_path, key_path = os.path.join(folder, "client.pem"), os.path.join(folder, "client.key")
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(key_pem.strip() + "\n")  # stored secrets may have lost the final newline
        with open(cert_path, "w", encoding="ascii") as fh:
            fh.write(cert_pem.strip() + "\n")
        ctx.load_cert_chain(cert_path, key_path)
    except (ssl.SSLError, ValueError, UnicodeEncodeError):
        raise ConfigError(f"the stored {what} certificate and key do not load (PEM certificate and unencrypted PEM key "
                          "expected)") from None
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    return ctx

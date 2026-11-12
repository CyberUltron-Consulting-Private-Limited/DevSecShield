"""SSH certificate authority for scan sessions (F1.4).

A team's CA signs the scan node's EXISTING public key (``cbomscannode.ssh_public_key``) into a short-lived OpenSSH user
certificate, so the node's private key never leaves the node and no login secret is stored for the servers.

* ``models``   the two tables (``cbomsshca``, ``cbomsshcertissued``: one audit row per certificate)
* ``flags``    ``CBOM_SSH_CA`` (default off): routes 404, ``ssh_ca`` refused at save, claim plugin a no-op
* ``keywrap``  CA private keys at rest: AWS KMS envelope when configured, otherwise the deployment key
* ``certs``    building and checking OpenSSH certificates (``cryptography``; no new dependency)
* ``ca``       ``CertificateAuthority`` (builtin or HashiCorp Vault SSH engine) and ``ca_for``
* ``vault``    an SSRF-checked client for the Vault SSH engine
* ``issue``    the issuing rules (who, for which job, which principals and addresses, TTL) and the audit row
* ``registry`` lineages, rotation overlap, ``usable_ca`` for policies (F1.2 seam)
* ``krl``      OpenSSH key revocation list writer (``RevokedKeys``)
* ``claim``    the claim plugin ``secret_refs`` calls (F1.1)
"""

# Network collector vs TLS zoo ground truth

Target 172.17.0.1: 19 endpoints incl. 7 hostile, 1 plain-HTTP (Gitea, remapped 3000->3300 in this lab), 1 honeypot SSH; IKE 500 listed. Ground truth: zoo3/state/tlszoo.json (19 items). Scan settings: 20 conn/s, 2 parallel per server, 12 handshakes per endpoint, SNI name strong.zslab.internal.

- host (OpenSSL 3.0): status success, 74 assets, 27.33 s wall clock, counts {'total': 1, 'ok': 1, 'failed': 0, 'skipped': 0}
- container (OpenSSL 3.5): status success, 66 assets, 27.41 s wall clock, counts {'total': 1, 'ok': 1, 'failed': 0, 'skipped': 0}

## Result: 19 of 19 ground-truth items fully match (container run)

| GT item | endpoint | match | checks |
|---|---|---|---|
| NET-ZOO-z01 | 172.17.0.1:8443 | yes | protocols: ok ['TLSv1.3']; pq_hybrid: ok False group X25519; cert key: ok EC/256; cert sig: ok sha256WithRSAEncryption; expired: ok False (2029-02-02T14:11:44Z) |
| NET-ZOO-z02 | 172.17.0.1:8444 | yes | protocols: ok ['TLSv1.0', 'TLSv1.1', 'TLSv1.2']; pq_hybrid: ok False group X25519; cert key: ok RSA/1024; cert sig: ok sha1WithRSAEncryption; expired: ok False (2036-10-28T14:11:44Z) |
| NET-ZOO-z03 | 172.17.0.1:8445 | yes | protocols: ok ['TLSv1.2']; pq_hybrid: ok False group X25519; cert key: ok RSA/2048; cert sig: ok sha256WithRSAEncryption; expired: ok False (2029-02-02T14:11:44Z) |
| NET-ZOO-z04 | 172.17.0.1:8446 | yes | protocols: ok ['TLSv1.2', 'TLSv1.3']; pq_hybrid: ok False group X25519; cert key: ok RSA/2048; cert sig: ok sha256WithRSAEncryption; expired: ok True (2021-01-01T00:00:00Z) |
| NET-ZOO-z05 | 172.17.0.1:8447 | yes | protocols: ok ['TLSv1.2', 'TLSv1.3']; pq_hybrid: ok True group X25519MLKEM768; cert key: ok EC/256; cert sig: ok sha256WithRSAEncryption; expired: ok False (2029-02-02T14:11:44Z) |
| NET-ZOO-z06 | 172.17.0.1:8448 | yes | protocols: ok ['TLSv1.2', 'TLSv1.3']; pq_hybrid: ok False group X25519; cert key: ok RSA/2048; cert sig: ok sha256WithRSAEncryption; expired: ok False (2029-02-02T14:11:45Z); client auth requested: ok |
| NET-ZOO-z07 | 172.17.0.1:8449 | yes | protocols: ok ['TLSv1.2', 'TLSv1.3']; pq_hybrid: ok False group X25519; cert key: ok RSA/1024; cert sig: ok sha1WithRSAEncryption; expired: ok False (2036-10-28T14:11:44Z); SNI strong.zslab.internal: ok EC |
| NET-ZOO-z08 | 172.17.0.1:2222 | yes | kex: ok ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1', 'kex-strict-s-v00@openssh.com']; ciphers: ok ['aes128-cbc', '3des-cbc']; macs: ok ['hmac-sha1', 'hmac-md5']; host key: ok ssh-rsa/2048 |
| NET-ZOO-z09 | 172.17.0.1:2525 | yes | protocols: ok ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']; pq_hybrid: ok False group X25519; cert key: ok RSA/2048; cert sig: ok sha256WithRSAEncryption; expired: ok False (2029-02-02T14:11:45Z) |
| NET-ZOO-z10 | 172.17.0.1:5433 | yes | protocols: ok ['TLSv1.2', 'TLSv1.3']; pq_hybrid: ok False group prime256v1; cert key: ok RSA/2048; cert sig: ok sha256WithRSAEncryption; expired: ok False (2029-02-02T14:11:44Z) |
| NET-ZOO-h01 | 172.17.0.1:9001 | yes | no fabricated assets: ok 0 assets; outcome timeout in 21144 ms |
| NET-ZOO-h02 | 172.17.0.1:9002 | yes | no fabricated assets: ok 0 assets; outcome timeout in 21041 ms |
| NET-ZOO-h03 | 172.17.0.1:9003 | yes | no fabricated assets: ok 0 assets; outcome error in 467 ms |
| NET-ZOO-h04 | 172.17.0.1:9004 | yes | no fabricated assets: ok 0 assets; outcome error in 442 ms |
| NET-ZOO-h05 | 172.17.0.1:9005 | yes | 40-cert chain parsed: ok 40 certs |
| NET-ZOO-h06 | 172.17.0.1:9006 | yes | hostile subject kept as inert text, no ESC bytes: ok |
| NET-ZOO-h07 | 172.17.0.1:9007 | yes | no fabricated assets: ok 0 assets; outcome error in 906 ms |
| NET-ZOO-gitea | 172.17.0.1:3000 | yes | no fabricated assets: ok 0 assets; outcome error in 449 ms |
| NET-ZOO-rogue_ssh | 172.17.0.1:2223 | yes | host key: ok ssh-rsa/3072 |

## Other evidence

- Honeypot SSH (2223): rogue_ssh.log has 0 auth_password / auth_publickey events (node does KEXINIT + key exchange only, never authenticates in network scans).
- IKE port listed: exactly one coverage row 'ike not_supported' per job (not silent).
- Hostile endpoints bounded: tarpit h01 and slow-drip h02 end as timeout in ~21 s each; garbage h03, RST h04, close h07 end as error in < 1 s; no assets fabricated; whole scan ~28 s (was 116 s before the per-endpoint early abort).
- Weak classes found: z02 SEED + anonymous ECDH + static RSA + CBC; z09 anonymous ECDH + static RSA + CBC; z10 DHE with a 2048-bit group.
- TLS_FALLBACK_SCSV honoured on z02, z04-z07, z10; not on z09 and h05/h06 (Python asyncio servers) -> fallback_scsv=false.
- OpenSSL 3.0 host run: same versions/certs; negotiated group for z05 is X25519 there (3.0 cannot offer ML-KEM) while the PQ HelloRetryRequest probe still detects X25519MLKEM768. In the container (OpenSSL 3.5) the full handshake itself negotiates X25519MLKEM768.

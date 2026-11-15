# Recorded Certificate Transparency provider answers

Every `body` here is a provider's answer recorded byte for byte on a GitHub runner by `bench/ct/capture.py`
(workflow `.github/workflows/cbom-ct-live.yml`); none is written by hand. Each folder keeps the request URL and time
(`request.json`), the status line and the headers.

| Recording | Run |
|---|---|
| everything except the three below | https://github.com/CyberUltron-Consulting-Private-Limited/DevSecShield/actions/runs/43272956731 (2026-11-12 17:46-17:54Z) |
| `certspotter_fullquota_10` (the real 429), `certspotter_paging_p1`, `certspotter_paging_p2` | https://github.com/CyberUltron-Consulting-Private-Limited/DevSecShield/actions/runs/43275038633 (17:58-17:59Z) |

* `certspotter_paging_p*/body.gz`: gzip of the recorded body (366 KB and 299 KB), unchanged otherwise.
* `oracle.json`: written by `bench/ct/oracle.py` (openssl x509 on each DER; no product code) from the body next to it.
* Tests replay an answer for the product's request by domain (and `after`), not by the exact URL: where the recorded
  URL differs from what the product sends (crt.sh `q=%.zeroshield.ai` recorded, `q=zeroshield.ai` sent; the two were
  recorded to give the same names, see `capture-results.md`), the test says so.
* Derived cases are built in the test from a recorded body and labelled there: the malformed JSON case is a recorded
  Cert Spotter body cut at a fixed byte; a network timeout is the transport raising `httpx.ReadTimeout` (the recorded
  `crtsh_reliability_06` is a 60 s read timeout with no body).

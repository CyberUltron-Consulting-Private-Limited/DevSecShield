"""Ubuntu's stock /etc/nginx/nginx.conf sets ``ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;`` in its http block and has
no server block (sites come from include files).  An http-level ssl_protocols is every server's default, so the code
scan flags it (WEAK_PROTOCOL), with the scan-node wording: file, line, the directive as written, the replacement and
how to apply it.  A modern http-level setting stays clean."""

from __future__ import annotations

from pathlib import Path

from aibom.cbom.normalize import normalize_crypto
from aibom.cbom.pipeline import scan_crypto

STOCK = (
    "user www-data;\nworker_processes auto;\npid /run/nginx.pid;\ninclude /etc/nginx/modules-enabled/*.conf;\n\n"
    "events {\n\tworker_connections 768;\n}\n\nhttp {\n\tsendfile on;\n\ttcp_nopush on;\n\ttypes_hash_max_size 2048;\n"
    "\tinclude /etc/nginx/mime.types;\n\tdefault_type application/octet-stream;\n\n\t##\n\t# SSL Settings\n\t##\n\n"
    "\tssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE\n"
    "\tssl_prefer_server_ciphers on;\n\n\taccess_log /var/log/nginx/access.log;\n\terror_log /var/log/nginx/error.log;\n"
    "\tgzip on;\n\tinclude /etc/nginx/conf.d/*.conf;\n\tinclude /etc/nginx/sites-enabled/*;\n}\n"
)


def _weak(root: Path) -> list[dict]:
    run = normalize_crypto(scan_crypto(root), duration_of_scan=0.0)
    return [r for r in run["results"] if "WEAK_PROTOCOL" in (r.get("finding_codes") or [])]


def test_stock_ubuntu_nginx_conf_http_protocols_are_flagged(tmp_path: Path) -> None:
    (tmp_path / "etc/nginx").mkdir(parents=True)
    (tmp_path / "etc/nginx/nginx.conf").write_text(STOCK)
    line = STOCK.splitlines().index(next(x for x in STOCK.splitlines() if "ssl_protocols" in x)) + 1
    rows = _weak(tmp_path)
    assert [(r["location"], r["line"]) for r in rows] == [("etc/nginx/nginx.conf", line)]
    text = rows[0]["description"]
    assert f"nginx enables TLSv1 and TLSv1.1 in etc/nginx/nginx.conf line {line}" in text
    assert "(ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;)" in text
    assert 'change it to "ssl_protocols TLSv1.2 TLSv1.3;"' in text and '"nginx -t"' in text and "reload nginx" in text


def test_modern_http_protocols_stay_clean(tmp_path: Path) -> None:
    (tmp_path / "nginx.conf").write_text(STOCK.replace("TLSv1 TLSv1.1 TLSv1.2 TLSv1.3", "TLSv1.2 TLSv1.3"))
    assert _weak(tmp_path) == []

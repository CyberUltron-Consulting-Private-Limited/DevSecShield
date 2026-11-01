"""Parsers for the output of the Linux collector's commands.  Pure functions; every input is untrusted text."""
from __future__ import annotations

import re
from typing import Any

from zs_scan_node.scrub import printable

CRYPTO_PACKAGES = re.compile(
    r"^(openssl|libssl[\w.\-]*|libcrypto[\w.\-]*|openssl-libs|gnutls|libgnutls[\w.\-]*|nss|libnss3|nss-softokn[\w\-]*|"
    r"libgcrypt[\w.\-]*|libsodium[\w.\-]*|wolfssl|libwolfssl[\w.\-]*|mbedtls|libmbed[\w.\-]*|botan[\w.\-]*|"
    r"libbotan[\w.\-]*|nettle|libnettle[\w.\-]*|openssh(-server|-client|-clients)?|libssh[\w.\-]*|"
    r"crypto-policies(-scripts)?|bouncycastle|libbcprov-java|java-[\w.\-]*openjdk[\w.\-]*|openjdk-[\w.\-]*|"
    r"temurin-[\w.\-]*|python3?-cryptography|libk5crypto3|krb5-libs|cryptsetup(-bin)?|libcryptsetup[\w.\-]*)$"
)


def os_release(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if k in ("ID", "ID_LIKE", "VERSION_ID", "PRETTY_NAME", "NAME"):
                out[k.lower()] = printable(v.strip().strip('"'), 120)
    return out


def packages(text: str) -> list[dict[str, str]]:
    out = []
    for line in text.splitlines():
        parts = line.strip().split("\t")
        if len(parts) != 2:
            continue
        name, version = parts[0].strip(), parts[1].strip()
        if CRYPTO_PACKAGES.match(name):
            out.append({"name": printable(name, 100), "version": printable(version, 100)})
    return out[:500]


def openssl_version(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    first = text.splitlines()[0] if text.strip() else ""
    m = re.match(r"(OpenSSL|LibreSSL|BoringSSL)\s+(\S+)", first)
    if m:
        out["implementation"], out["version"] = m.group(1), m.group(2)
    m = re.search(r"OPENSSLDIR:\s*\"?([^\"\n]+)", text)
    if m:
        out["openssldir"] = printable(m.group(1), 200)
    if "fips" in text.lower():
        out["fips_mentioned"] = True
    return out


_SSHD_LIST_KEYS = {"ciphers", "macs", "kexalgorithms", "hostkeyalgorithms", "pubkeyacceptedalgorithms",
                   "pubkeyacceptedkeytypes", "casignaturealgorithms", "hostbasedacceptedalgorithms"}
_SSHD_SCALAR_KEYS = {"passwordauthentication", "permitrootlogin", "pubkeyauthentication", "kbdinteractiveauthentication",
                     "challengeresponseauthentication", "protocol", "port", "hostkey", "requiredrsasize",
                     "include", "fingerprinthash", "usepam", "gssapiauthentication"}


def sshd_config(text: str, effective: bool) -> dict[str, Any]:
    """``sshd -T`` (effective, lower-case keys) or ``sshd_config`` (configured; Includes are not followed)."""
    out: dict[str, Any] = {"effective": effective}
    host_keys = []
    includes = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not effective and line.lower().startswith("match "):
            break  # Match blocks apply conditionally; the global section is what we report
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts[0].lower(), parts[1].strip()
        if key in _SSHD_LIST_KEYS:
            out[key] = [printable(v, 100) for v in value.split(",") if v][:100]
        elif key == "hostkey":
            host_keys.append(printable(value, 200))
        elif key == "include":
            includes.append(printable(value, 200))
        elif key in _SSHD_SCALAR_KEYS:
            out.setdefault(key, printable(value, 100))
    if host_keys:
        out["hostkey"] = host_keys[:10]
    if includes:
        out["includes_not_followed"] = includes[:10]
    return out


def ssh_keygen_l(text: str) -> list[dict[str, Any]]:
    """``ssh-keygen -l`` lines: '256 SHA256:abc comment (ED25519)'."""
    out = []
    for line in text.splitlines():
        m = re.match(r"^(\d+)\s+(\S+)\s+(.*?)\s*\(([A-Z0-9\-]+)\)\s*$", line.strip())
        if m:
            out.append({"bits": int(m.group(1)), "fingerprint": m.group(2), "comment": printable(m.group(3), 120),
                        "type": m.group(4)})
    return out[:200]


def ps_processes(text: str) -> dict[int, str]:
    out = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            out[int(parts[0])] = printable(parts[1], 64)
    return out


_SS_USER = re.compile(r'\("([^"]{0,64})",pid=(\d+),fd=\d+\)')


def ss_listen(text: str) -> list[dict[str, Any]]:
    """``ss -H -tlnp``: state recv send local peer [users:((...))]."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[3]
        if local.startswith("["):
            host, _, port = local.rpartition(":")
        else:
            host, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        users = [{"name": printable(n, 64), "pid": int(p)} for n, p in _SS_USER.findall(line)]
        out.append({"address": printable(host, 64), "port": int(port), "processes": users[:20]})
    return out[:2000]


_MAPS = re.compile(r"^/proc/(\d+)/maps:\S+\s+\S+\s+\S+\s+\S+\s+\d+\s+(/\S.*?)\s*$")


def proc_maps(text: str) -> dict[int, dict[str, bool]]:
    """{pid: {library_path: deleted}} from ``grep -HE <libs> /proc/*/maps``."""
    out: dict[int, dict[str, bool]] = {}
    for line in text.splitlines():
        m = _MAPS.match(line.strip())
        if not m:
            continue
        pid, path = int(m.group(1)), m.group(2)
        deleted = path.endswith(" (deleted)")
        if deleted:
            path = path[: -len(" (deleted)")]
        out.setdefault(pid, {})[printable(path, 300)] = deleted
    return out


def proc_exe(text: str) -> dict[int, str]:
    """{pid: exe} from ``find /proc -maxdepth 2 -name exe -printf '%h\\t%l\\n'``."""
    out = {}
    for line in text.splitlines():
        if "\t" not in line:
            continue
        head, target = line.split("\t", 1)
        m = re.fullmatch(r"/proc/(\d+)", head.strip())
        if m and target:
            out[int(m.group(1))] = printable(target.strip(), 300)
    return out


def dmsetup_crypt(text: str) -> list[dict[str, Any]]:
    """``dmsetup table --target crypt``: 'name: start len crypt cipher key iv_offset dev offset [opts]'."""
    out = []
    for line in text.splitlines():
        if ":" not in line or " crypt " not in line:
            continue
        name, rest = line.split(":", 1)
        fields = rest.split()
        try:
            i = fields.index("crypt")
        except ValueError:
            continue
        if len(fields) < i + 5:
            continue
        cipher, key = fields[i + 1], fields[i + 2]
        bits = None
        m = re.fullmatch(r":(\d+):[a-z]+:.*", key)  # keyring reference ':64:logon:...' (bytes)
        if m:
            bits = int(m.group(1)) * 8
        elif re.fullmatch(r"[0-9a-fA-F]+", key) and len(key) % 2 == 0:
            bits = len(key) * 4
        effective = bits // 2 if bits and "xts" in cipher else bits
        out.append({"name": printable(name.strip(), 100), "cipher": printable(cipher, 100), "key_bits": bits,
                    "effective_key_bits": effective, "device": printable(fields[i + 4], 100)})
    return out[:200]


def luks_versions(text: str) -> dict[str, int]:
    """``lsblk -nr -o MAJ:MIN,FSTYPE,FSVER`` -> {"7:4": 1} for LUKS block devices (keyed like dmsetup's device)."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "crypto_LUKS" and re.fullmatch(r"\d+:\d+", parts[0]) \
                and re.fullmatch(r"[12]", parts[2]):
            out[parts[0]] = int(parts[2])
    return out


def file_mode(text: str) -> int | None:
    """``stat -c %a`` -> permission bits as an int (e.g. '644' -> 0o644)."""
    t = text.strip()
    return int(t, 8) if re.fullmatch(r"[0-7]{3,4}", t) else None


def lsblk(text: str) -> list[dict[str, str]]:
    out = []
    lines = text.splitlines()
    for line in lines[1:] if lines and lines[0].lstrip().startswith("NAME") else lines:
        parts = re.sub(r"^[^A-Za-z0-9]+", "", line).split()  # drop the tree drawing (lsblk prints a tree)
        if not parts:
            continue
        name = parts[0]
        row = {"name": printable(name, 100), "type": parts[1] if len(parts) > 1 else "",
               "fstype": parts[2] if len(parts) > 2 else "", "mountpoint": parts[3] if len(parts) > 3 else ""}
        if row["type"] in ("crypt", "part", "disk", "lvm", "loop") or row["fstype"]:
            out.append(row)
    return out[:500]


def find_print0(data: bytes, limit: int = 5000) -> tuple[list[str], bool]:
    """Paths from ``find ... -print0``; names that are not absolute or contain control characters are dropped."""
    out = []
    truncated = False
    for raw in data.split(b"\x00"):
        if not raw:
            continue
        path = raw.decode("utf-8", "surrogateescape")
        if not safe_path(path):
            continue
        out.append(path)
        if len(out) >= limit:
            truncated = True
            break
    return out, truncated


_UNSAFE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # newline and tab are allowed: paths are always shell-quoted


def display_path(path: str) -> str:
    """A path as shown to people: newline/tab made visible (the real path is only used shell-quoted)."""
    return path.replace("\n", "\\n").replace("\t", "\\t")


def safe_path(path: str) -> bool:
    if not path.startswith("/") or len(path) > 4096 or _UNSAFE.search(path):
        return False
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return False  # undecodable bytes (surrogates) cannot be passed back to the shell faithfully
    return True


def classify_file(path: str) -> str:
    low = path.lower()
    name = low.rsplit("/", 1)[-1]
    if name == "authorized_keys":
        return "authorized_keys"
    if re.fullmatch(r"ssh_host_.+_key", name) or name in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"):
        return "ssh_private_key"
    for ext, kind in ((".pem", "pem"), (".crt", "cert"), (".cer", "cert"), (".der", "cert"), (".key", "key"),
                      (".p8", "key"), (".pk8", "key"), (".p12", "keystore"), (".pfx", "keystore"), (".jks", "keystore"),
                      (".jceks", "keystore"), (".bks", "keystore"), (".keystore", "keystore"),
                      (".truststore", "keystore")):
        if low.endswith(ext):
            return kind
    return "other"


# ----------------------------------------------------------------------------- openssl storeutl -text
def storeutl_certs(text: str) -> list[dict[str, Any]]:
    """Certificates from ``openssl storeutl -noout -text -certs`` (or ``x509 -text``) output."""
    blocks = re.split(r"(?m)^(?:\d+: Certificate\s*$|Certificate:\s*$)", text)
    out = []
    for block in blocks:
        if "Subject:" not in block and "Issuer:" not in block:
            continue
        cert: dict[str, Any] = {"source": "file"}
        m = re.search(r"Serial Number:\s*\n?\s*([0-9a-fA-F:]+|\d+ \(0x[0-9a-f]+\))", block)
        if m:
            cert["serial"] = printable(m.group(1).replace(":", "").strip(), 80)
        m = re.search(r"Signature Algorithm:\s*(\S+)", block)
        if m:
            cert["sig_alg"] = m.group(1)
        m = re.search(r"Issuer:\s*(.+)", block)
        if m:
            cert["issuer"] = printable(m.group(1).strip(), 512)
        m = re.search(r"Subject:\s*(.+)", block)
        if m:
            cert["subject"] = printable(m.group(1).strip(), 512)
        m = re.search(r"Not Before\s*:\s*(.+)", block)
        if m:
            cert["not_before"] = _openssl_date(m.group(1))
        m = re.search(r"Not After\s*:\s*(.+)", block)
        if m:
            cert["not_after"] = _openssl_date(m.group(1))
        m = re.search(r"Public Key Algorithm:\s*(\S+)", block)
        if m:
            alg = m.group(1)
            cert["key_alg"] = {"rsaEncryption": "RSA", "id-ecPublicKey": "EC", "ED25519": "Ed25519", "ED448": "Ed448",
                               "dsaEncryption": "DSA"}.get(alg, alg)
        m = re.search(r"Public-Key:\s*\((\d+) bit\)", block)
        if m:
            cert["key_size"] = int(m.group(1))
        m = re.search(r"(?:ASN1 OID|NIST CURVE):\s*(\S+)", block)
        if m:
            cert["curve"] = m.group(1)
        cert["is_ca"] = bool(re.search(r"CA:TRUE", block))
        m = re.search(r"Subject Alternative Name:\s*\n\s*(.+)", block)
        if m:
            cert["san"] = [printable(x.strip(), 253) for x in m.group(1).split(",")][:50]
        if cert.get("issuer") and cert.get("subject"):
            cert["self_signed"] = cert["issuer"] == cert["subject"]
        out.append(cert)
    return out[:500]


_MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
                                       "Dec"], 1)}


def _openssl_date(text: str) -> str | None:
    m = re.match(r"\s*([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})", text)
    if not m or m.group(1) not in _MONTHS:
        return None
    return f"{m.group(6)}-{_MONTHS[m.group(1)]:02d}-{int(m.group(2)):02d}T{m.group(3)}:{m.group(4)}:{m.group(5)}Z"


def keytool_list(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    m = re.search(r"Keystore type:\s*(\S+)", text)
    if m:
        out["store_type"] = m.group(1)
    m = re.search(r"Your keystore contains (\d+) entr", text)
    if m:
        out["entries"] = int(m.group(1))
    entries = []
    for block in re.split(r"(?m)^Alias name:\s*", text)[1:]:
        alias = block.splitlines()[0].strip() if block.strip() else ""
        e: dict[str, Any] = {"alias": printable(alias, 120)}
        m = re.search(r"Entry type:\s*(\S+)", block)
        if m:
            e["entry_type"] = m.group(1)
        m = re.search(r"Signature algorithm name:\s*(\S+)", block)
        if m:
            e["sig_alg"] = m.group(1)
        m = re.search(r"Subject Public Key Algorithm:\s*(\d+)-bit (\S+) key", block)
        if m:
            e["key_size"], e["key_alg"] = int(m.group(1)), m.group(2)
        else:
            m = re.search(r"Subject Public Key Algorithm:\s*(.+)", block)
            if m:
                e["key_alg"] = printable(m.group(1).strip(), 60)
        m = re.search(r"Valid from:.*until:\s*(.+)", block)
        if m:
            e["not_after_text"] = printable(m.group(1).strip(), 60)
        m = re.search(r"Owner:\s*(.+)", block)
        if m:
            e["subject"] = printable(m.group(1).strip(), 300)
        entries.append(e)
    out["entry_list"] = entries[:200]
    if "integrity of the information stored in your keystore" in text:
        out["integrity_unverified"] = True
    return out


# ----------------------------------------------------------------------------- services, configs, scripts
_SECRET_NAME = re.compile(r"(KEY|SECRET|PASSWORD|PASSWD|PASSPHRASE|TOKEN|CREDENTIAL)", re.I)
_NOT_SECRET_NAME = re.compile(r"(_FILE|_PATH|_DIR|_ID|_URL|_URI|_NAME|_ARN|_ALIAS|_TYPE|_SIZE|_LEN|_BITS|_ALG)$", re.I)
_HEX = re.compile(r"[0-9a-fA-F]+")
_B64 = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")


def _ok_abs(path: str) -> bool:
    return (path.startswith("/") and len(path) <= 512 and ".." not in path.split("/")
            and not any(ord(ch) < 32 or ord(ch) == 127 for ch in path))


def _env_pairs(text: str) -> list[tuple[str, str]]:
    import shlex
    try:
        parts = shlex.split(text)
    except ValueError:
        parts = text.split()
    out = []
    for p in parts:
        name, sep, value = p.partition("=")
        if sep and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name):
            out.append((name, value))
    return out


def secret_shape(name: str, value: str) -> dict[str, Any] | None:
    """Length/encoding of a secret-looking value -- never the value.  None when it is not key or passphrase material."""
    if not _SECRET_NAME.search(name) or _NOT_SECRET_NAME.search(name):
        return None
    v = value.strip()
    if not v or v.startswith(("$", "/", "file:", "env:", "@")) or v.lower() in ("true", "false", "none", "null", "changeme"):
        return None
    if _HEX.fullmatch(v) and len(v) >= 32 and len(v) % 2 == 0:
        return {"encoding": "hex", "length": len(v), "key_bits": len(v) * 4}
    if _B64.fullmatch(v) and len(v) >= 22:
        return {"encoding": "base64", "length": len(v), "key_bits": (len(v.rstrip("=")) * 6) // 8 * 8}
    if len(v) >= 8 and re.search(r"(PASS|SECRET|TOKEN|KEY)", name, re.I):
        return {"encoding": "text", "length": len(v), "key_bits": None}
    return None


def systemd_services(text: str) -> list[dict[str, Any]]:
    """``systemctl show -p Id -p FragmentPath -p Environment -p ExecStart '*'`` -> one dict per unit.

    Secret values are replaced by their shape here, so they never leave this function."""
    units: list[dict[str, str]] = []
    cur: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if cur:
                units.append(cur)
                cur = {}
            continue
        key, _sep, value = line.partition("=")
        if key in ("Id", "FragmentPath", "Environment", "ExecStart"):
            cur[key] = value
    if cur:
        units.append(cur)
    out = []
    for u in units[:3000]:
        env = _env_pairs(u.get("Environment", ""))
        argv_m = re.search(r"argv\[\]=(.*?) ; ignore_errors", u.get("ExecStart", ""))
        argv = argv_m.group(1) if argv_m else ""
        secrets_ = []
        for name, value in env:
            shape = secret_shape(name, value)
            if shape:
                secrets_.append({"name": name, **shape})
        openssl_conf = next((v for n, v in env if n == "OPENSSL_CONF" and _ok_abs(v)), None)
        jsec = re.search(r"-Djava\.security\.properties==?(\S+)", argv)
        java_props = jsec.group(1) if jsec and _ok_abs(jsec.group(1)) else None
        if not (secrets_ or openssl_conf or java_props):
            continue
        frag = u.get("FragmentPath") or ""
        out.append({"unit": printable(u.get("Id") or "", 255), "fragment": frag if _ok_abs(frag) else None,
                    "secrets": secrets_[:20], "openssl_conf": openssl_conf, "java_security": java_props,
                    "java_override_replaces": bool(jsec and "==" in jsec.group(0))})
    return out


def crypto_directives(text: str) -> dict[str, dict[str, Any]]:
    """``grep -n`` of MinProtocol/CipherString/jdk.*.disabledAlgorithms -> {directive: {value, line}}."""
    out: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        m = re.match(r"^(\d+):\s*([A-Za-z.]+)\s*=\s*(.*?)\s*$", line)
        if m:
            out[m.group(2).lower()] = {"value": printable(m.group(3), 300), "line": int(m.group(1))}
    return out


_ENC_CIPHER = re.compile(r"^-(aes-\d+-[a-z0-9]+|des(?:3|-ede3(?:-cbc)?|-ede(?:-cbc)?|-cbc|-ecb)?|bf(?:-cbc|-ecb)?|rc4(?:-40)?|rc2(?:-cbc)?|"
                         r"cast5?(?:-cbc)?|camellia-\d+-[a-z]+|chacha20)$", re.I)


def openssl_cli_uses(text: str) -> list[dict[str, Any]]:
    """``grep -rn`` hits of openssl enc/des/aes command lines -> cipher, digest, KDF and whether a literal passphrase
    is on the command line.  The passphrase itself is never kept."""
    out = []
    for line in text.splitlines()[:500]:
        m = re.match(r"^(/[^:]+):(\d+):(.*)$", line)
        if not m or not _ok_abs(m.group(1)):
            continue
        content = m.group(3)
        if content.lstrip().startswith("#"):
            continue
        tokens = content.replace("|", " | ").split()
        try:
            i = next(k for k, t in enumerate(tokens) if t.rsplit("/", 1)[-1] == "openssl")
        except StopIteration:
            continue
        args = tokens[i + 1:]
        cut = args.index("|") if "|" in args else len(args)
        args = args[:cut]
        if not args:
            continue
        sub = args[0]
        cipher = None
        if sub == "enc":
            cipher = next((a[1:] for a in args[1:] if _ENC_CIPHER.match(a)), None)
        elif _ENC_CIPHER.match("-" + sub):
            cipher = sub
        md = next((args[k + 1] for k, a in enumerate(args[:-1]) if a == "-md"), None)
        literal = False
        for k, a in enumerate(args[:-1]):
            nxt = args[k + 1]
            if a == "-k" and not nxt.startswith(("$", '"$')):
                literal = True
            if a in ("-pass", "-passin", "-passout") and nxt.startswith(("pass:", "'pass:", '"pass:')) and "$" not in nxt:
                literal = True
        out.append({"file": m.group(1), "line": int(m.group(2)), "command": "openssl " + sub,
                    "cipher": cipher.lower() if cipher else None, "md": md.lower() if md else None,
                    "pbkdf2": "-pbkdf2" in args or "-iter" in args, "salt": "-nosalt" not in args,
                    "decrypt": "-d" in args, "hardcoded_passphrase": literal})
    return out


def web_tls(text: str) -> dict[str, dict[str, Any]]:
    """nginx ssl_protocols/ssl_ciphers and Apache SSLProtocol/SSLCipherSuite per file."""
    out: dict[str, dict[str, Any]] = {}
    for line in text.splitlines()[:2000]:
        m = re.match(r"^(/[^:]+):(\d+):\s*(ssl_protocols|ssl_ciphers|SSLProtocol|SSLCipherSuite)\s+(.*?);?\s*$", line)
        if not m or not _ok_abs(m.group(1)):
            continue
        f = out.setdefault(m.group(1), {"server": "nginx" if m.group(3).startswith("ssl_") else "apache", "lines": []})
        f["lines"].append(int(m.group(2)))
        # "ssl_protocols TLSv1 TLSv1.1; # comment" -> directive value only, unquoted
        raw = m.group(4).split("#", 1)[0].split(";", 1)[0].strip()
        value = printable(raw.strip("'\"").strip(), 400)
        if m.group(3) in ("ssl_protocols", "SSLProtocol"):
            f["protocols_raw"] = value
            if m.group(3) == "ssl_protocols":
                f["protocols"] = [p for p in value.replace(";", " ").split() if p]
            else:  # Apache: all, +X, -X
                enabled = set()
                for tok in value.split():
                    t = tok.lstrip("+")
                    if tok.lower() == "all":
                        enabled |= {"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
                    elif tok.startswith("-"):
                        enabled.discard(tok[1:])
                    else:
                        enabled.add(t)
                f["protocols"] = sorted(enabled)
        else:
            f["ciphers"] = value
    return out

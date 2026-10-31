"""Every command the Linux collector runs on a customer server, exactly as it is sent.

This module is the single source of truth: the backend shows customers the same lists (Tier 1 runs as the
login user without sudo, Tier 2 runs through ``sudo -n`` and must match the ``zs-cbom`` sudoers file line for
line).  A test in the backend compares these strings with the sudoers template and the UI list.

``<file>`` is only ever a path printed by the Tier 2 key/certificate ``find``.  It must be absolute, contain no
control characters, and is passed through ``shlex.quote``.  Tier 1 commands run with a fixed ``PATH`` and
``LC_ALL=C`` (so a writable ``/usr/local/bin`` cannot hijack them) and with stdin closed.
"""
from __future__ import annotations

import shlex

# Prefix for every Tier 1 command: fixed PATH, C locale, stdin closed (passphrase prompts get EOF, never hang).
T1_ENV = "PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C"

# ----------------------------------------------------------------------------- Tier 1 (no sudo)
OS_RELEASE = "cat /etc/os-release"
KERNEL = "uname -r"
PACKAGES_DPKG = "dpkg-query -W -f '${Package}\\t${Version}\\n'"
PACKAGES_RPM = "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n'"
CRYPTO_POLICY = "cat /etc/crypto-policies/config"
FIPS = "cat /proc/sys/crypto/fips_enabled"
OPENSSL_VERSION = "openssl version -a"
SSHD_CONFIG = "cat /etc/ssh/sshd_config"
PROCESSES = "ps -eo pid=,comm="
HOST_KEY_TYPES = ("rsa", "ecdsa", "ed25519", "dsa")
# Per-file commands; {file} is a shlex-quoted absolute path from the Tier 2 find.
CERTS_IN_FILE = "openssl storeutl -noout -text -certs {file}"
PUBLIC_HALF_OF_KEY = "openssl pkey -pubout -passin pass: -in {file}"
HAS_PRIVATE_KEY = "grep -c 'PRIVATE KEY-----' {file}"
SSH_KEY_FINGERPRINT = "ssh-keygen -l -f {file}"
# No -storepass: with stdin closed keytool lists a JKS/JCEKS without verifying integrity (public metadata only;
# private entries stay encrypted).  PKCS#12 needs the password and is reported as password-protected.
KEYSTORE_LIST = "keytool -list -v -keystore {file}"

TIER1_DISPLAY = [
    OS_RELEASE,
    KERNEL,
    PACKAGES_DPKG + "  (or: " + PACKAGES_RPM + ")",
    CRYPTO_POLICY,
    FIPS,
    OPENSSL_VERSION,
    SSHD_CONFIG,
    "ssh-keygen -l -f /etc/ssh/ssh_host_<type>_key.pub",
    PROCESSES,
    CERTS_IN_FILE.format(file="<file>"),
    PUBLIC_HALF_OF_KEY.format(file="<file>"),
    HAS_PRIVATE_KEY.format(file="<file>"),
    SSH_KEY_FINGERPRINT.format(file="<file>"),
    KEYSTORE_LIST.format(file="<file>"),
]

# ----------------------------------------------------------------------------- Tier 2 (sudo -n, exact argv)
CRYPTO_LIBS_RE = "libssl|libcrypto|libgnutls|libnss3|libgcrypt|libsodium|libwolfssl|libmbedcrypto|libbotan|libnettle"
KEY_FILE_RE = (
    r".+(\.pem|\.crt|\.cer|\.der|\.key|\.p8|\.pk8|\.p12|\.pfx|\.jks|\.jceks|\.bks|\.keystore|\.truststore"
    r"|/id_rsa|/id_dsa|/id_ecdsa|/id_ed25519|/authorized_keys|/ssh_host_.+_key)"
)
KEY_FILE_ROOTS = ["/etc", "/opt", "/srv", "/home", "/root", "/usr/local"]

# Each Tier 2 check lists argv variants (merged /usr first, then classic /bin and /sbin paths).  The node tries
# them in order and stops at the first one sudo does not reject as "not allowed" or "command not found".
_FILES = [*KEY_FILE_ROOTS, "-xdev", "-type", "f", "-size", "-1024k", "-regextype", "posix-extended", "-regex", KEY_FILE_RE,
          "-print0"]
TIER2: dict[str, list[list[str]]] = {
    "listening_sockets": [["/usr/bin/ss", "-H", "-tlnp"], ["/usr/sbin/ss", "-H", "-tlnp"], ["/bin/ss", "-H", "-tlnp"],
                          ["/sbin/ss", "-H", "-tlnp"]],
    "process_crypto_libraries": [
        ["/usr/bin/find", "/proc", "-maxdepth", "2", "-name", "maps", "-exec", "/usr/bin/grep", "-HE", CRYPTO_LIBS_RE, "{}", "+"],
        ["/usr/bin/find", "/proc", "-maxdepth", "2", "-name", "maps", "-exec", "/bin/grep", "-HE", CRYPTO_LIBS_RE, "{}", "+"],
    ],
    "process_executables": [["/usr/bin/find", "/proc", "-maxdepth", "2", "-name", "exe", "-printf", r"%h\t%l\n"]],
    "sshd_effective_config": [["/usr/sbin/sshd", "-T"]],
    "disk_encryption": [["/usr/sbin/dmsetup", "table", "--target", "crypt"], ["/sbin/dmsetup", "table", "--target", "crypt"]],
    "block_devices": [["/usr/bin/lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"], ["/bin/lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"]],
    "key_and_certificate_files": [["/usr/bin/find", *_FILES]],
}


def sudo_line(argv: list[str]) -> str:
    """The shell command sent over SSH for a Tier 2 argv (sudo receives exactly ``argv``)."""
    return "sudo -n " + " ".join(shlex.quote(a) for a in argv)


def tier1_line(command: str) -> str:
    return f"{T1_ENV} {command} </dev/null"


def tier2_display() -> list[str]:
    """Human-readable Tier 2 lines (first variant of each check), as shown in the UI."""
    return [" ".join(variants[0]) for variants in TIER2.values()]


def sudoers_argv(argv: list[str]) -> str:
    """A Tier 2 argv written as a sudoers Cmnd entry.

    sudo matches arguments with fnmatch(), where a backslash escapes the next character, and the sudoers parser
    also treats a backslash as an escape: one literal backslash is written as four.  Commas, colons and equals
    signs are escaped once.  (Proven with visudo and real sudo on Ubuntu 22.04.)
    """
    out = []
    for arg in argv:
        text = arg.replace("\\", "\\\\\\\\")
        for ch in ",:=":
            text = text.replace(ch, "\\" + ch)
        out.append(text)
    return " ".join(out)


def sudoers_file(user: str = "zs-cbom") -> str:
    """The complete /etc/sudoers.d/zs-cbom file for these Tier 2 commands."""
    lines = []
    for variants in TIER2.values():
        for argv in variants:
            lines.append("    " + sudoers_argv(argv))
    body = ", \\\n".join(lines)
    return (
        f"# /etc/sudoers.d/{user} -- ZeroShield CBOM collector, Tier 2 allowlist (exact command lines only)\n"
        f"# Install: sudo install -m 0440 {user} /etc/sudoers.d/{user} && sudo visudo -cf /etc/sudoers.d/{user}\n"
        f"Defaults:{user} !lecture, env_reset, !setenv, !requiretty\n\n"
        f"Cmnd_Alias ZS_CBOM_TIER2 = \\\n{body}\n\n"
        f"{user} ALL=(root) NOPASSWD: ZS_CBOM_TIER2\n"
    )

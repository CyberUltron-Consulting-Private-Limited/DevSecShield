"""Round 5 WP8: code-scan codes for crypto libraries found in container images, binaries and firmware.

Language packages inside an image keep VULNERABLE_CRYPTO_LIBRARY (the advisory file, as for manifests). OS packages
and library versions read from binaries are judged by the knowledge base's upstream CVE ranges and end-of-life
dates; distributions back-port fixes without changing the upstream version, so a CVE-range hit is a Low triage
item (like the scan node's LIB_KNOWN_CVE) and the end of life is its own code. The base OS of an image reuses
EOL_BASE_IMAGE.
"""

import kb_text
from kb_text import entry

CODE_CODES = ["LIBRARY_CVE_RANGE", "EOL_CRYPTO_LIBRARY"]

_VERIFY_IMAGE = {
    "label": "Show the package version inside the image (replace IMAGE with the image name)",
    "command": "docker run --rm --entrypoint sh IMAGE -c \"dpkg -s {name} 2>/dev/null | grep Version || "
               "rpm -q {name} 2>/dev/null || apk info -v {name}\"",
}

entry(
    "LIBRARY_CVE_RANGE",
    title="Crypto library version inside a published CVE range (image, binary or firmware)",
    category="library",
    default_impact="Low",
    description=(
        "A crypto library shipped in a container image, a firmware image or a binary (an OS package such as "
        "libssl1.1, or the OpenSSL version text compiled into a library) has a version inside the affected range "
        "the CVE records publish. Distributions back-port fixes without changing the upstream version, so the hit "
        "is a triage item until the package's changelog shows whether each fix is in."
    ),
    attack=(
        "If the fix is not in the build, the published exploit for the CVE works against every service in the "
        "image or device that loads the library (memory corruption, side channels, certificate parsing flaws)."
    ),
    cwe=["CWE-1395"],
    owasp=["components"],
    cves=[],
    standards=[],
    compliance=["components"],
    remediation={
        "summary": "Rebuild the image or firmware with the distribution's current security update for the package "
                   "(or an upstream release past the fixed version), then redeploy everything built from it.",
        "steps": [
            {"platform": "Debian / Ubuntu image", "how": "apt-get update && apt-get install --only-upgrade <package> "
             "in the Dockerfile (or rebuild on a current base image); check security-tracker.debian.org / "
             "ubuntu.com/security/cves for the CVE"},
            {"platform": "RHEL / Alma / Amazon Linux image", "how": "dnf upgrade <package>; dnf updateinfo list "
             "--cve <CVE-ID> shows whether the fix is in"},
            {"platform": "Alpine image", "how": "apk upgrade --no-cache <package> (or a newer alpine base)"},
            {"platform": "Firmware / static binary", "how": "rebuild against a fixed upstream release and ship a "
             "firmware update"},
        ],
    },
    verify=[_VERIFY_IMAGE,
            {"label": "Back-ported fixes in the Debian changelog (inside the image)",
             "command": "docker run --rm --entrypoint sh IMAGE -c \"zgrep -i cve "
                        "/usr/share/doc/{name}/changelog.Debian.gz | head\""}],
    references=["https://security-tracker.debian.org/tracker/", "https://access.redhat.com/security/security-updates/backporting"],
)

entry(
    "EOL_CRYPTO_LIBRARY",
    title="End-of-life crypto library in an image, binary or firmware",
    category="library",
    default_impact="Medium",
    description=(
        "A container image, firmware image or binary ships (or links against) a crypto library release line its "
        "upstream project no longer maintains, for example OpenSSL 1.0.2 or 1.1.x, so vulnerabilities published "
        "after the end-of-life date are not fixed upstream."
    ),
    attack=(
        "New OpenSSL / GnuTLS advisories after the end of life stay exploitable in the shipped library unless a "
        "vendor back-ports them (paid extended support), and the build gets no further fixes."
    ),
    cwe=["CWE-1104", "CWE-1395"],
    owasp=["components"],
    cves=[],
    standards=[],
    compliance=["components"],
    remediation={
        "summary": "Rebuild on a supported release line (OpenSSL 3.5 LTS, or the distribution's current release), "
                   "or confirm and record the vendor's extended support for the line in use.",
        "steps": [
            {"platform": "Container image", "how": "move the FROM line to a supported release (debian:12-slim, "
             "ubuntu:24.04, alpine:3.22) and rebuild; replace bundled copies (a Python wheel built with its own "
             "OpenSSL) with current releases"},
            {"platform": "Firmware / static binary", "how": "rebuild against OpenSSL 3.x and ship a firmware "
             "update"},
        ],
    },
    verify=[_VERIFY_IMAGE,
            {"label": "OpenSSL version text inside the file", "command": "strings -a '{path}' | grep -m3 'OpenSSL [0-9]'"}],
    references=["https://openssl-library.org/policies/releasestrat/index.html", "https://endoflife.date/openssl"],
)

del kb_text

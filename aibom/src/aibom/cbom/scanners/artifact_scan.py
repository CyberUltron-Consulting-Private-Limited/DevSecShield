"""CBOM scanner: container images, compiled binaries and firmware (scan option ``scan_binaries``).

Reads the scan's one :func:`aibom.cbom.artifacts.collect` report (the certificate lane reads its certificate and
public-key files through :meth:`FileWalk.virtual_files`) and adds:

* the base OS of each image, flagged ``EOL_BASE_IMAGE`` when the release is past its end of life (same offline
  table as the Dockerfile check);
* crypto library rows with a package URL: OS packages (dpkg / apk / rpm), Python / npm / Maven / Go packages and
  library versions read from binaries. Language packages are matched against the offline advisory file
  (``VULNERABLE_CRYPTO_LIBRARY``, as for manifests). OS packages and binary version strings are matched against
  the knowledge base's upstream CVE ranges and end-of-life dates: a CVE-range hit is ``LIBRARY_CVE_RANGE`` (Low,
  in triage, because distributions back-port fixes without changing the upstream version) and a branch past its
  upstream end of life is ``EOL_CRYPTO_LIBRARY``;
* per binary: algorithm rows for imported crypto functions and for constant signatures (the weak-algorithm, mode
  and post-quantum lanes judge them like any other algorithm), linked crypto libraries (an OpenSSL 1.0 / 1.1
  soname is end of life), platform crypto APIs;
* private keys shipped inside an artifact: hard-coded key material (``HARDCODED_KEY``) and, for RSA / DSA, an
  algorithm row with the key size (``WEAK_KEY_SIZE`` below 2048 bits).
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from urllib.parse import quote

from aibom.cbom import crypto_kb, pkgdb
from aibom.cbom.files import file_walk
from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import algo_info
from aibom.model.component import CryptoAssetComponent, FrameworkComponent
from aibom.scan.registry import ScanContext, Scanner

LIBRARY_CVE_RANGE = "LIBRARY_CVE_RANGE"
EOL_CRYPTO_LIBRARY = "EOL_CRYPTO_LIBRARY"
EOL_BASE_IMAGE = "EOL_BASE_IMAGE"
_LISTED = 8
_ADVISORY_ECOSYSTEMS = frozenset({"pypi", "npm", "maven", "go", "cargo", "nuget"})
_ALGO_KEYS = {"MD5": "md5", "MD4": "md4", "SHA-1": "sha1", "DES": "des", "3DES": "3des", "RC4": "rc4", "RC2": "rc2",
              "Blowfish": "blowfish", "AES": "aes", "RSA": "rsa", "DSA": "dsa", "ChaCha20": "chacha20",
              "SHA-256": "sha256", "SHA-512": "sha512"}
# soname branch -> the upstream release line it stands for (1.0.x -> 1.0.2, 1.1.x -> 1.1.1: the last of each)
_SONAME_BRANCH = {"1.0": "1.0.2", "1.1": "1.1.1"}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:120] or "x"


# OS package names the knowledge base does not list (OpenWrt opkg, vendor builds) that are OpenSSL itself
_OPENSSL_NAMES = re.compile(r"^(?:lib)?(?:openssl|libssl|libcrypto)[-_.]?(?:\d[\w.]*)?(?:-(?:libs|dev|util|bin))?$")


def _kb_package(name: str) -> str:
    """The name the knowledge base knows a package by: itself, or ``openssl`` for an OpenSSL build it does not list."""
    if crypto_kb.library_for(name) is None and _OPENSSL_NAMES.match(name.lower()):
        return "openssl"
    return name


def _today() -> date:
    return datetime.now(UTC).date()


def _purl(pkg) -> str | None:
    eco, name, version = pkg.ecosystem, pkg.name, pkg.version
    if eco in ("deb", "apk", "rpm"):
        return pkgdb.purl(eco, name, version, pkg.distro, pkg.arch)
    if eco == "pypi":
        return f"pkg:pypi/{quote(re.sub(r'[-_.]+', '-', name.lower()), safe='')}@{quote(version, safe='')}"
    if eco == "npm":
        if name.startswith("@") and "/" in name:
            scope, base = name.split("/", 1)
            return f"pkg:npm/{quote(scope, safe='')}/{quote(base, safe='')}@{quote(version, safe='')}"
        return f"pkg:npm/{quote(name, safe='')}@{quote(version, safe='')}"
    if eco == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        return f"pkg:maven/{quote(group, safe='.')}/{quote(artifact, safe='.')}@{quote(version, safe='')}"
    if eco == "go":
        return f"pkg:golang/{quote(name, safe='/.')}@{quote(version, safe='')}"
    if version:
        return f"pkg:generic/{quote(name, safe='')}@{quote(version, safe='')}"
    return None


def _advisories(pkg):
    from aibom.cbom.advisories import _pin, group_by_pin, load_advisories, match_advisories

    pin = _pin(pkg.ecosystem, pkg.name, version_spec(pkg), pkg.where, direct=False)
    if pin is None:
        return None
    grouped = group_by_pin(match_advisories([pin], load_advisories()))
    return grouped[0] if grouped else None


def version_spec(pkg) -> str:
    """The version as the advisory matcher reads an exact pin."""
    return pkg.version if pkg.ecosystem != "pypi" else f"=={pkg.version}"


def _advisory_message(pkg, row) -> str:
    named = "; ".join(f"{a.id}: {a.summary}" for a in row.advisories[:_LISTED])
    more = len(row.advisories) - _LISTED
    if more > 0:
        named += f"; and {more} more"
    advice = f" Upgrade to {row.upgrade_to} or later (fixes every listed advisory)." if row.upgrade_to else \
        " At least one advisory has no fixed release: replace the library."
    inside = f" in container image {pkg.image}" if pkg.image else ""
    return f"{pkg.name} {pkg.version} ({pkg.ecosystem}{inside}, {pkg.where}) matches {named}.{advice}"


@cbom_register
class ArtifactScanner(Scanner):
    """Images, binaries and firmware. Runs after the advisory lane (16) and before the certificate lane (20), the
    weak-crypto flagger (40) and the post-quantum grader (50)."""

    name = "crypto_artifacts"
    order = 18
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        walk = file_walk(ctx)
        if not getattr(walk, "scan_binaries", False):
            return
        report = walk.artifacts()
        today = _today()
        self._systems(ctx, report, today)
        self._packages(ctx, report, today)
        self._binaries(ctx, report, today)
        self._private_keys(ctx, report)

    # ------------------------------------------------------------------ base OS
    def _systems(self, ctx: ScanContext, report, today: date) -> None:
        from aibom.cbom.posture.dockerfile import match_release

        for record in report.systems:
            rel = record.release
            distro, version = rel.get("id", ""), rel.get("version_id", "")
            if not distro:
                continue
            ref = f"crypto-artifact-os-{_slug(record.where)}"
            if ctx.has_ref(ref):
                continue
            label = rel.get("pretty_name") or f"{distro} {version}".strip()
            props = {"crypto:role": "library", "crypto:ecosystem": "os", "crypto:packageSource": "os-release",
                     "crypto:version": version or "unknown", "discovery:source": record.where, "crypto:line": "1"}
            if record.image:
                props["crypto:image"] = record.image
            release = match_release(f"{distro}:{version}") if version else None
            past = release is not None and release.eol <= today.isoformat()
            if past:
                props["crypto:eol"] = release.eol
            ctx.add_component(FrameworkComponent(bom_ref=ref, name=f"{label} (base OS)", version=version or None,
                                                 properties=props))
            if past:
                extended = f"; paid extended support until {release.extended}" if release.extended else ""
                where = f"container image {record.image}" if record.image else record.where
                ctx.add_flag(EOL_BASE_IMAGE, ref, severity="warning",
                             message=f"{where} runs {release.distro} {release.release}, past its end of life on "
                                     f"{release.eol}{extended}: its OpenSSL and other crypto libraries no longer get "
                                     f"free security fixes. Rebuild on a supported release. {release.source}")

    # ------------------------------------------------------------------ packages
    def _packages(self, ctx: ScanContext, report, today: date) -> None:
        seen: set[tuple[str, str, str, str]] = set()
        for pkg in report.packages:
            container = pkg.where.split("!", 1)[0]
            key = (container, pkg.ecosystem, pkg.name.lower(), pkg.version)
            if key in seen:
                continue
            seen.add(key)
            ref = f"crypto-artifact-pkg-{_slug(container)}-{_slug(pkg.ecosystem)}-{_slug(pkg.name)}-{_slug(pkg.version)}"[:180]
            if ctx.has_ref(ref):
                continue
            props = {"crypto:role": "library", "crypto:version": pkg.version or "unknown",
                     "crypto:ecosystem": pkg.ecosystem, "crypto:packageSource": pkg.origin,
                     "discovery:source": pkg.where, "crypto:line": "1"}
            if pkg.image:
                props["crypto:image"] = pkg.image
            flags: list[tuple[str, str, str]] = []
            if pkg.ecosystem in _ADVISORY_ECOSYSTEMS:
                hit = _advisories(pkg)
                if hit is not None:
                    props.update({"crypto:vulnerable": "true",
                                  "crypto:advisory": ",".join(a.id for a in hit.advisories),
                                  "crypto:advisoryCount": str(len(hit.advisories))})
                    if hit.upgrade_to:
                        props["crypto:fixedVersion"] = hit.upgrade_to
                    flags.append(("VULNERABLE_CRYPTO_LIBRARY", "error", _advisory_message(pkg, hit)))
            else:
                flags.extend(self._kb_flags(props, pkg.library or _kb_package(pkg.name), pkg.version, pkg, today))
            name = f"{pkg.name}@{pkg.version}" if pkg.version else pkg.name
            ctx.add_component(FrameworkComponent(bom_ref=ref, name=name, version=pkg.version or None,
                                                 purl=_purl(pkg), properties=props))
            for code, severity, message in flags:
                ctx.add_flag(code, ref, severity=severity, message=message)

    def _kb_flags(self, props: dict, package: str, version: str, pkg, today: date) -> list[tuple[str, str, str]]:
        status = crypto_kb.library_status(package, version, today=today) if version else None
        if not status:
            return []
        out: list[tuple[str, str, str]] = []
        upstream = f"{status['library']} {status['upstream_version']}"
        props.update({"crypto:library": status["library"], "crypto:upstreamVersion": status["upstream_version"]})
        inside = f" in container image {pkg.image}" if pkg.image else ""
        cves = status["cves"]
        if cves:
            listed = ", ".join(cves[:25]) + (f" and {len(cves) - 25} more" if len(cves) > 25 else "")
            props.update({"crypto:advisory": ",".join(cves), "crypto:advisoryCount": str(len(cves))})
            out.append((LIBRARY_CVE_RANGE, "note",
                        f"{pkg.name} {version}{inside} (upstream {upstream}) is inside the published affected range "
                        f"of {len(cves)} CVE(s): {listed}. In triage until checked against the distribution's "
                        f"back-ported fixes ({pkg.where})."))
        eol = status.get("eol") or {}
        if eol.get("passed"):
            props.update({"crypto:eol": eol["date"]})
            out.append((EOL_CRYPTO_LIBRARY, "warning",
                        f"{pkg.name} {version}{inside}: upstream {status['library']} {eol['branch']} reached end of "
                        f"life on {eol['date']}, so new vulnerabilities are not fixed upstream; confirm the vendor "
                        f"still ships fixes or move to a supported release ({pkg.where})."))
        return out

    # ------------------------------------------------------------------ binaries
    def _binaries(self, ctx: ScanContext, report, today: date) -> None:
        from aibom.cbom.binscan import is_crypto_library, soname_branch

        for record in report.binaries:
            facts, where = record.facts, record.where
            base = {"discovery:source": where, "crypto:binaryFormat": facts.format, "crypto:line": "1"}
            if record.image:
                base["crypto:image"] = record.image
            for display, how in sorted(facts.algorithms.items()):
                info = algo_info(_ALGO_KEYS.get(display, "")) or {}
                ref = f"crypto-algo-{_slug(display)}-{_slug(where)}"
                if ctx.has_ref(ref):
                    continue
                props = {**base, "crypto:assetType": "algorithm", "crypto:primitive": info.get("primitive", "other"),
                         "crypto:strength": info.get("strength", "unknown"),
                         "crypto:quantumVulnerable": str(bool(info.get("quantum_vulnerable", False))).lower(),
                         "crypto:detectedBy": "binary-import" if how["how"].startswith(("imports", "uses"))
                         else "binary-constant",
                         "crypto:evidence": how["how"]}
                if how.get("mode"):
                    props["crypto:mode"] = how["mode"]
                ctx.add_component(CryptoAssetComponent(bom_ref=ref, name=display, properties=props))
            for lib in sorted({n for n in facts.needed if is_crypto_library(n)} if record.detail else ()):
                ref = f"crypto-artifact-lib-{_slug(where)}-{_slug(lib)}"
                if ctx.has_ref(ref):
                    continue
                props = {**base, "crypto:role": "library", "crypto:linkedBy": where, "crypto:version": "unknown"}
                branch = soname_branch(lib)
                flags = []
                if branch and branch[1] in _SONAME_BRANCH:
                    release = _SONAME_BRANCH[branch[1]]
                    eol_date = ((crypto_kb.load().get("libraries") or {}).get("openssl", {}).get("eol") or {}).get(release)
                    if eol_date and eol_date <= today.isoformat():
                        props.update({"crypto:library": "openssl", "crypto:eol": eol_date})
                        flags.append((EOL_CRYPTO_LIBRARY, "warning",
                                      f"{where} is linked against {lib} (OpenSSL {branch[1]}.x, whose last release "
                                      f"line {release} reached end of life upstream on {eol_date}); confirm the image "
                                      "or vendor still ships fixes, or rebuild against OpenSSL 3."))
                ctx.add_component(FrameworkComponent(bom_ref=ref, name=lib, properties=props))
                for code, severity, message in flags:
                    ctx.add_flag(code, ref, severity=severity, message=message)
            for api in sorted(facts.apis):
                ref = f"crypto-artifact-api-{_slug(where)}-{_slug(api)}"
                if not ctx.has_ref(ref):
                    ctx.add_component(FrameworkComponent(bom_ref=ref, name=api, properties={
                        **base, "crypto:role": "library", "crypto:version": "platform"}))

    # ------------------------------------------------------------------ private keys
    def _private_keys(self, ctx: ScanContext, report) -> None:
        for key in report.private_keys:
            ref = f"crypto-material-private-key-{_slug(key.where)}"
            if ctx.has_ref(ref):
                continue
            name = key.where.rsplit("!", 1)[-1].rsplit("/", 1)[-1]
            props = {"crypto:assetType": "related-crypto-material", "crypto:materialKind": "private-key",
                     "discovery:source": key.where, "crypto:line": "1", "crypto:containerFormat": key.container}
            if key.container != "encrypted":
                props["crypto:hardcoded"] = "true"  # shipped inside the artifact: every copy carries the same key
            if key.algorithm:
                props["crypto:algorithm"] = key.algorithm
            if key.key_size:
                props["crypto:keySize"] = str(key.key_size)
            if key.curve:
                props["crypto:curve"] = key.curve
            ctx.add_component(CryptoAssetComponent(bom_ref=ref, name=f"private-key ({name})", properties=props))
            if key.algorithm in ("RSA", "DSA") and key.key_size:
                info = algo_info(key.algorithm.lower()) or {}
                aref = f"crypto-algo-{_slug(key.algorithm)}-{_slug(key.where)}"
                if not ctx.has_ref(aref):
                    ctx.add_component(CryptoAssetComponent(bom_ref=aref, name=key.algorithm, properties={
                        "crypto:assetType": "algorithm", "crypto:primitive": info.get("primitive", "pke"),
                        "crypto:strength": info.get("strength", "unknown"),
                        "crypto:quantumVulnerable": str(bool(info.get("quantum_vulnerable", True))).lower(),
                        "crypto:keySize": str(key.key_size), "discovery:source": key.where, "crypto:line": "1",
                        "crypto:detectedBy": "embedded-key"}))


__all__ = ["ArtifactScanner", "EOL_CRYPTO_LIBRARY", "LIBRARY_CVE_RANGE"]

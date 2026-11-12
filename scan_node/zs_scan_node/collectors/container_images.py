"""Container images pulled from a registry (Docker Registry HTTP API v2 / OCI Distribution Specification v1.1).

For each image reference the node fetches the manifest (following an image index / manifest list to linux/amd64, or
the first Linux image), then streams each layer blob once, never writing it to disk: the compressed bytes are hashed
and checked against the descriptor's digest and size, gzip is inflated with a capped output, and the tar stream is
read only for the files an inventory needs (dpkg ``status`` and ``status.d/*``, apk ``installed``, ``rpmdb.sqlite``,
``os-release``).  Layers are applied in order with the OCI whiteouts (``.wh.<name>``, ``.wh..wh..opq``; whiteouts
hide only lower layers), and the merged package databases are parsed by :mod:`zs_scan_node.pkgdb`, the same module
the code-scan engine uses for ``docker save`` / OCI uploads.  Crypto packages become ``crypto_library`` rows with a
package URL.  Nothing outside those files is kept.

Safety:
* HTTPS only.  Every host (the registry, its token service, a blob redirect such as S3 or a CDN) is resolved and
  connected through the network gate (``netutil.resolve_checked`` + ``netutil.http_client``), so the never-scan list
  applies and DNS cannot move a connection after the check.  Redirects are followed by hand (at most 5).  A token
  service or redirect target the registry names is never a loopback address (unless the registry itself is on
  loopback), a link-local one (cloud metadata, 169.254.169.254), an unspecified one or AWS's IPv6 metadata range.
* Credentials (anonymous, or a vault reference read on the node: ``username``/``password`` or ``token``) are sent
  only to the registry's own origin: as Basic to the registry, or to a Bearer token service (``WWW-Authenticate:
  Bearer realm=...``) on the SAME origin, or to the token service of a registry in ``TOKEN_SERVICES`` (Docker Hub:
  auth.docker.io; GitLab.com: gitlab.com).  Any other token service gets an anonymous token request; the registry's
  bearer token is never sent to a redirect target on another origin.
* Caps: manifests 4 MB, 128 layers, each layer and the whole image (``max_image_mb``, default 2048) by compressed
  size before download, and each blob stops at its descriptor's size as it streams; inflated output per layer
  (200 times its size plus 64 MB, 8 GB at most, inflated 1 MB at a time); one member's tar headers (long names, pax
  records, sparse maps) 1 MB; the inventory files kept for an image 128 MB in total (64 MB per file) and 1,000 dpkg
  ``status.d`` entries.  The job's stop flag and deadline are checked as every chunk arrives.  zstd layers (no
  decompressor in the standard library) and foreign / non-distributable layers are reported as coverage, not read.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import ssl
import tarfile
import time
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator
from urllib.parse import urlencode, urljoin, urlsplit

from zs_scan_node import linux_parsers as P
from zs_scan_node import netutil, pkgdb
from zs_scan_node.collectors import ConfigError
from zs_scan_node.jobctx import JobContext
from zs_scan_node.scrub import printable

MAX_IMAGES = 50
MAX_MANIFEST = 4 * 1024 * 1024
MAX_LAYERS = 128
MAX_LAYER_BYTES = 1024 * 1024 * 1024
DEFAULT_IMAGE_MB = 2048
MAX_INFLATE_RATIO = 200
MAX_INFLATED = 8 * 1024 * 1024 * 1024  # inflated output of one layer, whatever its descriptor says
INFLATE_STEP = 1024 * 1024  # output per inflate step: one compressed chunk never becomes one large buffer
MAX_FILE = pkgdb.MAX_DB_BYTES
MAX_KEPT = 128 * 1024 * 1024  # inventory files held for one image: the merged view plus the layer being read
MAX_STATUS_D = 1000  # dpkg status.d entries (files and whiteouts) held for one image
MAX_TAR_HEADER = 1024 * 1024  # one member's long-name, long-link, pax and sparse headers; the global pax records
MAX_TAR_CHAIN = 16  # extended headers in front of one member
MAX_PATH = 4096
MAX_REDIRECTS = 5
TIMEOUT = 30.0
ACCEPT = ", ".join((
    "application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))
INDEX_TYPES = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")
FOREIGN = ("application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
           "application/vnd.oci.image.layer.nondistributable.v1.tar", "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPO = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$")
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_HOST = re.compile(r"^(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?$")
WANTED = set(pkgdb.DPKG_STATUS) | set(pkgdb.APK_INSTALLED) | set(pkgdb.RPM_SQLITE) | set(pkgdb.OS_RELEASE)
UNPARSED = set(pkgdb.RPM_UNPARSED)
# Registries whose Bearer token service is on another host (Docker token authentication): the registry's API host ->
# the token service's host (HTTPS on 443), which may receive the registry credentials.  ghcr.io, quay.io, gcr.io,
# *.pkg.dev, *.azurecr.io, public.ecr.aws, nvcr.io, registry.redhat.io, Harbor, Nexus and Artifactory answer on the
# registry's own host and need no entry.  Any other token service host gets an anonymous token request (a
# self-managed GitLab whose registry and GitLab have different host names, for example).
TOKEN_SERVICES = {
    "registry-1.docker.io": "auth.docker.io",  # Docker Hub (docker.io)
    "registry.gitlab.com": "gitlab.com",  # GitLab.com
}
_AWS_V6_METADATA = ipaddress.ip_network("fd00:ec2::/32")


class ImageError(Exception):
    def __init__(self, status: str, detail: str) -> None:
        super().__init__(detail)
        self.status, self.detail = status, detail


# ----------------------------------------------------------------------------- references
@dataclass(frozen=True)
class ImageRef:
    registry: str  # host[:port] as written (docker.io for Docker Hub)
    repository: str
    reference: str  # tag or sha256 digest

    @property
    def api_host(self) -> str:
        return "registry-1.docker.io" if self.registry == "docker.io" else self.registry

    @property
    def label(self) -> str:
        sep = "@" if self.reference.startswith("sha256:") else ":"
        return f"{self.registry}/{self.repository}{sep}{self.reference}"


def parse_ref(text: str) -> ImageRef:
    """Docker's rules: the first component is a registry when it has a dot or a port or is ``localhost``; otherwise
    the image is on Docker Hub (``docker.io``, ``library/`` for one-component names); the tag defaults to latest."""
    ref = str(text or "").strip()
    if not ref or len(ref) > 512 or any(c.isspace() for c in ref):
        raise ConfigError(f"invalid image reference {ref[:80]!r}")
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
        if not _DIGEST.match(digest):
            raise ConfigError(f"invalid image digest in {text[:80]!r} (sha256 only)")
    first, _, rest = ref.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, path = first.lower(), rest
    else:
        registry, path = "docker.io", ref
    tag = None
    if ":" in path.rsplit("/", 1)[-1]:
        path, tag = path.rsplit(":", 1)
        if not _TAG.match(tag):
            raise ConfigError(f"invalid tag in {text[:80]!r}")
    if registry == "docker.io" and "/" not in path:
        path = f"library/{path}"
    if not _REPO.match(path) or not _HOST.match(registry):
        raise ConfigError(f"invalid image reference {text[:80]!r}")
    return ImageRef(registry, path, digest or tag or "latest")


# ----------------------------------------------------------------------------- HTTP through the gate
def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    return parts.scheme, (parts.hostname or "").lower(), parts.port or (443 if parts.scheme == "https" else 80)


class Registry:
    """One image's registry session: pinned clients per origin, auth challenge handling, manual redirects."""

    def __init__(self, ctx: JobContext, ref: ImageRef, creds: dict[str, str], ca_pem: str | None) -> None:
        self.ctx, self.ref, self.creds = ctx, ref, creds
        self.base = f"https://{ref.api_host}"
        self.origin = _origin(self.base)
        self.registry_tls = _tls(ca_pem, public=False)
        self.public_tls = _tls(ca_pem, public=True)
        self.auth: str | None = None  # Authorization header for the registry origin only
        self.clients: dict[tuple[str, str, int], Any] = {}
        self.registry_ip: str | None = None  # the address the registry's own host was pinned to
        self.notes: list[str] = []

    def close(self) -> None:
        for client in self.clients.values():
            client.close()

    def _client(self, url: str):
        """A client pinned to a gate-checked address of the URL's host (one per origin).  A host the registry named
        (its token service, a redirect) must not be one of the node's own or cloud-internal addresses."""
        origin = _origin(url)
        if origin[0] != "https":
            raise ImageError("tls_unavailable", f"{origin[1]} is not HTTPS; the node does not use plain HTTP")
        if origin not in self.clients:
            try:  # the registry, its token service and every redirect: one listed address skips the whole name
                ip = netutil.resolve_checked(origin[1], self.ctx.never_scan)[0]
            except netutil.Blocked as exc:
                if origin != self.origin and exc.entry == netutil.UNSPECIFIED:
                    # the gate refuses 0.0.0.0/8 and :: whatever the list says; when the REGISTRY named that host it
                    # is the registry steering the node to itself: report it as such, not as a never-scan skip
                    self._refuse_internal(origin[1], _internal_address(exc.address or exc.what, self.registry_ip))
                raise ImageError("skipped_never_scan", str(exc)) from None
            except OSError:
                raise ImageError("unreachable", f"{origin[1]} does not resolve") from None
            if origin == self.origin:
                self.registry_ip = ip
            else:
                self._refuse_internal(origin[1], _internal_address(ip, self.registry_ip))
            verify = self.registry_tls if origin == self.origin else self.public_tls
            self.clients[origin] = netutil.http_client(f"https://{origin[1]}:{origin[2]}", ip, self.ctx.never_scan,
                                                       verify=verify, timeout=TIMEOUT)
        return self.clients[origin]

    def _refuse_internal(self, host: str, problem: str | None) -> None:
        """Refuse a host the registry named (token service, redirect) that is one of the node's own or cloud-internal
        addresses (``problem`` from _internal_address; None: nothing to refuse)."""
        if problem:
            self.ctx.log("registry pointed at an internal address; refused", registry=self.ref.registry, host=host,
                         level="warn")
            raise ImageError("error", f"the registry sent the node to {host}, {problem}; refused")

    def _send(self, method: str, url: str, headers: dict[str, str], stream: bool = False):
        """Send through the gate, following redirects by hand; Authorization goes to the registry origin only."""
        import httpx

        for _ in range(MAX_REDIRECTS + 1):
            client = self._client(url)
            parts = urlsplit(url)
            path = parts.path + (f"?{parts.query}" if parts.query else "")
            # identity: digests are over the stored bytes, and blobs are compressed already
            hdrs = {"Accept-Encoding": "identity", **headers}
            if _origin(url) == self.origin and self.auth:
                hdrs["Authorization"] = self.auth
            try:
                request = client.build_request(method, path, headers=hdrs)
                response = client.send(request, stream=stream)
            except netutil.Blocked as exc:  # the address was listed while the pull ran
                raise ImageError("skipped_never_scan", str(exc)) from None
            except httpx.HTTPError as exc:
                raise ImageError(_http_status(exc), f"{parts.hostname}: {exc.__class__.__name__}") from None
            except ssl.SSLError as exc:
                raise ImageError("tls_unavailable", f"{parts.hostname}: TLS failed ({exc.__class__.__name__})") from None
            if response.status_code in (301, 302, 303, 307, 308) and response.headers.get("location"):
                response.close()
                url = urljoin(url, response.headers["location"])
                continue
            return response
        raise ImageError("error", "too many redirects")

    def get(self, path: str, accept: str | None = None, stream: bool = False):
        headers = {"Accept": accept} if accept else {}
        response = self._send("GET", self.base + path, headers, stream)
        if response.status_code == 401 and self.auth is None:
            challenge = response.headers.get("www-authenticate", "")
            response.close()
            self._authenticate(challenge)
            response = self._send("GET", self.base + path, headers, stream)
        if response.status_code in (401, 403):
            response.close()
            raise ImageError("auth_failed", f"the registry refused access ({response.status_code})"
                             + (f"; {self.notes[-1]}" if self.notes else ""))
        return response

    def _authenticate(self, challenge: str) -> None:
        scheme, params = _challenge(challenge)
        user, password = self.creds.get("username", ""), self.creds.get("password") or self.creds.get("token", "")
        basic = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode() if password else None
        if scheme == "basic":
            if not basic:
                raise ImageError("auth_failed", "the registry needs credentials and none are configured")
            self.auth = basic
            return
        if scheme != "bearer" or not params.get("realm"):
            raise ImageError("auth_failed", "the registry answered 401 without a usable challenge")
        realm = params["realm"]
        if _origin(realm)[0] != "https":
            raise ImageError("auth_failed", "the registry's token service is not HTTPS")
        query = {"service": params.get("service", ""), "scope": f"repository:{self.ref.repository}:pull"}
        query = {k: v for k, v in query.items() if v}
        realm_origin = _origin(realm)
        trusted = realm_origin == self.origin or realm_origin == ("https", TOKEN_SERVICES.get(self.ref.api_host, ""), 443)
        headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
        if basic and trusted:
            headers["Authorization"] = basic
        elif basic:
            # RFC 6750 / Docker token auth: the realm is whatever the registry says; credentials go to the
            # registry's own origin or its known token service only, so a registry (or a man in the middle) cannot
            # send them elsewhere
            self.notes.append(f"token service {_origin(realm)[1]} is on another host: credentials were not sent "
                              "to it (anonymous token requested)")
            self.ctx.log("registry token service on another host; credentials not sent", registry=self.ref.registry,
                         realm_host=_origin(realm)[1], level="warn")
        url = realm + ("&" if "?" in realm else "?") + urlencode(query)
        client = self._client(url)
        parts = urlsplit(url)
        try:
            r = client.get(parts.path + "?" + parts.query, headers=headers)
        except netutil.Blocked as exc:
            raise ImageError("skipped_never_scan", str(exc)) from None
        except Exception as exc:  # httpx.HTTPError, ssl errors
            raise ImageError("unreachable", f"token service: {exc.__class__.__name__}") from None
        if r.status_code != 200:
            raise ImageError("auth_failed", f"the token service refused the request ({r.status_code})")
        try:
            body = r.json()
        except ValueError:
            raise ImageError("auth_failed", "the token service did not answer JSON") from None
        token = body.get("token") or body.get("access_token")
        if not isinstance(token, str) or not token or len(token) > 16384:
            raise ImageError("auth_failed", "the token service answered no token")
        self.ctx.scrubber.add(token)
        self.auth = f"Bearer {token}"


def _tls(ca_pem: str | None, public: bool = True) -> ssl.SSLContext:
    """The registry's own origin trusts only ``ca_pem`` when one is configured; token services and blob redirects
    (a CDN, S3, or the same company's object store) trust the public CAs plus ``ca_pem``."""
    import httpx

    if ca_pem and not public:
        context = ssl.create_default_context(cadata=ca_pem)  # only the registry's private CA
    else:
        context = httpx.create_ssl_context()  # the public CAs httpx trusts (certifi)
        if ca_pem:
            context.load_verify_locations(cadata=ca_pem)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _internal_address(ip: str, registry_ip: str | None) -> str | None:
    """Why the node must not connect to ``ip`` for a host a registry named (its token service or a redirect), or None:
    link-local (cloud metadata at 169.254.169.254, fe80::/10), unspecified, multicast and AWS's IPv6 metadata range
    always; loopback unless the registry itself is on loopback (the node's own host, by the operator's choice)."""
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr.is_link_local or addr.is_unspecified or addr.is_multicast or addr in _AWS_V6_METADATA:
        return f"a link-local or metadata address ({ip})"
    if addr.is_loopback:
        own = ipaddress.ip_address(registry_ip) if registry_ip else None
        if isinstance(own, ipaddress.IPv6Address) and own.ipv4_mapped is not None:
            own = own.ipv4_mapped
        if own is None or not own.is_loopback:
            return f"a loopback address ({ip})"
    return None


def _http_status(exc: Exception) -> str:
    name = exc.__class__.__name__
    text = str(exc)
    if "CERTIFICATE_VERIFY_FAILED" in text or "SSL" in text or "TLS" in text:
        return "tls_unavailable"  # httpx reports TLS failures as ConnectError
    if "Timeout" in name:
        return "timeout"
    if "Connect" in name:
        return "unreachable"
    return "error"


def _challenge(header: str) -> tuple[str, dict[str, str]]:
    """``Bearer realm="https://auth.example/token",service="registry",scope="..."`` -> ("bearer", {...})."""
    scheme, _, rest = header.strip().partition(" ")
    params = {k.lower(): v for k, v in re.findall(r'(\w+)="([^"]*)"', rest)}
    return scheme.lower(), params


# ----------------------------------------------------------------------------- manifests
def _json(response, what: str) -> tuple[dict[str, Any], bytes]:
    data = b""
    for chunk in response.iter_raw(65536):
        data += chunk
        if len(data) > MAX_MANIFEST:
            response.close()
            raise ImageError("error", f"{what} larger than {MAX_MANIFEST // 1024 // 1024} MB")
    response.close()
    try:
        doc = json.loads(data)
    except ValueError:
        raise ImageError("error", f"{what} is not JSON") from None
    if not isinstance(doc, dict):
        raise ImageError("error", f"{what} is not a JSON object")
    return doc, data


def fetch_manifest(reg: Registry) -> tuple[dict[str, Any], str]:
    """The image manifest (an index is followed to linux/amd64) and its digest."""
    reference = reg.ref.reference
    for _depth in range(3):
        response = reg.get(f"/v2/{reg.ref.repository}/manifests/{reference}", accept=ACCEPT, stream=True)
        if response.status_code == 404:
            response.close()
            raise ImageError("error", "image not found in the registry")
        if response.status_code != 200:
            response.close()
            raise ImageError("error", f"manifest request answered {response.status_code}")
        media = (response.headers.get("content-type") or "").split(";", 1)[0].strip()
        doc, raw = _json(response, "manifest")
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if reference.startswith("sha256:") and digest != reference:
            raise ImageError("error", "the manifest does not match its digest")
        media = doc.get("mediaType") or media
        if media in INDEX_TYPES or "manifests" in doc:
            chosen = _platform(doc.get("manifests") or [])
            if chosen is None:
                raise ImageError("not_supported", "the image index lists no Linux image")
            reference = chosen
            continue
        if doc.get("schemaVersion") != 2 or not isinstance(doc.get("layers"), list):
            raise ImageError("not_supported", "only schema 2 / OCI image manifests are read")
        return doc, digest
    raise ImageError("error", "image index nesting too deep")


def _platform(manifests: list[Any]) -> str | None:
    linux = [m for m in manifests if isinstance(m, dict) and _DIGEST.match(str(m.get("digest") or ""))
             and (m.get("platform") or {}).get("os", "linux") == "linux"]
    for m in linux:
        if (m.get("platform") or {}).get("architecture") == "amd64":
            return m["digest"]
    return linux[0]["digest"] if linux else None


# ----------------------------------------------------------------------------- layers
class _Inflate:
    """A file-like over a blob response: hashes the compressed bytes and refuses any byte past the descriptor's size as
    it arrives, inflates gzip at most ``INFLATE_STEP`` bytes at a time with a capped total output, and checks the
    job's stop flag (cancel, deadline) before every chunk."""

    def __init__(self, response, size: int, limit: int, stop: Callable[[], str | None] | None = None) -> None:
        self.chunks: Iterator[bytes] = response.iter_raw(65536)
        self.size, self.limit, self.stop = size, limit, stop
        self.hash = hashlib.sha256()
        self.raw_bytes = 0
        self.out_bytes = 0
        self.inflater = None
        self.sniffed = False
        self.pending = b""  # compressed bytes not inflated yet
        self.buffer = bytearray()
        self.done = False

    def _raw(self) -> bytes | None:
        """The next compressed chunk (None at the end of the blob), hashed and counted against the descriptor."""
        if self.stop is not None:
            reason = self.stop()
            if reason:
                raise ImageError(reason, "the job stopped while a layer was being read")
        for chunk in self.chunks:
            if not chunk:
                continue
            self.hash.update(chunk)
            self.raw_bytes += len(chunk)
            if self.raw_bytes > self.size:
                raise ImageError("error", "a layer is larger than its descriptor says; the image was not read")
            return chunk
        return None

    def _out(self, data: bytes) -> None:
        self.out_bytes += len(data)
        if self.out_bytes > self.limit:
            raise ImageError("error", "layer inflates past the size cap (refused as a compression bomb)")
        self.buffer += data

    def _pull(self) -> None:
        if not self.pending:
            chunk = self._raw()
            if chunk is None:
                self.done = True
                return
            if not self.sniffed:
                # the compression is read from the bytes, not trusted from the media type
                while len(chunk) < 4 and (more := self._raw()) is not None:
                    chunk += more
                self.sniffed = True
                if chunk[:4] == b"\x28\xb5\x2f\xfd":
                    raise ImageError("not_supported", "a layer is zstd-compressed (not read: no decompressor in the "
                                                      "standard library)")
                if chunk[:2] == b"\x1f\x8b":
                    self.inflater = zlib.decompressobj(31)
            if self.inflater is None:
                self._out(chunk)
                return
            self.pending = chunk
        if self.inflater.eof:
            if not self.pending.strip(b"\x00"):
                self.pending = b""  # zero padding after the last gzip member
                return
            self.inflater = zlib.decompressobj(31)  # concatenated gzip members
        try:
            data = self.inflater.decompress(self.pending, INFLATE_STEP)
        except zlib.error:
            raise ImageError("error", "a layer is not valid gzip") from None
        self.pending = self.inflater.unused_data if self.inflater.eof else self.inflater.unconsumed_tail
        self._out(data)

    def read(self, n: int = -1) -> bytes:
        while (n < 0 or len(self.buffer) < n) and not self.done:
            self._pull()
        if n < 0:
            n = len(self.buffer)
        out = bytes(self.buffer[:n])
        del self.buffer[:n]
        return out

    def drain(self) -> None:
        """Hash the rest of the blob (tar padding after the end-of-archive blocks); nothing more is inflated."""
        self.buffer.clear()
        self.pending = b""
        while self._raw() is not None:
            pass
        self.done = True


def _norm(name: str) -> str | None:
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts) or "\x00" in name:
        return None
    return "/".join(parts)


def _wanted(path: str) -> bool:
    return path in WANTED or (path.startswith(pkgdb.DPKG_STATUS_DIR) and "/" not in path[len(pkgdb.DPKG_STATUS_DIR):])


_LOCATIONS = (*sorted(WANTED), pkgdb.DPKG_STATUS_DIR)


def _hides_wanted(path: str) -> bool:
    """Can a whiteout of ``path`` (or an opaque marker in it) hide something the merged view keeps?  The merged view
    holds only wanted paths, so only those paths and their parent directories matter."""
    return path == "" or _wanted(path) or any(loc.startswith(path + "/") for loc in _LOCATIONS)


class _HeaderBudget:
    """The stream as tarfile sees it while it reads one member's extended headers (GNU long names and links, pax
    records, GNU sparse maps): at most ``MAX_TAR_HEADER`` bytes and ``MAX_TAR_CHAIN`` headers, refused before they
    are read."""

    def __init__(self, stream) -> None:
        self.stream, self.left, self.chain = stream, MAX_TAR_HEADER, 1

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0 or n > self.left:
            raise ImageError("error", f"a layer has tar headers over {MAX_TAR_HEADER // 1048576} MB for one member "
                                      "(refused)")
        self.left -= n
        return self.stream.read(n)

    def __getattr__(self, name: str):
        return getattr(self.stream, name)


_EXTENDED = (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK, tarfile.GNUTYPE_SPARSE, tarfile.XHDTYPE,
             tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE)


class _TarInfo(tarfile.TarInfo):
    """tarfile reads a member's extended headers into memory before the caller sees the member (a long-name header
    may claim gigabytes): read them through a ``_HeaderBudget``.  ``_proc_member`` is the hook tarfile documents for
    subclasses."""

    def _proc_member(self, tar):
        if self.type not in _EXTENDED:
            return super()._proc_member(tar)
        if isinstance(tar.fileobj, _HeaderBudget):  # a header chained to an extended header: the same budget
            tar.fileobj.chain += 1
            if tar.fileobj.chain > MAX_TAR_CHAIN:
                raise ImageError("error", f"a layer chains more than {MAX_TAR_CHAIN} tar headers (refused)")
            member = super()._proc_member(tar)
        else:
            stream = tar.fileobj
            tar.fileobj = _HeaderBudget(stream)
            try:
                member = super()._proc_member(tar)
            finally:
                tar.fileobj = stream
        if self.type == tarfile.XGLTYPE and sum(len(k) + len(v) for k, v in tar.pax_headers.items()) > MAX_TAR_HEADER:
            raise ImageError("error", f"a layer's global pax headers exceed {MAX_TAR_HEADER // 1048576} MB (refused)")
        return member


@dataclass
class LayerDiff:
    files: dict[str, bytes | None] = field(default_factory=dict)  # None: something that is not a regular file
    whiteouts: list[str] = field(default_factory=list)  # only those that can hide a wanted path
    opaque: list[str] = field(default_factory=list)  # likewise
    notes: dict[str, int] = field(default_factory=dict)  # coverage key -> tar members


@dataclass
class Budget:
    """What the inventory files of one image may still hold (the merged view plus the layer being read)."""
    bytes: int = MAX_KEPT
    status_d: int = MAX_STATUS_D

    @classmethod
    def left(cls, merged: dict[str, bytes | None]) -> "Budget":
        return cls(MAX_KEPT - sum(len(v) for v in merged.values() if v),
                   MAX_STATUS_D - sum(1 for p in merged if p.startswith(pkgdb.DPKG_STATUS_DIR)))


def read_layer(fileobj, budget: Budget | None = None) -> LayerDiff:
    """The inventory files, whiteouts and opaque directories of one layer tar stream (nothing is extracted).  Memory
    stays bounded whatever the layer holds: extended headers are capped (``_TarInfo``), tarfile's list of members is
    emptied as the stream advances, only whiteouts that can hide a wanted path are kept, and the files kept count
    against ``budget``."""
    budget = budget if budget is not None else Budget()
    diff = LayerDiff()

    def note(key: str) -> None:
        diff.notes[key] = diff.notes.get(key, 0) + 1

    def status_d(path: str) -> None:
        if path.startswith(pkgdb.DPKG_STATUS_DIR):
            budget.status_d -= 1
            if budget.status_d < 0:
                raise ImageError("not_supported", f"the image has more than {MAX_STATUS_D} dpkg status.d entries "
                                                  "(not read)")

    try:
        with tarfile.open(fileobj=fileobj, mode="r|", tarinfo=_TarInfo) as tar:
            while (member := tar.next()) is not None:
                tar.members.clear()  # in stream mode tarfile keeps every member it has seen (~400 bytes each)
                if len(member.name) > MAX_PATH:
                    note("pathTooLong")
                    continue
                path = _norm(member.name)
                if path is None:
                    note("pathTraversal")
                    continue
                directory, _, base = path.rpartition("/")
                if base == ".wh..wh..opq":
                    if _hides_wanted(directory) and directory not in diff.opaque:
                        diff.opaque.append(directory)
                    continue
                if base.startswith(".wh."):
                    target = f"{directory}/{base[4:]}" if directory else base[4:]
                    if _hides_wanted(target) and target not in diff.whiteouts:
                        status_d(target)
                        diff.whiteouts.append(target)
                    continue
                if path in UNPARSED:
                    note("rpmBerkeleyDbNotParsed")
                if not _wanted(path):
                    continue
                if path not in diff.files:
                    status_d(path)
                budget.bytes += len(diff.files.pop(path, None) or b"")  # a later member of the same path wins
                if not member.isreg():
                    diff.files[path] = None
                    continue
                if member.size > MAX_FILE:
                    note("databaseTooLarge")
                    diff.files[path] = None
                    continue
                if member.size > budget.bytes:
                    raise ImageError("not_supported", f"the image's package databases exceed {MAX_KEPT // 1048576} "
                                                      "MB in total (not read)")
                handle = tar.extractfile(member)
                # exactly the member's size: read(n) allocates n bytes up front
                data = handle.read(member.size) if handle is not None else None
                budget.bytes -= len(data or b"")
                diff.files[path] = data
    except tarfile.TarError:
        raise ImageError("error", "a layer is not a readable tar archive") from None
    return diff


def apply_layer(merged: dict[str, bytes | None], diff: LayerDiff) -> None:
    """OCI image-spec "Applying Changesets": a layer's whiteouts hide lower-layer paths only, then its files win."""
    for directory in diff.opaque:
        prefix = f"{directory}/" if directory else ""
        for path in [p for p in merged if p.startswith(prefix)]:
            del merged[path]
    for target in diff.whiteouts:
        for path in [p for p in merged if p == target or p.startswith(target + "/")]:
            del merged[path]
    merged.update(diff.files)


def inventory(merged: dict[str, bytes | None]) -> tuple[str | None, list[dict[str, str]], dict[str, str], list[str]]:
    """(package manager, packages, os-release, notes) of a merged image view."""
    notes: list[str] = []
    release = merged.get("etc/os-release") or merged.get("usr/lib/os-release")
    os_info = pkgdb.os_release(release.decode("utf-8", "replace")) if release else {}
    status = merged.get(pkgdb.DPKG_STATUS[0])
    parts = [v for k, v in sorted(merged.items()) if k.startswith(pkgdb.DPKG_STATUS_DIR) and v]
    if status or parts:
        rows = pkgdb.dpkg_status(status.decode("utf-8", "replace")) if status else []
        for part in parts:
            rows += pkgdb.dpkg_status(part.decode("utf-8", "replace"))
        return "deb", rows, os_info, notes
    apk = merged.get(pkgdb.APK_INSTALLED[0])
    if apk:
        return "apk", pkgdb.apk_installed(apk.decode("utf-8", "replace")), os_info, notes
    for path in pkgdb.RPM_SQLITE:
        if merged.get(path):
            try:
                return "rpm", pkgdb.rpm_sqlite(merged[path] or b""), os_info, notes
            except ValueError:
                notes.append("the rpm database could not be read")
                return "rpm", [], os_info, notes
    return None, [], os_info, notes


def pull(reg: Registry, max_image_bytes: int) -> tuple[str, dict[str, bytes | None], dict[str, int]]:
    """(manifest digest, merged inventory files, coverage counts) of one image."""
    manifest, digest = fetch_manifest(reg)
    layers = [d for d in manifest["layers"] if isinstance(d, dict)]
    if len(layers) > MAX_LAYERS:
        raise ImageError("not_supported", f"the image has {len(layers)} layers (cap {MAX_LAYERS})")
    for desc in layers:  # every descriptor is checked before any is used (a negative size must not lower the total)
        size = desc.get("size")
        if (not _DIGEST.match(str(desc.get("digest") or "")) or isinstance(size, bool) or not isinstance(size, int)
                or not 0 <= size <= MAX_LAYER_BYTES):
            raise ImageError("not_supported", "a layer descriptor has an unsupported digest or size")
    total = sum(d["size"] for d in layers)
    if total > max_image_bytes:
        raise ImageError("not_supported", f"the image is {total // 1048576} MB compressed (cap "
                                          f"{max_image_bytes // 1048576} MB); raise max_image_mb to read it")
    merged: dict[str, bytes | None] = {}
    coverage: dict[str, int] = {}
    for desc in layers:
        media, ldigest, size = str(desc.get("mediaType") or ""), str(desc["digest"]), int(desc["size"])
        if media in FOREIGN or desc.get("urls"):
            coverage["foreignLayersNotRead"] = coverage.get("foreignLayersNotRead", 0) + 1
            continue
        if "zstd" in media:
            coverage["zstdLayersNotRead"] = coverage.get("zstdLayersNotRead", 0) + 1
            continue
        stop = reg.ctx.should_stop()
        if stop:
            raise ImageError(stop, "the job stopped before every layer was read")
        response = reg.get(f"/v2/{reg.ref.repository}/blobs/{ldigest}", stream=True)
        if response.status_code != 200:
            response.close()
            raise ImageError("error", f"layer download answered {response.status_code}")
        try:
            limit = min(max(size, 1) * MAX_INFLATE_RATIO + 64 * 1024 * 1024, MAX_INFLATED)
            stream = _Inflate(response, size, limit, stop=reg.ctx.should_stop)
            diff = read_layer(stream, Budget.left(merged))
            stream.drain()
        finally:
            response.close()
        if stream.raw_bytes != size or "sha256:" + stream.hash.hexdigest() != ldigest:
            raise ImageError("error", "a layer does not match its digest; the image was not read")
        for note, count in diff.notes.items():
            coverage[note] = coverage.get(note, 0) + count
        apply_layer(merged, diff)
    return digest, merged, coverage


# ----------------------------------------------------------------------------- entry points
def _creds(ctx: JobContext, config: dict, secrets: dict) -> dict[str, str]:
    ctype = config.get("credential_type") or "anonymous"
    if ctype == "anonymous":
        return {}
    if ctype == "vault":
        from zs_scan_node import vault

        ref = config.get("vault") or {}
        creds = vault.fetch(str(ref.get("provider")), str(ref.get("path") or ""), ctx.vault_prefix)
        for value in creds.values():
            ctx.scrubber.add(value)
        if not (creds.get("password") or creds.get("token")):
            raise ConfigError("the vault secret has neither 'password' nor 'token'")
        return {k: v for k, v in creds.items() if k in ("username", "password", "token")}
    raise ConfigError(f"credential type {ctype} is not supported for registries (anonymous or vault)")


def _images(config: dict) -> list[ImageRef]:
    raw = config.get("images") or []
    if not isinstance(raw, list) or not raw:
        raise ConfigError("no images are configured")
    return [parse_ref(r) for r in raw[:MAX_IMAGES]]


def collect(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    images = _images(config)
    creds = _creds(ctx, config, secrets)
    max_bytes = max(1, min(int(config.get("max_image_mb") or DEFAULT_IMAGE_MB), 8192)) * 1024 * 1024
    for ref in images:
        started = time.monotonic()
        stop = ctx.should_stop()
        if stop:
            ctx.outcome(ref.label, stop, started=started)
            continue
        reg = Registry(ctx, ref, creds, config.get("ca_pem"))
        try:
            digest, merged, coverage = pull(reg, max_bytes)
            n = _emit(ctx, ref, digest, merged, coverage)
            ctx.outcome(ref.label, "ok", started=started, assets=n)
            ctx.log("image read", image=ref.label, digest=digest, assets=n)
        except ImageError as exc:
            ctx.outcome(ref.label, exc.status, exc.detail, started=started)
            ctx.log("image not read", image=ref.label, status=exc.status, detail=exc.detail)
        except Exception as exc:  # never let one image end the job
            ctx.outcome(ref.label, "error", exc.__class__.__name__, started=started)
            ctx.log("image error", image=ref.label, error=exc.__class__.__name__)
        finally:
            reg.close()
    return None


def _emit(ctx: JobContext, ref: ImageRef, digest: str, merged: dict[str, bytes | None], coverage: dict[str, int]) -> int:
    manager, packages, os_info, notes = inventory(merged)
    distro = {"id": os_info.get("id", ""), "version_id": os_info.get("version_id", "")} if os_info.get("id") else None
    n = 0
    for pkg in packages:
        if not P.CRYPTO_PACKAGES.match(pkg["name"]):
            continue
        name, version = printable(pkg["name"], 100), printable(pkg["version"], 100)
        ctx.emit("crypto_library", ref.label, f"package:{name}", name=name,
                 facts={"name": name, "version": version, "arch": pkg.get("arch", ""), "source": "container_image",
                        "package_manager": manager, "image": ref.label, "image_digest": digest,
                        "os": {k: printable(v, 120) for k, v in os_info.items() if k in ("id", "version_id", "pretty_name")},
                        "purl": pkgdb.purl(manager or "", name, version, distro, pkg.get("arch", ""))})
        n += 1
    if manager is None:
        ctx.coverage(ref.label, "package list", "not_supported",
                     "no dpkg, apk or rpm (sqlite) package database in the image (distroless or scratch?)")
    for note in notes:
        ctx.coverage(ref.label, "package list", "error", note)
    labels = {"zstdLayersNotRead": "zstd-compressed layers are not read",
              "foreignLayersNotRead": "foreign (non-distributable) layers are not downloaded",
              "rpmBerkeleyDbNotParsed": "the rpm database is in the Berkeley DB format, which is not parsed",
              "databaseTooLarge": "a package database is larger than 64 MB", "pathTraversal": "tar members with '..' skipped",
              "pathTooLong": f"tar members with names over {MAX_PATH} characters skipped"}
    for key, count in sorted(coverage.items()):
        ctx.coverage(ref.label, "image layers", "not_supported", f"{labels.get(key, key)} ({count})")
    return n


def test(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    try:
        images = _images(config)
        creds = _creds(ctx, config, secrets)
    except ConfigError as exc:
        ctx.samples.append({"target": "images", "status": "error", "reachable": None, "login": False,
                            "privilege": None, "note": str(exc)})
        return str(exc)
    for ref in images[:5]:
        sample = {"target": ref.label, "status": "ready", "reachable": True, "login": True, "privilege": None, "note": ""}
        reg = Registry(ctx, ref, creds, config.get("ca_pem"))
        try:
            manifest, digest = fetch_manifest(reg)
            sample["note"] = f"{len(manifest.get('layers') or [])} layers, {digest[:19]}"
        except ImageError as exc:
            sample.update(status=exc.status, note=exc.detail,
                          reachable=exc.status not in ("unreachable", "timeout", "skipped_never_scan"),
                          login=exc.status not in ("auth_failed", "unreachable", "timeout"))
        except Exception as exc:
            sample.update(status="error", note=exc.__class__.__name__)
        finally:
            reg.close()
        ctx.samples.append(sample)
    return None

#!/usr/bin/env python3
"""CI-built images for the Chola production kit (deploy/chola-prod/README.md, "Images from a CI run").

Standard library only, Python 3.8+. One contract, used on both sides:

* .github/workflows/chola-prod-images.yml (its own commit's copy of this file) writes the run's manifest and checks
  every image layout before it uploads it;
* scripts/deploy/chola-prod.sh (images | infra | deploy --from-run RUN) reads the manifest, extracts each downloaded
  artifact while it streams in (no zip file on disk) and checks each image layout before it pushes it to ECR.

  artifacts.py unzip-stream --dest D (--oci | --file NAME)  < artifact zip
      Extract a GitHub artifact zip read from stdin, without a seekable file (local headers; deflate, or stored with
      known sizes; data descriptors; zip64). --oci: only an OCI image layout's names (oci-layout, index.json,
      blobs/sha256/<64 hex> and their directories); --file NAME: exactly that one file. Any other name (a path
      outside D included) is refused before a byte of it is written; every entry's CRC-32 and size are checked.
  artifacts.py oci-check --layout D [--digest sha256:X] [--revision SHA] [--label K=V ...] [--normalize]
      The layout holds exactly ONE linux/amd64 image: index.json names one manifest (--normalize: one nested index is
      resolved to its single linux/amd64 manifest and index.json rewritten; buildx output); every blob the manifest
      names is present with its size and sha256; the config says linux/amd64; the org.opencontainers.image.revision
      label is --revision; each --label K=V is set; --digest is the manifest's digest. Prints "<digest> <bytes>".
  artifacts.py manifest-init --out F --commit SHA --api-url URL [--repository R] [--run-id N] [--run-attempt N]
                             [--ref REF]
  artifacts.py manifest-add-image --manifest F --component C --artifact A --source S --layout D [--index-digest D]
      oci-check (revision = the manifest's commit; the frontend also its api-url label), then records the image.
  artifacts.py manifest-set-infra --manifest F --artifact A --file PATH --image REF@sha256:X [...]
  artifacts.py manifest-check --manifest F [--sha SHA] [--api-url URL] [--component C ...] [--infra REF@sha256:X ...]
      Refuses a manifest of another schema, commit or API URL, one whose infrastructure pins are not --infra, an image
      whose revision is not --sha or whose digest is no sha256. Prints "image <component> <artifact> <digest>
      <bytes>" per --component and "infra <artifact> <file> <sha256> <bytes>" when --infra is given.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
import zlib

SCHEMA = "devsecshield-chola-images/1"
COMPONENTS = ("backend", "frontend", "scan-worker", "dast-worker")
PLATFORM = ("linux", "amd64")
REVISION_LABEL = "org.opencontainers.image.revision"
API_URL_LABEL = "com.zeroshield.devsecshield.api-url"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
OCI_NAMES = re.compile(r"^(oci-layout|index\.json|blobs/sha256/[0-9a-f]{64})$")
OCI_DIRS = ("blobs/", "blobs/sha256/")
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
INFRA_REF = re.compile(r"^[a-z0-9][a-z0-9./_-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$")
MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json")
INDEX_TYPES = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")
CHUNK = 1 << 20

SIG_LOCAL = b"PK\x03\x04"
SIG_DESCRIPTOR = b"PK\x07\x08"
SIG_ENDS = (b"PK\x01\x02", b"PK\x05\x06", b"PK\x06\x06", b"PK\x06\x07")  # central directory, zip64 end records


class Refused(Exception):
    pass


# ------------------------------------------------------------------------------------------------ streaming unzip
class _Reader:
    """Exact reads from a non-seekable stream; bytes read past an entry's end are pushed back."""

    def __init__(self, stream):
        self.stream = stream
        self.buf = b""

    def peek(self, n):
        while len(self.buf) < n:
            chunk = self.stream.read(CHUNK)
            if not chunk:
                break
            self.buf += chunk
        return self.buf[:n]

    def read(self, n):
        data = self.peek(n)
        self.buf = self.buf[len(data):]
        return data

    def exact(self, n, what):
        data = self.read(n)
        if len(data) != n:
            raise Refused(f"the artifact zip ends inside {what} (download cut short?)")
        return data

    def some(self):
        if self.buf:
            data, self.buf = self.buf, b""
            return data
        return self.stream.read(CHUNK)

    def unread(self, data):
        self.buf = data + self.buf


def _allowed(name, oci, file_name):
    if oci:
        return bool(OCI_NAMES.match(name)) or name in OCI_DIRS
    return name == file_name


def _zip64_sizes(extra):
    """(uncompressed, compressed) from a local header's zip64 extra field, or None."""
    i = 0
    while i + 4 <= len(extra):
        tag, size = struct.unpack("<HH", extra[i:i + 4])
        if tag == 1 and size >= 16:
            return struct.unpack("<QQ", extra[i + 4:i + 20])
        i += 4 + size
    return None


def _skip_descriptor(r, crc, usize, csize):
    """Consume a data descriptor (optional signature, CRC, 4- or 8-byte sizes) and check it against what was read."""
    if r.peek(4) == SIG_DESCRIPTOR:
        r.read(4)
    head = r.peek(4 + 16 + 4)
    if len(head) < 12:
        raise Refused("the artifact zip ends inside a data descriptor (download cut short?)")
    got_crc = struct.unpack("<I", head[:4])[0]
    for width, fmt in ((4, "<II"), (8, "<QQ")):
        if len(head) < 4 + 2 * width:
            continue
        c, u = struct.unpack(fmt, head[4:4 + 2 * width])
        after = head[4 + 2 * width:4 + 2 * width + 4]
        if (u == usize % (1 << (8 * width)) and c == csize % (1 << (8 * width))
                and (after in (SIG_LOCAL,) + SIG_ENDS or after == b"")):
            r.read(4 + 2 * width)
            if got_crc != crc:
                raise Refused("CRC-32 mismatch in the artifact zip (damaged download)")
            return
    raise Refused("unreadable data descriptor in the artifact zip")


def unzip_stream(stream, dest, oci=False, file_name=None):
    """Extract the zip read from `stream` into `dest`; returns {name: bytes}. See the module docstring."""
    if oci == bool(file_name):
        raise Refused("give exactly one of --oci or --file")
    if file_name and not SAFE_NAME.match(file_name):
        raise Refused(f"not a plain file name: {file_name!r}")
    os.makedirs(dest, exist_ok=True)
    r = _Reader(stream)
    seen = {}
    while True:
        sig = r.peek(4)
        if sig in SIG_ENDS or (sig == b"" and seen):
            break
        if sig != SIG_LOCAL:
            raise Refused("not a zip file (or an unexpected record in it)" if not seen else
                          "unexpected record in the artifact zip (damaged download?)")
        head = r.exact(30, "a local file header")
        _, _ver, flags, method, _t, _d, crc, csize, usize, nlen, xlen = struct.unpack("<IHHHHHIIIHH", head)
        raw = r.exact(nlen, "a file name")
        extra = r.exact(xlen, "a header extra field")
        name = raw.decode("utf-8" if flags & 0x800 else "cp437")
        if flags & 0x1:
            raise Refused(f"{name}: encrypted entries are not accepted")
        if not _allowed(name, oci, file_name):
            raise Refused(f"unexpected entry {name!r} in the artifact (expected "
                          f"{'an OCI image layout' if oci else file_name}); nothing of it was written")
        if name in seen:
            raise Refused(f"{name} appears twice in the artifact")
        z64 = _zip64_sizes(extra)
        if z64 and (usize == 0xFFFFFFFF or csize == 0xFFFFFFFF):
            usize, csize = z64
        descriptor = bool(flags & 0x8)
        if method not in (0, 8):
            raise Refused(f"{name}: compression method {method} is not supported")
        if method == 0 and descriptor:
            raise Refused(f"{name}: a stored entry without its size cannot be streamed")
        is_dir = name.endswith("/")
        out = None
        tmp = None
        if not is_dir:
            fd, tmp = tempfile.mkstemp(prefix=".part-", dir=dest)
            out = os.fdopen(fd, "wb")
        got_crc, got_u, got_c = 0, 0, 0
        try:
            if method == 0:
                left = csize
                while left:
                    data = r.read(min(left, CHUNK))
                    if not data:
                        raise Refused(f"the artifact zip ends inside {name} (download cut short?)")
                    left -= len(data)
                    got_c += len(data)
                    got_u += len(data)
                    got_crc = zlib.crc32(data, got_crc)
                    if out:
                        out.write(data)
            else:
                inflater = zlib.decompressobj(-15)
                while not inflater.eof:
                    data = r.some()
                    if not data:
                        raise Refused(f"the artifact zip ends inside {name} (download cut short?)")
                    plain = inflater.decompress(data)
                    used = len(data) - len(inflater.unused_data)
                    got_c += used
                    if inflater.unused_data:
                        r.unread(inflater.unused_data)
                    if plain:
                        got_u += len(plain)
                        got_crc = zlib.crc32(plain, got_crc)
                        if out:
                            out.write(plain)
            if out:
                out.close()
                out = None
            if descriptor:
                _skip_descriptor(r, got_crc, got_u, got_c)
            else:
                if got_crc != crc or got_u != usize:
                    raise Refused(f"{name}: CRC-32 or size mismatch in the artifact zip (damaged download)")
            if is_dir:
                if got_u:
                    raise Refused(f"{name}: a directory entry with content")
                os.makedirs(os.path.join(dest, name), exist_ok=True)
            else:
                target = os.path.join(dest, name)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                os.replace(tmp, target)
                tmp = None
        finally:
            if out:
                out.close()
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)
        seen[name] = got_u
    if not seen:
        raise Refused("the artifact zip is empty")
    if file_name and file_name not in seen:
        raise Refused(f"the artifact has no {file_name}")
    return seen


# ------------------------------------------------------------------------------------------------ OCI image layout
def _blob_path(layout, digest):
    if not DIGEST.match(digest or ""):
        raise Refused(f"not a sha256 digest: {digest!r}")
    return os.path.join(layout, "blobs", "sha256", digest[7:])


def _hash_file(path):
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
            size += len(chunk)
    return "sha256:" + h.hexdigest(), size


def _blob(layout, desc, what):
    digest = desc.get("digest", "")
    path = _blob_path(layout, digest)
    if not os.path.isfile(path) or os.path.islink(path):
        raise Refused(f"{what} {digest} is missing from the layout")
    got, size = _hash_file(path)
    if got != digest:
        raise Refused(f"{what} {digest} is damaged (its content hashes to {got})")
    if "size" in desc and desc["size"] != size:
        raise Refused(f"{what} {digest} is {size} bytes, not {desc['size']}")
    return path, size


def _load_json(path, what):
    try:
        with open(path, "rb") as fh:
            return json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError) as e:
        raise Refused(f"cannot read {what}: {e}") from None


def _write_index(layout, desc):
    index = {"schemaVersion": 2, "mediaType": INDEX_TYPES[0], "manifests": [desc]}
    tmp = os.path.join(layout, ".index.json.new")
    with open(tmp, "w") as fh:
        json.dump(index, fh, indent=2)
    os.replace(tmp, os.path.join(layout, "index.json"))


def oci_check(layout, digest=None, revision=None, labels=None, normalize=False):
    """Check the single linux/amd64 image of an OCI layout; returns (manifest digest, total bytes)."""
    marker = _load_json(os.path.join(layout, "oci-layout"), "oci-layout")
    if not isinstance(marker, dict) or not marker.get("imageLayoutVersion"):
        raise Refused("oci-layout has no imageLayoutVersion: not an OCI image layout")
    index = _load_json(os.path.join(layout, "index.json"), "index.json")
    entries = index.get("manifests") if isinstance(index, dict) else None
    if not isinstance(entries, list) or len(entries) != 1:
        raise Refused(f"index.json must name exactly one image, it names {len(entries or [])}")
    desc = entries[0]
    if desc.get("mediaType") in INDEX_TYPES:
        if not normalize:
            raise Refused("index.json names an image index, not one image (the workflow normalizes buildx output)")
        path, _ = _blob(layout, desc, "image index")
        inner = [m for m in _load_json(path, "the nested index").get("manifests", [])
                 if (m.get("platform") or {}).get("os") == PLATFORM[0]
                 and (m.get("platform") or {}).get("architecture") == PLATFORM[1]]
        if len(inner) != 1:
            raise Refused(f"the nested index has {len(inner)} linux/amd64 manifests, not one")
        desc = {k: inner[0][k] for k in ("mediaType", "digest", "size") if k in inner[0]}
        desc["platform"] = {"architecture": PLATFORM[1], "os": PLATFORM[0]}
        _write_index(layout, desc)
    if desc.get("mediaType") not in MANIFEST_TYPES:
        raise Refused(f"index.json names a {desc.get('mediaType')!r}, not an image manifest")
    mpath, total = _blob(layout, desc, "manifest")
    manifest = _load_json(mpath, "the image manifest")
    if digest and desc["digest"] != digest:
        raise Refused(f"the layout holds image {desc['digest']}, not {digest}")
    cdesc = manifest.get("config") or {}
    cpath, size = _blob(layout, cdesc, "config")
    total += size
    config = _load_json(cpath, "the image config")
    plat = (config.get("os"), config.get("architecture"))
    if plat != PLATFORM:
        raise Refused(f"the image is {plat[0]}/{plat[1]}, not linux/amd64")
    got_labels = (config.get("config") or {}).get("Labels") or {}
    want = dict(labels or {})
    if revision:
        want[REVISION_LABEL] = revision
    for key, value in want.items():
        if got_labels.get(key) != value:
            raise Refused(f"label {key} is {got_labels.get(key)!r}, not {value!r}")
    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        raise Refused("the image manifest has no layers")
    for i, layer in enumerate(layers):
        _, size = _blob(layout, layer, f"layer {i + 1}/{len(layers)}")
        total += size
    return desc["digest"], total


# ------------------------------------------------------------------------------------------------ the run's manifest
def _read_manifest(path):
    data = _load_json(path, "the run manifest")
    if not isinstance(data, dict):
        raise Refused("the run manifest is not a JSON object")
    return data


def _write_manifest(path, data):
    tmp = path + ".new"
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def manifest_init(out, commit, api_url, repository="", run_id="", run_attempt="", ref=""):
    if not SHA40.match(commit):
        raise Refused(f"--commit must be a full 40-character commit, not {commit!r}")
    _write_manifest(out, {"schema": SCHEMA, "commit": commit, "api_url": api_url, "images": {}, "infra": None,
                          "workflow": {"repository": repository, "run_id": str(run_id),
                                       "run_attempt": str(run_attempt), "ref": ref}})


def manifest_add_image(path, component, artifact, source, layout, index_digest=""):
    data = _read_manifest(path)
    if component not in COMPONENTS:
        raise Refused(f"unknown component {component!r}")
    if not SAFE_NAME.match(artifact):
        raise Refused(f"not an artifact name: {artifact!r}")
    if index_digest and not DIGEST.match(index_digest):
        raise Refused(f"--index-digest is not a sha256 digest: {index_digest!r}")
    labels = {API_URL_LABEL: data["api_url"]} if component == "frontend" else {}
    digest, size = oci_check(layout, revision=data["commit"], labels=labels)
    data["images"][component] = {"artifact": artifact, "source": source, "index_digest": index_digest,
                                 "digest": digest, "revision": data["commit"], "platform": "linux/amd64",
                                 "bytes": size}
    _write_manifest(path, data)
    return digest, size


def manifest_set_infra(path, artifact, file_path, images):
    data = _read_manifest(path)
    if not SAFE_NAME.match(artifact):
        raise Refused(f"not an artifact name: {artifact!r}")
    for ref in images:
        if not INFRA_REF.match(ref):
            raise Refused(f"not a digest-pinned image reference: {ref!r}")
    digest, size = _hash_file(file_path)
    data["infra"] = {"artifact": artifact, "file": os.path.basename(file_path), "sha256": digest[7:],
                     "bytes": size, "images": list(images)}
    _write_manifest(path, data)
    return digest[7:], size


def manifest_check(path, sha, api_url=None, components=(), infra=None):
    """Validated lines for the kit (see the module docstring)."""
    data = _read_manifest(path)
    if data.get("schema") != SCHEMA:
        raise Refused(f"the run manifest is {data.get('schema')!r}, this kit reads {SCHEMA!r} (another kit version?)")
    if components and not sha:
        raise Refused("--component needs --sha (each image's revision is checked against it)")
    if sha is not None and data.get("commit") != sha:
        raise Refused(f"the run built commit {data.get('commit')!r}, not {sha} (--from-run of another commit?)")
    if api_url is not None and data.get("api_url") != api_url:
        raise Refused(f"the run's frontend was built for {data.get('api_url')!r}, not {api_url}")
    lines = []
    images = data.get("images") or {}
    for c in components:
        img = images.get(c)
        if not isinstance(img, dict):
            raise Refused(f"the run has no {c} image")
        if img.get("revision") != sha:
            raise Refused(f"the run's {c} image is revision {img.get('revision')!r}, not {sha}")
        if not DIGEST.match(str(img.get("digest"))) or not SAFE_NAME.match(str(img.get("artifact"))):
            raise Refused(f"the run's {c} entry has no valid digest or artifact name")
        if img.get("platform") != "linux/amd64":
            raise Refused(f"the run's {c} image is {img.get('platform')!r}, not linux/amd64")
        lines.append(f"image {c} {img['artifact']} {img['digest']} {int(img.get('bytes') or 0)}")
    if infra is not None:
        inf = data.get("infra")
        if not isinstance(inf, dict):
            raise Refused("the run has no infrastructure archive")
        if list(inf.get("images") or []) != list(infra):
            raise Refused("the run's infrastructure images are not this kit's pins (INFRA_IMAGES): "
                          f"{' '.join(inf.get('images') or [])}")
        if (not SAFE_NAME.match(str(inf.get("artifact"))) or not SAFE_NAME.match(str(inf.get("file")))
                or not re.match(r"^[0-9a-f]{64}$", str(inf.get("sha256")))):
            raise Refused("the run's infrastructure entry has no valid artifact, file or sha256")
        lines.append(f"infra {inf['artifact']} {inf['file']} {inf['sha256']} {int(inf.get('bytes') or 0)}")
    return lines


# ------------------------------------------------------------------------------------------------ CLI
def _labels(pairs):
    out = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise Refused(f"--label needs K=V, not {pair!r}")
        k, v = pair.split("=", 1)
        out[k] = v
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("unzip-stream")
    u.add_argument("--dest", required=True)
    g = u.add_mutually_exclusive_group(required=True)
    g.add_argument("--oci", action="store_true")
    g.add_argument("--file")
    o = sub.add_parser("oci-check")
    o.add_argument("--layout", required=True)
    o.add_argument("--digest")
    o.add_argument("--revision")
    o.add_argument("--label", action="append")
    o.add_argument("--normalize", action="store_true")
    mi = sub.add_parser("manifest-init")
    mi.add_argument("--out", required=True)
    mi.add_argument("--commit", required=True)
    mi.add_argument("--api-url", required=True)
    mi.add_argument("--repository", default="")
    mi.add_argument("--run-id", default="")
    mi.add_argument("--run-attempt", default="")
    mi.add_argument("--ref", default="")
    ma = sub.add_parser("manifest-add-image")
    ma.add_argument("--manifest", required=True)
    ma.add_argument("--component", required=True)
    ma.add_argument("--artifact", required=True)
    ma.add_argument("--source", required=True)
    ma.add_argument("--layout", required=True)
    ma.add_argument("--index-digest", default="")
    ms = sub.add_parser("manifest-set-infra")
    ms.add_argument("--manifest", required=True)
    ms.add_argument("--artifact", required=True)
    ms.add_argument("--file", required=True)
    ms.add_argument("--image", action="append", required=True)
    mc = sub.add_parser("manifest-check")
    mc.add_argument("--manifest", required=True)
    mc.add_argument("--sha")
    mc.add_argument("--api-url")
    mc.add_argument("--component", action="append", default=[])
    mc.add_argument("--infra", action="append")
    args = p.parse_args(argv)
    try:
        if args.cmd == "unzip-stream":
            got = unzip_stream(sys.stdin.buffer, args.dest, oci=args.oci, file_name=args.file)
            print(f"extracted {len([n for n in got if not n.endswith('/')])} files, {sum(got.values())} bytes")
        elif args.cmd == "oci-check":
            digest, size = oci_check(args.layout, args.digest, args.revision, _labels(args.label), args.normalize)
            print(f"{digest} {size}")
        elif args.cmd == "manifest-init":
            manifest_init(args.out, args.commit, args.api_url, args.repository, args.run_id, args.run_attempt,
                          args.ref)
        elif args.cmd == "manifest-add-image":
            digest, size = manifest_add_image(args.manifest, args.component, args.artifact, args.source, args.layout,
                                              args.index_digest)
            print(f"{args.component}: {digest} ({size} bytes, linux/amd64)")
        elif args.cmd == "manifest-set-infra":
            digest, size = manifest_set_infra(args.manifest, args.artifact, args.file, args.image)
            print(f"infra: {os.path.basename(args.file)} sha256 {digest} ({size} bytes)")
        elif args.cmd == "manifest-check":
            for line in manifest_check(args.manifest, args.sha, args.api_url, args.component, args.infra):
                print(line)
    except Refused as e:
        print(f"artifacts.py: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

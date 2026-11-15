"""What `docker load` of a `docker save` archive needs where Docker stores images, in bytes (staging.sh save).

Reads the uncompressed `docker save` tar on stdin (`gzip -dc <archive> | python3 -I archive_need.py`) and prints one
number: every layer as stored in the archive (the containerd image store keeps it in its content store; the classic
store extracts it to a temporary directory) plus every layer unpacked (the snapshots or overlay2 layers). A layer saved
gzip-compressed (a containerd-store builder) counts its compressed and its unpacked size; an uncompressed layer tar (a
classic-store builder) counts twice. Configs and manifests are small and not counted. Nothing is written; exit 2 when
a layer cannot be read (zstd without Python's compression.zstd), so the caller falls back to its factor.

Measured on the archive of Deploy staging run 43572299641: 34 gzip layers, 5,500,325,457 bytes stored, 11,193,004,544
unpacked, so 16,693,330,001 bytes for a 5,484,863,244-byte archive (3.04x).
"""

from __future__ import annotations

import sys
import tarfile
import zlib

CHUNK = 1 << 20


def unpacked_size(f, head: bytes) -> int | None:
    """Uncompressed size of a gzip or zstd layer whose first bytes are <head>; None when it is not compressed."""
    if head[:2] == b"\x1f\x8b":
        d = zlib.decompressobj(wbits=31)
        n = len(d.decompress(head))
        while chunk := f.read(CHUNK):
            n += len(d.decompress(chunk))
        return n + len(d.flush())
    if head[:4] == b"\x28\xb5\x2f\xfd":
        try:
            from compression import zstd  # Python 3.14+
        except ImportError:
            print("archive_need: a zstd layer and no compression.zstd to read it", file=sys.stderr)
            sys.exit(2)
        d = zstd.ZstdDecompressor()
        n = len(d.decompress(head))
        while chunk := f.read(CHUNK):
            n += len(d.decompress(chunk))
        return n
    return None


def main() -> int:
    stored = unpacked = layers = 0
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as tf:
        for member in tf:
            if not member.isfile():
                continue
            f = tf.extractfile(member)
            head = f.read(min(member.size, 1 << 16))
            size = unpacked_size(f, head)
            if size is None:
                if not (len(head) > 262 and head[257:262] == b"ustar"):
                    continue  # config, manifest, index: not a layer
                size = member.size
            layers += 1
            stored += member.size
            unpacked += size
    if not layers:
        print("archive_need: no layers in the archive", file=sys.stderr)
        return 2
    print(f"archive_need: {layers} layers, {stored} bytes stored, {unpacked} unpacked", file=sys.stderr)
    print(stored + unpacked)
    return 0


if __name__ == "__main__":
    sys.exit(main())

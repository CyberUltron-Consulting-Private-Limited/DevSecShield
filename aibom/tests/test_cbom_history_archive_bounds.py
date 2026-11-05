"""Round-5 review fixes (group E): the git-history and archive readers parse attacker-controlled bytes (the ``.git``
of an uploaded archive, archives committed in the tree), so their memory and work are bounded by the reader, never
by what the input declares, and a malformed object is a coverage count, never a failed scan.

Memory-bounded cases assert on bytes produced, Python allocations (tracemalloc) or exceptions, never on RSS.
"""

from __future__ import annotations

import hashlib
import io
import struct
import tracemalloc
import zipfile
import zlib
from collections import deque
from pathlib import Path

import pytest

from aibom.cbom import archives, githistory
from aibom.cbom.archives import ArchiveBudget, VirtualFile, archive_members
from aibom.cbom.githistory import GitObjects, history_key_files
from aibom.cbom.pipeline import scan_crypto

_HEX = "00112233445566778899aabbccddeeff"


# --------------------------------------------------------------------------- #
# Builders: loose objects, packs and pack indexes written byte by byte
# --------------------------------------------------------------------------- #


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _obj_header(kind: int, size: int) -> bytes:
    b = [(kind << 4) | (size & 15)]
    size >>= 4
    while size:
        b[-1] |= 0x80
        b.append(size & 0x7F)
        size >>= 7
    return bytes(b)


def _ofs(rel: int) -> bytes:
    buf = [rel & 0x7F]
    rel >>= 7
    while rel:
        rel -= 1
        buf.insert(0, 0x80 | (rel & 0x7F))
        rel >>= 7
    return bytes(buf)


def _put(git: Path, kind: bytes, body: bytes) -> str:
    raw = b"%s %d\0" % (kind, len(body)) + body
    sha = hashlib.sha1(raw).hexdigest()  # noqa: S324 (git object name)
    d = git / "objects" / sha[:2]
    d.mkdir(parents=True, exist_ok=True)
    (d / sha[2:]).write_bytes(zlib.compress(raw))
    return sha


def _tree(entries: list[tuple[bytes, bytes, str]]) -> bytes:
    return b"".join(mode + b" " + name + b"\0" + bytes.fromhex(sha) for mode, name, sha in entries)


def _write_pack(git: Path, name: str, pack: bytes, objects: dict[str, int]) -> None:
    """A pack and its v2 index naming ``objects`` (sha -> offset)."""
    (git / "objects" / "pack").mkdir(parents=True, exist_ok=True)
    shas = sorted(objects)
    fan = b"".join(struct.pack(">I", sum(1 for s in shas if int(s[:2], 16) <= i)) for i in range(256))
    idx = (b"\xfftOc" + struct.pack(">I", 2) + fan + b"".join(bytes.fromhex(s) for s in shas)
           + bytes(4 * len(shas)) + b"".join(struct.pack(">I", objects[s]) for s in shas) + bytes(40))
    (git / "objects" / "pack" / f"pack-{name}.idx").write_bytes(idx)
    (git / "objects" / "pack" / f"pack-{name}.pack").write_bytes(pack + hashlib.sha1(pack).digest())  # noqa: S324


def _delta_bomb(root: Path, copies: int) -> str:
    """The reviewer's .git: HEAD is an OFS_DELTA declaring a 100-byte result whose body repeats a 16 MB copy of a
    1 MB zero blob ``copies`` times (each copy yields the whole base: 1 MB)."""
    git = root / ".git"
    base = b"\0" * 1_000_000
    pack = bytearray(b"PACK" + struct.pack(">II", 2, 2))
    off_base = len(pack)
    pack += _obj_header(3, len(base)) + zlib.compress(base)
    delta = _varint(len(base)) + _varint(100) + b"\xf0\xff\xff\xff" * copies
    off_delta = len(pack)
    pack += _obj_header(6, len(delta)) + _ofs(off_delta - off_base) + zlib.compress(delta)
    head = hashlib.sha1(b"fake head").hexdigest()  # noqa: S324
    _write_pack(git, "bomb", bytes(pack), {head: off_delta})
    (git / "HEAD").write_text(head + "\n")
    return head


def _delta_chain(root: Path, levels: int, size: int) -> str:
    """A VALID delta chain: each level rebuilds ``size`` bytes from its base in 1-byte copy instructions."""
    git = root / ".git"
    pack = bytearray(b"PACK" + struct.pack(">II", 2, levels + 1))
    prev = len(pack)
    pack += _obj_header(3, size) + zlib.compress(b"\0" * size)
    delta = _varint(size) + _varint(size) + b"\x90\x01" * size
    for _ in range(levels):
        here = len(pack)
        pack += _obj_header(6, len(delta)) + _ofs(here - prev) + zlib.compress(delta)
        prev = here
    head = hashlib.sha1(b"chain").hexdigest()  # noqa: S324
    _write_pack(git, "chain", bytes(pack), {head: prev})
    (git / "HEAD").write_text(head + "\n")
    return head


def _cd_zip(n: int, declared: int | None = None) -> bytes:
    """A zip whose central directory has ``n`` entries all pointing at one local header (zip64 end records;
    ``declared`` overrides the entry count the end record states)."""
    name, data = b"a.pem", b"x"
    crc = zlib.crc32(data)
    local = struct.pack("<4s5H3L2H", b"PK\x03\x04", 20, 0, 0, 0, 0, crc, 1, 1, len(name), 0) + name + data
    cd = b"".join(struct.pack("<4s6H3L5H2L", b"PK\x01\x02", 20, 20, 0, 0, 0, 0, crc, 1, 1, 11, 0, 0, 0, 0, 0, 0)
                  + b"%07d.pem" % i for i in range(n))
    count = n if declared is None else declared
    z64 = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, count, count, len(cd), len(local))
    loc = struct.pack("<4sLQL", b"PK\x06\x07", 0, len(local) + len(cd), 1)
    eocd = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    return local + cd + z64 + loc + eocd


def _zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# 1. Git-history delta bomb (rev5 #1)
# --------------------------------------------------------------------------- #


def test_delta_bomb_is_refused_before_it_is_rebuilt(tmp_path: Path) -> None:
    head = _delta_bomb(tmp_path, copies=40)  # 40 MB from ~1 KB before the fix
    store = GitObjects(tmp_path / ".git")
    try:
        assert store.get(head.encode()) is None
        assert store.corrupt == 1
        assert store.bytes_read < 2_000_000  # the 1 MB base and the delta, nothing rebuilt
    finally:
        store.close()
    files, coverage = history_key_files(tmp_path)
    assert files == [] and coverage["crypto:coverage:gitHistoryObjectsUnreadable"] == "1"


@pytest.mark.parametrize("delta, why", [
    (_varint(4) + _varint(8) + b"\x90\x08", "copy past the base"),          # copy base[0:8] of a 4-byte base
    (_varint(4) + _varint(2) + b"\x90\x04", "past the declared size"),      # 4 bytes into a 2-byte result
    (_varint(4) + _varint(4) + b"\x91\x02\x04", "copy outside the base"),   # base[2:6]
    (_varint(5) + _varint(4) + b"\x90\x04", "base of another size"),
    (_varint(4) + _varint(6) + b"\x90\x04", "result shorter than declared"),
    (_varint(4) + _varint(4) + b"\x05ab", "insert past the delta"),
    (_varint(4) + b"\xff" * 20, "endless size"),
])
def test_delta_git_would_refuse_is_refused(delta: bytes, why: str) -> None:
    with pytest.raises(ValueError):
        githistory._apply_delta(b"abcd", delta, 10**9)


def test_valid_delta_is_rebuilt_and_its_work_counted() -> None:
    delta = _varint(4) + _varint(7) + b"\x90\x04" + b"\x03xyz"  # copy "abcd", insert "xyz"
    assert githistory._apply_delta(b"abcd", delta, 10**9) == (b"abcdxyz", 7 + 2 * githistory._DELTA_OP_COST)
    with pytest.raises(githistory.HistoryBudgetExceeded):
        githistory._apply_delta(b"abcd", delta, 7 + githistory._DELTA_OP_COST)  # stops before the second instruction


def test_work_budget_ends_a_valid_but_costly_chain(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(githistory, "MAX_READ_BYTES", 300_000, raising=False)
    _delta_chain(tmp_path, levels=40, size=2_000)  # 40 levels x (2 KB + 2,000 instructions)
    files, coverage = history_key_files(tmp_path)
    assert files == []
    assert coverage["crypto:coverage:gitHistoryBudgetExceeded"] == "true"
    monkeypatch.setattr(githistory, "MAX_READ_BYTES", 10**9)
    store = GitObjects(tmp_path / ".git")
    try:  # within budget the same chain is a valid object: nothing above refuses good data
        kind, body = store.get(hashlib.sha1(b"chain").hexdigest().encode())  # noqa: S324
        assert kind == b"blob" and body == b"\0" * 2_000 and store.corrupt == 0
    finally:
        store.close()


def test_parents_and_refs_beyond_the_pending_cap_are_counted_not_queued(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(githistory, "_MAX_PENDING", 50, raising=False)
    longest = [0]

    class Tracked(deque):
        def append(self, item) -> None:
            super().append(item)
            longest[0] = max(longest[0], len(self))

    monkeypatch.setattr(githistory, "deque", Tracked)
    git = tmp_path / ".git"
    tree = _put(git, b"tree", b"")
    parents = b"".join(b"parent %040x\n" % (i + 1) for i in range(500))
    head = _put(git, b"commit", b"tree %s\n%s\nmsg\n" % (tree.encode(), parents))
    (git / "HEAD").write_text(head + "\n")
    (git / "packed-refs").write_bytes(b"".join(b"%040x refs/tags/t%d\n" % (10_000 + i, i) for i in range(80)))
    _, coverage = history_key_files(tmp_path)
    assert longest[0] <= 50
    assert int(coverage["crypto:coverage:gitHistoryCommitsNotRead"]) >= 500 + 80 - 50


# --------------------------------------------------------------------------- #
# Other shapes of the same root cause: the reader's memory follows what the input declares
# --------------------------------------------------------------------------- #


def test_pack_index_is_searched_in_place_not_loaded_into_a_table(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    n = 200_000  # a 5.6 MB index; one Python table entry per object is ~30 MB
    (git / "objects" / "pack").mkdir(parents=True)
    names = b"".join(struct.pack(">BQQxxx", (i * 256) // n, i, 0) for i in range(n))
    counts = [0] * 256
    for i in range(n):
        counts[(i * 256) // n] += 1
    acc, fan = 0, b""
    for c in counts:
        acc += c
        fan += struct.pack(">I", acc)
    offsets = b"".join(struct.pack(">I", 12 + i) for i in range(n))
    idx = b"\xfftOc" + struct.pack(">I", 2) + fan + names + bytes(4 * n) + offsets + bytes(40)
    (git / "objects" / "pack" / "pack-big.idx").write_bytes(idx)
    (git / "objects" / "pack" / "pack-big.pack").write_bytes(b"PACK" + struct.pack(">II", 2, 0))
    tracemalloc.start()
    try:
        store = GitObjects(git)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    try:
        assert peak < 1_000_000
        pack = store.packs[0]
        probe = struct.pack(">BQQxxx", (12_345 * 256) // n, 12_345, 0).hex().encode()
        assert pack.find(probe) == 12 + 12_345
        assert pack.find(b"f" * 40) is None and pack.find(b"0" * 39 + b"1") is None
    finally:
        store.close()


def test_pack_count_is_capped(tmp_path: Path, monkeypatch) -> None:
    """Each pack holds a mapping and a descriptor until the read ends: a .git with thousands of packs would take
    the worker's descriptors from every other scan."""
    monkeypatch.setattr(githistory, "_MAX_PACKS", 1, raising=False)
    _delta_chain(tmp_path, levels=1, size=10)
    _delta_bomb(tmp_path, copies=1)
    store = GitObjects(tmp_path / ".git")
    assert len(store.packs) == 1
    store.close()
    _, coverage = history_key_files(tmp_path)
    assert coverage["crypto:coverage:gitHistoryBudgetExceeded"] == "true"


def test_truncated_pack_index_is_counted(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    (git / "objects" / "pack").mkdir(parents=True)
    fan = struct.pack(">I", 0) * 255 + struct.pack(">I", 1_000_000)  # claims a million objects, holds none
    (git / "objects" / "pack" / "pack-t.idx").write_bytes(b"\xfftOc" + struct.pack(">I", 2) + fan)
    store = GitObjects(git)
    assert store.packs == [] and store.corrupt == 1
    store.close()


def test_endless_size_header_and_base_offset_are_corrupt(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    endless_size = b"\x9f" + b"\xff" * 5_000 + b"\x00"
    endless_base = _obj_header(6, 4) + b"\xff" * 5_000 + b"\x00"
    pack = b"PACK" + struct.pack(">II", 2, 2)
    a, b = hashlib.sha1(b"a").hexdigest(), hashlib.sha1(b"b").hexdigest()  # noqa: S324
    _write_pack(git, "v", pack + endless_size + endless_base, {a: 12, b: 12 + len(endless_size)})
    store = GitObjects(git)
    try:
        assert store.get(a.encode()) is None and store.get(b.encode()) is None
        assert store.corrupt == 2
    finally:
        store.close()


def test_deep_tree_paths_are_bounded_and_never_held_whole(tmp_path: Path) -> None:
    """Nested trees naming each child twice: a depth-first walk kept one full path string per level pending
    (quadratic memory). Paths longer than PATH_MAX are not paths a file system holds."""
    git = tmp_path / ".git"
    child = _put(git, b"tree", _tree([(b"100644", b"deep.key", _put(git, b"blob", _HEX.encode()))]))
    for i in range(3_000):
        child = _put(git, b"tree", _tree([(b"40000", b"a%04d" % i, child), (b"40000", b"b%04d" % i, child)]))
    head = _put(git, b"commit", b"tree %s\n\nm\n" % child.encode())
    (git / "HEAD").write_text(head + "\n")
    tracemalloc.start()
    try:
        files, _ = history_key_files(tmp_path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert files == []  # the key sits 3,000 levels (18 KB of path) deep
    assert peak < 4_000_000  # ~30 MB of pending path strings before the fix


def test_key_blobs_looked_at_are_capped(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(githistory, "MAX_FILES", 3, raising=False)
    git = tmp_path / ".git"
    entries = [(b"100644", b"k%d.key" % i, _put(git, b"blob", b"%s%d\n" % (_HEX.encode(), i))) for i in range(5)]
    head = _put(git, b"commit", b"tree %s\n\nm\n" % _put(git, b"tree", _tree(entries)).encode())
    (git / "HEAD").write_text(head + "\n")
    files, coverage = history_key_files(tmp_path)
    assert [f.rel for f in files] == ["k0.key", "k1.key", "k2.key"]
    assert coverage["crypto:coverage:gitHistoryBudgetExceeded"] == "true"


# --------------------------------------------------------------------------- #
# 2. A malformed object is coverage, not a failed scan (rev5 #2)
# --------------------------------------------------------------------------- #


def test_malformed_tree_is_counted_and_the_rest_of_history_is_read(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    good = _put(git, b"tree", _tree([(b"100644", b"old.key", _put(git, b"blob", (_HEX + "\n").encode()))]))
    first = _put(git, b"commit", b"tree %s\n\nadd\n" % good.encode())
    bad = _put(git, b"tree", b"100644 key.pem")  # the reviewer's tree: no NUL, not an entry
    head = _put(git, b"commit", b"tree %s\nparent %s\n\nbreak\n" % (bad.encode(), first.encode()))
    (git / "HEAD").write_text(head + "\n")
    result = scan_crypto(tmp_path)  # raised ValueError("subsection not found") before the fix
    rows = [c for c in result.components if (c.properties or {}).get("discovery:source") == "old.key"]
    assert len(rows) == 1 and rows[0].properties["crypto:historyOnly"] == "true"
    assert result.properties["crypto:coverage:gitHistoryObjectsUnreadable"] == "1"
    assert result.properties["crypto:coverage:gitHistoryCommits"] == "2"


def test_truncated_tree_entry_is_corrupt(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    tree = _put(git, b"tree", b"100644 a.key\0" + b"\x01" * 7)  # 7 of the 20 name bytes
    head = _put(git, b"commit", b"tree %s\n\nm\n" % tree.encode())
    (git / "HEAD").write_text(head + "\n")
    files, coverage = history_key_files(tmp_path)
    assert files == [] and coverage["crypto:coverage:gitHistoryObjectsUnreadable"] == "1"


def test_loose_object_of_another_size_than_declared_is_corrupt(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    raw = b"commit 999\0tree " + b"0" * 40 + b"\n\nm\n"
    sha = hashlib.sha1(raw).hexdigest()  # noqa: S324
    (git / "objects" / sha[:2]).mkdir(parents=True)
    (git / "objects" / sha[:2] / sha[2:]).write_bytes(zlib.compress(raw))
    store = GitObjects(git)
    assert store.get(sha.encode()) is None and store.corrupt == 1
    store.close()


# --------------------------------------------------------------------------- #
# 3. Names with "@" keep their suffix (rev5 #3)
# --------------------------------------------------------------------------- #


def test_suffix_drops_only_the_history_commit_tag() -> None:
    commit = "0123456789ab" + "c" * 28
    assert VirtualFile("smime/alice@example.com.crt", b"").suffix == ".crt"
    assert VirtualFile("a.zip!smime/alice@example.com.crt", b"").suffix == ".crt"
    assert VirtualFile("smime/alice@example.com.crt@0123456789ab", b"", {"crypto:gitCommit": commit}).suffix == ".crt"
    assert VirtualFile("cfg/deploy.key@0123456789ab", b"", {"crypto:gitCommit": commit}).suffix == ".key"
    assert VirtualFile("a.zip!x.pem@0123456789ab", b"").suffix == ".pem@0123456789ab"  # not a history tag


def test_key_named_with_an_at_sign_inside_an_archive_is_found(tmp_path: Path) -> None:
    (tmp_path / "bundle.zip").write_bytes(_zip({"keys/ops@example.com.key": (_HEX + "\n").encode()}))
    result = scan_crypto(tmp_path)
    assert [c for c in result.components
            if (c.properties or {}).get("discovery:source") == "bundle.zip!keys/ops@example.com.key"]


def test_history_key_named_with_an_at_sign_is_found(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    tree = _put(git, b"tree", _tree([(b"100644", b"ops@example.com.key", _put(git, b"blob", (_HEX + "\n").encode()))]))
    (git / "HEAD").write_text(_put(git, b"commit", b"tree %s\n\nm\n" % tree.encode()) + "\n")
    result = scan_crypto(tmp_path)
    assert [c for c in result.components if (c.properties or {}).get("discovery:source") == "ops@example.com.key"]


# --------------------------------------------------------------------------- #
# 4. A central directory too large to parse is never parsed (rev5 #5)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("declared", [None, 1])  # an honest entry count, and one that lies (zipfile ignores it)
def test_oversized_central_directory_is_refused_before_parsing(tmp_path: Path, monkeypatch, declared) -> None:
    monkeypatch.setattr(archives, "MAX_DIRECTORY_BYTES", 100_000, raising=False)
    parsed: list[object] = []
    real = zipfile.ZipFile
    monkeypatch.setattr(archives.zipfile, "ZipFile", lambda *a, **k: (parsed.append(a), real(*a, **k))[1])
    (tmp_path / "big.zip").write_bytes(_cd_zip(5_000, declared))  # 285 KB of directory
    budget = ArchiveBudget()
    assert archive_members(tmp_path, [tmp_path / "big.zip"], budget) == []
    assert parsed == [] and budget.members == 0
    assert budget.coverage() == {"crypto:coverage:archiveDirectoryTooLarge": "1"}


def test_more_entries_than_twice_the_member_budget_is_refused(tmp_path: Path) -> None:
    (tmp_path / "many.zip").write_bytes(_cd_zip(2 * archives.MAX_MEMBERS + 1))
    budget = ArchiveBudget()
    assert archive_members(tmp_path, [tmp_path / "many.zip"], budget) == []
    assert budget.members == 0 and budget.skipped_directory == 1


def test_nested_archive_with_an_oversized_directory_is_refused(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(archives, "MAX_DIRECTORY_BYTES", 100_000, raising=False)
    (tmp_path / "outer.zip").write_bytes(_zip({"inner.jar": _cd_zip(5_000), "ok.key": (_HEX + "\n").encode()}))
    budget = ArchiveBudget()
    out = archive_members(tmp_path, [tmp_path / "outer.zip"], budget)
    assert [v.rel for v in out] == ["outer.zip!ok.key"]
    assert budget.skipped_directory == 1 and budget.members == 2


@pytest.mark.parametrize("method", [zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
def test_corrupt_compressed_member_is_coverage_not_a_failed_scan(tmp_path: Path, method: int) -> None:
    """Found by fuzzing while fixing #5: a corrupt deflate (zlib.error) or LZMA (LZMAError) stream escaped the
    archive reader and failed the whole scan."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as zf:
        zf.writestr("bad.key", b"0011223344556677" * 64)
        zf.writestr("good.key", (_HEX + "\n").encode())
    raw = bytearray(buf.getvalue())
    start = raw.find(b"bad.key") + len(b"bad.key")
    for i in range(start + 4, start + 24):
        raw[i] ^= 0x5A
    (tmp_path / "a.zip").write_bytes(bytes(raw))
    result = scan_crypto(tmp_path)
    assert [c for c in result.components if (c.properties or {}).get("discovery:source") == "a.zip!good.key"]
    assert result.properties["crypto:coverage:archiveUnsupported"] == "1"


def _zip_with_claimed_directory(size: int) -> bytes:
    import io as _io
    import struct as _struct
    import zipfile as _zipfile

    buf = _io.BytesIO()
    with _zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", "x")
    data = bytearray(buf.getvalue())
    i = data.rfind(b"PK\x05\x06")
    _struct.pack_into("<I", data, i + 12, size)  # central directory size in the end record
    return bytes(data)


def test_binary_lane_zips_check_the_end_record_before_parsing():
    """The binary lane (unpack.Walk._zip, artifacts.Collector._jar) opened in-memory blobs of up to 128 MB with
    zipfile.ZipFile directly, the same central-directory memory problem the code-scan lane had."""
    from aibom.cbom import archives as A
    from aibom.cbom.artifacts import ArtifactReport, Collector
    from aibom.cbom.unpack import Walk

    blob = _zip_with_claimed_directory(A.MAX_DIRECTORY_BYTES + 1)
    budget = A.ArchiveBudget()
    seen: list[str] = []
    Walk(budget, lambda path, member: seen.append(path))._zip("big.zip", blob, 0)
    assert budget.skipped_directory == 1 and seen == []
    budget = A.ArchiveBudget()
    assert Collector(ArtifactReport(), budget, detail=True)._jar(blob, 0, "big-1.0.jar") == []
    assert budget.skipped_directory == 1

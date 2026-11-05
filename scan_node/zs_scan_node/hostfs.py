"""Read-only access to the host's file system as mounted into an agent-mode node (``ZS_HOST_ROOT``, default ``/host``).

Every path is resolved inside the mount the way a ``chroot`` would resolve it: an absolute symlink target is taken
relative to the host root and ``..`` never climbs above it, so a symlink on the host (``/etc/ssl/certs/x.pem ->
/usr/share/ca-certificates/...``) reads the host's file and never one of the node container's own files
(``/proc/self/environ``, ``/var/lib/zs-node``).  The final file is opened with ``O_NOFOLLOW | O_NONBLOCK`` and must
be a regular file (a FIFO or device never blocks or streams), and every read is capped.  The walk does not follow
symlinks and stays on the device of the directory it starts in (like ``find -xdev``), so pod volumes and other
mounts under the host root are never searched.
"""
from __future__ import annotations

import errno
import os
import re
import stat
from dataclasses import dataclass, field
from typing import Iterator

MAX_LINKS = 40
_O_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)


@dataclass
class Read:
    status: str  # ok | missing | denied | too_large | not_file | loop
    data: bytes = b""
    mode: int | None = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def text(self) -> str:
        return self.data.decode("utf-8", "replace")


@dataclass
class WalkStats:
    files: int = 0
    denied_dirs: int = 0
    other_devices: int = 0
    symlinks: int = 0
    truncated: bool = False
    denied_examples: list[str] = field(default_factory=list)


class HostFS:
    def __init__(self, root: str) -> None:
        self.root = os.path.realpath(root or "/")

    def _join(self, parts: list[str]) -> str:
        return os.path.join(self.root, *parts) if parts else self.root

    def resolve(self, path: str) -> str | None:
        """The real path under the root for a host path (``/etc/os-release``), following symlinks inside the root
        only.  None when a component is missing or the link chain is too long."""
        todo = [p for p in str(path).split("/") if p not in ("", ".")]
        done: list[str] = []
        links = 0
        while todo:
            part = todo.pop(0)
            if part == "..":
                if done:
                    done.pop()
                continue
            candidate = self._join(done + [part])
            try:
                st = os.lstat(candidate)
            except OSError:
                return None
            if stat.S_ISLNK(st.st_mode):
                links += 1
                if links > MAX_LINKS:
                    return None
                try:
                    target = os.readlink(candidate)
                except OSError:
                    return None
                if target.startswith("/"):
                    done = []
                todo = [p for p in target.split("/") if p not in ("", ".")] + todo
                continue
            done.append(part)
        return self._join(done)

    def read(self, path: str, limit: int) -> Read:
        real = self.resolve(path)
        if real is None:
            return Read("missing")
        try:
            fd = os.open(real, _O_FLAGS)
        except PermissionError:
            return Read("denied")
        except OSError as exc:
            return Read("loop" if exc.errno == errno.ELOOP else "missing")
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return Read("not_file", mode=stat.S_IMODE(st.st_mode))
            if st.st_size > limit:
                return Read("too_large", mode=stat.S_IMODE(st.st_mode))
            chunks, total = [], 0
            while total <= limit:
                chunk = os.read(fd, min(65536, limit + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            if total > limit:  # grew while we read it
                return Read("too_large", mode=stat.S_IMODE(st.st_mode))
            return Read("ok", b"".join(chunks), stat.S_IMODE(st.st_mode))
        except PermissionError:
            return Read("denied")
        except OSError:
            return Read("missing")
        finally:
            os.close(fd)

    def listdir(self, path: str) -> list[str] | None:
        real = self.resolve(path)
        if real is None:
            return None
        try:
            return sorted(os.listdir(real))
        except OSError:
            return None

    def walk(self, top: str, name_re: re.Pattern[str], max_files: int, max_size: int,
             stats: WalkStats) -> Iterator[str]:
        """Host paths of regular files under ``top`` whose host path matches ``name_re`` (no symlinks followed, one
        device, files up to ``max_size`` bytes)."""
        real_top = self.resolve(top)
        if real_top is None:
            return
        try:
            device = os.lstat(real_top).st_dev
        except OSError:
            return
        host_top = "/" + "/".join(p for p in top.split("/") if p)
        stack = [(real_top, host_top)]
        while stack:
            real_dir, host_dir = stack.pop()
            try:
                entries = sorted(os.scandir(real_dir), key=lambda e: e.name)
            except PermissionError:
                stats.denied_dirs += 1
                if len(stats.denied_examples) < 5:
                    stats.denied_examples.append(host_dir)
                continue
            except OSError:
                continue
            subdirs = []
            for entry in entries:
                host_path = f"{host_dir.rstrip('/')}/{entry.name}"
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    stats.symlinks += 1
                    continue
                if stat.S_ISDIR(st.st_mode):
                    if st.st_dev != device:
                        stats.other_devices += 1
                        continue
                    subdirs.append((entry.path, host_path))
                    continue
                if not stat.S_ISREG(st.st_mode) or st.st_size > max_size or not name_re.fullmatch(host_path):
                    continue
                if stats.files >= max_files:
                    stats.truncated = True
                    return
                stats.files += 1
                yield host_path
            stack.extend(reversed(subdirs))

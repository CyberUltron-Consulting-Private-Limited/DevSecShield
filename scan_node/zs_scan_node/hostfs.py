"""Read-only access to the host's file system as mounted into an agent-mode node (``ZS_HOST_ROOT``, default ``/host``).

Every path is resolved inside the mount the way a ``chroot`` would resolve it: an absolute symlink target is taken
relative to the host root and ``..`` never climbs above it.  Resolution works on descriptors, one component at a
time from a descriptor of the host root: each directory is opened with ``O_NOFOLLOW | O_DIRECTORY`` relative to its
parent's descriptor and a symlink is read with ``readlink(name, dir_fd=parent)``, so a host user who swaps a directory
for a symlink while the node reads cannot lead it outside the root (the kernel never resolves a whole path string).
The host's kernel file systems (``/proc``, ``/sys``, ``/dev``) are not read at all: their files are not inventory,
and the host's ``/proc/self`` would be the node process itself.  So a symlink on the host (``/etc/ssl/certs/x.pem ->
/usr/share/ca-certificates/...``) reads the host's file and never one of the node container's own files
(``/proc/self/environ``, ``/var/lib/zs-node``).  The final file is opened with ``O_NOFOLLOW | O_NONBLOCK`` and must be
a regular file (a FIFO or device never blocks or streams), and every read is capped.

The walk does not follow symlinks and stays on the device of the directory it starts in (like ``find -xdev``), so pod
volumes and other mounts under the host root are never searched.  It holds one open directory per level (no
directory is listed into memory), at most ``MAX_DEPTH`` levels, ``MAX_DIR_ENTRIES`` entries per directory and
``MAX_WALK_ENTRIES`` entries per collection, and stops when the job's stop flag (cancel, deadline) is set; what it
skips is counted in ``WalkStats`` for the coverage rows.
"""
from __future__ import annotations

import errno
import os
import re
import stat
from dataclasses import dataclass, field
from typing import Callable, Iterator

MAX_LINKS = 40
MAX_DEPTH = 48
MAX_DIR_ENTRIES = 50_000
MAX_WALK_ENTRIES = 1_000_000
STOP_EVERY = 512  # entries between two checks of the stop flag
KERNEL_DIRS = frozenset({"proc", "sys", "dev"})
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_FLAGS = os.O_RDONLY | _NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | _CLOEXEC
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _NOFOLLOW | _CLOEXEC  # a directory to list
# a directory passed through: O_PATH needs only search permission on it, like a path lookup (a 0711 home directory)
_PASS_FLAGS = (getattr(os, "O_PATH", 0) or os.O_RDONLY) | getattr(os, "O_DIRECTORY", 0) | _NOFOLLOW | _CLOEXEC


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
    entries: int = 0  # directory entries looked at, across every walk that shares these stats
    denied_dirs: int = 0
    other_devices: int = 0
    symlinks: int = 0
    too_deep: int = 0  # directories below MAX_DEPTH, not searched
    big_dirs: int = 0  # directories with more than MAX_DIR_ENTRIES entries, searched in part
    truncated: bool = False  # max_files reached
    entries_capped: bool = False  # MAX_WALK_ENTRIES reached
    stopped: str | None = None  # the job's stop reason, when the walk ended early for it
    denied_examples: list[str] = field(default_factory=list)
    big_examples: list[str] = field(default_factory=list)


def _parts(path: str) -> list[str]:
    return [p for p in str(path).split("/") if p not in ("", ".")]


class HostFS:
    def __init__(self, root: str) -> None:
        self.root = os.path.realpath(root or "/")

    def _join(self, parts: list[str]) -> str:
        return os.path.join(self.root, *parts) if parts else self.root

    def resolve(self, path: str) -> str | None:
        """The real path under the root for a host path (``/etc/os-release``), following symlinks inside the root
        only; None when a component is missing, under a kernel file system, or the link chain is too long.  For
        display and tests: files are opened with ``open_fd``, which does the same walk on descriptors."""
        todo = _parts(path)
        done: list[str] = []
        links = 0
        while todo:
            part = todo.pop(0)
            if part == "..":
                if done:
                    done.pop()
                continue
            if not done and part in KERNEL_DIRS:
                return None
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
                todo = _parts(target) + todo
                continue
            done.append(part)
        return self._join(done)

    def open_fd(self, path: str, directory: bool = False) -> int:
        """A descriptor of a host path, resolved inside the root on descriptors (see the module docstring).  The final
        component is opened with ``O_NOFOLLOW | O_NONBLOCK`` (``| O_DIRECTORY`` for ``directory``).  Raises
        OSError: FileNotFoundError for a missing path, one under /proc, /sys or /dev, or a link chain longer than
        MAX_LINKS; PermissionError when a directory on the way or the file is not readable."""
        todo = _parts(path)
        final = _DIR_FLAGS if directory else _O_FLAGS
        stack = [os.open(self.root, _PASS_FLAGS & ~_NOFOLLOW)]  # the mount point itself may be reached by a link
        links = 0
        try:
            while todo:
                part = todo.pop(0)
                if part == "..":
                    if len(stack) > 1:
                        os.close(stack.pop())
                    continue
                if len(stack) == 1 and part in KERNEL_DIRS:
                    raise FileNotFoundError(errno.ENOENT, "kernel file systems are not read", part)
                last = not todo
                try:
                    fd = os.open(part, final if last else _PASS_FLAGS, dir_fd=stack[-1])
                except OSError as exc:
                    if exc.errno not in (errno.ELOOP, errno.ENOTDIR):
                        raise
                    try:  # O_NOFOLLOW met a symlink: read it relative to the same parent descriptor
                        target = os.readlink(part, dir_fd=stack[-1])
                    except OSError as again:
                        if again.errno != errno.EINVAL or exc.errno == errno.ENOTDIR:
                            raise exc from None  # a file where a directory was needed, or gone
                        target = None  # it stopped being a symlink in between: look again
                    links += 1
                    if links > MAX_LINKS:
                        raise FileNotFoundError(errno.ELOOP, "too many symbolic links", path) from None
                    if target is None:
                        todo.insert(0, part)
                        continue
                    if target.startswith("/"):
                        while len(stack) > 1:
                            os.close(stack.pop())
                    todo = _parts(target) + todo
                    continue
                if last:
                    return fd
                stack.append(fd)
            # the path ended at a directory passed through (the root, '..', a link to a directory): open it for real
            return os.open(".", final, dir_fd=stack[-1])
        finally:
            for fd in stack:
                os.close(fd)

    def read(self, path: str, limit: int) -> Read:
        try:
            fd = self.open_fd(path)
        except PermissionError:
            return Read("denied")
        except OSError as exc:
            return Read("loop" if exc.errno == errno.ELOOP and not isinstance(exc, FileNotFoundError) else "missing")
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
        try:
            fd = self.open_fd(path, directory=True)
        except OSError:
            return None
        try:
            return sorted(os.listdir(fd))
        except OSError:
            return None
        finally:
            os.close(fd)

    def walk(self, top: str, name_re: re.Pattern[str], max_files: int, max_size: int, stats: WalkStats,
             stop: Callable[[], str | None] | None = None) -> Iterator[str]:
        """Host paths of regular files under ``top`` whose host path matches ``name_re`` (no symlinks followed, one
        device, files up to ``max_size`` bytes), depth first.  Memory does not grow with a directory's size."""
        if stats.truncated or stats.entries_capped or stats.stopped:
            return
        try:
            top_fd = self.open_fd(top, directory=True)
        except PermissionError:
            self._denied(stats, "/" + "/".join(_parts(top)))
            return
        except OSError:
            return
        levels: list[list] = []  # [fd, scandir iterator, host path, entries seen]
        try:
            device = os.fstat(top_fd).st_dev
            levels.append([top_fd, os.scandir(top_fd), "/" + "/".join(_parts(top)), 0])
        except OSError:
            os.close(top_fd)
            return
        try:
            while levels:
                level = levels[-1]
                fd, entries, host_dir = level[0], level[1], level[2]
                try:
                    entry = next(entries, None)
                except OSError:
                    entry = None
                if entry is None:
                    entries.close()
                    os.close(fd)
                    levels.pop()
                    continue
                level[3] += 1
                stats.entries += 1
                if level[3] > MAX_DIR_ENTRIES:  # the rest of this directory is not searched
                    stats.big_dirs += 1
                    if len(stats.big_examples) < 5:
                        stats.big_examples.append(host_dir)
                    entries.close()
                    os.close(fd)
                    levels.pop()
                    continue
                if stats.entries > MAX_WALK_ENTRIES:
                    stats.entries_capped = True
                    return
                if stop is not None and stats.entries % STOP_EVERY == 0:
                    reason = stop()
                    if reason:
                        stats.stopped = reason
                        return
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
                    if len(levels) >= MAX_DEPTH:
                        stats.too_deep += 1
                        continue
                    try:
                        sub = os.open(entry.name, _DIR_FLAGS, dir_fd=fd)
                    except PermissionError:
                        self._denied(stats, host_path)
                        continue
                    except OSError:  # gone, or swapped for a symlink since it was listed
                        continue
                    try:
                        if os.fstat(sub).st_dev != device:
                            stats.other_devices += 1
                            os.close(sub)
                            continue
                        listing = os.scandir(sub)
                    except PermissionError:
                        os.close(sub)
                        self._denied(stats, host_path)
                        continue
                    except OSError:
                        os.close(sub)
                        continue
                    levels.append([sub, listing, host_path, 0])
                    continue
                if not stat.S_ISREG(st.st_mode) or st.st_size > max_size or not name_re.fullmatch(host_path):
                    continue
                if stats.files >= max_files:
                    stats.truncated = True
                    return
                stats.files += 1
                yield host_path
        finally:
            for fd, entries, _host, _n in levels:
                entries.close()
                os.close(fd)

    @staticmethod
    def _denied(stats: WalkStats, host_path: str) -> None:
        stats.denied_dirs += 1
        if len(stats.denied_examples) < 5:
            stats.denied_examples.append(host_path)

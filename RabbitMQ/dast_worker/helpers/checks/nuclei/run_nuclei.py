import os
import signal
import subprocess
import tempfile
import threading
from helpers.general.dir_load import load_dir_to_documents
import shutil
from rich.console import Console
console = Console(markup=False)

_limiter_lock = threading.Lock()
_nuclei_limiter = threading.BoundedSemaphore(1)
_nuclei_limiter_n = 1

_TRUE = {"1", "true", "yes", "on"}


def set_nuclei_concurrency(n: int) -> int:
    """Cap parallel headless Nuclei/Chrome processes across the worker."""
    global _nuclei_limiter, _nuclei_limiter_n
    bounded = max(1, min(int(n), 32))
    with _limiter_lock:
        _nuclei_limiter = threading.BoundedSemaphore(bounded)
        _nuclei_limiter_n = bounded
    return bounded


def get_nuclei_concurrency() -> int:
    return _nuclei_limiter_n


def build_nuclei_command(
    url: str,
    template_path: str,
    timeout_seconds: int = 90,
    output_dir: str | None = None,
) -> list[str]:
    template_timeout = max(5, min(int(timeout_seconds), 180))
    command = [
        "nuclei",
        "-u",
        url,
        "-headless",
        "-t",
        template_path,
        "-timeout",
        str(template_timeout),
        "-retries",
        "0",
        "-ni",
        "-silent",
    ]
    if output_dir:
        command.extend(["-me", output_dir])
    return command


def _reap_enabled() -> bool:
    """Never pkill Chrome on a developer laptop. Docker / explicit opt-in only."""
    flag = os.getenv("DAST_REAP_BROWSERS")
    if flag is not None:
        return flag.strip().lower() in _TRUE
    return os.getenv("IS_DOCKER_CONTAINER", "False") == "True"


def _is_browser_comm(comm: str) -> bool:
    name = (comm or "").strip().lower()
    return name.startswith("chrome") or name.startswith("chromium")


def _browser_pids() -> set[int]:
    proc = "/proc"
    if not os.path.isdir(proc):
        return set()
    pids: set[int] = set()
    try:
        entries = os.listdir(proc)
    except OSError:
        return set()
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(os.path.join(proc, entry, "comm"), encoding="utf-8") as fh:
                comm = fh.read()
        except OSError:
            continue
        if _is_browser_comm(comm):
            pids.add(int(entry))
    return pids


def _iter_browser_procs():
    proc = "/proc"
    if not os.path.isdir(proc):
        return
    try:
        entries = os.listdir(proc)
    except OSError:
        return
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(os.path.join(proc, entry, "comm"), encoding="utf-8") as fh:
                comm = fh.read().strip()
            if not _is_browser_comm(comm):
                continue
            ppid = 0
            state = ""
            with open(os.path.join(proc, entry, "status"), encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("PPid:"):
                        ppid = int(line.split()[1])
                    elif line.startswith("State:"):
                        state = line.split()[1]
        except (OSError, ValueError, IndexError):
            continue
        yield pid, ppid, comm, state


def _kill_pid(pid: int) -> None:
    if pid <= 1:
        return
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _reap_new_browser_pids(before: set[int]) -> int:
    if not _reap_enabled():
        return 0
    extra = _browser_pids() - set(before)
    for pid in extra:
        _kill_pid(pid)
    return len(extra)


def reap_orphan_browsers(*, enabled=None, iter_procs=None, kill_fn=None) -> int:
    """Kill Chromium leftover with ppid=1 (Nuclei exited, Chrome did not)."""
    if enabled is None:
        enabled = _reap_enabled()
    if not enabled:
        return 0
    iterator = iter_procs or _iter_browser_procs
    killer = kill_fn or _kill_pid
    reaped = 0
    for pid, ppid, comm, state in iterator():
        if not _is_browser_comm(comm):
            continue
        if ppid == 1 or (state or "").startswith("Z"):
            killer(pid)
            reaped += 1
    if reaped:
        console.print(f"Reaped {reaped} orphan Chromium process(es)", style="bold yellow")
    return reaped


def run_nuclei(url: str, template_path: str, timeout_seconds: int = 90):
    temp_dir = None
    proc = None
    limiter = _nuclei_limiter
    limiter.acquire()
    try:
        temp_dir = tempfile.mkdtemp(prefix="nuclei_")
        command = build_nuclei_command(
            url=url,
            template_path=template_path,
            timeout_seconds=timeout_seconds,
            output_dir=temp_dir,
        )
        console.print(f"Running nuclei for {url} (timeout={timeout_seconds}s)", style="bold green")
        proc = subprocess.Popen(
            command,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            _, stderr = proc.communicate(timeout=int(timeout_seconds) + 20)
        except subprocess.TimeoutExpired:
            console.print(f"Nuclei timed out after {timeout_seconds}s for {url}", style="bold red")
            return []
        if proc.returncode != 0:
            err = (stderr or b"").decode("utf-8", "replace")[:300]
            console.print(f"Nuclei exited {proc.returncode} for {url}: {err}", style="bold red")
            return []
        documents = load_dir_to_documents(temp_dir)
        console.print(f"Loaded {len(documents)} documents from the temp directory", style="bold green")
        return documents
    except Exception as e:
        console.print(f"Error in nuclei: {str(e)}", style="bold red")
        return []
    finally:
        if proc is not None:
            _kill_process_group(proc)
        limiter.release()
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


def _kill_process_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:
            pass
    try:
        proc.wait(timeout=5)
    except Exception:
        pass

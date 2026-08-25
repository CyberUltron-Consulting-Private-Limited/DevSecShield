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


def run_nuclei(url: str, template_path: str, timeout_seconds: int = 90):
    temp_dir = None
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
            _kill_process_group(proc)
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

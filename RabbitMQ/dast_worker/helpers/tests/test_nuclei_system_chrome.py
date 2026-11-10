"""The DAST worker's nuclei uses the Chromium the image ships; nothing is downloaded at run time.

Found on the local production stack (round 5, L1): headless nuclei (authenticated page fetch, XSS, page analysis)
let go-rod download its own Chromium from storage.googleapis.com into /root/.cache/rod on first use: the
dast-worker container grew 581 MB, an air-gapped site cannot do it at all, and a Juice Shop scan logged
"Could not create runner: [launcher] Failed to get the debug url". Now nuclei runs with -system-chrome and the
Dockerfile links Playwright's Chromium as /usr/local/bin/chromium (what go-rod's LookPath finds).

Live proof (13:25 UTC Nov 10, image dss-staging/dast-worker:l1 + the link): the worker's command with
-system-chrome ran a headless template against http://backend:8080/docs (rc 0, page extracted) and
/root/.cache/rod did not exist afterwards ($S/ui/l1/bin/nuclei_syschrome.sh).

Run: cd RabbitMQ/dast_worker && python -m pytest helpers/tests/test_nuclei_system_chrome.py -q   (no worker deps needed)
"""
import importlib.util
import re
import sys
import types
from pathlib import Path

WORKER = Path(__file__).resolve().parents[2]


def _load_run_nuclei():
    # run_nuclei imports rich and the worker's document loader; stub them so this test needs no worker deps
    for name in ("rich", "rich.console"):
        sys.modules.setdefault(name, types.ModuleType(name))
    sys.modules["rich.console"].Console = lambda *a, **k: types.SimpleNamespace(print=lambda *a, **k: None)
    spec = importlib.util.spec_from_file_location("run_nuclei_under_test", WORKER / "helpers/checks/nuclei/run_nuclei.py")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except ImportError:
        return None
    return module


def test_nuclei_command_uses_the_system_chrome():
    text = (WORKER / "helpers/checks/nuclei/run_nuclei.py").read_text()
    body = text[text.index("def build_nuclei_command"):text.index("def _reap_enabled")]
    assert '"-headless"' in body and '"-system-chrome"' in body
    module = _load_run_nuclei()
    if module is not None:
        command = module.build_nuclei_command(url="https://example.com", template_path="/tmp/t.yaml")
        assert "-headless" in command and "-system-chrome" in command


def test_dockerfile_links_the_shipped_chromium_after_copying_it():
    dockerfile = (WORKER / "Dockerfile").read_text()
    runtime = dockerfile[dockerfile.rindex("\nFROM "):]
    copy = runtime.index("COPY --from=builder /root/.cache/ms-playwright /root/.cache/ms-playwright")
    link = re.search(r"ln -s \"\$\{chrome\}\" /usr/local/bin/chromium", runtime)
    assert link and link.start() > copy, "chromium must be linked in the runtime stage, after the browsers are copied"
    assert "test -x" in runtime[copy:link.start()], "the build must fail when the shipped Chromium is missing"

"""Customer QA on staging (14 Nov), checked on the files a customer downloads (the real node_artifacts.py output):

* #229: the Helm chart's README sent customers to https://api.zeroshield.ai, which does not exist, and talked about a
  repository checkout customers never have. No downloadable kit may name a zeroshield.ai host other than the company
  site itself; the API URL is the one the wizard shows.
* #228: the README commands put `sha256sum -c` and `docker load` / `packer build` on separate lines, so a tampered
  image file was used anyway. Each README block is RUN in bash (stub docker/helm/packer, the real sha256sum) with a
  genuine and a tampered image file: nothing is loaded, pushed, installed or built after a failed check.
* #230: the OVA/AMI kits download Ubuntu and run apt-get while building; their READMEs say so up front and name the
  offline ways (the image file, Helm with your own registry)."""
from __future__ import annotations

import io
import re
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest
from test_staging_node_artifacts import VERSION, make_artifacts

pytestmark = pytest.mark.skipif(shutil.which("bash") is None or shutil.which("sha256sum") is None,
                                reason="needs bash and sha256sum")

ALLOWED_HOSTS = {"zeroshield.ai"}  # the company site (Chart.yaml home, the unit's Documentation=)
HOST = re.compile(r"(?<![A-Za-z0-9.-])((?:[A-Za-z0-9-]+\.)*zeroshield\.ai)\b", re.I)


@pytest.fixture(scope="module")
def kits(tmp_path_factory) -> dict[str, dict[str, str]]:
    """{download file name: {member path: text}} of every downloadable kit, as a customer unpacks it."""
    out = tmp_path_factory.mktemp("node-artifacts")
    files = make_artifacts(out)["files"]
    texts: dict[str, dict[str, str]] = {}
    for key, name in files.items():
        data = (out / name).read_bytes()
        members: dict[str, str] = {}
        if name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                members = {n: zf.read(n).decode("utf-8", "replace") for n in zf.namelist() if not n.endswith("/")}
        elif name.endswith(".tgz"):
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                members = {m.name: tf.extractfile(m).read().decode("utf-8", "replace") for m in tf.getmembers() if m.isfile()}
        if members:
            texts[name] = members
    assert {n for n in texts} == {f"cbom-scan-node-{VERSION}.tgz", f"cbom-scan-node-ova-kit-{VERSION}.zip",
                                  f"cbom-scan-node-ami-kit-{VERSION}.zip"}
    return texts


def _member(kits, suffix: str) -> str:
    found = [text for members in kits.values() for path, text in members.items() if path.endswith(suffix)]
    assert len(found) == 1, suffix
    return found[0]


# ------------------------------------------------------------------------------------------------ #229
def test_no_kit_names_a_zeroshield_host_that_does_not_exist(kits):
    for kit, members in kits.items():
        for path, text in members.items():
            hosts = {h.lower() for h in HOST.findall(text)}
            assert hosts <= ALLOWED_HOSTS, (kit, path, sorted(hosts - ALLOWED_HOSTS))


def test_the_chart_readme_uses_the_wizards_api_url_and_no_repository(kits):
    readme = _member(kits, "cbom-scan-node/README.md")
    assert "the API URL shown in the Add scan node wizard" in readme
    assert '--set apiUrl="$ZS_API_URL"' in readme
    for internal in ("From a checkout", "deploy/helm/", "scripts/release/", "make node-image"):
        assert internal not in readme, internal


def test_the_repository_docs_use_the_placeholder_too():
    root = Path(__file__).resolve().parents[2]
    for rel in ("scan_node/README.md", "deploy/node-images/README.md", "deploy/helm/cbom-scan-node/README.md"):
        assert "api.zeroshield.ai" not in (root / rel).read_text(), rel


# ------------------------------------------------------------------------------------------------ #228
STUBS = {
    "docker": 'echo "docker $1" >> "$LOG"',
    "helm": 'echo "helm $1" >> "$LOG"',
    "packer": 'echo "packer $1" >> "$LOG"',
    "openssl": "echo 0123456789abcdef",
    "unzip": 'z=${@: -1}; mkdir -p "${z%.zip}"',
}


def _blocks(readme: str) -> list[str]:
    return re.findall(r"```sh\n(.*?)```", readme, re.S)


def _run(tmp_path: Path, script: str, tampered: bool) -> list[str]:
    bin_dir, host = tmp_path / "bin", tmp_path / "host"
    for d in (bin_dir, host):
        d.mkdir(exist_ok=True)
    for name, body in STUBS.items():
        (bin_dir / name).write_text(f"#!/usr/bin/env bash\n{body}\n")
        (bin_dir / name).chmod(0o755)
    image = f"scan-node-{VERSION}.tar.gz"
    genuine = b"docker-save-archive"
    (host / image).write_bytes(genuine + (b"x" if tampered else b""))
    digest = subprocess.run(["sha256sum"], input=genuine, capture_output=True, check=True).stdout.split()[0].decode()
    (host / f"{image}.sha256").write_text(f"{digest}  {image}\n")
    # the README's placeholders, as a customer fills them in
    script = script.replace("/path/to/", "./").replace("'<the API URL shown in the Add scan node wizard>'", "'https://api.bank.example'")
    script = re.sub(r"^unzip (\S+) && cd (\S+) && ", lambda m: f"mkdir -p {m.group(2)} && cd {m.group(2)} && ", script, flags=re.M)
    script = script.replace("cp ./" + image + " ./" + image + ".sha256 .", f"cp ../{image} ../{image}.sha256 .")
    log = tmp_path / "log"
    log.unlink(missing_ok=True)
    proc = subprocess.run(["bash", "-c", script], cwd=host, capture_output=True, text=True, timeout=60,
                          env={"PATH": f"{bin_dir}:/usr/bin:/bin", "LOG": str(log), "HOME": str(tmp_path)})
    assert subprocess.run(["bash", "-n", "-c", script]).returncode == 0, script
    steps = log.read_text().split("\n") if log.exists() else []
    return [s for s in steps if s] + ([f"exit {proc.returncode}"] if proc.returncode else [])


def test_the_chart_readme_install_stops_on_a_tampered_image(kits, tmp_path):
    block = _blocks(_member(kits, "cbom-scan-node/README.md"))[0]
    assert _run(tmp_path, block, tampered=False) == ["docker load", "docker tag", "docker push", "helm upgrade"]
    steps = _run(tmp_path, block, tampered=True)
    assert not [s for s in steps if not s.startswith("exit")], steps
    assert steps and steps[-1] != "exit 0"


@pytest.mark.parametrize("kind", ["ova", "ami"])
def test_the_kit_readme_build_stops_on_a_tampered_image(kits, tmp_path, kind):
    block = _blocks(_member(kits, f"cbom-scan-node-{kind}-kit-{VERSION}/README.md"))[0]
    assert _run(tmp_path, block, tampered=False) == ["packer init", "packer build"]
    steps = _run(tmp_path, block, tampered=True)
    assert not [s for s in steps if s.startswith("packer")], steps


# ------------------------------------------------------------------------------------------------ #230
@pytest.mark.parametrize("kind,downloads", [("ova", ("cloud-images.ubuntu.com", "apt-get", "packer init")),
                                            ("ami", ("Canonical", "apt-get", "packer init"))])
def test_the_kit_readmes_say_the_build_needs_internet_and_name_the_offline_ways(kits, kind, downloads):
    readme = _member(kits, f"cbom-scan-node-{kind}-kit-{VERSION}/README.md")
    head = readme.split("## What you need", 1)[0]
    assert "needs internet access" in head, "said before anything else"
    assert "## Needs internet access to build" in readme
    for word in downloads:
        assert word in readme, word
    assert "scan node image file" in readme and "Helm" in readme and "own registry" in readme


def test_the_install_script_really_downloads_what_the_readme_says():
    root = Path(__file__).resolve().parents[2]
    install = (root / "deploy/node-images/scripts/install.sh").read_text()
    assert "apt-get update" in install and "apt-get install" in install
    assert "cloud-images.ubuntu.com" in (root / "deploy/node-images/ova.pkr.hcl").read_text()

"""WP8b: the VM images' first-boot path (deploy/node-images): vApp properties -> /etc/zs-node/env -> docker run.

The Packer builds themselves need AWS or KVM and are not run here; these tests check the scripts the images run
and that the templates, the OVF descriptor and the UI's install text agree with each other."""
from __future__ import annotations

import os
import stat
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
IMAGES = REPO / "deploy" / "node-images"
pytestmark = pytest.mark.skipif(not IMAGES.exists(), reason="deploy/node-images not in this checkout")

OVF_ENV = """<?xml version="1.0" encoding="UTF-8"?>
<Environment xmlns="http://schemas.dmtf.org/ovf/environment/1" xmlns:oe="http://schemas.dmtf.org/ovf/environment/1">
  <PropertySection>
    <Property oe:key="zs.api_url" oe:value="https://api.zeroshield.ai"/>
    <Property oe:key="zs.registration_token" oe:value="zsr_abcdefghijklmnopqrstu"/>
    <Property oe:key="zs.https_proxy" oe:value="http://proxy.bank.local:8080 ; rm -rf /"/>
    <Property oe:key="zs.mode" oe:value=""/>
    <Property oe:key="other.key" oe:value="ignored"/>
  </PropertySection>
</Environment>
"""


def _exe(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o755)


def test_ovf_environment_becomes_the_node_env_file(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (tmp_path / "ovfenv.xml").write_text(OVF_ENV)
    _exe(bin_dir / "vmtoolsd", f"#!/bin/sh\ncat {tmp_path / 'ovfenv.xml'}\n")
    env_file = tmp_path / "etc" / "env"
    run = subprocess.run(["python3", str(IMAGES / "files" / "zs-ovf-env")], capture_output=True, text=True,
                         env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "ZS_NODE_ENV": str(env_file)})
    assert run.returncode == 0, run.stderr
    assert env_file.read_text() == "ZS_API_URL=https://api.zeroshield.ai\nZS_REGISTRATION_TOKEN=zsr_abcdefghijklmnopqrstu\n"
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert "zs.https_proxy has characters that are not allowed" in run.stderr  # never written into the env file
    (tmp_path / "ovfenv.xml").write_text(OVF_ENV.replace("https://api.zeroshield.ai", "https://changed.example"))
    subprocess.run(["python3", str(IMAGES / "files" / "zs-ovf-env")], check=True, capture_output=True,
                   env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "ZS_NODE_ENV": str(env_file)})
    assert "changed" not in env_file.read_text()  # written once, at first boot


def _node_run(tmp_path, env_text: str):
    (tmp_path / "env").write_text(env_text)
    (tmp_path / "image").write_text("localhost/zeroshield/cbom-scan-node:1.0.0\n")
    _exe(tmp_path / "docker", f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {tmp_path / 'argv'}\n")
    run = subprocess.run(["sh", str(IMAGES / "files" / "zs-node-run")], capture_output=True, text=True,
                         env={**os.environ, "ZS_NODE_ENV": str(tmp_path / "env"),
                              "ZS_NODE_IMAGE_FILE": str(tmp_path / "image"), "ZS_DOCKER": str(tmp_path / "docker")})
    argv = (tmp_path / "argv").read_text().splitlines() if (tmp_path / "argv").exists() else []
    return run, argv


def test_node_run_starts_the_container_with_the_env_file(tmp_path):
    # the cloud-config the wizard shows for the AMI (logic.ts installCommand "ami") writes exactly these lines
    run, argv = _node_run(tmp_path, "ZS_API_URL=https://api.zeroshield.ai\nZS_REGISTRATION_TOKEN=zsr_x\n")
    assert run.returncode == 0, run.stderr
    assert argv[:4] == ["run", "--rm", "--name", "zs-scan-node"]
    assert argv[argv.index("--env-file") + 1] == str(tmp_path / "env")
    assert "zs-node:/var/lib/zs-node" in argv and argv[-1] == "localhost/zeroshield/cbom-scan-node:1.0.0"
    assert "/:/host:ro" not in argv


def test_node_run_in_agent_mode_mounts_the_vm_read_only(tmp_path):
    run, argv = _node_run(tmp_path, "ZS_API_URL=https://api.zeroshield.ai\nZS_REGISTRATION_TOKEN=zsr_x\nZS_MODE=agent\n")
    assert run.returncode == 0, run.stderr
    assert "/:/host:ro" in argv and "ZS_HOST_ROOT=/host" in argv
    run, argv = _node_run(tmp_path, "ZS_REGISTRATION_TOKEN=zsr_x\n")
    assert run.returncode == 64 and "ZS_API_URL is not set" in run.stderr


def test_ovf_descriptor_properties_match_the_wizard_and_the_reader():
    text = (IMAGES / "ovf" / "zs-scan-node.ovf.in").read_text()
    filled = (text.replace("@VERSION@", "1.0").replace("@DISK@", "d.vmdk").replace("@SIZE@", "1")
              .replace("@CAPACITY@", "17179869184"))
    root = ET.fromstring(filled)
    ns = {"o": "http://schemas.dmtf.org/ovf/envelope/1"}
    keys = {p.get("{http://schemas.dmtf.org/ovf/envelope/1}key") for p in root.iterfind(".//o:Property", ns)}
    reader = (IMAGES / "files" / "zs-ovf-env").read_text()
    wizard = (REPO / "frontend" / "components" / "cbom" / "sources" / "logic.ts").read_text()
    for key in ("zs.api_url", "zs.registration_token", "zs.https_proxy"):
        assert key in keys and f'"{key}"' in reader and f"{key} = " in wizard
    hardware = root.find(".//o:VirtualHardwareSection", ns)
    assert hardware.get("{http://schemas.dmtf.org/ovf/envelope/1}transport") == "com.vmware.guestInfo"


def test_packer_templates_reference_files_that_exist():
    for template in ("ami.pkr.hcl", "ova.pkr.hcl"):
        text = (IMAGES / template).read_text()
        for ref in ("files/zs-node-run", "files/zs-scan-node.service", "scripts/install.sh"):
            assert ref in text and (IMAGES / ref).exists(), (template, ref)
        assert "ubuntu" in text.lower() and "24.04" in text
    assert "099720109477" in (IMAGES / "ami.pkr.hcl").read_text()  # Canonical's AWS account
    ova = (IMAGES / "ova.pkr.hcl").read_text()
    assert "files/zs-ovf-env" in ova and "scripts/make-ova.sh" in ova and (IMAGES / "scripts" / "make-ova.sh").exists()
    unit = (IMAGES / "files" / "zs-scan-node.service").read_text()
    assert "ConditionPathExists=/etc/zs-node/env" in unit and "ExecStart=/usr/local/sbin/zs-node-run" in unit

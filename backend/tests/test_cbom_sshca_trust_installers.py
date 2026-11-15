"""Issue #83: Salt, Ansible and SSM install the SSH CA trust files the same way the fetch script does.

The token stays in the transport's secret store. These artifacts do not need a zs-collect release.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

from test_cbom_sources_api import api, world
from backend.utilities.cbom_sources.sshca.fetch_script import trust_fetch_script

FIXTURES = (api, world)  # the shared CBOM Sources fixtures, used by name below
BASE = "/1/cbom/sources/fleet/transports"
NAMES = ("sshca-trust-salt", "sshca-trust-ansible", "sshca-trust-ssm")
_TOKEN = re.compile(r"zst_[A-Za-z0-9_-]{40}")


@pytest.fixture(autouse=True)
def _flags(monkeypatch):
    monkeypatch.setenv("CBOM_FLEET_TRANSPORTS", "1")
    monkeypatch.setenv("CBOM_SSH_CA", "1")


def _script_in(name: str, body: dict) -> str:
    if name == "sshca-trust-salt":
        return body["files"]["zeroshield/zs-trust-fetch.sh"]
    if name == "sshca-trust-ansible":
        return body["files"]["roles/zs_cbom_sshca_trust/files/zs-trust-fetch.sh"]
    lines = body["content"]["mainSteps"][0]["inputs"]["runCommand"]
    start = lines.index("cat > /usr/local/sbin/zs-trust-fetch <<'ZS_TRUST_FETCH_EOF'") + 1
    end = lines.index("ZS_TRUST_FETCH_EOF")
    return "\n".join(lines[start:end]) + "\n"


def _sh_ok(text: str) -> None:
    if not shutil.which("sh"):
        return
    ran = subprocess.run(["sh", "-n", "-c", text], check=False, capture_output=True, text=True)
    assert ran.returncode == 0, ran.stderr


def test_installers_need_no_release_and_embed_the_page_script(api):
    page = api("GET", "/1/cbom/sources/fleet/ssh-ca/templates/trust-fetch").text
    assert page == trust_fetch_script(1)
    for needle in ("If-None-Match", "X-ZS-Trust-Token", "X-ZS-Fetcher", "ssh-keygen -Q -l -f",
                   "chmod 0644", "mv -f", 'mktemp "$dest.new.XXXXXX"', "keeping $dest", '[ ! -s "$tmp" ]'):
        assert needle in page, needle
    check = page.index("if sshd -t;")
    assert check < page.index('sh -c "${ZS_RELOAD:-systemctl reload ssh', check)
    _sh_ok(page)
    for name in NAMES:
        response = api("GET", BASE + "/artifacts/" + name)
        assert response.status_code == 200, response.text
        body = response.json()
        assert _script_in(name, body) == page
        assert _TOKEN.search(json.dumps(body)) is None
        assert "BEGIN OPENSSH PRIVATE KEY" not in response.text and "AKIA" not in response.text


def test_salt_reads_the_pillar_and_refreshes_with_splay(api):
    body = api("GET", BASE + "/artifacts/sshca-trust-salt").json()["files"]
    state = body["zeroshield/sshca_trust.sls"]
    assert "team 1" in state and "contents_pillar: zs_cbom_trust_token" in state and 'mode: "0600"' in state
    assert "minutes: 5" in state and "splay: 120" in state and "enabled: true" in state
    assert "salt://zeroshield/zs-trust-fetch.sh" in state and "salt://zeroshield/zs-cbom-trust-run.sh" in state
    assert "zs_cbom_trust_token" not in body["zeroshield/zs-cbom-trust-run.sh"]
    _sh_ok(body["zeroshield/zs-cbom-trust-run.sh"])
    rendered = trust_fetch_script(7)
    assert "team 7" in rendered and "zs-7-" in rendered and "team 1" not in rendered


def test_ansible_reads_the_credential_environment_and_schedules_five_minutes(api):
    files = api("GET", BASE + "/artifacts/sshca-trust-ansible").json()["files"]
    tasks = files["roles/zs_cbom_sshca_trust/tasks/main.yml"]
    assert "lookup('env', 'ZS_TRUST_TOKEN')" in tasks and "no_log: true" in tasks
    assert "121 | random" in tasks and 'mode: "0755"' in tasks
    assert "INTERVAL=5" in files["awx-schedule.yml"] and "FREQ=MINUTELY" in files["awx-schedule.yml"]
    assert "zs_cbom_sshca_trust" in files["zs-cbom-trust.yml"]
    defaults = files["roles/zs_cbom_sshca_trust/defaults/main.yml"]
    assert 'zs_url: ""' in defaults and "zst_" not in defaults


def test_ssm_document_reads_a_securestring_and_rejects_shell_metacharacters(api):
    body = api("GET", BASE + "/artifacts/sshca-trust-ssm").json()
    assert body["name"] == "devsecshield-sshca-trust"
    document = body["content"]
    assert document["mainSteps"][0]["inputs"]["timeoutSeconds"] == "300"
    command = "\n".join(document["mainSteps"][0]["inputs"]["runCommand"])
    assert "aws ssm get-parameter" in command and "--with-decryption" in command
    assert "/dev/urandom" in command and "% 121" in command and "exec /usr/local/sbin/zs-trust-fetch" in command
    assert "?" * 44 in command  # the token must be exactly zst_ plus 40 characters
    _sh_ok(command)
    params = document["parameters"]
    assert params["TrustTokenParameter"]["default"] == "/zeroshield/cbom/ssh-ca-trust-token"
    assert re.fullmatch(params["TrustTokenParameter"]["allowedPattern"], params["TrustTokenParameter"]["default"])
    assert re.fullmatch(params["TrustTokenParameter"]["allowedPattern"], "/x;rm") is None
    assert re.fullmatch(params["TrustTokenParameter"]["allowedPattern"], "/$(id)") is None
    assert re.fullmatch(params["ZsUrl"]["allowedPattern"], "https://api.example.invalid")
    assert re.fullmatch(params["ZsUrl"]["allowedPattern"], "http://api.example.invalid") is None
    assert re.fullmatch(params["ZsUrl"]["allowedPattern"], "https://api.example.invalid/$(id)") is None
    assert re.fullmatch(params["ZsGroups"]["allowedPattern"], "")
    assert re.fullmatch(params["ZsGroups"]["allowedPattern"], "prod edge")
    assert re.fullmatch(params["ZsGroups"]["allowedPattern"], "prod;edge") is None
    association = body["association"]
    assert association["Name"] == body["name"] and association["ScheduleExpression"] == "rate(5 minutes)"
    assert association["Parameters"]["ZsUrl"] == ["https://api.example.invalid"]


def test_installers_are_absent_while_the_fleet_flag_is_off(api, monkeypatch):
    monkeypatch.setenv("CBOM_FLEET_TRANSPORTS", "0")
    for name in NAMES:
        assert api("GET", BASE + "/artifacts/" + name).status_code == 404


def test_a_bad_team_id_is_refused():
    with pytest.raises(ValueError):
        trust_fetch_script(0)
    with pytest.raises(ValueError):
        trust_fetch_script(True)  # type: ignore[arg-type]

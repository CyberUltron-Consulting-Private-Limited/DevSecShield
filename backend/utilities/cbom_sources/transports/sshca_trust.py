"""SSH CA trust installers served next to the zs-collect transport artifacts (issue #83).

Salt, Ansible (AWX / AAP) and SSM each install the same trust-fetch script the SSH CA page serves, and
run it every 5 minutes with jitter. The trust token stays in that transport's secret store (a Salt
pillar, an AWX credential's environment, an SSM SecureString). None of these files contain a token.
"""
from __future__ import annotations

from typing import Any

from backend.utilities.cbom_sources.sshca.fetch_script import trust_fetch_script

NAMES = ("sshca-trust-salt", "sshca-trust-ansible", "sshca-trust-ssm")
DOCUMENT = "devsecshield-sshca-trust"
# zst_ + 40 characters. Checked by length only, so this file never contains a token prefix.
_TOKEN_LENGTH = 44
_MARKER = "ZS_TRUST_FETCH_EOF"

_URL_PATTERN = r"^https://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$"
_GROUPS_PATTERN = r"^$|^[a-z0-9][a-z0-9._-]{0,47}( [a-z0-9][a-z0-9._-]{0,47}){0,15}$"
_PARAM_PATTERN = r"^/[A-Za-z0-9_./-]{1,256}$"

_RUNNER = """#!/bin/sh
# Reads the trust token from the root-only file the Salt state wrote from the pillar. The token is not
# an argument, so it is not in the schedule. Jitter is the schedule's splay.
set -eu
DIR=/etc/ssh/zs-cbom
ZS_TRUST_TOKEN="$(tr -d '\\r\\n' < "$DIR/trust-token")"
ZS_URL="$(tr -d '\\r\\n' < "$DIR/api-url")"
ZS_GROUPS="$(tr '\\r\\n' '  ' < "$DIR/groups" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr -s ' ')"
export ZS_TRUST_TOKEN ZS_URL ZS_GROUPS
exec /usr/local/sbin/zs-trust-fetch
"""

_SALT = """# ZeroShield CBOM SSH CA trust (team @TEAM_ID@).
# Token: Salt pillar zs_cbom_trust_token, stored mode 0600. This file does not contain it.
# Also set pillar zs_cbom_url (https API address) and zs_cbom_groups (space-separated, may be empty).
# Refresh: salt schedule every 5 minutes, splay 120 seconds. One apply also fetches immediately.
{%- set groups = salt['pillar.get']('zs_cbom_groups', '') | string %}
/etc/ssh/zs-cbom:
  file.directory:
    - user: root
    - group: root
    - mode: "0755"

/usr/local/sbin/zs-trust-fetch:
  file.managed:
    - source: salt://zeroshield/zs-trust-fetch.sh
    - user: root
    - group: root
    - mode: "0755"

/usr/local/sbin/zs-cbom-trust-run:
  file.managed:
    - source: salt://zeroshield/zs-cbom-trust-run.sh
    - user: root
    - group: root
    - mode: "0755"

/etc/ssh/zs-cbom/trust-token:
  file.managed:
    - contents_pillar: zs_cbom_trust_token
    - user: root
    - group: root
    - mode: "0600"
    - require:
      - file: /etc/ssh/zs-cbom

/etc/ssh/zs-cbom/api-url:
  file.managed:
    - contents_pillar: zs_cbom_url
    - user: root
    - group: root
    - mode: "0644"
    - require:
      - file: /etc/ssh/zs-cbom

/etc/ssh/zs-cbom/groups:
  file.managed:
    - contents: |
        {{ groups | replace('\\n', ' ') }}
    - user: root
    - group: root
    - mode: "0644"
    - require:
      - file: /etc/ssh/zs-cbom

zs-cbom-trust-now:
  cmd.run:
    - name: /usr/local/sbin/zs-cbom-trust-run
    - require:
      - file: /usr/local/sbin/zs-trust-fetch
      - file: /usr/local/sbin/zs-cbom-trust-run
      - file: /etc/ssh/zs-cbom/trust-token
      - file: /etc/ssh/zs-cbom/api-url
      - file: /etc/ssh/zs-cbom/groups

zs-cbom-trust-fetch:
  schedule.present:
    - function: cmd.run
    - job_args:
      - /usr/local/sbin/zs-cbom-trust-run
    - minutes: 5
    - splay: 120
    - maxrunning: 1
    - enabled: true
    - return_job: false
    - require:
      - file: /usr/local/sbin/zs-cbom-trust-run
"""

_ANSIBLE_TASKS = """---
# Token: AWX custom credential injector env ZS_TRUST_TOKEN. Nothing here is a token.
- name: Wait 0-120 seconds so a 5-minute schedule does not hit every host together
  ansible.builtin.command: "sleep {{ 121 | random }}"
  changed_when: false

- name: The trust token is in the job environment
  ansible.builtin.assert:
    that:
      - lookup('env', 'ZS_TRUST_TOKEN') | length > 0
    fail_msg: Inject ZS_TRUST_TOKEN from an AWX credential (environment), not extra vars.
  no_log: true

- name: The API address is https
  ansible.builtin.assert:
    that:
      - zs_url is match('^https://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$')
    fail_msg: Set zs_url to ZeroShield's https API address.

- name: Groups are empty or a space-separated list of server groups
  ansible.builtin.assert:
    that:
      - zs_groups is match('^$|^[a-z0-9][a-z0-9._-]{0,47}( [a-z0-9][a-z0-9._-]{0,47})*$')
    fail_msg: zs_groups is space-separated server groups (letters, digits, . _ -).

- name: Install the trust-fetch script
  ansible.builtin.copy:
    src: zs-trust-fetch.sh
    dest: /usr/local/sbin/zs-trust-fetch
    owner: root
    group: root
    mode: "0755"

- name: Refresh SSH CA trust
  ansible.builtin.command: /usr/local/sbin/zs-trust-fetch
  environment:
    ZS_TRUST_TOKEN: "{{ lookup('env', 'ZS_TRUST_TOKEN') }}"
    ZS_URL: "{{ zs_url }}"
    ZS_GROUPS: "{{ zs_groups }}"
  no_log: true
"""

_ANSIBLE_DEFAULTS = """---
# No trust token belongs in defaults. AWX injects ZS_TRUST_TOKEN into the environment.
zs_url: ""
zs_groups: ""
"""

_ANSIBLE_PLAY = """---
# Job template name: zs-cbom-trust. Limit it to the Linux servers that trust this CA.
- name: Keep SSH CA trust current
  hosts: all
  become: true
  gather_facts: false
  roles:
    - zs_cbom_sshca_trust
"""

_ANSIBLE_SCHEDULE = """---
# Run once, on AWX, with a controller credential. Jitter is the sleep in the role, not this rule.
- name: Schedule the SSH CA trust refresh
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Every 5 minutes
      awx.awx.schedule:
        name: zs-cbom-sshca-trust
        unified_job_template: "{{ zs_job_template | default('zs-cbom-trust') }}"
        rrule: "DTSTART:20261115T000000Z RRULE:FREQ=MINUTELY;INTERVAL=5"
        enabled: true
"""


def _salt(script: str, team_id: int) -> dict[str, str]:
    return {
        "zeroshield/sshca_trust.sls": _SALT.replace("@TEAM_ID@", str(team_id)),
        "zeroshield/zs-trust-fetch.sh": script,
        "zeroshield/zs-cbom-trust-run.sh": _RUNNER,
    }


def _ansible(script: str) -> dict[str, str]:
    root = "roles/zs_cbom_sshca_trust"
    return {
        "zs-cbom-trust.yml": _ANSIBLE_PLAY,
        "awx-schedule.yml": _ANSIBLE_SCHEDULE,
        f"{root}/tasks/main.yml": _ANSIBLE_TASKS,
        f"{root}/defaults/main.yml": _ANSIBLE_DEFAULTS,
        f"{root}/files/zs-trust-fetch.sh": script,
    }


def _ssm(script: str) -> dict[str, Any]:
    if _MARKER in script:
        raise RuntimeError("trust-fetch script collides with the SSM heredoc marker")
    lines = [
        "set -eu",
        "umask 077",
        # /bin/sh on Debian is dash, which has no RANDOM. Two bytes of urandom give the 0-120s jitter.
        "sleep $(( $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 121 ))",
        "mkdir -p /usr/local/sbin /etc/ssh/zs-cbom",
        f"cat > /usr/local/sbin/zs-trust-fetch <<'{_MARKER}'",
        *script.rstrip("\n").split("\n"),
        _MARKER,
        "chmod 0755 /usr/local/sbin/zs-trust-fetch",
        ("token=\"$(aws ssm get-parameter --name '{{ TrustTokenParameter }}' "
         "--with-decryption --query Parameter.Value --output text)\" || exit 1"),
        "case \"$token\" in",
        f"  {'?' * _TOKEN_LENGTH}) ;;",
        "  *) echo \"zs-trust-fetch: trust token parameter is unusable; the files on disk were kept\" >&2; exit 1 ;;",
        "esac",
        "export ZS_TRUST_TOKEN=\"$token\"",
        "unset token",
        "export ZS_URL='{{ ZsUrl }}'",
        "export ZS_GROUPS='{{ ZsGroups }}'",
        "exec /usr/local/sbin/zs-trust-fetch",
    ]
    document = {
        "schemaVersion": "2.2",
        "description": (
            f"ZeroShield CBOM SSH CA trust ({DOCUMENT}). Reads the trust token at run time from an SSM "
            "SecureString (ssm:GetParameter and kms:Decrypt on that parameter for the instance). "
            "The token is not stored in this document. Sleeps 0-120 seconds, then installs and runs "
            "the trust-fetch script. The sample association's ZsUrl is https://api.example.invalid; "
            "replace it with the API address before creating the association."
        ),
        "parameters": {
            "TrustTokenParameter": {
                "type": "String",
                "default": "/zeroshield/cbom/ssh-ca-trust-token",
                "allowedPattern": _PARAM_PATTERN,
                "description": "Name of the SecureString parameter that holds the trust token",
            },
            "ZsUrl": {
                "type": "String",
                "allowedPattern": _URL_PATTERN,
                "description": "ZeroShield API address (https), the one the scan nodes use",
            },
            "ZsGroups": {
                "type": "String",
                "default": "",
                "allowedPattern": _GROUPS_PATTERN,
                "description": "This server's groups, space-separated (principals zs-<team>-<group>)",
            },
        },
        "mainSteps": [{
            "action": "aws:runShellScript",
            "name": "sshCaTrust",
            "precondition": {"StringEquals": ["platformType", "Linux"]},
            "inputs": {"timeoutSeconds": "300", "runCommand": lines},
        }],
    }
    association = {
        "Name": DOCUMENT,
        "AssociationName": "zs-cbom-sshca-trust",
        "ScheduleExpression": "rate(5 minutes)",
        "Parameters": {
            "TrustTokenParameter": ["/zeroshield/cbom/ssh-ca-trust-token"],
            # .invalid is reserved (RFC 2606). Replace it with the API address before creating the association.
            "ZsUrl": ["https://api.example.invalid"],
            "ZsGroups": [""],
        },
    }
    return {"name": DOCUMENT, "content": document, "association": association}


def render(name: str, team_id: int) -> tuple[str, Any]:
    """(media type, body). Raises KeyError for another name."""
    if name not in NAMES:
        raise KeyError(name)
    script = trust_fetch_script(team_id)
    if name == "sshca-trust-salt":
        return "application/json", {"files": _salt(script, team_id)}
    if name == "sshca-trust-ansible":
        return "application/json", {"files": _ansible(script)}
    return "application/json", _ssm(script)

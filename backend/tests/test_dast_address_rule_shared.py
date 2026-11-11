"""The backend's DAST URL check and the DAST worker's connect-time check apply ONE address rule.

The worker image cannot import the backend, so address_rule.py exists twice; these tests fail when the two copies
differ, and pin the rule's decisions (metadata refused even when the operator lists it).

Run (repo root): backend/.venv/bin/python -m pytest backend/tests/test_dast_address_rule_shared.py -q -p no:cacheprovider
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from backend.utilities.dast import address_rule  # noqa: E402
from backend.utilities.dast.address_rule import DastSsrfError, checked_addresses, parse_allowlist  # noqa: E402

BACKEND_COPY = REPO / "backend" / "utilities" / "dast" / "address_rule.py"
WORKER_COPY = REPO / "RabbitMQ" / "dast_worker" / "helpers" / "net" / "address_rule.py"


def test_backend_and_worker_rule_files_are_byte_identical():
    assert WORKER_COPY.read_bytes() == BACKEND_COPY.read_bytes(), (
        "RabbitMQ/dast_worker/helpers/net/address_rule.py drifted from backend/utilities/dast/address_rule.py; "
        "copy the changed file over the other one")


def test_backend_ssrf_uses_the_shared_rule():
    from backend.utilities.dast import ssrf

    assert ssrf.DastSsrfError is address_rule.DastSsrfError
    assert ssrf.ENV_ALLOWED_PRIVATE == "DAST_ALLOWED_PRIVATE"


@pytest.mark.parametrize("address", ["169.254.169.254", "169.254.1.1", "fe80::1", "fd00:ec2::254",
                                     "::ffff:169.254.169.254", "0.0.0.0", "224.0.0.1"])
def test_metadata_link_local_unspecified_multicast_refused_even_when_listed(address):
    everything = parse_allowlist("0.0.0.0/0,::/0,meta.example")
    with pytest.raises(DastSsrfError):
        checked_addresses("meta.example", everything, lambda _h: [address])
    with pytest.raises(DastSsrfError):
        checked_addresses(address, everything, lambda _h: [])


@pytest.mark.parametrize("address", ["10.0.0.5", "172.17.0.2", "192.168.1.1", "127.0.0.1", "100.64.0.1", "::1",
                                     "fc00::1"])
def test_private_needs_the_operator_allowlist(address):
    with pytest.raises(DastSsrfError, match="DAST_ALLOWED_PRIVATE"):
        checked_addresses("app.example", parse_allowlist(""), lambda _h: [address])
    assert checked_addresses("app.example", parse_allowlist("app.example"), lambda _h: [address]) == [address]
    assert checked_addresses("app.example", parse_allowlist("0.0.0.0/0,::/0"), lambda _h: [address]) == [address]


def test_one_private_answer_refuses_the_host():
    with pytest.raises(DastSsrfError, match="10.0.0.5"):
        checked_addresses("app.example", parse_allowlist(""), lambda _h: ["93.184.216.34", "10.0.0.5"])
    assert checked_addresses("app.example", parse_allowlist(""), lambda _h: ["93.184.216.34"]) == ["93.184.216.34"]

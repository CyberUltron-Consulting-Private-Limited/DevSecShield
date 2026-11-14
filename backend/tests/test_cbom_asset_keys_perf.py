"""CB-21 perf follow-up: the faster correlation gives EXACTLY the answers of #137's ``asset_keys``.

The reference is a frozen copy of the merged module (``fixtures/asset_keys_ref_v1.py``). Checked here:
* a 50,000-observation randomized estate (certificates seen by prober / file / Windows / ACM / CT / code views,
  conflicting copies, same-CN fleets, counting CAs, noisy spellings, unhashable facts, endpoints with scopes, cloud
  ids, link-less rows): same keys, aliases and contested keys;
* ``CorrelationIndex`` (the store's incremental path) after random add / replace / remove sequences: equal to a full
  ``correlate_detail`` over the current set, and to the reference;
* every call the 65 tests of ``test_cbom_asset_keys.py`` make, re-checked against the reference
  (``test_the_asset_keys_suite_gives_the_reference_answers`` runs that file with a comparing wrapper).
"""
from __future__ import annotations

import importlib.util
import random
import sys
from pathlib import Path
from typing import Any

import pytest

from backend.utilities.cbom_sources import asset_keys as AK

_REF_PATH = Path(__file__).parent / "fixtures" / "asset_keys_ref_v1.py"


def _load_ref():
    spec = importlib.util.spec_from_file_location("asset_keys_ref_v1", _REF_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


REF = _load_ref()


def to_ref(obj: Any) -> Any:
    """The same observation for the reference module (its own ``Observation`` class)."""
    if isinstance(obj, AK.Observation):
        return REF.Observation(kind=obj.kind, facts=obj.facts, location=obj.location, target=obj.target,
                               origin=obj.origin, cdx_type=obj.cdx_type, scope=obj.scope)
    return obj


def norm(value: Any) -> Any:
    return "NOT_CORRELATED" if type(value).__name__ == "NotCorrelated" else value


def same(observations: list[Any]) -> None:
    got = AK.correlate_detail(observations)
    want = REF.correlate_detail([to_ref(o) for o in observations])
    assert [norm(k) for k in got.keys] == [norm(k) for k in want.keys]
    assert got.aliases == want.aliases
    assert got.contested == want.contested


# ----------------------------------------------------------------------------- a randomized estate
def estate(n: int, seed: int) -> list[Any]:
    rng = random.Random(seed)
    out: list[Any] = []
    cas = ["CN=Example Issuing CA 2,O=Example Corp,C=US", "CN=Test CA", "CN=Test CA,O=Internet Widgits Pty Ltd",
           "CN=Amazon RSA 2048 M02,O=Amazon,C=US", "CN=Device CA,O=Maker", "CN=R11,O=Let's Encrypt,C=US"]

    def noisy(text: str) -> str:
        r = rng.random()
        if r < 0.1:
            return text.upper()
        if r < 0.2:
            return text.replace(",", ", ")
        if r < 0.25 and text.startswith("CN="):
            return "/" + "/".join(reversed(text.split(",")))
        return text

    certs = []
    for c in range(n // 6):
        issuer = rng.choice(cas)
        short = rng.random() < 0.15
        serial = format(rng.randrange(1, 40) if short else rng.getrandbits(rng.choice([60, 64, 128, 159])), "x")
        cn = f"host-{rng.randrange(n // 20)}.example.com" if rng.random() < 0.5 else f"device-{c}"
        subject = "" if rng.random() < 0.05 else (f"CN={cn},SERIALNUMBER=SN{c}" if rng.random() < 0.1 else f"CN={cn}")
        nb = f"2026-{rng.randrange(1, 13):02d}-01T00:00:00Z"
        na = rng.choice(["9999-12-31T23:59:59Z", f"2027-{rng.randrange(1, 13):02d}-{rng.randrange(1, 28):02d}T"
                                                 f"{rng.randrange(24):02d}:00:00Z"])
        certs.append(dict(subject=subject, issuer=issuer, serial=serial, not_before=nb, not_after=na,
                          fingerprint_sha256=format(rng.getrandbits(256), "064x"), thumb=format(rng.getrandbits(160), "040x")))
    for _ in range(n):
        r = rng.random()
        if r < 0.55 and certs:
            cert = rng.choice(certs)
            view = rng.random()
            if view < 0.35:  # prober / file
                facts = {"subject": noisy(cert["subject"]), "issuer": noisy(cert["issuer"]), "serial": cert["serial"],
                         "not_before": cert["not_before"], "not_after": cert["not_after"],
                         "fingerprint_sha256": cert["fingerprint_sha256"]}
            elif view < 0.5:  # Windows
                facts = {"subject": noisy(cert["subject"]).replace(",", ", "), "issuer": cert["issuer"].replace(",", ", "),
                         "thumbprint": cert["thumb"].upper(), "not_after": cert["not_after"].replace("Z", ".0000000Z")}
            elif view < 0.6:  # ACM
                s = cert["serial"].zfill(len(cert["serial"]) + len(cert["serial"]) % 2)
                facts = {"subject": cert["subject"].split(",")[0], "issuer": "Amazon",
                         "serial": ":".join(s[i:i + 2] for i in range(0, len(s), 2)), "not_before": cert["not_before"],
                         "not_after": cert["not_after"]}
            elif view < 0.67:  # CT precertificate
                facts = {"subject": cert["subject"], "issuer": cert["issuer"], "serial": cert["serial"],
                         "not_before": cert["not_before"], "not_after": cert["not_after"],
                         "precert_sha256": format(rng.getrandbits(256), "064x")}
            elif view < 0.75:  # a re-signed copy keeping serial and dates
                facts = {"subject": cert["subject"], "issuer": "CN=Corp TLS Inspection CA,O=Corp", "serial": cert["serial"],
                         "not_before": cert["not_before"], "not_after": cert["not_after"],
                         "fingerprint_sha256": format(rng.getrandbits(256), "064x")}
            elif view < 0.85:  # code scan (CN-only names, maybe no notBefore)
                facts = {"subject": cert["subject"].split(",")[0].split("=")[-1], "issuer": cert["issuer"].split(",")[0].split("=")[-1],
                         "not_before": cert["not_before"] if rng.random() < 0.7 else None, "not_after": cert["not_after"]}
                out.append(AK.Observation(kind="certificate", facts=facts, origin="code"))
                continue
            elif view < 0.9:  # a reissue: same names and expiry, new everything else
                facts = {"subject": cert["subject"], "issuer": cert["issuer"], "serial": format(rng.getrandbits(128), "x"),
                         "not_before": "2026-12-01T00:00:00Z", "not_after": cert["not_after"],
                         "fingerprint_sha256": format(rng.getrandbits(256), "064x")}
            elif view < 0.92:  # an unhashable fact value (no memo path)
                facts = {"subject": cert["subject"], "issuer": cert["issuer"], "serial": [cert["serial"]],
                         "not_after": cert["not_after"], "fingerprint_sha256": cert["fingerprint_sha256"]}
            else:  # bare: nothing identifying
                facts = {"key_alg": "RSA"} if rng.random() < 0.5 else {"subject": cert["subject"], "issuer": cert["issuer"]}
            kind = rng.choice(["certificate", "certificate", "k8s_certificate"])
            out.append(AK.Observation(kind=kind, facts=facts, location=f"loc-{rng.randrange(n)}",
                                      scope=f"src-{rng.randrange(6)}"))
        elif r < 0.75:  # endpoints
            host = rng.choice([f"10.0.{rng.randrange(4)}.{rng.randrange(20)}", f"93.184.{rng.randrange(4)}.{rng.randrange(20)}",
                               f"[2001:db8::{rng.randrange(30):x}]", f"[2600:1f18::{rng.randrange(30):x}]",
                               f"WWW{rng.randrange(10)}.Example.com.", "127.0.0.1"])
            port = rng.choice([22, 443, 8443])
            location = rng.choice([f"{host}:{port}", f"https://{host}/", f"{host}:{port}#chain[0]"])
            out.append(AK.Observation(kind=rng.choice(["tls_endpoint", "ssh_endpoint", "database_tls"]), facts={},
                                      location=location, target=host.strip("[]"), scope=rng.choice(["", "src-1", "src-2"])))
        elif r < 0.88:  # cloud ids
            cid = rng.choice([f"arn:aws:kms:us-east-1:1:key/k{rng.randrange(300)}",
                              f"/subscriptions/S1/resourceGroups/RG/providers/Microsoft.KeyVault/vaults/V{rng.randrange(50)}",
                              f"//sqladmin.googleapis.com/projects/p/instances/i{rng.randrange(50)}",
                              f"projects/p/instances/i{rng.randrange(50)}",
                              f"https://v{rng.randrange(20)}.vault.azure.net/keys/k/{rng.getrandbits(32):x}"])
            kind = rng.choice(["kms_key", "key_vault", "load_balancer_tls", "secret"])
            out.append(AK.Observation(kind=kind, facts={"identity": cid}, location=rng.choice([cid, "elsewhere"])))
        else:  # link-less: libraries, local keys, code-declared cloud resources
            if rng.random() < 0.3:
                out.append(AK.Observation(kind="key", facts={"cloud_resource": "aws_kms_key"}, location="main.tf",
                                          origin="code"))
            else:
                out.append(AK.Observation(kind=rng.choice(["crypto_library", "private_key", "ssh_host_key"]), facts={},
                                          location=f"/lib/{rng.randrange(100)}"))
    rng.shuffle(out)
    return out


def test_a_50k_randomized_estate_gives_the_reference_answers():
    observations = estate(50_000, seed=21)
    same(observations)
    keys = AK.correlate(observations)
    assert len({k for k in keys if isinstance(k, str)}) < len(observations)  # it did correlate something


@pytest.mark.parametrize("seed", range(8))
def test_small_randomized_estates_give_the_reference_answers(seed):
    same(estate(600, seed=seed))  # small sets: more shared buckets per observation, more conflicts


def test_the_incremental_index_equals_a_full_correlation_after_random_updates():
    rng = random.Random(167)
    pool = estate(6_000, seed=3)
    current: dict[int, Any] = {i: pool[i] for i in range(3_000)}
    index = AK.CorrelationIndex(current)
    spare = list(range(3_000, 6_000))
    for _round in range(25):
        changes: dict[int, Any] = {}
        for _ in range(rng.randrange(1, 120)):
            what = rng.random()
            if what < 0.4 and spare:  # a new observation
                oid = spare.pop()
                changes[oid] = pool[oid]
            elif what < 0.7 and current:  # an observation changed (another view of something)
                changes[rng.choice(list(current))] = pool[rng.randrange(len(pool))]
            elif current:  # an observation removed
                changes[rng.choice(list(current))] = None
        before = {oid: (index.key(oid), index.aliases(oid)) for oid in current}
        moved = index.update(changes)
        for oid, obs in changes.items():
            if obs is None:
                current.pop(oid, None)
            else:
                current[oid] = obs
        ids = sorted(current)
        full = AK.correlate_detail([current[i] for i in ids])
        got = index.correlation(ids)
        assert got.keys == full.keys and got.aliases == full.aliases and got.contested == full.contested
        want = REF.correlate_detail([to_ref(current[i]) for i in ids])
        assert [norm(k) for k in got.keys] == [norm(k) for k in want.keys] and got.contested == want.contested
        # what update reports as changed is exactly what changed
        after = {oid: (index.key(oid), index.aliases(oid)) for oid in current}
        truly = {oid for oid in set(before) | set(after) if before.get(oid) != after.get(oid)}
        assert truly <= moved


def test_lone_and_link_less_observations_keep_the_pure_answer():
    for obs in estate(2_000, seed=9):
        assert norm(AK.correlate_detail([obs]).keys[0]) == norm(REF.correlate_detail([to_ref(obs)]).keys[0])
        assert norm(AK.asset_key(obs)) == norm(REF.asset_key(to_ref(obs)))


def test_observation_keys_are_the_per_source_keys():
    from backend.new_models import CbomCollectedAsset
    from backend.utilities.cbom_sources import identity as ID

    rows = [CbomCollectedAsset(team_id=1, run_id=1, job_id=1, attempt=1, asset_key=f"k{i}", asset_type="kms_key",
                               cdx_type="related-crypto-material", target="t", location=f"l{i}") for i in range(3)]
    assert AK.observation_keys(rows, "src") == [ID.stable_key("node", "src", ID.node_identity(r)) for r in rows]


# ----------------------------------------------------------------------------- the 65 tests, against the reference
def test_the_asset_keys_suite_gives_the_reference_answers(monkeypatch):
    """Runs ``test_cbom_asset_keys.py`` with every ``correlate_detail`` / ``asset_key`` / ``link_keys`` call
    compared with the reference."""
    calls = {"n": 0}
    new_corr, new_key, new_links = AK.correlate_detail, AK.asset_key, AK.link_keys

    def corr(observations):
        observations = list(observations)
        got = new_corr(observations)
        want = REF.correlate_detail([to_ref(o) for o in observations])
        assert [norm(k) for k in got.keys] == [norm(k) for k in want.keys]
        assert got.aliases == want.aliases and got.contested == want.contested
        calls["n"] += 1
        return got

    def key(obj):
        got = new_key(obj)
        assert norm(got) == norm(REF.asset_key(to_ref(obj)))
        calls["n"] += 1
        return got

    def links(obj):
        got = new_links(obj)
        assert [(k.basis, k.value, k.key) for k in got] == [(k.basis, k.value, k.key) for k in REF.link_keys(to_ref(obj))]
        return got

    monkeypatch.setattr(AK, "correlate_detail", corr)
    monkeypatch.setattr(AK, "asset_key", key)
    monkeypatch.setattr(AK, "link_keys", links)
    suite = str(Path(__file__).parent / "test_cbom_asset_keys.py")
    assert pytest.main(["-q", "-p", "no:cacheprovider", "-o", "addopts=", suite]) == 0
    assert calls["n"] > 100

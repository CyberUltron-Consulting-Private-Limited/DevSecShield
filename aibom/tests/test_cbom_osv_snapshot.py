"""CB-29: the offline OSV snapshot of crypto-library advisories.

No network: ``fixtures/osv/recorded.json`` holds OSV's records for six packages (every
page, trimmed to the fields
the snapshot reads) and OSV's own answer for one version of each (``answer_ids``),
recorded with the time asked.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
from pathlib import Path

import pytest

from aibom.cbom import advisories as ADV
from aibom.cbom import osv_snapshot as SNAP

_ROOT = Path(__file__).resolve().parents[1]
_RECORDED = _ROOT / "tests" / "fixtures" / "osv" / "recorded.json"
_CORPUS = _ROOT.parent / "e2e" / "fixtures" / "cbom-d1-corpus"
_ECO = {"NuGet": "nuget", "Go": "go", "PyPI": "pypi", "Maven": "maven", "npm": "npm"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for var in (
        "CBOM_OSV_SNAPSHOT",
        "CBOM_OSV_SNAPSHOT_URL",
        "CBOM_OSV_PUBKEYS",
        "CBOM_KB_PUBKEYS",
        "CBOM_OSV_ONLINE",
        "CBOM_OSV_MAX_AGE_DAYS",
        "CBOM_OSV_SNAPSHOT_SIG",
    ):
        monkeypatch.delenv(var, raising=False)
    SNAP.load.cache_clear()
    ADV._STATUS.clear()
    yield
    SNAP.load.cache_clear()
    ADV._STATUS.clear()


def _recorded() -> dict:
    return json.loads(_RECORDED.read_text())


def _triples(recorded: dict) -> list:
    return [
        (_ECO[p["ecosystem"]], p["name"].lower(), r)
        for p in recorded["packages"]
        for page in p["pages"]
        for r in page["vulns"]
    ]


def _doc(date: dt.date, recorded: dict | None = None) -> dict:
    rec = recorded or _recorded()
    packages: dict[str, list[str]] = {}
    for p in rec["packages"]:
        packages.setdefault(_ECO[p["ecosystem"]], []).append(p["name"])
    return SNAP.build_document(
        SNAP.rows_from_records(_triples(rec)),
        packages=packages,
        generated_at=date,
        source=rec["source"],
    )


def _osv_ids(rows: list[dict], ecosystem: str, name: str, version: str) -> set[str]:
    pin = ADV._pin(ecosystem, name, version, "x", direct=True)
    assert pin is not None
    advisories = ADV.snapshot_advisories(rows)
    return {a.source.rsplit("/", 1)[-1] for a in advisories if ADV._affected(pin, a)}


# --------------------------------------------------------------------------------------
# the oracle
@pytest.mark.parametrize("index", range(6))
def test_offline_match_equals_osvs_own_answer(index):
    """For the recorded version of each package, the rows built from OSV's records match
    exactly the advisories
    OSV itself returned for that version (BouncyCastle 1.8.1 and
    System.IdentityModel.Tokens.Jwt 5.1.4 on NuGet,
    dgrijalva/jwt-go v3.2.0 on Go: the CB-29 failing-first cases; cryptography,
    bcprov-jdk15on, jsonwebtoken)."""
    rec = _recorded()
    pkg = rec["packages"][index]
    rows = SNAP.rows_from_records(_triples({**rec, "packages": [pkg]}))
    got = _osv_ids(rows, _ECO[pkg["ecosystem"]], pkg["name"], pkg["version"])
    assert got == set(pkg["answer_ids"]), (pkg["name"], pkg["version"])


def test_online_and_offline_give_the_same_rows_and_hits():
    """Same OSV data, two paths: the snapshot built from the records and the online
    fallback asking OSV (a fake that
    serves the recorded pages, page tokens included) give identical rows, so identical
    matches."""
    rec = _recorded()
    pages = {(p["ecosystem"], p["name"]): p["pages"] for p in rec["packages"]}
    asked = []

    def fake_post(url, body):
        key = (body["package"]["ecosystem"], body["package"]["name"])
        asked.append((key, body.get("page_token")))
        seq = pages[key]
        i = int(body.get("page_token") or 0)
        page = dict(seq[i])
        page.pop("next_page_token", None)
        if i + 1 < len(seq):
            page["next_page_token"] = str(i + 1)
        return page

    online, answered = SNAP.online_rows(
        {(_ECO[e], n) for e, n in pages}, post=fake_post
    )
    offline = _doc(dt.date(2026, 11, 14))["advisories"]
    assert online == offline and len(answered) == 6
    assert any(token for _key, token in asked) or all(
        len(p) == 1 for p in pages.values()
    )


# --------------------------------------------------------------------------------------
# records -> rows
def test_record_rows_follow_the_osv_schema():
    record = {
        "id": "GHSA-x",
        "aliases": ["CVE-2020-1", "GO-1"],
        "summary": "s",
        "modified": "m",
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "example.com/m"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.2.0"},
                            {"introduced": "2.0.0"},
                            {"last_affected": "2.1.0"},
                        ],
                    },
                    {"type": "GIT", "events": [{"introduced": "abc"}]},
                ],
            },
            {
                "package": {"ecosystem": "Go", "name": "example.com/m/v3"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
            },
            {
                "package": {"ecosystem": "PyPI", "name": "example.com/m"},
                "versions": ["1.0"],
            },
        ],
    }
    rows = SNAP.rows_from_record(record, "go", "example.com/m")
    assert [(r["introduced"], r["fixed"], r["last_affected"]) for r in rows] == [
        (None, "1.2.0", None),
        ("2.0.0", None, "2.1.0"),
    ]
    assert {r["id"] for r in rows} == {"CVE-2020-1"} and rows[0]["source"].endswith(
        "/GHSA-x"
    )
    assert (
        SNAP.rows_from_record(
            {**record, "withdrawn": "2021-01-01"}, "go", "example.com/m"
        )
        == []
    )
    adv = ADV.snapshot_advisories(rows)

    def hit(v, name="example.com/m"):
        pin = ADV._pin("go", name, v, "x", direct=True)
        return any(ADV._affected(pin, a) for a in adv)

    assert hit("1.1.9") and not hit("1.2.0") and hit("v2.1.0") and not hit("2.1.1")
    assert not hit(
        "1.0.0", "example.com/m/v3/sub"
    )  # a major-version module is another module
    assert hit("1.0.0", "example.com/m/sub")  # a package of the module is the module
    listed = ADV.snapshot_advisories(
        [{"id": "X", "ecosystem": "pypi", "name": "p", "versions": ["1.0", "1.1"]}]
    )
    assert ADV._affected(ADV._pin("pypi", "p", "1.1", "x", direct=True), listed[0])
    assert not ADV._affected(
        ADV._pin("pypi", "p", "1.2", "x", direct=True), listed[0]
    )  # only those versions


# --------------------------------------------------------------------------------------
# integrity
def test_checksum_and_signature(tmp_path, monkeypatch):
    pytest.importorskip(
        "cryptography",
        reason="signing needs the cryptography package (the checksum does not)",
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    doc = _doc(dt.date(2026, 11, 14))
    data = SNAP.dumps(doc)
    assert SNAP.check(data, sig_path=None, keys="", require_signature=False)[0] == doc
    tampered = json.loads(data)
    tampered["advisories"][0]["fixed"] = "999"
    assert (
        SNAP.check(
            json.dumps(tampered).encode(),
            sig_path=None,
            keys="",
            require_signature=False,
        )[2]
        == "checksum does not match the content"
    )
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = base64.b64encode(
        key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    (tmp_path / "s.json").write_bytes(data)
    (tmp_path / "s.json.sig").write_bytes(SNAP.sign(data, pem))
    doc2, signed, problem = SNAP.check(
        data, sig_path=str(tmp_path / "s.json.sig"), keys=pub, require_signature=True
    )
    assert doc2 == doc and signed and problem is None
    other = base64.b64encode(
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    assert (
        SNAP.check(
            data,
            sig_path=str(tmp_path / "s.json.sig"),
            keys=other,
            require_signature=True,
        )[0]
        is None
    )
    assert SNAP.check(data, sig_path=None, keys=pub, require_signature=True)[
        2
    ].startswith("signature")


def test_the_shipped_snapshot_verifies_and_covers_the_six_ecosystems():
    snap = SNAP.load()
    assert (
        snap.origin == "builtin"
        and not snap.problems
        and snap.document["sha256"] == SNAP.checksum(snap.document)
    )
    assert set(snap.document["packages"]) == {
        "maven",
        "nuget",
        "npm",
        "pypi",
        "go",
        "cargo",
    }
    assert {r["ecosystem"] for r in snap.rows} == {
        "maven",
        "nuget",
        "npm",
        "pypi",
        "go",
        "cargo",
    }
    assert snap.document["packages"] == SNAP.package_list()


# --------------------------------------------------------------------------------------
# loading
def _write(tmp_path: Path, doc: dict, name: str = "snap.json") -> Path:
    path = tmp_path / name
    path.write_bytes(SNAP.dumps(doc))
    return path


def test_a_newer_operator_file_wins_and_a_bad_one_is_reported(tmp_path, monkeypatch):
    builtin = SNAP.load()
    newer = _doc(builtin.generated_at + dt.timedelta(days=3))
    monkeypatch.setenv("CBOM_OSV_SNAPSHOT", str(_write(tmp_path, newer)))
    SNAP.load.cache_clear()
    assert (
        SNAP.load().origin == "file"
        and SNAP.load().version == newer["snapshot_version"]
    )
    older = _doc(builtin.generated_at - dt.timedelta(days=3))
    monkeypatch.setenv("CBOM_OSV_SNAPSHOT", str(_write(tmp_path, older, "old.json")))
    SNAP.load.cache_clear()
    assert SNAP.load().origin == "builtin"  # never go back to older data
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({**newer, "sha256": "0" * 64}))
    monkeypatch.setenv("CBOM_OSV_SNAPSHOT", str(bad))
    SNAP.load.cache_clear()
    snap = SNAP.load()
    assert snap.origin == "builtin" and snap.problems == (
        "CBOM_OSV_SNAPSHOT rejected: checksum does not match the content",
    )


def test_an_unsigned_file_is_refused_when_trusted_keys_are_configured(
    tmp_path, monkeypatch
):
    newer = _doc(SNAP.load().generated_at + dt.timedelta(days=3))
    monkeypatch.setenv("CBOM_OSV_SNAPSHOT", str(_write(tmp_path, newer)))
    monkeypatch.setenv("CBOM_OSV_PUBKEYS", base64.b64encode(b"\x01" * 32).decode())
    SNAP.load.cache_clear()
    snap = SNAP.load()
    assert snap.origin == "builtin" and snap.problems[0].startswith(
        "CBOM_OSV_SNAPSHOT rejected: signature"
    )


def test_a_download_is_loaded_and_verified(tmp_path, monkeypatch):
    newer = _doc(SNAP.load().generated_at + dt.timedelta(days=5))
    monkeypatch.setenv(
        "CBOM_OSV_SNAPSHOT_URL", "https://updates.example/osv_snapshot.json"
    )
    monkeypatch.setattr(SNAP, "_download", lambda url: (SNAP.dumps(newer), None, None))
    SNAP.load.cache_clear()
    assert SNAP.load().origin == "download"
    monkeypatch.setattr(
        SNAP, "_download", lambda url: (None, None, "download failed (URLError)")
    )
    SNAP.load.cache_clear()
    snap = SNAP.load()
    assert snap.origin == "builtin" and "download failed" in snap.problems[0]


# --------------------------------------------------------------------------------------
# freshness, fallback
def _stale_builtin(monkeypatch, days: int = 40):
    doc = _doc(dt.date.today() - dt.timedelta(days=days))
    monkeypatch.setattr(SNAP, "_builtin_bytes", lambda: SNAP.dumps(doc))
    SNAP.load.cache_clear()
    return doc


def _go_tree(tmp_path: Path) -> Path:
    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\ngo 1.20\n\nrequire (\n"
        "\tgithub.com/dgrijalva/jwt-go v3.2.0+incompatible\n)\n"
    )
    return tmp_path


def test_a_stale_snapshot_offline_is_used_and_said_to_be_stale(tmp_path, monkeypatch):
    _stale_builtin(monkeypatch)
    hits = ADV.find_vulnerable(_go_tree(tmp_path))
    assert {h.advisory.id for h in hits} == {"CVE-2020-26160"}
    status = ADV.last_status()
    assert (
        status["stale"] is True and status["age_days"] == 40 and "online" not in status
    )
    monkeypatch.setenv("CBOM_OSV_MAX_AGE_DAYS", "60")
    SNAP.load.cache_clear()
    ADV.find_vulnerable(_go_tree(tmp_path))
    assert ADV.last_status()["stale"] is False


def test_a_stale_snapshot_online_asks_osv_for_the_packages_found(tmp_path, monkeypatch):
    _stale_builtin(monkeypatch)
    monkeypatch.setenv("CBOM_OSV_ONLINE", "1")
    asked = []
    fresh = {
        "id": "GHSA-new",
        "aliases": ["CVE-2099-1"],
        "summary": "new",
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "github.com/dgrijalva/jwt-go"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
            }
        ],
    }

    def fake_post(url, body):
        asked.append(body["package"]["name"])
        return {"vulns": [fresh]}

    monkeypatch.setattr(SNAP, "_post", fake_post)
    hits = ADV.find_vulnerable(_go_tree(tmp_path))
    assert asked == [
        "github.com/dgrijalva/jwt-go"
    ]  # only the tracked packages the tree names
    assert {h.advisory.id for h in hits} == {
        "CVE-2099-1"
    }  # OSV's answer replaces the snapshot's rows
    assert ADV.last_status()["online"] == {"asked": 1, "answered": 1}
    monkeypatch.setattr(
        SNAP, "_post", lambda url, body: None
    )  # OSV down: the stale snapshot's rows stand
    hits = ADV.find_vulnerable(_go_tree(tmp_path))
    assert {h.advisory.id for h in hits} == {"CVE-2020-26160"}
    assert ADV.last_status()["online"] == {"asked": 1, "answered": 0}


def test_a_fresh_snapshot_never_calls_the_network(tmp_path, monkeypatch):
    monkeypatch.setenv("CBOM_OSV_ONLINE", "1")
    monkeypatch.setattr(
        SNAP, "_post", lambda url, body: pytest.fail("no network for a fresh snapshot")
    )
    ADV.find_vulnerable(_go_tree(tmp_path))
    assert ADV.last_status()["stale"] is False


# --------------------------------------------------------------------------------------
# manifests, outputs
def test_csproj_package_references_are_pins(tmp_path):
    (tmp_path / "App.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk">\n  <ItemGroup>\n'
        '    <PackageReference Include="BouncyCastle" Version="1.8.1" />\n'
        '    <PackageReference Include="System.IdentityModel.Tokens.Jwt">\n'
        "      <Version>5.1.4</Version>\n"
        "    </PackageReference>\n"
        '    <PackageReference Include="Central.Managed" />\n'
        '    <PackageReference Include="Prop.Version" Version="$(JwtVersion)" />\n'
        "  </ItemGroup>\n</Project>\n"
    )
    pins = {p.name: p for p in ADV.iter_pins(tmp_path)}
    assert set(pins) == {"bouncycastle", "system.identitymodel.tokens.jwt"}
    assert (pins["bouncycastle"].version, pins["bouncycastle"].line) == ("1.8.1", 3)
    assert pins["system.identitymodel.tokens.jwt"].version == "5.1.4"


def test_the_cb29_failing_first_libraries_are_flagged():
    """bench/cbom/d1 libraries L3, L4, L6 (BouncyCastle 1.8.1,
    System.IdentityModel.Tokens.Jwt 5.1.4 in a .csproj;
    dgrijalva/jwt-go v3.2.0 in go.mod) with the shipped snapshot, no network."""
    names = {h.pin.name for h in ADV.find_vulnerable(_CORPUS)}
    assert {
        "bouncycastle",
        "system.identitymodel.tokens.jwt",
        "github.com/dgrijalva/jwt-go",
    } <= names
    nuget_bc = [h for h in ADV.find_vulnerable(_CORPUS) if h.pin.name == "bouncycastle"]
    assert all(
        h.advisory.id != "CVE-2023-33201" for h in nuget_bc
    )  # the Java-only LDAP flaw is not cited on NuGet


def test_the_scan_says_which_advisory_data_it_used(tmp_path):
    from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield

    run = scan_crypto_to_devsecshield(str(_go_tree(tmp_path)), level=1)
    data = run["advisory_data"]
    assert (
        data["source"] == "osv-snapshot"
        and data["generated_at"] == SNAP.load().document["generated_at"]
    )
    props = {p["name"]: p["value"] for p in run["cbom_json"]["metadata"]["properties"]}
    assert props["zs:advisory_snapshot_date"] == data["generated_at"]
    assert props["zs:advisory_snapshot_stale"] == "false"
    assert props["zs:advisory_snapshot_sha256"] == SNAP.load().document["sha256"]

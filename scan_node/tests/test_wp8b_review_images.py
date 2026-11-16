"""Round-5 review (lens 6) of registry image pulls: a small malicious layer must not exhaust the node's memory, a blob
stream stops at its descriptor's size and at the job's deadline, vault credentials reach the token services of
Docker Hub and GitLab.com (and no other host), and a registry cannot send the node to loopback or link-local
addresses."""
from __future__ import annotations

import gzip
import io
import tarfile
import time
import tracemalloc
import zlib

import pytest

from test_wp8b_agent_registry import _collect, _ctx, _image_layers, _layer, lab_factory  # noqa: F401

from zs_scan_node import netutil
from zs_scan_node.collectors import container_images as CI

MB = 1024 * 1024


class _Resp:
    """A blob response streaming ``blob`` (then ``tail`` chunks, if any) in 64 KiB pieces."""

    status_code = 200

    def __init__(self, blob: bytes, tail=None) -> None:
        self.blob, self.tail, self.served = blob, tail, 0

    def iter_raw(self, n):
        for i in range(0, len(self.blob), n):
            self.served += len(self.blob[i:i + n])
            yield self.blob[i:i + n]
        for chunk in self.tail or ():
            self.served += len(chunk)
            yield chunk

    def close(self):
        pass


def _peak(fn) -> tuple[object, int]:
    """(result or exception, peak bytes Python allocated while fn ran)."""
    tracemalloc.start()
    try:
        try:
            out = fn()
        except Exception as exc:  # the refusal is the expected outcome in most tests
            out = exc
        return out, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def _gz_tar(headers_and_data: list[tuple[tarfile.TarInfo, int]], fill: bytes = b"a") -> bytes:
    """gzip of tar members whose data is ``size`` bytes of ``fill`` (streamed, never built in memory)."""
    comp = zlib.compressobj(6, zlib.DEFLATED, 31)
    out = []
    for info, size in headers_and_data:
        out.append(comp.compress(info.tobuf(format=tarfile.GNU_FORMAT)))
        block = fill * MB
        left = size
        while left > 0:
            out.append(comp.compress(block[:left]))
            left -= MB
        if size % 512:
            out.append(comp.compress(b"\0" * (512 - size % 512)))
    out.append(comp.compress(b"\0" * 1024))
    out.append(comp.flush())
    return b"".join(out)


def _member(name: str, size: int, kind: bytes = tarfile.REGTYPE) -> tuple[tarfile.TarInfo, int]:
    info = tarfile.TarInfo(name)
    info.size, info.type = size, kind
    return info, size


# ----------------------------------------------------------------------------- finding 1: memory
def test_a_long_name_header_claiming_64_mb_is_refused_before_tarfile_reads_it():
    blob = _gz_tar([_member("././@LongLink", 64 * MB, tarfile.GNUTYPE_LONGNAME)])
    assert len(blob) < 200 * 1024
    stream = CI._Inflate(_Resp(blob), len(blob), 10 ** 12)
    out, peak = _peak(lambda: CI.read_layer(stream))
    assert isinstance(out, CI.ImageError) and "tar headers" in out.detail
    assert peak < 8 * MB, peak  # before: the whole 64 MB name was read into memory (and copied)


def test_pax_headers_and_chains_of_extended_headers_are_capped():
    blob = _gz_tar([_member("././@PaxHeader", 32 * MB, tarfile.XHDTYPE)], fill=b"9")
    out, peak = _peak(lambda: CI.read_layer(CI._Inflate(_Resp(blob), len(blob), 10 ** 12)))
    assert isinstance(out, CI.ImageError) and "tar headers" in out.detail and peak < 8 * MB
    chain = [_member("././@LongLink", 100, tarfile.GNUTYPE_LONGNAME) for _ in range(CI.MAX_TAR_CHAIN + 1)]
    blob = _gz_tar(chain + [_member("etc/os-release", 3)])
    with pytest.raises(CI.ImageError, match="chains"):
        CI.read_layer(CI._Inflate(_Resp(blob), len(blob), 10 ** 12))
    ok = _gz_tar([_member("././@LongLink", 300, tarfile.GNUTYPE_LONGNAME), _member("x", 0),
                  _member("var/lib/dpkg/status", 4)])  # an ordinary long name still works
    assert CI.read_layer(CI._Inflate(_Resp(ok), len(ok), 10 ** 12)).files == {"var/lib/dpkg/status": b"aaaa"}


def test_status_d_entries_are_capped_per_image():
    members = [_member(f"var/lib/dpkg/status.d/pkg{i}", 10) for i in range(CI.MAX_STATUS_D + 1)]
    blob = _gz_tar(members, fill=b"\n")
    with pytest.raises(CI.ImageError, match="status.d"):
        CI.read_layer(CI._Inflate(_Resp(blob), len(blob), 10 ** 12))
    # the merged view of earlier layers counts too
    merged = {f"var/lib/dpkg/status.d/p{i}": b"x" for i in range(CI.MAX_STATUS_D)}
    blob = _gz_tar([_member("var/lib/dpkg/status.d/one-more", 10)], fill=b"\n")
    with pytest.raises(CI.ImageError, match="status.d"):
        CI.read_layer(CI._Inflate(_Resp(blob), len(blob), 10 ** 12), CI.Budget.left(merged))


def test_inventory_files_kept_for_an_image_have_a_byte_budget():
    # the reviewer's case: many status.d members of tens of MB each, all kept (598 KiB -> 600 MiB)
    blob = _gz_tar([_member(f"var/lib/dpkg/status.d/pkg{i}", 4 * MB) for i in range(8)], fill=b"\n")
    budget = CI.Budget(bytes=8 * MB)
    out, peak = _peak(lambda: CI.read_layer(CI._Inflate(_Resp(blob), len(blob), 10 ** 12), budget))
    assert isinstance(out, CI.ImageError) and "package databases exceed" in out.detail
    assert peak < 20 * MB, peak  # the budget plus one file's read buffers, not 8 x 4 MB
    assert CI.Budget.left({"var/lib/dpkg/status": b"x" * 10}).bytes == CI.MAX_KEPT - 10
    # the same path twice in one layer: the later member replaces the earlier one in the budget
    twice = _gz_tar([_member("var/lib/dpkg/status", 6 * MB), _member("var/lib/dpkg/status", 6 * MB)], fill=b"\n")
    assert len(CI.read_layer(CI._Inflate(_Resp(twice), len(twice), 10 ** 12), CI.Budget(bytes=10 * MB))
               .files["var/lib/dpkg/status"]) == 6 * MB


def test_tarfile_member_list_does_not_grow_with_the_layer():
    blob = _gz_tar([_member(f"usr/share/x/f{i:08d}", 0) for i in range(60000)])
    out, peak = _peak(lambda: CI.read_layer(CI._Inflate(_Resp(blob), len(blob), 10 ** 12)))
    assert isinstance(out, CI.LayerDiff) and not out.files
    assert peak < 8 * MB, peak  # before: ~400 bytes per member kept in TarFile.members (24 MB here)


def test_only_whiteouts_that_can_hide_a_wanted_path_are_kept():
    names = [f"usr/share/doc/.wh.pkg{i}" for i in range(5000)] + ["var/lib/dpkg/status.d/.wh.gone", "var/.wh..wh..opq"]
    blob = _gz_tar([_member(n, 0) for n in names])
    diff = CI.read_layer(CI._Inflate(_Resp(blob), len(blob), 10 ** 12))
    assert diff.whiteouts == ["var/lib/dpkg/status.d/gone"] and diff.opaque == ["var"]


def test_inflate_cap_has_an_absolute_ceiling(lab_factory, monkeypatch):
    # an honest 2 KB layer that inflates to 4 MB: under 200 x size + 64 MB, over an 1 MB absolute ceiling
    lab = lab_factory()
    lab.push("big", [_layer({"var/lib/dpkg/status": b"\n" * (4 * MB)})])
    monkeypatch.setattr(CI, "MAX_INFLATED", 1 * MB)
    _s, _e, ctx = _collect(lab, f"localhost:{lab.registry.server_port}/team/app:big")
    assert ctx.outcomes[0].status == "error" and "compression bomb" in ctx.outcomes[0].error


def test_inflate_works_in_bounded_steps():
    blob = gzip.compress(b"\0" * (32 * MB))  # one 64 KiB chunk of this inflates to tens of MB at once
    stream = CI._Inflate(_Resp(blob), len(blob), 10 ** 12)
    stream.read(10240)
    assert len(stream.buffer) <= CI.INFLATE_STEP


# ----------------------------------------------------------------------------- finding 2: the blob stream
@pytest.mark.parametrize("filler", [b"\0" * 65536, gzip.compress(b"") * (65536 // len(gzip.compress(b"")))])
def test_a_blob_stream_stops_at_its_descriptor_size(filler):
    real = _layer({"var/lib/dpkg/status": b"Package: openssl\nStatus: install ok installed\nVersion: 3.0\n\n"})

    def endless():
        while True:
            yield filler

    resp = _Resp(real, endless())
    stream = CI._Inflate(resp, len(real), len(real) * CI.MAX_INFLATE_RATIO + 64 * MB)
    diff = CI.read_layer(stream)
    assert list(diff.files) == ["var/lib/dpkg/status"]
    with pytest.raises(CI.ImageError, match="larger than its descriptor"):
        stream.drain()
    assert resp.served <= len(real) + 65536  # before: read (and hashed) without end


def test_layer_descriptors_are_all_checked_before_the_total_and_any_download(monkeypatch):
    gb = 1024 ** 3
    layer = {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:" + "a" * 64}
    requested = []

    class Reg:
        ctx = _ctx()

        class ref:
            repository = "app"

        def get(self, path, stream=False):
            requested.append(path)
            return _Resp(b"")

    for sizes in ([gb, gb, -2 * gb], [gb, True], [gb, "12"], [gb, None], [gb, 1.5]):
        manifest = {"schemaVersion": 2, "layers": [{**layer, "size": s} for s in sizes]}
        monkeypatch.setattr(CI, "fetch_manifest", lambda reg, m=manifest: (m, "sha256:" + "0" * 64))
        with pytest.raises(CI.ImageError, match="unsupported digest or size"):
            CI.pull(Reg(), 1 * MB)
    assert requested == []  # before: the first 1 GB layer was downloaded under a 1 MB cap


def test_the_job_deadline_and_cancel_stop_a_layer_download():
    blob = _layer({"var/lib/dpkg/status": b"x" * 100})
    flags = iter([None, "skipped_cancelled"])
    stream = CI._Inflate(_Resp(blob, [b"\0" * 65536]), len(blob) + 65536, 10 ** 12, stop=lambda: next(flags, "x"))
    with pytest.raises(CI.ImageError) as err:
        stream.read(-1)
    assert err.value.status == "skipped_cancelled"
    ctx = _ctx()
    ctx.deadline = time.monotonic() - 1
    stream = CI._Inflate(_Resp(blob), len(blob), 10 ** 12, stop=ctx.should_stop)
    with pytest.raises(CI.ImageError) as err:
        stream.drain()
    assert err.value.status == "skipped_deadline"


# ----------------------------------------------------------------------------- findings 3 and 8: auth and addresses
class _FakeClient:
    seen: list[tuple[str, str, str, bool]] = []
    redirect_to: str | None = None

    def __init__(self, url, ip):
        self.url, self.ip = url, ip

    def get(self, path, headers=None):
        _FakeClient.seen.append((self.url, self.ip, path, "Authorization" in (headers or {})))
        return type("R", (), {"status_code": 200, "headers": {}, "json": lambda self: {"token": "tok-" + "x" * 20},
                              "close": lambda self: None})()

    def build_request(self, method, path, headers=None):
        return (method, path, headers)

    def send(self, request, stream=False):
        _FakeClient.seen.append((self.url, self.ip, request[1], "Authorization" in (request[2] or {})))
        if _FakeClient.redirect_to and "/blobs/" in request[1]:
            return type("R", (), {"status_code": 307, "headers": {"location": _FakeClient.redirect_to},
                                  "close": lambda self: None})()
        return type("R", (), {"status_code": 200, "headers": {}, "close": lambda self: None})()

    def close(self):
        pass


@pytest.fixture()
def fake_net(monkeypatch):
    _FakeClient.seen, _FakeClient.redirect_to = [], None
    addresses = {"registry-1.docker.io": "203.0.113.7", "auth.docker.io": "203.0.113.8", "registry.gitlab.com":
                 "203.0.113.9", "gitlab.com": "203.0.113.10", "registry.example.com": "203.0.113.11",
                 "auth.example.com": "203.0.113.12", "evil.example.com": "203.0.113.13",
                 "meta.example.com": "169.254.169.254", "local.example.com": "127.0.0.1",
                 "v6meta.example.com": "fd00:ec2::254", "mapped.example.com": "::ffff:127.0.0.1",
                 "sink.example.com": "0.0.0.0", "v6sink.example.com": "::",  # what DNS sinkholes answer
                 "zero8.example.com": "0.1.2.3", "nat64sink.example.com": "64:ff9b::"}  # the rest of 0.0.0.0/8, NAT64
    monkeypatch.setattr(netutil, "resolve", lambda name, timeout=5.0: [addresses[name]])
    monkeypatch.setattr(netutil, "http_client", lambda url, ip, never, **kw: _FakeClient(url, ip))
    return _FakeClient


CREDS = {"username": "acme", "password": "s3cret"}


@pytest.mark.parametrize("image,realm,sent", [
    ("acme/private-app:1.0", 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"', True),
    ("registry.gitlab.com/acme/app:1.0", 'Bearer realm="https://gitlab.com/jwt/auth",service="container_registry"', True),
    ("registry.example.com/app:1", 'Bearer realm="https://auth.example.com/token"', False),
    ("acme/private-app:1.0", 'Bearer realm="https://evil.example.com/token"', False),  # not Docker Hub's service
    ("acme/private-app:1.0", 'Bearer realm="https://auth.docker.io:8443/token"', False),  # another port
    ("registry.gitlab.com/acme/app:1.0", 'Bearer realm="https://auth.docker.io/token"', False),  # another pair
])
def test_vault_credentials_reach_docker_hub_and_gitlab_token_services_only(fake_net, image, realm, sent):
    reg = CI.Registry(_ctx(), CI.parse_ref(image), dict(CREDS), None)
    reg._client(reg.base + "/v2/")  # the registry is contacted first, as fetch_manifest does
    reg._authenticate(realm)
    token_calls = [s for s in fake_net.seen if "token" in s[2] or "auth" in s[2]]
    assert len(token_calls) == 1 and token_calls[0][3] is sent
    assert bool(reg.notes) is not sent  # an anonymous request says why in the outcome
    assert reg.auth.startswith("Bearer tok-")


@pytest.mark.parametrize("realm_host", ["127.0.0.1", "169.254.169.254", "meta.example.com", "local.example.com",
                                        "v6meta.example.com", "mapped.example.com", "0.0.0.0", "sink.example.com",
                                        "v6sink.example.com", "0.1.2.3", "[64:ff9b::]", "[::ffff:0.1.2.3]",
                                        "zero8.example.com", "nat64sink.example.com"])
def test_a_registry_cannot_send_the_node_to_loopback_or_link_local(fake_net, realm_host):
    reg = CI.Registry(_ctx(), CI.parse_ref("registry.example.com/app:1"), dict(CREDS), None)
    reg._client(reg.base + "/v2/")
    # reported as the registry steering the node (status "error", "refused"), also for the unspecified addresses
    # that the never-scan gate refuses on its own: a hostile registry must not look like a never-scan skip
    with pytest.raises(CI.ImageError, match="refused") as err:
        reg._authenticate(f'Bearer realm="https://{realm_host}/token"')
    assert err.value.status == "error"
    _FakeClient.redirect_to = f"https://{realm_host}/latest/meta-data/"
    with pytest.raises(CI.ImageError, match="refused") as err:
        reg.get("/v2/app/blobs/sha256:" + "a" * 64, stream=True)
    assert err.value.status == "error"
    assert not [s for s in fake_net.seen if s[0].startswith(f"https://{realm_host}")]


@pytest.mark.parametrize("realm_host", ["0.0.0.0", "sink.example.com", "v6sink.example.com", "0.1.2.3",
                                        "[64:ff9b::]", "zero8.example.com"])
def test_a_registry_steering_the_node_to_itself_is_worded_as_such(fake_net, realm_host):
    """0.0.0.0/8 and :: are neither link-local nor metadata: the refusal says the address reaches the node itself."""
    reg = CI.Registry(_ctx(), CI.parse_ref("registry.example.com/app:1"), dict(CREDS), None)
    reg._client(reg.base + "/v2/")
    with pytest.raises(CI.ImageError) as err:
        reg._authenticate(f'Bearer realm="https://{realm_host}/token"')
    assert "an address that reaches the node itself" in err.value.detail and "link-local" not in err.value.detail


def test_a_registry_on_loopback_may_use_loopback_for_its_token_service_and_blobs(lab_factory):
    lab = lab_factory(redirect_blobs=True)  # registry on 127.0.0.1, blobs redirected to 127.0.0.2
    lab.push("1.0", _image_layers())
    status, error, ctx = _collect(lab, f"localhost:{lab.registry.server_port}/team/app:1.0")
    assert status == "success", (error, ctx.outcomes)
    assert [s for s in lab.seen if s[0] == "other"]

"""#215: container images Save and test (and collection) against the image's real size and its tag.

* Save and test compares the manifest's compressed layer sizes with ``max_image_mb`` and says so; dev passed the
  test for a 2 MB image with a 1 MB cap, and the collection then failed.
* ``repo:tag@sha256:...``: Docker reads the digest. dev dropped the tag without a word, so a tag that points at
  another image was never reported. The tag is now resolved and compared with the digest (the digest itself, or
  an image index that lists it): a mismatch fails the test sample and is noted on the collected image.

The fake registry is test_wp8b_agent_registry.Lab (a real TLS server on 127.0.0.1).
"""
from __future__ import annotations

import time

from test_wp8b_agent_registry import Lab, _image_layers, lab_factory  # noqa: F401  (lab_factory is a fixture)

from zs_scan_node.collectors import container_images as CI
from zs_scan_node.collectors import run_job
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber


def _ctx(kind: str) -> JobContext:
    return JobContext(job_id=1, attempt=1, run_id=None, kind=kind, source_kind="container_images", scrubber=Scrubber(),
                      never_scan=NeverScan([]), deadline=time.monotonic() + 600)


def _run(lab: Lab, kind: str, image: str, **cfg):
    ctx = _ctx(kind)
    config = {"images": [image], "credential_type": "anonymous", "ca_pem": lab.ca_pem, **cfg}
    status, error, summary = run_job(ctx, {"id": 1, "kind": kind}, {}, {"kind": "container_images", "config": config,
                                                                        "secrets": {}})
    ctx.flush()
    return ctx, status, summary


def _big_layers() -> list[bytes]:
    import os

    return _image_layers() + [os.urandom(2 * 1024 * 1024)]  # about 2 MB compressed (random bytes do not shrink)


def test_save_and_test_checks_the_size_cap(lab_factory):  # noqa: F811
    lab = lab_factory()
    lab.push("big", _big_layers())
    ctx, status, _summary = _run(lab, "test_connection", f"localhost:{lab.registry.server_port}/team/app:big",
                                 max_image_mb=1)
    (sample,) = ctx.samples
    assert sample["status"] == "not_supported"  # dev: "ready" ("4 layers, sha256:...")
    assert sample["note"] == "the image is 2.0 MB compressed (cap 1 MB); raise max_image_mb to read it"
    assert not [s for s in lab.seen if "/blobs/" in s[1]]  # the manifest only: no layer is downloaded by a test


def test_an_image_under_the_cap_still_tests_ready(lab_factory):  # noqa: F811
    lab = lab_factory()
    lab.push("small", _image_layers())
    ctx, _status, _summary = _run(lab, "test_connection", f"localhost:{lab.registry.server_port}/team/app:small",
                                  max_image_mb=1)
    assert ctx.samples[0]["status"] == "ready"


def _digest_of(lab: Lab, tag: str) -> str:
    import hashlib
    import json

    body = lab.manifests[tag]
    doc = json.loads(body)
    if "manifests" in doc:  # an index: its amd64 image
        return next(m["digest"] for m in doc["manifests"] if m["platform"]["architecture"] == "amd64")
    return "sha256:" + hashlib.sha256(body).hexdigest()


def test_a_tag_that_points_at_another_image_than_the_digest_is_reported(lab_factory):  # noqa: F811
    lab = lab_factory()
    lab.push("3.16", _image_layers())
    lab.push("other", _image_layers()[:1])  # another (valid) image: its first layer only
    other = _digest_of(lab, "other")
    image = f"localhost:{lab.registry.server_port}/team/app:3.16@{other}"
    ctx, _status, _summary = _run(lab, "test_connection", image)
    (sample,) = ctx.samples
    assert sample["status"] == "error"  # dev: "ready", the tag never looked at
    assert sample["note"].startswith("the tag 3.16 points to sha256:")
    assert f"not to the digest given ({other[:19]}" in sample["note"] and sample["note"].endswith(
        "the image is read by its digest")
    # a collection reads the digest (Docker's rule) and notes the mismatch on the image's assets and its target row
    ctx, status, _summary = _run(lab, "collect", image)
    assert status == "success" and ctx.outcomes[0].status == "ok" and "points to" in (ctx.outcomes[0].error or "")
    facts = [a["facts"] for a in ctx.collected if a.get("type") == "crypto_library"]
    assert facts and all(f["image_tag"] == "3.16" and f["tag_matches_digest"] is False for f in facts)


def test_a_tag_and_its_own_digest_agree(lab_factory):  # noqa: F811
    lab = lab_factory()
    lab.push("1.0", _image_layers())
    image = f"localhost:{lab.registry.server_port}/team/app:1.0@{_digest_of(lab, '1.0')}"
    ctx, _status, _summary = _run(lab, "test_connection", image)
    assert ctx.samples[0]["status"] == "ready"
    ctx, _status, _summary = _run(lab, "collect", image)
    facts = [a["facts"] for a in ctx.collected if a.get("type") == "crypto_library"]
    assert facts and all(f["tag_matches_digest"] is True for f in facts) and not ctx.outcomes[0].error


def test_a_multi_arch_tag_matches_the_digest_of_one_of_its_images(lab_factory):  # noqa: F811
    lab = lab_factory()
    lab.push("1.0", _image_layers(), index=True)
    image = f"localhost:{lab.registry.server_port}/team/app:1.0@{_digest_of(lab, '1.0')}"  # the amd64 image's digest
    ctx, _status, _summary = _run(lab, "test_connection", image)
    assert ctx.samples[0]["status"] == "ready"


def test_the_reference_keeps_its_label_and_its_tag():
    ref = CI.parse_ref("10.232.0.40/lab/alpine:3.16@sha256:" + "a" * 64)
    assert ref.reference == "sha256:" + "a" * 64 and ref.tag == "3.16"
    assert ref.label == "10.232.0.40/lab/alpine@sha256:" + "a" * 64  # unchanged: the asset identity stays stable
    assert CI.parse_ref("10.232.0.40/lab/alpine:3.16").tag is None  # a tag alone is the reference itself

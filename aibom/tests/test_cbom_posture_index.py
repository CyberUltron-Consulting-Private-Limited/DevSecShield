"""One walk, two reservation groups."""

from pathlib import Path

from aibom.cbom.posture.context import CbomScanContext


def test_index_is_memoized(tmp_path: Path) -> None:
    (tmp_path / "redis.conf").write_text("port 1\n", encoding="utf-8")
    sink = CbomScanContext(tmp_path).posture
    assert sink.index() is sink.index()


def test_config_is_reserved_before_source_files(tmp_path: Path) -> None:
    for number in range(50):
        (tmp_path / f"{number:02d}.py").write_text("x = 1\n", encoding="utf-8")
    infra = tmp_path / "infra"
    infra.mkdir()
    target = infra / "main.tf"
    target.write_text('resource "aws_s3_bucket" "b" {}\n', encoding="utf-8")
    files = CbomScanContext(tmp_path).posture.index().files
    rels = [item.rel for item in files]
    assert rels[0] == "infra/main.tf"
    assert rels[1].endswith(".py")


def test_read_included_charges_the_budget(tmp_path: Path) -> None:
    (tmp_path / "snippet.conf").write_text("listen 80;\n", encoding="utf-8")
    sink = CbomScanContext(tmp_path).posture
    before = sink.bytes_read
    decoded = sink.read_included("snippet.conf", "web-server")
    assert decoded is not None
    assert sink.bytes_read > before
    assert sink.included_files == 1
    assert sink.read_included("snippet.conf", "web-server") is decoded

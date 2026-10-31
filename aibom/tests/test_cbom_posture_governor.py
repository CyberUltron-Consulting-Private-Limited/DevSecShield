"""Size-governor bounds used before a run object is built."""

from pathlib import Path

from aibom.cbom.posture.assemble import (
    estimate_fact,
    n_pre,
    reduce_record,
    validations_for,
)


def test_typical_facts_pre_prune_at_3390() -> None:
    assert n_pre([estimate_fact() for _ in range(4_000)]) == 3_390


def test_only_the_final_build_is_validated() -> None:
    assert validations_for(0) == 0
    assert validations_for(1) == 1
    assert validations_for(4) == 1


def test_build_keeps_the_finding_when_the_budget_holds_one_fact() -> None:
    from aibom.cbom.posture.assemble import build_posture_block, fact_component
    from aibom.cbom.posture.context import CbomScanResult, PostureSidecar
    from aibom.cbom.posture.model import EncryptionFact
    from aibom.model.component import MetadataComponent

    def fact(address: str, codes: tuple[str, ...] = ()) -> EncryptionFact:
        return EncryptionFact(
            id=address,
            kind="relational_db",
            provider="aws",
            native_type="aws_db_instance",
            address=address,
            path="main.tf",
            line=1,
            format="terraform",
            layers={"service": "NOT_ENCRYPTED"},
            verdict="NOT_ENCRYPTED",
            finding_codes=codes,
        )

    result = CbomScanResult(
        subject=MetadataComponent(name="budget"),
        components=[
            fact_component(fact("plain")),
            fact_component(fact("flagged", ("UNENCRYPTED_AT_REST",))),
        ],
        posture=PostureSidecar.empty(),
    )
    block = build_posture_block(result, budget=5_000)
    assert [row["address"] for row in block["facts"]] == ["flagged"]
    assert block["dropped"]["run_object_budget"] == 1
    assert block["validations"] == 1
    full = build_posture_block(result)
    assert len(full["facts"]) == 2
    assert full["dropped"]["run_object_budget"] == 0
    assert full["validations"] == 1


def test_fixture_normalize_validates_the_bom_once(monkeypatch) -> None:
    from aibom.cbom.normalize import normalize_crypto
    from aibom.cbom.pipeline import scan_crypto
    from aibom.emit import cyclonedx
    from aibom.emit.validate import validate_cyclonedx

    calls: list[int] = []

    def spy(bom: dict) -> list[str]:
        calls.append(1)
        return validate_cyclonedx(bom)

    monkeypatch.setattr(cyclonedx, "validate_cyclonedx", spy)
    tree = Path(__file__).resolve().parent / "fixtures" / "synthetic-config-aws-tf"
    run = normalize_crypto(scan_crypto(tree), duration_of_scan=0.0)
    assert calls == [1]
    assert run["cbom_json"]["bomFormat"] == "CycloneDX"
    assert run["cbom_posture"]["validations"] == 1


def test_phase1_record_does_not_keep_the_parse_tree() -> None:
    record = reduce_record(["parse-node"])
    assert record == {}

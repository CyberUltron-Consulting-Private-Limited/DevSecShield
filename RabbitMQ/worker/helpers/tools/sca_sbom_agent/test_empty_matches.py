"""Hermetic: empty Grype matches must not raise Documents are not set.

Also locks multi-engine enrich metadata + CERT-In requirement count (41).

Runnable without pytest::
  cd RabbitMQ/worker && uv run python -m unittest \\
    helpers.tools.sca_sbom_agent.test_empty_matches -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Repo root for aibom enrich import
_REPO_ROOT = Path(__file__).resolve().parents[4]
if str(_REPO_ROOT / "aibom" / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "aibom" / "src"))


def _write_cdx(path: Path, components: list[dict]) -> Path:
    path.write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}),
        encoding="utf-8",
    )
    return path


class TestEmptyGrypeMatches(unittest.TestCase):
    def test_populate_empty_matches_skips_map_reduce(self) -> None:
        from helpers.tools.sca_sbom_agent.main import SCASBOMAgent

        agent = SCASBOMAgent.__new__(SCASBOMAgent)
        agent.directory = "/tmp/sbom-empty-matches-hermetic"
        agent.vulnerabilities = None
        agent.state_update_writer = None
        agent.sbom_json_file = None
        agent.inventory_rows = []
        agent.bom_properties = {}
        agent.sbom_json = None

        mock_ctx = MagicMock()
        mock_ctx.results = {"matches": []}
        syft_p = _write_cdx(
            Path(tempfile.mkstemp(suffix=".cdx.json")[1]),
            [{"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}],
        )

        with (
            patch(
                "helpers.tools.sca_sbom_agent.main.run_syft",
                return_value=syft_p,
            ),
            patch(
                "helpers.tools.sca_sbom_agent.main.run_cdxgen",
                return_value=None,
            ),
            patch(
                "helpers.tools.sca_sbom_agent.main.OpenSourceContext",
                return_value=mock_ctx,
            ),
        ):
            agent.populate_opensource_context()

        self.assertEqual(agent.vulnerabilities, [])
        self.assertGreaterEqual(len(agent.inventory_rows), 1)
        self.assertIn("syft", agent.bom_properties.get("sbom:inventory_tools", ""))
        self.assertEqual(agent.bom_properties.get("sbom:vuln_scanner"), "grype")
        self.assertIsInstance(agent.sbom_json, dict)
        names = [c.get("name") for c in agent.sbom_json.get("components") or []]
        self.assertIn("requests", names)
        for c in agent.sbom_json.get("components") or []:
            ref = str(c.get("bom-ref") or "")
            self.assertFalse(ref.lower().startswith("sbom-dep"))
        mock_ctx.generate_map_reduce_summary.assert_not_called()

    def test_populate_empty_matches_does_not_surface_documents_error(self) -> None:
        from helpers.tools.sca_sbom_agent.main import SCASBOMAgent

        agent = SCASBOMAgent.__new__(SCASBOMAgent)
        agent.directory = "/tmp/sbom-empty-matches-hermetic"
        agent.vulnerabilities = None
        agent.inventory_rows = []
        agent.bom_properties = {}
        agent.sbom_json = None

        mock_ctx = MagicMock()
        mock_ctx.results = {"matches": []}
        mock_ctx.generate_map_reduce_summary.side_effect = ValueError(
            "Documents are not set"
        )

        with (
            patch(
                "helpers.tools.sca_sbom_agent.main.run_syft",
                return_value=None,
            ),
            patch(
                "helpers.tools.sca_sbom_agent.main.run_cdxgen",
                return_value=None,
            ),
            patch(
                "helpers.tools.sca_sbom_agent.main.OpenSourceContext",
                return_value=mock_ctx,
            ),
        ):
            agent.populate_opensource_context()

        self.assertEqual(agent.vulnerabilities, [])

    def test_enrich_empty_findings_still_carries_cert_in_sbom(self) -> None:
        from aibom.integrations.sbom_devsecshield import enrich_sbom_scan

        out = enrich_sbom_scan([], 0.5)
        self.assertIn("sbom_compliance", out)
        ci = out["sbom_compliance"]["cert_in_sbom"]
        self.assertEqual(len(ci.get("requirements") or []), 41)

    def test_enrich_with_inventory_and_tool_props_passes_provenance(self) -> None:
        from aibom.integrations.sbom_devsecshield import enrich_sbom_scan

        rows = [
            {
                "dependency": "requests==2.31.0",
                "title": "Inventory: requests",
                "description": "HTTP library",
                "impact": "Low",
                "reachability": "not_reachable",
                "license_type": "Apache-2.0",
                "license": "Apache-2.0",
                "purl": "pkg:pypi/requests@2.31.0",
                "cves": {},
                "inventory_only": True,
                "vuln_assessed": True,
            }
        ]
        out = enrich_sbom_scan(
            rows,
            1.0,
            bom_properties={
                "sbom:inventory_tools": "syft,cdxgen",
                "sbom:vuln_scanner": "grype",
                "sbom:automation_cyclonedx": "true",
                "sbom:multi_format_emit": "true",
            },
            sbom_json={"bomFormat": "CycloneDX", "components": []},
        )
        by_id = {
            r["id"]: r
            for r in out["sbom_compliance"]["cert_in_sbom"]["requirements"]
        }
        self.assertEqual(by_id["T5-Inventory-Tools"]["verdict"], "pass")
        self.assertEqual(by_id["T5-Vuln-Scanner"]["verdict"], "pass")
        self.assertEqual(by_id["T5-Multi-Format-Emit"]["verdict"], "pass")
        self.assertEqual(by_id["T5-Automation-CycloneDX"]["verdict"], "pass")
        self.assertIn("sbom_json", out)


class TestMergeInventory(unittest.TestCase):
    def test_merge_dedupes_by_purl(self) -> None:
        from helpers.tools.sca_sbom_agent.merge_inventory import (
            inventory_to_finding_rows,
            merge_cdx_components,
        )

        a = _write_cdx(
            Path(tempfile.mkstemp(suffix=".a.json")[1]),
            [
                {
                    "name": "flask",
                    "version": "3.0.0",
                    "purl": "pkg:pypi/flask@3.0.0",
                    "description": "from-syft",
                }
            ],
        )
        b = _write_cdx(
            Path(tempfile.mkstemp(suffix=".b.json")[1]),
            [
                {
                    "name": "flask",
                    "version": "3.0.0",
                    "purl": "pkg:pypi/flask@3.0.0",
                    "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                },
                {"name": "click", "version": "8.1.0", "purl": "pkg:pypi/click@8.1.0"},
            ],
        )
        merged = merge_cdx_components(a, b)
        self.assertEqual(len(merged), 2)
        flask = next(c for c in merged if c["name"] == "flask")
        self.assertEqual(flask.get("description"), "from-syft")
        self.assertTrue(flask.get("licenses"))
        rows = inventory_to_finding_rows(merged, vuln_assessed=True)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r.get("vuln_assessed") for r in rows))
        for r in rows:
            self.assertNotEqual(str(r.get("license_type", "")).lower(), "unknown")
            self.assertNotIn("unknown", str(r.get("license", "")).lower())
            self.assertIn(r["license_type"], {
                "permissive", "public_domain", "weak_copyleft", "creative_commons",
                "commercial", "strong_copyleft", "network_copyleft", "source_available",
                "not_declared",
            })
        flask_row = next(r for r in rows if "flask" in r["dependency"])
        self.assertEqual(flask_row["license"], "BSD-3-Clause")
        self.assertEqual(flask_row["license_type"], "permissive")
        click_row = next(r for r in rows if "click" in r["dependency"])
        self.assertEqual(click_row["license"], "BSD-3-Clause")  # curated map
        self.assertEqual(click_row["license_type"], "permissive")

    def test_assemble_cyclonedx_uses_real_package_names(self) -> None:
        from helpers.tools.sca_sbom_agent.merge_inventory import assemble_cyclonedx

        doc = assemble_cyclonedx(
            [
                {
                    "name": "requests",
                    "version": "2.31.0",
                    "purl": "pkg:pypi/requests@2.31.0",
                    "bom-ref": "sbom-dep-0",
                },
                {"name": "flask", "version": "3.0.0", "purl": "pkg:pypi/flask@3.0.0"},
            ],
            tools=["syft", "cdxgen"],
            subject_name="my-app",
        )
        self.assertEqual(doc["bomFormat"], "CycloneDX")
        names = [c["name"] for c in doc["components"]]
        self.assertEqual(names, ["requests", "flask"])
        for c in doc["components"]:
            self.assertNotIn("sbom-dep", str(c.get("bom-ref") or "").lower())
            self.assertNotIn("sbom dependency", str(c.get("name") or "").lower())
        self.assertEqual(doc["metadata"]["component"]["name"], "my-app")


class TestInventoryLicenseNeverUnknown(unittest.TestCase):
    def test_missing_license_is_not_declared(self) -> None:
        from helpers.tools.sca_sbom_agent.merge_inventory import inventory_to_finding_rows

        rows = inventory_to_finding_rows(
            [{"name": "obscure-pkg-xyz", "version": "1.0.0"}],
            vuln_assessed=False,
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["license_type"], "not_declared")
        self.assertEqual(rows[0]["license"], "LicenseRef-not-declared")
        self.assertEqual(rows[0]["reachability"], "not_reachable")


if __name__ == "__main__":
    unittest.main()

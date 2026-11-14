"""CBOM end-to-end evidence harness (CB-01): judges one Tier-L gate run directory.

Rules (DEVILS-ADVOCATE.md §3, §4): an expected value never comes from product code, the product's knowledge base,
product fixtures or a product view (O-1). This package therefore imports nothing from backend/, aibom/, scan_node/
or frontend/; backend/tests/test_cbom_e2e_harness.py enforces that. Standard library plus PyYAML only.
"""

SCHEMA_REPORT = "zs-cbom-gate-report/1"
SCHEMA_MANIFEST = "zs-cbom-gate-manifest/1"

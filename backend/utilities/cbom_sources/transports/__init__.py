"""F1.3: agentless fleet transports (AWX/AAP, Salt, AWS SSM) and the zs-collect releases they run.

``base.py``, ``zsdoc.py``, ``wrappers.py`` and ``zs-release-ed25519.pub`` are byte-identical copies of the scan node's
(``scan_node/zs_scan_node/transports/`` and ``scan_node/zs_collect/``); ``backend/tests/test_cbom_transports.py``
compares them.  Everything else here is backend-only.
"""

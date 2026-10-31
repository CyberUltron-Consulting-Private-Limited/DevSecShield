"""CBOM collection sources: scan nodes, servers, clusters, databases, cloud, network scope, evidence.

The CBOM engine in ``aibom/`` stays air-gapped (see ``.kiro/specs/cbom-config-encryption-posture``):
nothing in this package is imported by it, and nothing here reaches a customer network.  Customer
networks are reached by scan nodes, which pull jobs over HTTPS from ``backend/routers/cbom_node.py``.
"""

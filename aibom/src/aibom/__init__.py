"""clinithread-aibom: healthcare-grade AI Bill of Materials engine.

A healthcare-focused extension of DevSecShield's AIBOM. Scans an ML model
repo into a normalized, serializer-agnostic inventory
(:mod:`aibom.model.component`) and emits schema-validated CycloneDX 1.6
ML-BOMs (:mod:`aibom.emit.cyclonedx`) with clinical-imaging / regulatory
metadata carried in namespaced ``properties[]`` (clinical:/regulatory:/dataset:).
"""

__version__ = "0.1.0"

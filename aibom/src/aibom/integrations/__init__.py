"""Integrations that adapt the clinithread-aibom engine into host platforms.

These are OUTBOUND adapters: they consume a scored
:class:`~aibom.model.result.ScanResult` and normalize it into a host's result
schema. They never change engine internals (lanes stay intact) and import
nothing from the host — the host imports *this*.

Currently: :mod:`.devsecshield` (DevSecShield native-scanner contract).
"""

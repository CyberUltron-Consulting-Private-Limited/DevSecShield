"""Classifier extensions: one module per feature area; each calls classify.register(asset_type, rule, cdx_type).

A rule receives (out, facts, algorithm, key_size, now), adds finding codes with out.add(code, impact, text) and
returns the quantum verdict for the asset (True, False or None). Add every new code to a kb_ext module too.
"""

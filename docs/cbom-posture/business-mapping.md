# Business mapping

The extractor reads one optional mapping file from the scanned repository. The first existing path wins:

1. `.devsecshield/cbom-mapping.yaml`
2. `.devsecshield/cbom-mapping.json`
3. `cbom-mapping.yaml`
4. `cbom-mapping.json`

Each other existing candidate records diagnostic `mapping_file_ignored`. A `version` other than the integer `1` ignores that file with the same diagnostic.

`defaults` applies to every fact. `entries` override it field by field, and a later entry overrides an earlier one. An entry applies only when every selector it gives matches: `match.resource` is a glob over the fact address, `match.path` is a glob over the repository-relative path, and `match.kind` is one exact fact kind. There is no regular expression.

The closed string fields are `system`, `owner`, `data_classification`, and `data_lifetime`. Control characters are removed and each value is cut to 256 characters. Unknown keys record `mapping_unknown_key`. An entry of the wrong type, an unknown kind, or a non-string field records `mapping_entry_invalid` and that entry is skipped. The loader keeps at most 10,000 entries. Further entries are counted and dropped.

Applied values are stored with source `mapping_file`. They print as declared text. They do not change a verdict and they do not fill an assessor cell.

Example:

```yaml
version: 1
defaults:
  system: billing
  owner: platform
entries:
  - match:
      path: apps/pay/*
      kind: object_store
    owner: payments
    data_classification: confidential
    data_lifetime: 7y
```

## CODEOWNERS

The first existing file of `.github/CODEOWNERS`, `CODEOWNERS`, and `docs/CODEOWNERS` supplies `owner_hint`. The last matching gitignore-style pattern wins. The hint is stored separately from `owner` and is not merged into it. A pattern that uses negation or a character class is skipped and records `codeowners_pattern_unsupported`.

When neither a mapping entry nor a CODEOWNERS pattern applies, the data-at-rest report leaves the system, owner, classification, and lifetime cells for an assessor. There is no database table, API field, or UI form for this mapping.

# Business mapping

An optional in-repo file named `cbom-mapping.yaml` or `cbom-mapping.json` attaches declared business context to encryption facts. The file is a list of objects. The closed fields are `system`, `owner`, `data_classification`, and `data_lifetime`.

Unknown keys record diagnostic `mapping_unknown_key`. An entry that is not an object records `mapping_entry_invalid`. The loader keeps at most 10,000 entries.

Example:

```yaml
- system: payments
  owner: payments-team
  data_classification: confidential
  data_lifetime: 7y
```

Values print as declared text. They do not change a verdict and they do not fill an assessor cell.

## CODEOWNERS

A `CODEOWNERS` file supplies `owner_hint` when a rule matches the fact path. The hint is the last matching rule. There is no database table, API field, or UI form for this mapping.

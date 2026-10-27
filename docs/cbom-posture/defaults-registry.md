# Defaults registry

Each data file under `aibom/src/aibom/cbom/data/` carries `data_version` and `valid_as_of`. The engine loads those files with `importlib.resources` through `files("aibom.cbom").joinpath("data")`. It does not read a path from the environment and it does not refresh the files over the network.

## Row contents

A default row names the provider or software, the resource type or directive, the attribute, the documented default, the encryption effect, and a public URL. A row that can raise a finding from an absent attribute is listed in `aibom/tests/cbom_posture_reviewed_rows.txt`. Other omissions stay UNKNOWN.

## Authoring

Write a row from the vendor or standards page named by its URL. This is a clean-room record of that page's documented default. Do not copy rule text from another scanner. A URL must be present in `aibom/tests/cbom_posture_url_allowlist.txt`.

When a default depends on a provider or software version and the scanned input does not pin that version, the verdict is UNKNOWN `provider_version_dependent`.

## Update procedure

1. Read the current vendor page.
2. Change the row, its URL, and `valid_as_of` together.
3. Keep Terraform and CloudFormation spellings of one semantic rule paired.
4. Run the posture content tests. Do not format files under `tests/fixtures`.

# chroma fixture (external clone — not vendored)

`tests/fixtures/chroma/` is a clone of `chroma-core/chroma`. It is **not
committed** (~71 MB, and it carries its own `.git`, so vendoring it would create
an embedded-repo gitlink). The committed artifacts are the oracle goldens
captured against it:

- `tests/oracles/trusera/chroma.json`
- `tests/oracles/cisco/chroma.json`

Reproduce the working tree the oracles were captured against:

```bash
git clone https://github.com/chroma-core/chroma tests/fixtures/chroma
git -C tests/fixtures/chroma checkout 207de398a18c703cd69b43aae54078d9e3064747
```

The clone directory is git-ignored (`tests/fixtures/.gitignore`).

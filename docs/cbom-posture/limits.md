# Limits

These integers are the posture lane limits. Units are bytes, files, nodes, lines, or steps. The serialized posture block cap is `POSTURE_BLOCK_BYTES`. A separate 15 MiB adapter-dict budget is described in the design and is not a constant in `limits.py`.

<!-- table:limits -->
| name | value |
| --- | --- |
| BYTES_PER_CONFIG_FILE | 5242880 |
| BYTES_PER_LINE | 1048576 |
| BYTES_PER_SCAN | 268435456 |
| BYTES_PER_TLS_RESULT | 20971520 |
| FACTS_PER_SCAN | 50000 |
| FILES_PER_SCAN | 10000 |
| GLOB_STEPS | 20000000 |
| INCLUDE_DEPTH | 5 |
| MAPPING_ENTRIES | 10000 |
| NESTING_DEPTH | 100 |
| NUL_PROBE_BYTES | 8192 |
| PATH_MAX_BYTES | 512 |
| POSTURE_BLOCK_BYTES | 8388608 |
| POSTURE_COMPONENTS | 20000 |
| SNIFF_BYTES | 65536 |
| STORED_DIAGNOSTICS | 1000 |
| YAML_ALIASES | 1000 |
| YAML_NODES | 500000 |

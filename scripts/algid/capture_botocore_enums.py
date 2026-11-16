"""Capture the AWS enum values algid needs from the botocore service models (run with the backend's pinned botocore).

    docker run --rm --network none --entrypoint /backend/.venv/bin/python -v "$PWD:/w" \
        dss-staging/devsecshield-backend:stack /w/scripts/algid/capture_botocore_enums.py \
        > scripts/algid/sources/botocore-enums.json
"""
import json

import botocore
import botocore.session

WANT = (("acm", "KeyAlgorithm"), ("acm-pca", "KeyAlgorithm"), ("acm-pca", "SigningAlgorithm"),
        ("kms", "KeySpec"), ("kms", "SigningAlgorithmSpec"), ("apigateway", "SecurityPolicy"))
session = botocore.session.get_session()
out = {"botocore": botocore.__version__, "enums": {}}
for service, shape in WANT:
    out["enums"][f"{service}.{shape}"] = list(session.get_service_model(service).shape_for(shape).enum)
print(json.dumps(out, indent=1, sort_keys=True))

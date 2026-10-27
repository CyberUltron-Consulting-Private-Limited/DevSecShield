# Air gap

The posture scanners import only the Python standard library, pydantic, pyyaml, and `aibom` modules. A posture scan does not open a socket and does not start a process. Reference data is read from the installed package.

Zip upload in the product stack uses an S3-compatible store addressed by `AWS_ENDPOINT_URL_S3`. That store is an internal dependency of the upload path. It is not a posture-scanner dependency.

The isolated-network proof has not been run for this change. That proof is the Docker overlay, the gateway, the scan worker, and the `/proc/net/tcp` allow-list. It is outside this documentation commit. Do not treat this page as that proof.

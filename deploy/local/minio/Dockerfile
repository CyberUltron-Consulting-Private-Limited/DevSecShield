# S3 stand-in for the local install (deploy/local/README.md): MinIO server built from its source release.
# minio/minio is no longer on Docker Hub and MinIO publishes no other community image (deploy/staging/README.md), so
# .github/workflows/publish-ghcr.yml builds this for linux/amd64 and linux/arm64 as
# ghcr.io/<owner>/devsecshield-minio:<tag>. Local use only: it holds scan uploads and reports of a test stack.
#
#   docker buildx build -t devsecshield-minio:local deploy/local/minio
#
# Nothing is copied from the build context (deploy/local/minio/.dockerignore excludes everything); the source is
# MinIO's last community release tag, checked against its commit id below.
ARG GO_BASE_IMAGE=golang:1.26-bookworm
ARG RUNTIME_BASE_IMAGE=debian:bookworm-slim

FROM ${GO_BASE_IMAGE} AS build
# RELEASE.2025-10-15T17-29-55Z: the last source release (includes the fix for CVE-2025-62506).
ARG MINIO_TAG=RELEASE.2025-10-15T17-29-55Z
ARG MINIO_COMMIT=9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local
WORKDIR /src
RUN git clone --quiet --depth 1 --branch "${MINIO_TAG}" https://github.com/minio/minio.git . \
 && test "$(git rev-parse HEAD)" = "${MINIO_COMMIT}" \
 || { echo "minio ${MINIO_TAG} is not commit ${MINIO_COMMIT}" >&2; exit 1; }
# The version flags MinIO's own release build sets (buildscripts/gen-ldflags.go with MINIO_RELEASE=RELEASE).
ARG MINIO_VERSION=2025-10-15T17:29:55Z
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    pkg=github.com/minio/minio/cmd \
 && go build -tags kqueue -trimpath -o /out/minio -ldflags "-s -w -X ${pkg}.Version=${MINIO_VERSION} \
      -X ${pkg}.CopyrightYear=2025 -X ${pkg}.ReleaseTag=${MINIO_TAG} -X ${pkg}.CommitID=${MINIO_COMMIT} \
      -X ${pkg}.ShortCommitID=$(printf '%.12s' "${MINIO_COMMIT}")" . \
 && /out/minio --version

FROM ${RUNTIME_BASE_IMAGE}
COPY --from=build /out/minio /usr/local/bin/minio
# Not root. A new named volume mounted at /data takes this directory's owner.
RUN useradd --system --uid 10002 --home-dir /data --shell /usr/sbin/nologin minio \
 && mkdir -p /data && chown minio:minio /data && chmod 0700 /data
USER 10002
VOLUME ["/data"]
EXPOSE 9000
ENTRYPOINT ["minio"]
CMD ["server", "/data"]

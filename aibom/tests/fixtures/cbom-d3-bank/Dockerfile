ARG PY_VERSION=3.11
FROM python:${PY_VERSION}-slim AS build
RUN pip install --no-cache-dir -r requirements.txt
FROM build AS test
FROM gcr.io/distroless/python3-debian12@sha256:0f1f7d2c4b3a6e5d8c9b0a1f2e3d4c5b6a7980716253443526170819a0b1c2d3
COPY --from=build /app /app

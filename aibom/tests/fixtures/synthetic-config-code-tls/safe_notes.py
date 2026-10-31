"""Always keep TLS certificate verification enabled in production clients."""

# Do not disable peer verification when calling HTTPS APIs.
import requests

requests.get("https://example.com/health")

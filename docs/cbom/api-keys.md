# CBOM API keys: scripted onboarding

A CBOM API key lets a script (Terraform, a CMDB sync job, a CI pipeline) add CBOM sources, start collection runs
and download their CBOM without a person signing in. Keys belong to one team and carry scopes. They are shown once,
and they keep working until they expire or a team admin revokes them.

## Create a key

In **Settings → API keys** (`/<team id>/settings/api-keys`), a team admin enters a name, picks one or more scopes and
an optional expiry (1 to 730 days), then copies the secret. **The secret is shown only once.** The server stores
only its SHA-256, so a lost key cannot be recovered. Revoke it and create a new one.

| Scope | Allows |
|---|---|
| `cbom.read` | Read sources, scan nodes, runs, run results, posture, diffs and exports (CycloneDX CBOM, OSCAL) |
| `cbom.sources:write` | Add, change, test and remove sources. Includes `cbom.read` |
| `cbom.runs:write` | Price, start and cancel runs. Includes `cbom.read` |

Keys look like `zsk_` followed by 43 URL-safe characters (`zsk_[A-Za-z0-9_-]{43}`), so secret scanners can find
a leaked key. Keep the key in your secret store (Vault, a CI secret) and never in a repository.

## What a key can and cannot do

* It works only on the CBOM Sources routes for sources, scan nodes (read only), jobs, estimates and runs, and on
  the run exports (`/runs/{run_id}/cbom`, `/oscal`, `/results`, `/posture`, `/assets`, `/diff`, `/changes`,
  `/heatmap`). It works only for its own team and only with the scope the route needs.
* Everything else refuses it: account settings, team and billing, API key management, CBOM settings, scan node
  enrolment (registration tokens), evidence, the audit log, other products.
* A key acts as the admin who created it. It stops working when that person is no longer an admin of the team.
  Create a new key from a current admin's account.
* Every use is rate-limited for that key (300 reads and 60 writes a minute) and recorded in the CBOM audit log as
  `api_key.use` (refusals as `api_key.refused` with the reason). Changes made with a key appear with actor
  `api_key` and the key's id. **Last used** on the settings page shows the latest use.

| Status | Meaning |
|---|---|
| 401 `Invalid API key` | Unknown or malformed key |
| 401 `This API key was revoked` / `... expired at ...` | Ask a team admin for a new key |
| 403 `This API key lacks the <scope> scope` | Create a key with that scope |
| 403 `This API key belongs to another team` | Use the team id the key was created in |
| 403 `API keys cannot call this route ...` | The route needs a signed-in team member |
| 429 `Too Many Requests` | Wait for the number of seconds in `Retry-After` |

## Example: onboard a source and start a run

The key needs `cbom.sources:write` and `cbom.runs:write`. A team admin has enrolled a scan node once in the UI
(scan node enrolment hands out a registration token, so keys cannot do it).

```bash
set -euo pipefail
API="https://app.example.com/api"        # your DevSecShield API base URL
TEAM=42                                  # your team id (in the app's URLs)
AUTH="Authorization: Bearer $ZS_API_KEY" # the zsk_... key from your secret store

# 1. pick the scan node that reaches the new hosts
NODE=$(curl -sS -X GET "$API/$TEAM/cbom/sources/nodes" -H "$AUTH" | jq -r '.nodes[] | select(.name=="dc-mumbai-01") | .id')

# 2. add the source (secrets are write-only: the response lists their names, never their values)
SOURCE=$(curl -sS -X POST "$API/$TEAM/cbom/sources/items" -H "$AUTH" -H "Content-Type: application/json" \
  -d @- <<JSON | jq -r '.source.id'
{"kind": "linux_servers", "name": "cmdb-linux-mumbai", "node_id": $NODE,
 "config": {"targets": ["10.20.0.0/29", "app-01.bank.local"], "credential_type": "password", "login_user": "zs-cbom",
            "host_key_policy": "pinned", "known_hosts": "$(cat known_hosts)", "window": "any"},
 "secrets": {"password": "$LINUX_PASSWORD"}}
JSON
)

# 3. price the run, then start it (client_request_id makes a retried call start nothing twice)
CREDITS=$(curl -sS -X POST "$API/$TEAM/cbom/sources/estimate" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"include": {"servers": true}}' | jq -r '.total_credits')
RUN=$(curl -sS -X POST "$API/$TEAM/cbom/sources/runs" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"include\": {\"servers\": true}, \"source_ids\": [$SOURCE], \"expected_credits\": $CREDITS,
       \"client_request_id\": \"cmdb-$(date +%Y%m%d)-$SOURCE\"}" | jq -r '.run.id')

# 4. follow the run, then download its CycloneDX CBOM
curl -sS -X GET "$API/$TEAM/cbom/sources/runs/$RUN" -H "$AUTH" | jq '.run.status'
curl -sS -X GET "$API/$TEAM/cbom/sources/runs/$RUN/cbom?format=json" -H "$AUTH" -o "cbom-run-$RUN.cdx.json"
```

The request and response bodies of every route are in the API's OpenAPI document (`/openapi.json`, tag
`cbom-sources`).

## Rotate a key

1. Create a new key with the same scopes.
2. Put it in your secret store and run the job once.
3. Revoke the old key (Settings → API keys → Revoke). Revocation applies to the next request.

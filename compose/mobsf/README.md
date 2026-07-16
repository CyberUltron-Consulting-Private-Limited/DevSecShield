# Mobile App Security analyzer (private)

Internal static analysis sidecar used by DevSecShield Mobile App Security scans.
Do not expose this port publicly. The UI never references this service by name.

## Start

```powershell
cd DevSecShield
docker compose -f compose\mobsf\docker-compose.yml --env-file compose\mobsf\.env up -d
```

Listens on `127.0.0.1:8000` only.

## Worker env

Set in `RabbitMQ/worker/.env` (and container-test overrides):

- `MOBSF_URL=http://127.0.0.1:8000` (native) or `http://host.docker.internal:8000` (worker in Docker)
- `MOBSF_API_KEY` — must match `compose/mobsf/.env`

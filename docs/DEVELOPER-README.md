# DevSecShield Chola (Production): Developer Guide

Everything the development team needs to deploy and operate on the Chola production infrastructure. No secret values live in this file; secrets are stored in AWS Secrets Manager (`devsec-chola/prod/*`) and rendered onto the instance as mode `0600` environment files (`deploy/chola-prod/`).

**Account:** `935951870001`  
**Region:** `ap-south-1`  
**IAM user:** `AnshSinghal-Cyberultron` (`--profile chola`)

## 1. Key infrastructure facts

| Item | Value |
|---|---|
| Instance | `i-0b7fe756ebfd4d1e6` (`m7i.2xlarge`, `x86_64`, 8 vCPU, 32 GB RAM), Ubuntu 24.04, user `ubuntu`, private IP `10.60.10.108` (no public IP) |
| Outbound NAT EIP | `13.127.93.213` (`nat-09f353434e4239f4d`, `devsec-chola-prod-nat-eip`) — fixed source IP for all scans and STS/Git egress |
| Docker | Engine 29.10 and Compose plugin v5.8. Data root `/var/lib/docker` is on the 200 GB `gp3` volume `vol-02a57fae6510bb790` |
| ALB | `devsec-chola-prod-alb-126072335.ap-south-1.elb.amazonaws.com` (HTTPS on 443 with ACM certificate) |
| Hostnames | `chola.zeroshield.ai` (frontend -> `frontend:3000`), `chola-api.zeroshield.ai` (backend API -> `backend:8080`) |
| ALB target | EC2 **port 80 only** (plain HTTP; TLS terminates at the ALB) |
| ALB health check | `GET /nginx-health` -> HTTP `200` (`ok`) |
| `DSS_REAL_IP_FROM` | `10.60.1.0/24,10.60.2.0/24` (ALB public subnets) |
| S3 bucket | `devsecshield-storage` (`ap-south-1`, `AWS_ENDPOINT_URL_S3` unset) |
| Bedrock models | `openai.gpt-oss-120b-1:0` (`LLM_MODEL`) and `global.anthropic.claude-haiku-4-5-20251001-v1:0` (`CBOM_AI_MODEL`) in `ap-south-1` |
| Mail relay | Google SMTP (`smtp.gmail.com`, port `465`, `SMTP_SECURITY=ssl`, sender `support@zeroshield.ai`) |
| Scan-node artifacts | Version `1.0.9` served from `/opt/devsecshield-chola/node-artifacts` (`/node-artifacts` in `backend`) + GHCR public image/chart refs |
| Stack directory | `/opt/devsecshield-chola` (`deploy/chola-prod/docker-compose.yml`, Compose project `dss-chola`, managed by `scripts/deploy/chola-prod.sh`) |

Only `nginx` publishes port `80` on the host. `frontend:3000`, `backend:8080`, `postgres`, `mongo`, `rabbitmq`, and `qdrant` stay on private Docker networks (`edge` and internal `data`). There is no service on port `7000`.

## 2. Log in to the instance

Add this entry to `~/.ssh/config`:

```sshconfig
Host devsec-chola
    HostName i-0b7fe756ebfd4d1e6
    User ubuntu
    IdentityFile ~/.ssh/devsec-chola-admin.pem
    IdentitiesOnly yes
    ServerAliveInterval 30
    StrictHostKeyChecking accept-new
    ProxyCommand aws ec2-instance-connect open-tunnel --profile chola --region ap-south-1 --instance-id %h
```

Fetch the SSH private key once from Secrets Manager (section 3), then connect with:

```bash
ssh devsec-chola
```

## 3. Secrets in AWS Secrets Manager (`ap-south-1`)

| Secret ID | Contents |
|---|---|
| `devsec-chola/prod/ssh-admin` | SSH private key (`private_key_pem`) for `ubuntu` |
| `devsec-chola/prod/app-user` | `devsec-chola-prod-app-user` access keys (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) for S3 and Bedrock. **Required**: scan workers build explicit S3/Bedrock clients from env vars and do not fall back to the EC2 instance role. |
| `devsec-chola/prod/cbom-collector` | `devsec-chola-prod-cbom-collector` access keys (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `USER_ARN`), scoped strictly to `sts:AssumeRole` |
| `devsec-chola/prod/app-secrets` | JSON object with `JWT_SECRET_KEY`, `JWT_REFRESH_SECRET_KEY`, `ENCRYPTION_KEY` (Fernet), `CERTIN_HMAC_SECRET`, `PG_USER_PASS`, `MONGO_INITDB_ROOT_PASSWORD`, `RABBIT_ADMIN_PASSWORD`, `QDRANT_API_KEY`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `MAIL_FROM` |

Save the SSH key locally:

```bash
mkdir -p ~/.ssh
aws secretsmanager get-secret-value --profile chola --region ap-south-1 \
  --secret-id devsec-chola/prod/ssh-admin --query SecretString --output text \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['private_key_pem'])" > ~/.ssh/devsec-chola-admin.pem
chmod 600 ~/.ssh/devsec-chola-admin.pem
```

`deploy/chola-prod/kit.py render-env` reads `app-secrets`, `app-user`, and `cbom-collector` on the instance via the instance role and writes four `0600` files in `/opt/devsecshield-chola/deploy/chola-prod/`:
- `.env` (Compose interpolation + datastore credentials only)
- `backend.env` (API, `migrate`, `cbom-cloud-worker`, `dast-scheduler`; `DSS_ENV=production`, never `DSS_DEV_MODE`)
- `scan-worker.env` (`scan-worker`, `cicd-worker`, including `QDRANT_*` and `LLM_MODEL`)
- `dast-worker.env` (`dast-worker`)

## 4. ECR repositories (`linux/amd64`)

Registry: `935951870001.dkr.ecr.ap-south-1.amazonaws.com`

- `devsec-chola/devsecshield-frontend` (built with `NEXT_PUBLIC_BACKEND_URL=https://chola-api.zeroshield.ai`)
- `devsec-chola/devsecshield-backend`
- `devsec-chola/scan-worker`
- `devsec-chola/dast-worker`

```bash
aws ecr get-login-password --profile chola --region ap-south-1 \
  | docker login --username AWS --password-stdin 935951870001.dkr.ecr.ap-south-1.amazonaws.com
```

## 5. Deploy, scan-node artifacts, and backups

Full runbook: `deploy/chola-prod/README.md`.

```bash
export AWS_PROFILE=chola
scripts/deploy/chola-prod.sh preflight --sha <commit>
scripts/deploy/chola-prod.sh deploy --sha <commit>
scripts/deploy/chola-prod.sh node-artifacts          # installs/refreshes scan-node 1.0.9 downloads if missing
scripts/deploy/chola-prod.sh smtp-test               # verifies Google SMTP login on 465 SSL without sending mail
scripts/deploy/chola-prod.sh verify                  # checks ALB health, /nginx-health, UI /login, API /health
```

Manual pre-deployment EBS snapshot of the 200 GB data volume (kept 14 days):

```bash
aws backup start-backup-job --profile chola --region ap-south-1 \
  --backup-vault-name devsec-chola-prod-backup-vault \
  --resource-arn arn:aws:ec2:ap-south-1:935951870001:volume/vol-02a57fae6510bb790 \
  --iam-role-arn arn:aws:iam::935951870001:role/devsec-chola-prod-backup-role \
  --lifecycle DeleteAfterDays=14 \
  --recovery-point-tags Application=DevSecShield,CostCenter=DevSecShield-Production,Deployment=Chola,Environment=Production,ManagedBy=DevOps,Name=devsec-chola-prod-pre-deployment,Owner=CyberUltron,Project=DevSecShield
```

## 6. Verification commands

```bash
# ALB target group health
aws elbv2 describe-target-health --profile chola --region ap-south-1 \
  --target-group-arn arn:aws:elasticloadbalancing:ap-south-1:935951870001:targetgroup/devsec-chola-prod-tg/3c35d6b360c5c80a \
  --query "TargetHealthDescriptions[].TargetHealth.State" --output text

# On the instance
ssh devsec-chola 'curl -fsS http://127.0.0.1/nginx-health'

# Public endpoints
curl -fsSI https://chola.zeroshield.ai/login
curl -fsS https://chola-api.zeroshield.ai/health
```

## 7. Network & Backup notes

- Daily automated backups: EBS data volume (`vol-02a57fae6510bb790`) at 18:00 UTC (14-day retention) and instance AMI at 18:30 UTC (7-day retention).
- Outbound allowed: HTTPS (`443`) to AWS services, GitHub, GitLab, Bitbucket, and Grype DB; SMTP (`465` and `587`); HTTP (`80`) for `apt`. Git over SSH (`22`) and SMTP `25` are blocked — use HTTPS repository URLs.

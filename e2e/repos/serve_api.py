"""F3 browser proof: the REAL API (``backend.main:app``, every router, real auth) on a throw-away PostgreSQL database,
with the fake GitHub API of the backend tests (``backend/tests/support/fake_scm.py``) playing the customer's
organisation. ``e2e/repos/import-wizard.spec.ts`` drives the Repositories pages against it in a real browser, so the
wizard's requests, the server's validation, discovery (paginated, through the real provider client) and the inventory
are all real; only GitHub is simulated. Dev tooling: never shipped, never imported by product code.

    PYTHONPATH=<repo> backend/.venv/bin/python e2e/repos/serve_api.py \\
        --db postgresql://user@127.0.0.1:5432/throwaway --port 18081 --cors http://127.0.0.1:13000 \\
        --state e2e/.work/repos/state.json

The database's tables are DROPPED and re-created. ``state.json`` (mode 0600, git-ignored under e2e/.work) holds the
API URL, the fake GitHub URL, the team, and short-lived access tokens for an admin and a member, signed with a JWT key
generated for this run only; nothing secret is printed. Stop it with SIGTERM / Ctrl-C.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import sys
from pathlib import Path
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

ORG = "acme"
REPOS = 240  # three pages of 100: the wizard's discovery really paginates
TOKEN = "ghp_E2eFakeOrgToken0000000000000000000000"  # accepted by the fake API only
USERS = {"admin": ("ada.admin@acme.e2e", "admin"), "member": ("max.member@acme.e2e", "member")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="PostgreSQL URL of a throw-away database (tables are dropped)")
    ap.add_argument("--port", type=int, default=18081)
    ap.add_argument("--cors", required=True, help="the frontend origin, e.g. http://127.0.0.1:13000")
    ap.add_argument("--state", required=True, help="where to write state.json")
    ap.add_argument("--latency", type=float, default=0.4, help="seconds the fake API takes per page")
    args = ap.parse_args()

    db = urlsplit(args.db)
    # Configuration the backend reads at import time: set before importing it. Fresh secrets for this run only.
    os.environ.update({
        "PG_HOST": db.hostname or "127.0.0.1", "PG_PORT": str(db.port or 5432), "PG_USER": db.username or "postgres",
        "PG_USER_PASS": db.password or "unused", "PG_DB": db.path.lstrip("/"),
        "JWT_SECRET_KEY": secrets.token_hex(32), "JWT_REFRESH_SECRET_KEY": secrets.token_hex(32),
        "CORS_ORIGINS": args.cors, "REPO_SCHEDULER": "0",
    })
    from cryptography.fernet import Fernet

    os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    os.environ.pop("DSS_DEV_MODE", None)
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"):
        os.environ.pop(name, None)  # the simulated world needs no cloud account; never hand one to this process

    from backend.tests.support.fake_scm import FakeScmServer, FakeScmState, make_repos

    state = FakeScmState(latency_s=args.latency)
    state.add_tokens(TOKEN)
    state.github_orgs[ORG] = make_repos(ORG, REPOS)
    fake = FakeScmServer(state).__enter__()
    # the operator allow-list that gates self-hosted API URLs (and cloning): the fake API is the only one allowed
    os.environ["GIT_ALLOWED_HOSTS"] = fake.url

    import uvicorn
    from sqlmodel import Session, SQLModel

    from backend.get_db import get_db
    from backend.main import app
    from backend.new_models import Team, TeamMembership, User
    from backend.utilities.auth import auth_utils

    engine = get_db()
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    tokens = {}
    with Session(engine) as s:
        s.add(Team(id=1, name="Acme Bank", credit_balance=500.0))
        s.commit()
        for key, (email, role) in USERS.items():
            user = User(email=email, password="!", first_name=key.title(), last_name="E2e", profile_photo=None,
                        session_active=True, default_team_id=1)
            s.add(user)
            s.commit()
            s.refresh(user)
            s.add(TeamMembership(team_id=1, user_id=user.id, role=role))
            s.commit()
            tokens[key] = auth_utils.create_access_token(email)

    out = Path(args.state)
    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({"api": f"http://127.0.0.1:{args.port}", "fake_api": fake.url, "team_id": 1, "org": ORG,
                   "repos": REPOS, "org_token": TOKEN, "admin_token": tokens["admin"],
                   "member_token": tokens["member"]}, fh)
    print(f"serve_api: API http://127.0.0.1:{args.port}, fake GitHub {fake.url} ({REPOS} repositories in {ORG}); "
          f"state {out}", flush=True)

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=args.port, log_level="warning"))
    signal.signal(signal.SIGTERM, lambda *_: setattr(server, "should_exit", True))
    try:
        server.run()
    finally:
        fake.__exit__(None, None, None)
        print(f"serve_api: fake GitHub answered {sum(state.responses.values())} requests {dict(state.responses)}",
              flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

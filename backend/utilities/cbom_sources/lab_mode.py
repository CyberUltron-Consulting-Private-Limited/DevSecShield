"""Lab mode for test deployments: AWS collection from the deployment's own account (CB-A1 PLAN §2).

A customer's reader role normally may never be in ZeroShield's own AWS account (the one CBOM_AWS_PRINCIPAL_ARN
names): that account's inventory must never land in a customer's CBOM.  A test deployment whose only AWS account is
the one it runs its collector from (the sandbox) cannot test AWS collection end to end without an exception, so:

* ``CBOM_AWS_LAB_SAME_ACCOUNT=1`` allows a single-account source whose role is in the deployment's own account;
* only where the deployment says it is NOT production: ``DSS_ENV`` must name a test deployment (``staging``, ``lab``,
  ``development``/``dev``, ``test``, ``local``).  ``DSS_ENV=production`` (or ``prod``), any other value, or no value at
  all refuses the switch (fail closed: a production deployment that never heard of DSS_ENV stays safe);
* nothing else is relaxed: the external ID (and the refusal without it), SecurityAudit, the data-plane deny and the
  denied secret read are all still checked, at validation and again at collection;
* every use is logged (WARNING, with the team) and audited; a refused switch is logged as an ERROR naming the reason;
* the form and every run of such a source carry :data:`LAB_BANNER`.
"""
from __future__ import annotations

import os

from backend.utilities.cbom_sources.common import log

LAB_FLAG = "CBOM_AWS_LAB_SAME_ACCOUNT"
ENV_VAR = "DSS_ENV"
LAB_BANNER = "Lab mode: same-account collection — not for production"
LAB_MODE = "same_account"  # the job result's and the validation's lab_mode value
TEST_DEPLOYMENTS = frozenset({"staging", "lab", "development", "dev", "test", "local"})
OWN_ACCOUNT_REFUSED = "This role is in ZeroShield's own AWS account; use a role in your account"
ORGANIZATION_REFUSED = ("Lab mode allows only a single-account source in this deployment's own AWS account; "
                        "an organization source there is refused")


def _flag_on() -> bool:
    return os.environ.get(LAB_FLAG, "").strip().lower() in ("1", "true", "yes", "on")


def refusal_reason() -> str | None:
    """Why the switch is refused on this deployment, or None when it may be used (or is simply off)."""
    if not _flag_on():
        return None
    env = os.environ.get(ENV_VAR, "").strip().lower()
    if env in ("production", "prod"):
        return f"{ENV_VAR}={env}"
    if env not in TEST_DEPLOYMENTS:
        return f"{ENV_VAR} is {'unset' if not env else 'not a test deployment (' + env[:32] + ')'}"
    return None


def lab_same_account() -> bool:
    """True when the switch is on and this deployment says it is a test deployment.  Never raises (fail closed)."""
    try:
        return _flag_on() and refusal_reason() is None
    except Exception:
        return False


def own_account_decision(role_arn_account: str | None, own_account: str | None, scope: str, *, team_id: int,
                         where: str) -> tuple[str | None, bool]:
    """The own-account guard, in one place for validation and collection.

    Returns ``(refusal, lab)``: ``refusal`` is the sentence to show when the role may not be used (None when it may),
    ``lab`` is True when the role is in the deployment's own account and lab mode allowed it.  Logs every use and
    every refused attempt to use the switch."""
    if not own_account or role_arn_account != own_account:
        return None, False
    if not _flag_on():
        return OWN_ACCOUNT_REFUSED, False
    reason = refusal_reason()
    if reason is not None or not lab_same_account():
        log(f"ERROR lab_mode same_account REFUSED reason={reason or 'error'} ({LAB_FLAG} is set on a deployment that "
            f"is not a test deployment)", team=team_id, where=where)
        return OWN_ACCOUNT_REFUSED, False
    if scope != "account":
        log("WARNING lab_mode same_account refused for an organization source", team=team_id, where=where)
        return ORGANIZATION_REFUSED, False
    log(f"WARNING lab_mode same_account USED account={own_account} (test deployment; refused in production)",
        team=team_id, where=where)
    return None, True

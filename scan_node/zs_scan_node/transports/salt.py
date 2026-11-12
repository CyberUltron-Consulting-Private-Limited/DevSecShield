"""Salt transport: the customer's salt-api (rest_cherrypy) runs zs-collect on minions or over salt-ssh.

Config (``transport`` in the claim payload): ``base_url`` (https), ``eauth`` (pam, ldap, ...), ``client``
(``local`` | ``local_async`` | ``ssh``), ``mode`` (``state``: ``state.apply zeroshield.zs_collect`` with the nonce and
tier as pillar; ``cmd``: ``cmd.script salt://zeroshield/zs-collect-run.sh``), ``batch_size``, ``timeout_s``,
``verify_tls``, ``ca_pem``.  Secrets: ``username``, ``password`` (an eauth account allowed to run exactly that).

The files the master serves (``zeroshield/zs_collect.sls`` and ``zeroshield/zs-collect-run.sh``) come from the
transport's ``salt-state`` artifact.  Each minion (or salt-ssh host) returns the launcher's stdout, which holds one
zs-collect/1 document; it is validated (format, nonce, version, schema) before it is handed on.  A minion that does
not answer in time is ``unreachable``; a salt-ssh host that cannot be logged in to is ``unreachable`` or
``auth_failed``; the launcher's integrity refusal (exit 4) is ``refused``.
"""
from __future__ import annotations

import time
from typing import Any, ClassVar, Iterator, Sequence

from zs_scan_node.netutil import NeverScan
from zs_scan_node.transports import control
from zs_scan_node.transports import zsdoc
from zs_scan_node.transports.base import (CollectOptions, CollectTarget, TargetResult, TransportCredential,
                                          TransportError)
from zs_scan_node.transports.wrappers import host_timeout, salt_args

WHAT = "salt-api"
SCRIPT = "salt://zeroshield/zs-collect-run.sh"
STATE = "zeroshield.zs_collect"
POLL_S = 3.0
DEFAULT_BATCH = 50
MAX_BATCH = 500
MAX_SSH_BATCH = 100  # salt-ssh: one synchronous request per batch, ~80 MB of master memory per concurrent process
NO_RETURN = ("minion did not return", "no response", "not connected")


class SaltTransport:
    name: ClassVar[str] = "salt"

    def __init__(self, never: NeverScan, log=None, poll_s: float = POLL_S, check_options: CollectOptions | None = None,
                 grace_s: float = 30.0):
        self.never = never
        self.grace_s = grace_s  # how long after the minions' own timeout the job lookup keeps waiting
        self.log = log or (lambda *a, **k: None)
        self.poll_s = poll_s
        self.check_options = check_options

    # ------------------------------------------------------------------ login
    def _login(self, credential: TransportCredential):
        secrets = credential.secrets or {}
        if not secrets.get("username") or not secrets.get("password"):
            raise TransportError("auth_failed", "no salt-api username and password are stored for this transport")
        timeout = float(credential.config.get("timeout_s") or 300) + 60
        http = control.client(credential.config, self.never, headers={"Accept": "application/json"},
                              timeout=timeout, what=WHAT)
        try:
            resp = control.request(http, "POST", "/login", WHAT, json={
                "username": secrets["username"], "password": secrets["password"],
                "eauth": str(credential.config.get("eauth") or "pam")})
            if resp.status_code in (401, 403):
                raise TransportError("auth_failed", f"salt-api refused the login ({resp.status_code})")
            if resp.status_code >= 400:
                raise TransportError("error", f"salt-api login failed ({resp.status_code})")
            try:
                token = resp.json()["return"][0]["token"]
            except (ValueError, KeyError, IndexError, TypeError):
                raise TransportError("error", "salt-api answered the login without a token") from None
        except BaseException:
            http.close()
            raise
        http.headers["X-Auth-Token"] = str(token)
        return http

    def _post(self, http, low: dict[str, Any]) -> Any:
        resp = control.request(http, "POST", "/", WHAT, json=[low])
        control.raise_for_auth(resp, WHAT)
        if resp.status_code >= 400:
            raise TransportError("error", f"salt-api refused the {low.get('fun')} call ({resp.status_code})")
        try:
            return resp.json()["return"][0]
        except (ValueError, KeyError, IndexError, TypeError):
            raise TransportError("error", "salt-api answered with something that is not a salt return") from None

    # ------------------------------------------------------------------ protocol
    def check(self, credential: TransportCredential, sample: Sequence[CollectTarget]) -> list[TargetResult]:
        self._login(credential).close()
        if self.check_options is None:
            return []
        return list(self.run_collect(list(sample)[:5], credential, self.check_options))

    def run_collect(self, targets: Sequence[CollectTarget], credential: TransportCredential,
                    options: CollectOptions) -> Iterator[TargetResult]:
        cfg = credential.config
        client = str(cfg.get("client") or "local_async")
        if client not in ("local", "local_async", "ssh"):
            raise TransportError("error", f"salt client {client} is not supported (local, local_async, ssh)")
        mode = str(cfg.get("mode") or "cmd")
        if mode not in ("cmd", "state"):
            raise TransportError("error", f"salt mode {mode} is not supported (cmd, state)")
        size = max(1, min(int(cfg.get("batch_size") or DEFAULT_BATCH), MAX_SSH_BATCH if client == "ssh" else MAX_BATCH))
        # salt's own wait for the script covers zs-collect's per-host timeout (and its command slack)
        timeout = max(int(cfg.get("timeout_s") or 300), host_timeout(options) + 60)
        http = self._login(credential)  # already used for /login: closed in the finally below, not a with block
        try:
            for start in range(0, len(targets), size):
                batch = list(targets[start:start + size])
                stop = options.should_stop()
                if stop:
                    for t in batch:
                        yield TargetResult(t, stop, None, None)
                    continue
                low = self._lowstate(client, mode, batch, options, timeout)
                if client == "local_async":
                    returns = self._async(http, low, batch, options, timeout)
                else:
                    returns = self._post(http, low)
                    returns = returns if isinstance(returns, dict) else {}
                for t in batch:
                    try:
                        res = self._result(t, client, mode, returns.get(t.handle, _MISSING), options)
                    except Exception as exc:  # one minion's output is that minion's error, never the batch's
                        res = TargetResult(t, "error", f"the salt return for this host could not be read "
                                                       f"({exc.__class__.__name__})", None)
                    yield res
        finally:
            http.close()

    # ------------------------------------------------------------------ calls
    @staticmethod
    def _lowstate(client: str, mode: str, batch: list[CollectTarget], options: CollectOptions,
                  timeout: int) -> dict[str, Any]:
        tier = int(options.tier)
        if mode == "state":
            fun, arg = "state.apply", [STATE]
            kwarg: dict[str, Any] = {"pillar": {"zs_nonce": options.run_nonce, "zs_tier": tier,
                                                "zs_timeout_s": host_timeout(options)}}
        else:
            fun, arg = "cmd.script", [SCRIPT, salt_args(options.run_nonce, tier, timeout_s=host_timeout(options))]
            kwarg = {"timeout": timeout}
        low: dict[str, Any] = {"client": client, "tgt": [t.handle for t in batch], "tgt_type": "list", "fun": fun,
                               "arg": arg, "kwarg": kwarg}
        if client in ("local", "local_async"):
            low["timeout"] = timeout
            low["full_return"] = True
        return low

    def _async(self, http, low: dict[str, Any], batch: list[CollectTarget], options: CollectOptions,
               timeout: int) -> dict[str, Any]:
        """Start the job, poll which minions have returned (a cheap status), then fetch the returns once: the full
        lookup carries every minion's whole document (35-130 KB each), so it is not repeated on every poll."""
        started = self._post(http, low)
        jid = (started or {}).get("jid") if isinstance(started, dict) else None
        if not jid:
            raise TransportError("error", "salt-api did not return a job id")
        expected = {t.handle for t in batch}
        self.log("salt job started", jid=jid, minions=len(expected))
        until = min(options.deadline, time.monotonic() + timeout + self.grace_s)
        while not (expected <= self._returned(http, jid, expected) or options.should_stop()
                   or time.monotonic() >= until):
            time.sleep(self.poll_s)
        return self._returns(http, jid, expected)

    def _returned(self, http, jid: str, expected: set[str]) -> set[str]:
        """The minions whose return is in the job cache: the runner's ``jobs.exit_success`` answers minion -> bool
        (the same '@jobs' permission as the job lookup), without the returns themselves."""
        resp = control.request(http, "POST", "/", WHAT, json=[{"client": "runner", "fun": "jobs.exit_success",
                                                               "jid": jid}])
        self._lookup_allowed(resp, jid)
        try:
            ret = resp.json()["return"][0]
        except (ValueError, KeyError, IndexError, TypeError):
            return set()
        return {m for m, done in ret.items() if done is True and m in expected} if isinstance(ret, dict) else set()

    def _returns(self, http, jid: str, expected: set[str]) -> dict[str, Any]:
        resp = control.request(http, "GET", f"/jobs/{jid}", WHAT)
        self._lookup_allowed(resp, jid)
        try:
            ret = resp.json()["return"][0]
        except (ValueError, KeyError, IndexError, TypeError):
            return {}
        return {k: v for k, v in ret.items() if k in expected} if isinstance(ret, dict) else {}

    @staticmethod
    def _lookup_allowed(resp, jid: str) -> None:
        control.raise_for_auth(resp, WHAT)
        if resp.status_code >= 400:  # e.g. the runner client is not enabled: waiting would not help
            raise TransportError("error", f"salt-api could not look up job {jid} ({resp.status_code}): enable the "
                                          "'runner' client (netapi_enable_clients) and '@jobs' for this account")

    # ------------------------------------------------------------------ results
    def _result(self, t: CollectTarget, client: str, mode: str, ret: Any, options: CollectOptions) -> TargetResult:
        if ret is _MISSING:
            stop = options.should_stop()
            if stop:
                return TargetResult(t, stop, None, None)
            return TargetResult(t, "unreachable", "the minion did not return in time" if client != "ssh" else
                                "salt-ssh returned nothing for this host", None)
        script, problem = _script_result(ret, client, mode)
        if problem:
            return TargetResult(t, *problem, None)
        stdout, stderr, rc = script
        if rc == 4:
            return TargetResult(t, "refused", f"zs-collect integrity check failed: {stderr.strip()[-200:]}", None)
        if rc == 3:
            return TargetResult(t, "error", f"zs-collect is not installed on the host: {stderr.strip()[-200:]}", None)
        try:
            doc = zsdoc.parse_output(stdout, options.run_nonce)
        except (zsdoc.ChunkError, ValueError) as exc:
            return TargetResult(t, "error", f"no zs-collect document from salt (exit {rc}): {str(exc)[:120]} "
                                            f"{stderr.strip()[-120:]}".strip(), None)
        problem_text = zsdoc.validate_document(doc, options.run_nonce, options.collector_version)
        if problem_text:
            return TargetResult(t, "error", f"zs-collect document refused: {problem_text}", None)
        return TargetResult(t, "ok", None, doc)


_MISSING = object()


def _as_text(value: Any) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


def _script_result(ret: Any, client: str, mode: str) -> tuple[tuple[str, str, int | None], tuple[str, str] | None]:
    """((stdout, stderr, retcode), None) or (_, (status, error)) from one host's salt return, in the shapes of the
    local client (plain or full_return), the async job lookup and salt-ssh."""
    empty = ("", "", None)
    if client == "ssh" and isinstance(ret, dict) and "return" not in ret and ret.get("retcode") not in (None, 0):
        # salt-ssh could not run anything there: {"retcode": 255, "stderr": "ssh: connect to host ..."}
        err = (_as_text(ret.get("stderr")) or _as_text(ret.get("stdout"))).strip()
        low = err.lower()
        status = "auth_failed" if "permission denied" in low else "unreachable"
        return empty, (status, f"salt-ssh: {err[-200:] or 'exit ' + str(ret.get('retcode'))}")
    if isinstance(ret, dict) and "return" in ret and set(ret) & {"retcode", "jid", "id", "fun", "success"}:
        ret = ret["return"]  # full_return / salt-ssh wrapper
    elif isinstance(ret, dict) and "ret" in ret and "retcode" in ret:
        ret = ret["ret"]
    if isinstance(ret, str):
        low = ret.lower()
        if any(s in low for s in NO_RETURN):
            return empty, ("unreachable", ret[:200])
        return empty, ("error", f"salt: {ret[:200]}")
    if not isinstance(ret, dict):
        return empty, ("error", "salt returned nothing usable for this host")
    if mode == "state":
        for key, state in ret.items():
            if not isinstance(state, dict) or "_|-zs_collect_|-" not in str(key):
                continue
            if str(key).startswith("test_|-"):
                return empty, ("error", f"salt state refused: {_as_text(state.get('comment'))[:200]}")
            changes = state.get("changes") or {}
            if isinstance(changes, dict) and "stdout" in changes:
                return (_as_text(changes.get("stdout")), _as_text(changes.get("stderr")),
                        _int(changes.get("retcode"))), None
            return empty, ("error", f"salt state zs_collect: {_as_text(state.get('comment'))[:200]}")
        return empty, ("error", "the salt state result has no zs_collect step (is zeroshield/zs_collect.sls on the "
                                "master's file roots?)")
    if "stdout" in ret or "retcode" in ret:
        return (_as_text(ret.get("stdout")), _as_text(ret.get("stderr")), _int(ret.get("retcode"))), None
    return empty, ("error", "the cmd.script result has no stdout")


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

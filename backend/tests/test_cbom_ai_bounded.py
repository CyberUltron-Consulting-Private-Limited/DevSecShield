"""Bounded AI answers (issues #448, #449; staging QA rows R7-03, R7-04, R7-05).

R7-04: every Plan for TLS / SSH / appliance / RSA-1024 findings was withheld as "not in the required format": the answer
was cut at the 700-token output cap, the JSON never closed, and the Converse ``stopReason`` was never read. Each mode now
has a budget that fits its answer, a cut-off answer is retried once (shorter, with more room) and is then shown as far as
it is complete, or withheld as too long, never as a format error.

R7-05: a slow or hung call ran past the host proxy's 60 s read timeout, so the browser got the proxy's 504 without a
CORS header ("could not be reached"). The whole request now answers within ``CBOM_AI_DEADLINE_S`` (50 s by default),
as the app's own "took too long, try again" answer; an idle pooled connection is not reused and a dropped one is
retried once on a fresh connection; building the client never probes instance metadata.

Bedrock is the real botocore client with its HTTP send stubbed (test_cbom_ai.py's ``bedrock`` fixture) answering with
recorded Converse response bodies (tests/fixtures/cbom_ai_converse_replies.json). No AWS account, no network.
"""
from __future__ import annotations

import dataclasses
import json
import re
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from bson import ObjectId

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_ai as _ai  # noqa: E402
import test_cbom_ai_fix as _fx  # noqa: E402
import test_cbom_sources_api as _harness  # noqa: E402

from backend.utilities.cbom_ai import config as C  # noqa: E402
from backend.utilities.cbom_ai import fix as FIX  # noqa: E402
from backend.utilities.cbom_ai import prompt as P  # noqa: E402
from backend.utilities.cbom_ai import service as S  # noqa: E402
from backend.utilities.cbom_ai import transport as T  # noqa: E402
from backend.utilities.cbom_ai import validator as V  # noqa: E402

world = _harness.world
api = _harness.api
bedrock = _ai.bedrock
captured = _ai.captured
mongo = _fx.mongo
_clean_ai = _ai._clean_ai

ROOT = Path(__file__).resolve().parents[2]
REPLIES = json.loads((Path(__file__).resolve().parent / "fixtures" / "cbom_ai_converse_replies.json").read_text())
TLS = "10.20.0.1:443"  # K1 PROTO_TLS10, K2 WEAK_CIPHER, K3 NO_PQ_KEX: the KB steps of a TLS endpoint, as on staging


def _converse(*names: str):
    """A ``bedrock["reply"]`` answering with the recorded bodies in order (the last one repeats)."""
    queue = list(names)

    def reply(_request):
        return 200, REPLIES[queue.pop(0) if len(queue) > 1 else queue[0]]

    return reply


def _body(text: str, stop: str) -> dict:
    return {"output": {"message": {"role": "assistant", "content": [{"text": text}]}}, "stopReason": stop,
            "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2}}


def _requests(bedrock) -> list[dict]:
    return [json.loads(s["body"]) for s in bedrock["sent"]]


def _audit(lines: list[str]) -> str:
    found = [ln for ln in lines if "cbom_ai audit" in ln]
    assert found, lines
    return found[-1]


def _plan(api, world, mode="plan", question=None):
    engine, _ = world
    asset = _ai._assets(api, engine)[TLS]["id"]
    r = _ai._assist(api, asset, mode=mode, question=question)
    assert r.status_code == 200, r.text
    return r.json(), asset


# ------------------------------------------------------------------------------------------------ R7-04 budgets
def test_each_mode_has_an_output_budget_that_fits_its_answer(monkeypatch):
    cfg = C.AiConfig(provider="openai_compat", base_url="http://127.0.0.1:1/v1", model="m", api_key=None,
                     ca_file=None, timeout_s=60, max_tokens=0, concurrency=1, redact_hosts=False,
                     allow_nonprivate=False)
    # the largest answer the validator keeps; commands, ids and JSON punctuation are about 3 characters a token
    schema_chars = V.MAX_SUMMARY + V.MAX_STEPS * V.MAX_STEP + V.MAX_COMMANDS * V.MAX_COMMAND + \
        V.MAX_CAVEATS * V.MAX_CAVEAT
    assert S.token_budget(cfg, "plan") * 3 >= schema_chars
    # a question can ask for a whole plan (the long "complete plan" question on asset 6901 was withheld too)
    assert S.token_budget(cfg, "question") == S.token_budget(cfg, "plan")
    assert 700 < S.token_budget(cfg, "explain") <= S.token_budget(cfg, "plan")
    assert S.token_budget(cfg, "fix") == FIX.FIX_MAX_TOKENS
    for mode in ("explain", "plan", "question", "fix"):
        assert S.token_budget(cfg, mode) < S.token_budget(cfg, mode, retry=True) <= S.RETRY_MAX_TOKENS
    # CBOM_AI_MAX_TOKENS is the operator's cap (a model with a small output or context limit): a retry keeps it
    capped = dataclasses.replace(cfg, max_tokens=900)
    assert S.token_budget(capped, "plan") == S.token_budget(capped, "plan", retry=True) == 900
    assert S.token_budget(capped, "fix") == FIX.FIX_MAX_TOKENS
    monkeypatch.setenv("CBOM_AI_PROVIDER", "bedrock")
    assert C.load().max_tokens == 0  # unset: each mode's own budget
    for raw, expected in (("900", 900), ("10", 64), ("99999", 8192), ("abc", 0), ("", 0)):
        monkeypatch.setenv("CBOM_AI_MAX_TOKENS", raw)
        assert C.load().max_tokens == expected, raw


def test_a_complete_plan_is_one_call_with_the_plan_budget(api, world, bedrock, captured):
    bedrock["reply"] = _converse("end_turn_plan")
    out, _asset = _plan(api, world)
    assert out["status"] == "ok" and not out.get("truncated") and len(out["steps"]) == 6, out
    assert [r["inferenceConfig"]["maxTokens"] for r in _requests(bedrock)] == [S.MODE_MAX_TOKENS["plan"]]
    line = _audit(captured)
    assert "outcome=ok" in line and "stop=end_turn" in line and "attempts=1" in line


def test_a_plan_cut_at_max_tokens_is_asked_again_shorter_with_more_room(api, world, bedrock, captured):
    bedrock["reply"] = _converse("max_tokens_plan", "end_turn_compact")
    out, _asset = _plan(api, world)
    assert out["status"] == "ok" and not out.get("truncated"), out
    assert [s["cites"] for s in out["steps"]] == [["K1.fix"], ["K2.fix"]]
    first, second = _requests(bedrock)
    assert first["inferenceConfig"]["maxTokens"] == S.MODE_MAX_TOKENS["plan"]
    assert second["inferenceConfig"]["maxTokens"] == min(2 * S.MODE_MAX_TOKENS["plan"], S.RETRY_MAX_TOKENS)
    assert P.COMPACT not in json.dumps(first) and P.COMPACT in second["messages"][-1]["content"][0]["text"]
    line = _audit(captured)
    assert "stop=max_tokens,end_turn" in line and "attempts=2" in line, line
    assert f"max_tokens={S.MODE_MAX_TOKENS['plan']},{second['inferenceConfig']['maxTokens']}" in line


def test_a_plan_cut_off_twice_shows_its_complete_steps_and_says_so(api, world, bedrock, captured):
    bedrock["reply"] = _converse("max_tokens_plan")
    out, _asset = _plan(api, world)
    assert out["status"] == "ok" and out["truncated"] is True, out
    # the three steps written before the cut, each checked like any answer; the fourth was cut mid-sentence
    assert [s["cites"] for s in out["steps"]] == [["K1.s1"], ["K1.s2"], ["K1.s3"]]
    assert out["summary"] and out["caveats"][0] == V.TRUNCATED_NOTE
    assert "required format" not in json.dumps(out)
    assert len(bedrock["sent"]) == 2
    assert "outcome=ok_truncated" in _audit(captured) and "stop=max_tokens,max_tokens" in _audit(captured)


def test_a_cut_answer_with_nothing_complete_is_withheld_as_too_long_not_as_format(api, world, bedrock, captured):
    bedrock["reply"] = _converse("max_tokens_nothing_complete")
    out, _asset = _plan(api, world)
    assert out["status"] == "withheld" and out["withheld_reason"] == V.WITHHELD_TRUNCATED, out
    assert out["truncated"] is True and "required format" not in out["withheld_reason"]
    # the knowledge-base steps stay visible
    assert out["baseline"] is True and out["steps"] and all(s["cites"] for s in out["steps"])
    assert "outcome=withheld_truncated" in _audit(captured)


def test_malformed_json_at_end_turn_is_a_format_withhold_asked_again_on_the_next_click(api, world, bedrock, captured):
    bedrock["reply"] = _converse("end_turn_malformed")
    out, asset = _plan(api, world)
    assert out["status"] == "withheld" and out["withheld_reason"] == V.WITHHELD_FORMAT, out
    assert out["baseline"] is True and out["steps"]
    assert len(bedrock["sent"]) == 1  # not cut off: no retry
    line = _audit(captured)
    assert "outcome=withheld_format" in line and "stop=end_turn" in line
    # "ask again" really asks again: a format failure is not served from the answer cache
    again = _ai._assist(api, asset).json()
    assert again["cached"] is False and len(bedrock["sent"]) == 2


def test_a_reasoning_model_that_spends_the_budget_before_any_text_is_retried(api, world, bedrock):
    """gpt-oss (the default model) writes reasoningContent first; cut there, the answer has no text block at all."""
    thinking = {"output": {"message": {"role": "assistant", "content": [
        {"reasoningContent": {"reasoningText": {"text": "The user wants a plan. Steps: nginx, Apache, ..."}}}]}},
        "stopReason": "max_tokens"}
    replies = [thinking, REPLIES["end_turn_compact"]]
    bedrock["reply"] = lambda _r: (200, replies.pop(0) if len(replies) > 1 else replies[0])
    out, _asset = _plan(api, world)
    assert out["status"] == "ok" and len(bedrock["sent"]) == 2, out


class _Chat:
    """An OpenAI-compatible endpoint on 127.0.0.1 answering with (content, finish_reason) pairs in order."""

    def __init__(self, answers: list[tuple[str, str]]):
        self.answers, self.requests = list(answers), []
        chat = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                chat.requests.append(body)
                content, finish = chat.answers.pop(0) if len(chat.answers) > 1 else chat.answers[0]
                data = json.dumps({"id": "x", "object": "chat.completion", "model": body.get("model"), "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": content},
                     "finish_reason": finish}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def test_openai_compatible_finish_reason_length_is_a_cut_off_answer(api, world, monkeypatch):
    cut = REPLIES["max_tokens_plan"]["output"]["message"]["content"][0]["text"]
    compact = REPLIES["end_turn_compact"]["output"]["message"]["content"][0]["text"]
    chat = _Chat([(cut, "length"), (compact, "stop")])
    try:
        _ai.configure(monkeypatch, f"http://127.0.0.1:{chat.port}/v1")
        out, _asset = _plan(api, world)
        assert out["status"] == "ok" and not out.get("truncated"), out
        first, second = chat.requests
        assert first["max_tokens"] == S.MODE_MAX_TOKENS["plan"] < second["max_tokens"]
        assert P.COMPACT in second["messages"][-1]["content"]
    finally:
        chat.close()


def test_a_fix_cut_off_once_gets_more_room_and_still_rewrites_aes_ecb(api, world, bedrock, mongo):
    """R7-02 (AES-ECB -> AES-GCM with a fresh os.urandom(12) nonce) keeps working through the retry."""
    oid = ObjectId()
    mongo.append({"_id": oid, "scan_id": 77, "finding_data": _fx.FINDING})
    full = _fx._fix_answer(_fx.GOOD)
    replies = [_body(full[:150], "max_tokens"), _body(full, "end_turn")]
    bedrock["reply"] = lambda _r: (200, replies.pop(0) if len(replies) > 1 else replies[0])
    out = _fx._post_fix(api, oid).json()
    assert out["status"] == "ok", out.get("withheld_reason")
    assert out["fix"]["fixed_code"] == _fx.GOOD.rstrip("\n") and "+    nonce = os.urandom(12)" in out["fix"]["diff"]
    budgets = [r["inferenceConfig"]["maxTokens"] for r in _requests(bedrock)]
    assert budgets == [FIX.FIX_MAX_TOKENS, min(2 * FIX.FIX_MAX_TOKENS, S.RETRY_MAX_TOKENS)]
    assert P.COMPACT_FIX in _requests(bedrock)[1]["messages"][-1]["content"][0]["text"]


def test_a_fix_cut_off_twice_is_withheld_as_too_long(api, world, bedrock, mongo):
    oid = ObjectId()
    mongo.append({"_id": oid, "scan_id": 77, "finding_data": _fx.FINDING})
    bedrock["reply"] = lambda _r: (200, _body(_fx._fix_answer(_fx.GOOD)[:150], "max_tokens"))
    out = _fx._post_fix(api, oid).json()
    assert out["status"] == "withheld" and out["withheld_reason"] == S.FIX_TRUNCATED, out
    assert out["fix"] is None and out["baseline"] is True and out["summary"] and out["truncated"] is True


# ------------------------------------------------------------------------------------------------ R7-05 deadline
def test_the_whole_request_fits_under_a_60_s_proxy(monkeypatch):
    monkeypatch.setenv("CBOM_AI_PROVIDER", "bedrock")
    for timeout in ("60", "180"):  # the default, and the value on the staging host (#449: a 170 s read timeout)
        monkeypatch.setenv("CBOM_AI_TIMEOUT_S", timeout)
        cfg = C.load()
        connect, read = T.bedrock_timeouts(cfg)
        assert cfg.deadline_s == C.DEFAULT_DEADLINE_S <= 50
        assert T.bedrock_deadline_s(cfg) == cfg.deadline_s
        # the worker thread (slot wait, connect, read) ends before the caller stops waiting
        assert T.SLOT_WAIT_S + connect + read < cfg.deadline_s, (timeout, connect, read)
    monkeypatch.setenv("CBOM_AI_DEADLINE_S", "600")
    assert C.load().deadline_s == C.MAX_DEADLINE_S
    monkeypatch.setenv("CBOM_AI_DEADLINE_S", "1")
    assert C.load().deadline_s == C.MIN_DEADLINE_S
    # the UI waits longer than any deadline, so the app's own answer always arrives first
    ui = re.search(r"CBOM_AI_UI_TIMEOUT_MS = ([\d_]+)", (ROOT / "frontend/utils/backend_api.ts").read_text())
    assert ui and C.MAX_DEADLINE_S * 1000 < int(ui.group(1).replace("_", ""))


def test_a_slow_model_gets_the_apps_timeout_answer_with_cors_before_the_deadline(api, world, bedrock, monkeypatch,
                                                                                  captured):
    real_load = C.load
    monkeypatch.setattr(C, "load", lambda: dataclasses.replace(real_load(), deadline_s=1.5))

    def slow(_request):
        time.sleep(4)  # a hung connection or a slow model: longer than the request may take
        return 200, REPLIES["end_turn_plan"]

    bedrock["reply"] = slow
    engine, _ = world
    asset = _ai._assets(api, engine)[TLS]["id"]
    r = api("POST", "/1/cbom/ai/assist", headers={"Origin": "http://localhost:3000"},
            json={"subject": {"kind": "run_asset", "asset_id": asset}, "mode": "plan"})
    # the app's own answer, with the CORS header the proxy's 504 lacked
    assert r.status_code == 200 and r.headers.get("access-control-allow-origin") == "http://localhost:3000"
    out = r.json()
    assert out["status"] == "timeout" and out["caveats"] == [S.TIMEOUT_TEXT], out
    assert "try again" in S.TIMEOUT_TEXT.lower()
    # measured inside the app: TestClient's per-request event loop waits for the still-sleeping worker thread when
    # it shuts down, uvicorn's does not
    line = _audit(captured)
    assert "outcome=timeout" in line and int(re.search(r"latency_ms=(\d+)", line).group(1)) < 2500, line


def test_a_dropped_pooled_connection_is_retried_once_on_a_fresh_one(api, world, bedrock, captured):
    from botocore.exceptions import ConnectionClosedError

    calls = []

    def reply(request):
        calls.append(1)
        if len(calls) == 1:  # the reused keep-alive connection was gone (RST / EOF)
            raise ConnectionClosedError(endpoint_url=request.url)
        return 200, REPLIES["end_turn_plan"]

    bedrock["reply"] = reply
    out, _asset = _plan(api, world)
    assert out["status"] == "ok" and len(bedrock["sent"]) == 2, out
    assert "stop=connection_lost,end_turn" in _audit(captured)


def test_a_connection_idle_past_the_reuse_window_is_not_reused(bedrock, monkeypatch):
    """After minutes idle a NAT / firewall / load balancer may have dropped the pooled connection without a FIN
    reaching us; reusing it hangs until the read timeout (170 s on staging). Such a pool is closed first."""
    cfg = C.load()
    client = T._bedrock_client(cfg)
    closed: list[int] = []
    real_close = client.close
    monkeypatch.setattr(client, "close", lambda: (closed.append(1), real_close())[1])
    messages = [{"role": "user", "content": "x"}]
    assert T.bedrock_chat(cfg, messages).stop == "end_turn"
    T.bedrock_chat(cfg, messages)  # back to back: the warm connection is reused
    assert closed == []
    monkeypatch.setattr(T, "IDLE_REUSE_S", 0.0)
    time.sleep(0.01)
    T.bedrock_chat(cfg, messages)
    assert closed == [1]


def test_building_the_client_never_probes_instance_metadata(bedrock, monkeypatch):
    """AWS_DEFAULTS_MODE=auto (environment or AWS config file) makes botocore ask IMDS for the region on every client
    it builds; on a host that is not EC2 each probe waits for its timeout. The client is built in legacy mode."""
    monkeypatch.delenv("AWS_EC2_METADATA_DISABLED")
    monkeypatch.delenv("AWS_EXECUTION_ENV", raising=False)
    monkeypatch.setenv("AWS_DEFAULTS_MODE", "auto")
    tried: list = []

    def refuse(self, addr, *_a):
        tried.append(addr)
        raise ConnectionRefusedError("no network in this test")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    T._bedrock_client(C.load())
    # before the fix: the region probe went out, through the environment proxy the fixture sets (127.0.0.1:9)
    assert tried == []


def test_status_warms_the_client_for_local_credentials_without_contacting_anything(api, world, bedrock, monkeypatch):
    assert T._clients == {}
    assert api("GET", "/1/cbom/ai/status").json()["available"] is True
    assert len(T._clients) == 1 and bedrock["connects"] == [] and bedrock["sent"] == []
    # a source that fetches credentials over the network is never touched by a status check
    monkeypatch.delenv("AWS_EC2_METADATA_DISABLED")
    monkeypatch.setenv("CBOM_AI_AWS_CREDENTIALS", "instance")
    T.reset_bedrock_clients()
    _ai.R._address_ok.clear()
    assert api("GET", "/1/cbom/ai/status").json()["available"] is True
    assert T._clients == {} and bedrock["connects"] == []


# ------------------------------------------------------------------------------------------------ item 4: no dead ends
def test_every_withheld_or_failed_outcome_says_why_and_what_to_do_next():
    for reason in (V.WITHHELD_UNKNOWN_ID, V.WITHHELD_FORMAT, V.WITHHELD_UNCITED, V.WITHHELD_TRUNCATED):
        assert reason.startswith("AI answer withheld: "), reason
        why, _sep, nxt = reason.partition("; ")
        assert why and re.search(r"\bask\b", nxt), reason
        assert not reason.endswith("."), reason  # the panels add "Showing the knowledge-base steps instead ..."
    assert S.FIX_TRUNCATED.startswith("AI fix withheld: ") and not S.FIX_TRUNCATED.endswith(".")
    for text in (S.TIMEOUT_TEXT, S.BUSY_TEXT, S.ERROR_TEXT):
        assert "try again" in text.lower() and "knowledge-base remediation" in text, text
    assert "cut off" in V.TRUNCATED_NOTE and "Ask about one platform" in V.TRUNCATED_NOTE

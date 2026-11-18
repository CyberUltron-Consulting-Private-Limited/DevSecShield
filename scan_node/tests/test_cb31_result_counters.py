"""CB-31 (R4 OBS-5): the job result carries what the node sent and what the server answered (rejected, duplicate),
so the server can tell assets it refused from assets it stored. Before: only ``asset_count`` (the server's own
accepted count) was reported, and 5 sent / 3 stored read as "all read"."""
import time

from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber


def _ctx():
    return JobContext(job_id=1, attempt=1, run_id=2, kind="collect", source_kind="linux_servers",
                      scrubber=Scrubber(["topsecretpw"]), never_scan=NeverScan([]), deadline=time.monotonic() + 60)


def test_the_result_reports_sent_rejected_and_duplicate():
    answers = iter([{"accepted": 3, "duplicate": 0, "rejected": 2}, {"accepted": 0, "duplicate": 2, "rejected": 0}])

    ctx = _ctx()
    ctx.poster = lambda batch, batch_id: next(answers)
    for i in range(5):
        ctx.emit("certificate", "h", f"/etc/{i}.pem", facts={"n": i})
    ctx.flush()
    ctx.emit("certificate", "h", "/etc/0.pem", facts={"n": 0})
    ctx.emit("certificate", "h", "/etc/1.pem", facts={"n": 1})
    ctx.flush()
    r = ctx.result()
    assert (r["sent"], r["rejected"], r["duplicate"], r["asset_count"]) == (7, 2, 2, 3)


def test_a_job_that_sent_nothing_reports_zeros():
    r = _ctx().result()
    assert (r["sent"], r["rejected"], r["duplicate"]) == (0, 0, 0)

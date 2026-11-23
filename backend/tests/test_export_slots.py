"""Host-wide export slots: the CBOM pool and the scan PDF pool are separate (export_slots.py).

A slot is an exclusive flock on a lock file; the two pools use different files and capacities, so one pool full never
blocks the other, and each pool's 429 names its own work.
"""
from __future__ import annotations

import multiprocessing
import os

import pytest

from backend.utilities.cbom_sources import export_slots as ES


@pytest.fixture()
def slots(monkeypatch, tmp_path):
    monkeypatch.setattr(ES, "LOCK_DIR", str(tmp_path))
    monkeypatch.setattr(ES, "SLOTS", 2)
    monkeypatch.setattr(ES, "PDF_SLOTS", 1)
    return tmp_path


def test_a_full_pdf_pool_never_blocks_a_cbom_export_and_the_other_way_round(slots):
    with ES.pdf_slot() as index:
        assert index == 0
        with pytest.raises(ES.Busy):
            with ES.pdf_slot():
                pass
        with ES.slot() as a, ES.slot() as b:  # both CBOM slots are still free
            assert (a, b) == (0, 1)
            with pytest.raises(ES.Busy):
                with ES.slot():
                    pass
            with pytest.raises(ES.Busy):
                with ES.pdf_slot():
                    pass
    with ES.slot(), ES.slot():  # the CBOM pool full: the PDF pool is not
        with ES.pdf_slot() as index:
            assert index == 0
    assert sorted(os.listdir(slots)) == ["zs-cbom-export-slot-0.lock", "zs-cbom-export-slot-1.lock",
                                         "zs-pdf-export-slot-0.lock"]


def test_capacities_are_their_own(slots, monkeypatch):
    monkeypatch.setattr(ES, "PDF_SLOTS", 3)
    monkeypatch.setattr(ES, "SLOTS", 1)
    with ES.pdf_slot(), ES.pdf_slot(), ES.pdf_slot():
        with ES.slot():
            pass
        with pytest.raises(ES.Busy):
            with ES.pdf_slot():
                pass


def _hold(lock_dir: str, ready, release) -> None:
    ES.LOCK_DIR = lock_dir
    ES.PDF_SLOTS = 1
    with ES.pdf_slot():
        ready.set()
        release.wait(30)


def test_the_pools_are_host_wide_across_processes(slots):
    """Another worker process holding the only scan PDF slot: this process gets 429 for a scan PDF, not for CBOM."""
    ctx = multiprocessing.get_context("fork")
    ready, release = ctx.Event(), ctx.Event()
    worker = ctx.Process(target=_hold, args=(str(slots), ready, release))
    worker.start()
    try:
        assert ready.wait(30)
        with pytest.raises(ES.Busy):
            with ES.pdf_slot():
                pass
        with ES.slot():
            pass
    finally:
        release.set()
        worker.join(30)
    with ES.pdf_slot():  # the kernel released it with the process
        pass


def test_each_pool_says_whose_exports_are_busy():
    assert ES.CBOM_BUSY == "The server is busy building other large CBOM exports."
    assert ES.PDF_BUSY == "The server is busy building other large scan PDF reports."
    # no wait in the words: Retry-After carries it, so a client's countdown never disagrees with the text
    for detail in (ES.CBOM_BUSY, ES.PDF_BUSY):
        assert not any(ch.isdigit() for ch in detail) and "retry" not in detail.lower()
    assert ES.PDF_SLOTS >= 1 and ES.SLOTS >= 1

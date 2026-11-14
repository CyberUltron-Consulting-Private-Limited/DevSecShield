"""CB-24 PR-4b, PKCS#11 half: a token's class (hardware or software) for the fix class, from the token's info and
its slot's flags, never guessed (hsm_pkcs11.token_classification):

* SoftHSM v2 (manufacturerID "SoftHSM project", model "SoftHSM v2", slots flagged only CKF_TOKEN_PRESENT: RECORDED
  from SoftHSM 2.6.1, Ubuntu softhsm2 2.6.1-2.2ubuntu3, 2026-11-14) -> software;
* a slot flagged CKF_HW_SLOT (PKCS#11 CK_SLOT_INFO: "TRUE if the slot is a hardware slot, as opposed to a software
  slot implementing a 'soft token'") -> hardware: an HSM, or with CKF_REMOVABLE_DEVICE a smart card / USB token;
* anything else -> not read (token_class None): agility's R-HW-UNREAD says unknown rather than calling it software.

The live SoftHSM run (test_hsm_softhsm_live.py) checks the real token end to end; the hardware rows here are
SYNTHETIC (python-pkcs11's own flag enums on stand-in slot and token objects)."""
from __future__ import annotations

import time

import pytest

pkcs11 = pytest.importorskip("pkcs11")
from pkcs11 import SlotFlag, TokenFlag  # noqa: E402

from zs_scan_node.collectors import hsm_pkcs11 as H  # noqa: E402

SOFTHSM_INFO = {"token_manufacturer": "SoftHSM project", "token_model": "SoftHSM v2",
                "library_manufacturer": "SoftHSM", "slot_manufacturer": "SoftHSM project"}


@pytest.mark.parametrize("info,flags,expected", [
    (SOFTHSM_INFO, ["TOKEN_PRESENT"], ("software", "software")),
    (SOFTHSM_INFO, ["TOKEN_PRESENT", "HW_SLOT"], ("software", "software")),  # the reviewed list wins over a flag
    ({"token_manufacturer": "softhsm PROJECT", "token_model": ""}, None, ("software", "software")),
    ({"token_manufacturer": "Acme HSM Inc.", "token_model": "Acme 9000"}, ["TOKEN_PRESENT", "HW_SLOT"], ("hardware", "hsm")),
    ({"token_manufacturer": "Card Co", "token_model": "PIV"}, ["TOKEN_PRESENT", "REMOVABLE_DEVICE", "HW_SLOT"],
     ("hardware", "smartcard")),
    ({"token_manufacturer": "Acme HSM Inc.", "token_model": "Acme 9000"}, ["TOKEN_PRESENT"], (None, "unknown")),
    ({"token_manufacturer": "Acme HSM Inc.", "token_model": "Acme 9000"}, None, (None, "unknown")),
    ({}, [], (None, "unknown")),
])
def test_token_classification(info, flags, expected):
    out = H.token_classification(info, flags)
    assert (out["token_class"], out["token_kind"]) == expected, out
    assert out["token_class_basis"]
    if expected[0] is None:
        assert out["token_class_basis"].startswith("not read: ")


class _Slot:
    def __init__(self, flags):
        self.flags, self.slot_description, self.manufacturer_id, self.slot_id = flags, "slot 1", "Acme", 1


class _Token:
    def __init__(self, maker, model):
        self.label, self.manufacturer_id, self.model, self.serial = "tok", maker, model, "0001"
        self.hardware_version = self.firmware_version = (1, 0)
        self.flags = TokenFlag.TOKEN_INITIALIZED | TokenFlag.LOGIN_REQUIRED


class _Lib:
    manufacturer_id, library_description, library_version, cryptoki_version = "Acme", "Acme PKCS#11", (1, 0), (2, 40)


def test_token_info_reads_the_slot_flags_and_classifies():
    hw = H._token_info("acme", _Lib(), _Slot(SlotFlag.TOKEN_PRESENT | SlotFlag.HW_SLOT), _Token("Acme HSM Inc.", "A9"))
    assert hw["slot_flags"] == ["HW_SLOT", "TOKEN_PRESENT"]
    assert (hw["token_class"], hw["token_kind"], hw["token_class_basis"]) == ("hardware", "hsm", "slot flag CKF_HW_SLOT")
    card = H._token_info("acme", _Lib(), _Slot(SlotFlag.TOKEN_PRESENT | SlotFlag.HW_SLOT | SlotFlag.REMOVABLE_DEVICE),
                         _Token("Card Co", "PIV"))
    assert (card["token_class"], card["token_kind"]) == ("hardware", "smartcard")
    soft = H._token_info("softhsm", _Lib(), _Slot(SlotFlag.TOKEN_PRESENT), _Token("SoftHSM project", "SoftHSM v2"))
    assert (soft["token_class"], soft["token_kind"]) == ("software", "software")


def test_unreadable_slot_flags_leave_the_class_not_read():
    class _BadSlot(_Slot):
        @property
        def flags(self):
            raise RuntimeError("CKR_FUNCTION_FAILED")

        @flags.setter
        def flags(self, _v):
            pass

    info = H._token_info("acme", _Lib(), _BadSlot(None), _Token("Acme HSM Inc.", "A9"))
    assert "slot_flags" not in info
    assert (info["token_class"], info["token_class_basis"]) == (None, "not read: slot flags not read")


def test_every_key_carries_its_tokens_class(monkeypatch):
    """The managed_key rows carry the token class (agility reads it on the key, not only on the key store)."""
    from zs_scan_node.jobctx import JobContext
    from zs_scan_node.netutil import NeverScan
    from zs_scan_node.scrub import Scrubber

    class _Obj:
        object_class = pkcs11.ObjectClass.PRIVATE_KEY

    class _Session:
        def get_objects(self):
            return [_Obj()]

        def close(self):
            pass

    token = _Token("Acme HSM Inc.", "A9")
    token.open = lambda rw=False, user_pin=None: _Session()
    monkeypatch.setattr(H, "read_attributes", lambda obj, names: {
        "CLASS": pkcs11.ObjectClass.PRIVATE_KEY, "KEY_TYPE": pkcs11.KeyType.RSA, "MODULUS_BITS": 2048, "LABEL": "k1"})
    ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="key_manager",
                     scrubber=Scrubber([]), never_scan=NeverScan(), deadline=time.monotonic() + 60)
    H._read_token(ctx, "acme", _Lib(), _Slot(SlotFlag.TOKEN_PRESENT | SlotFlag.HW_SLOT), token, "1234")
    ctx.flush()
    key = next(a for a in ctx.collected if a["type"] == "managed_key")
    assert (key["facts"]["store"], key["facts"]["token_class"], key["facts"]["token_kind"]) == ("pkcs11", "hardware", "hsm")
    store = next(a for a in ctx.collected if a["type"] == "key_store")
    assert store["facts"]["token_class"] == "hardware"

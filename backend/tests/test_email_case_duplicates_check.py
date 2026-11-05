"""scripts/ops/check_email_case_duplicates.py: finds accounts whose e-mails differ only in case (WP13).

The groups agree with sign-in (``auth_utils.user_by_email`` resolves to the lowest id) and nothing it prints
contains an address.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from sqlmodel import Session, SQLModel, create_engine

from backend.new_models import User
from backend.utilities.auth.auth_utils import user_by_email

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ops" / "check_email_case_duplicates.py"
_spec = importlib.util.spec_from_file_location("check_email_case_duplicates", _SCRIPT)
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)

EMAILS = ["Ana@Example.com", "solo@example.com", "ana@example.com", "BOB@corp.test", "bob@corp.test",
          "Bob@Corp.Test"]


@pytest.fixture()
def session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'users.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        for email in EMAILS:
            s.add(User(email=email, password="x", first_name=None, last_name=None, profile_photo=None))
        s.commit()
        yield s


def test_groups_match_what_sign_in_resolves(session):
    groups = check.find_case_duplicates(session)
    assert groups == [[1, 3], [4, 5, 6]]
    for group in groups:
        winner = user_by_email(session, "ANA@example.com" if group[0] == 1 else "bob@CORP.test")
        assert winner.id == group[0]


def test_output_has_counts_and_ids_but_never_an_address(session):
    groups = check.find_case_duplicates(session)
    for show_ids in (False, True):
        text = "\n".join(check.report(groups, show_ids))
        assert "2 e-mail address(es) are shared by 5 accounts" in text and "3 of those accounts cannot sign in" in text
        assert "@" not in text and "ana" not in text.lower() and "bob" not in text.lower()
    assert "group 2: signs in as user 4; unreachable: 5, 6" in "\n".join(check.report(groups, True))
    assert check.report([], False) == ["No e-mail addresses differ only in case."]


def test_exit_status_and_unreadable_database(monkeypatch, capsys):
    import backend.get_db as get_db_module

    def no_db():
        raise KeyError("PG_USER")

    monkeypatch.setattr(get_db_module, "get_db", no_db)
    assert check.main([]) == 2
    err = capsys.readouterr().err
    assert "Could not read the user table (KeyError)" in err and "PG_USER" not in err

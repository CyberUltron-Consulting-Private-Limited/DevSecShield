"""The team report logo (PDF reports plan v2, sections 5 and 8 "Logo API"): upload, normalise, store, read, remove.

* every accepted format (PNG, JPEG, WebP, MPO), Content-Type handling (413, 415, missing / octet-stream accepted);
* the decode pipeline: decompression bomb, animation, 16-bit grey, ICC, EXIF orientation, transparency, aspect ratio,
  minimum size, the 300 KB retry, RGB for opaque logos, tone;
* RBAC and the audit trail, a concurrent first upload, team deletion (with and without SQLite foreign keys),
  cross-team isolation, ``load_report_branding`` (including garbage bytes in the table), the migration's columns.

Images are made in memory with Pillow and kept tiny.

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r \
      AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \
      python -m pytest tests/test_team_branding.py -q -p no:cacheprovider
"""
import concurrent.futures
import hashlib
import importlib.util
import io
import logging
import os
import random
import sys
import types
import warnings
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "team-branding-test-access-secret-0123456789")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "team-branding-test-refresh-secret-0123456789")

from fastapi.testclient import TestClient  # noqa: E402
from PIL import Image, ImageCms  # noqa: E402
from sqlalchemy import event  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.branding_models import TeamBranding  # noqa: E402
from backend.main import app  # noqa: E402
from backend.new_models import AuditEvent, Team  # noqa: E402
from backend.utilities import ratelimit  # noqa: E402
from backend.utilities.rbac.policy import NOT_IN_TEAM  # noqa: E402
from backend.utilities.team import branding, logo_image  # noqa: E402
from backend.tests.support.rbac import bearer, join, make_user, patch_all_get_db  # noqa: E402

OWNER, ADMIN, MEMBER, VIEWER = "olivia@acme.test", "adam@acme.test", "max@acme.test", "vic@acme.test"
OTHER_ADMIN = "otto@other.test"
NAVY = (12, 30, 66)


# ------------------------------------------------------------------------------------------------ world

def _engine(path: Path, *, foreign_keys: bool = False):
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    if foreign_keys:
        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_connection, _record):
            dbapi_connection.execute("PRAGMA foreign_keys=ON")
    SQLModel.metadata.create_all(engine)
    return engine


def _populate(engine) -> dict:
    ids = {}
    with Session(engine) as s:
        for key, name in (("team", "Acme"), ("other", "Other Corp")):
            team = Team(name=name)
            s.add(team)
            s.commit()
            s.refresh(team)
            ids[key] = team.id
        for email, role in ((OWNER, "owner"), (ADMIN, "admin"), (MEMBER, "member"), (VIEWER, "viewer")):
            user = make_user(s, email)
            ids[email] = user.id
            join(s, ids["team"], user.id, role)
        ids[OTHER_ADMIN] = make_user(s, OTHER_ADMIN).id
        join(s, ids["other"], ids[OTHER_ADMIN], "admin")
    return ids


@pytest.fixture()
def world(tmp_path, monkeypatch):
    engine = _engine(tmp_path / "branding.db")
    patch_all_get_db(monkeypatch, engine)
    ratelimit.reset_all()
    yield engine, _populate(engine)
    ratelimit.reset_all()


@pytest.fixture()
def client(world):
    return TestClient(app)


# ------------------------------------------------------------------------------------------------ helpers

def enc(image: Image.Image, fmt: str, **options) -> bytes:
    out = io.BytesIO()
    image.save(out, fmt, **options)
    return out.getvalue()


def logo(size=(120, 40), color=NAVY, mode="RGB") -> Image.Image:
    return Image.new(mode, size, color if mode == "RGB" else (*color, 255))


def light_mark(size) -> Image.Image:
    """A near-white mark with a transparent corner (so the stored logo keeps alpha): a "light" logo."""
    image = Image.new("RGBA", size, (250, 250, 250, 255))
    image.putpixel((0, size[1] // 2), (0, 0, 0, 0))
    return image


def put(client, team_id, who, raw: bytes, content_type: str | None = "image/png"):
    ratelimit.reset_all()
    headers = dict(bearer(who))
    if content_type is not None:
        headers["Content-Type"] = content_type
    return client.put(f"/team/{team_id}/branding/logo", headers=headers, content=raw)


def get(client, path, who):
    ratelimit.reset_all()
    return client.get(path, headers=bearer(who))


def stored(engine, team_id) -> TeamBranding | None:
    with Session(engine) as s:
        return s.get(TeamBranding, team_id)


def stored_image(engine, team_id) -> Image.Image:
    return Image.open(io.BytesIO(stored(engine, team_id).logo_png))


def events(engine, action=None):
    with Session(engine) as s:
        q = select(AuditEvent).order_by(AuditEvent.id)
        if action:
            q = q.where(AuditEvent.action == action)
        return s.exec(q).all()


def normalise(image_bytes: bytes, content_type: str | None = None):
    return logo_image.normalize_logo(image_bytes, content_type)


def refused(raw: bytes, content_type: str | None = None) -> logo_image.LogoError:
    with pytest.raises(logo_image.LogoError) as caught:
        normalise(raw, content_type)
    return caught.value


# ------------------------------------------------------------------------------------------------ formats

@pytest.mark.parametrize("fmt,content_type,options", [
    ("PNG", "image/png", {}),
    ("JPEG", "image/jpeg", {"quality": 95}),
    ("WEBP", "image/webp", {"lossless": True}),
])
def test_each_format_is_stored_as_a_normalised_png(world, client, fmt, content_type, options):
    engine, ids = world
    response = put(client, ids["team"], ADMIN, enc(logo(), fmt, **options), content_type)
    assert response.status_code == 200, response.text
    meta = response.json()
    row = stored(engine, ids["team"])
    assert meta == {"logo_set": True, "sha256": row.logo_sha256, "width": 120, "height": 40, "tone": "dark",
                    "bytes": len(row.logo_png), "updated_at": row.updated_at.isoformat() + "Z"}
    assert row.logo_sha256 == hashlib.sha256(row.logo_png).hexdigest() and row.logo_bytes == len(row.logo_png)
    assert row.updated_by_user_id == ids[ADMIN] and row.has_alpha is False
    assert row.logo_png.startswith(b"\x89PNG\r\n\x1a\n")
    assert get(client, f"/team/{ids['team']}/branding", VIEWER).json() == meta
    image = get(client, f"/team/{ids['team']}/branding/logo", VIEWER)
    assert image.status_code == 200 and image.content == row.logo_png
    assert image.headers["content-type"] == "image/png"
    assert image.headers["cache-control"] == "no-store"
    assert image.headers["x-content-type-options"] == "nosniff"
    assert image.headers["etag"] == f'"{row.logo_sha256}"'
    [set_event] = events(engine, "team.branding.logo.set")
    assert set_event.outcome == "success" and set_event.team_id == ids["team"]
    assert set_event.details == {"sha256": row.logo_sha256, "bytes": len(row.logo_png), "w": 120, "h": 40,
                                 "tone": "dark", "format_in": fmt.lower()}


def test_mpo_is_accepted_and_its_first_picture_is_stored(world, client):
    engine, ids = world
    raw = enc(logo(color=(220, 0, 0)), "MPO", save_all=True, append_images=[logo(color=(0, 0, 220))])
    assert Image.open(io.BytesIO(raw)).format == "MPO"
    response = put(client, ids["team"], ADMIN, raw, "image/jpeg")
    assert response.status_code == 200, response.text
    red, green, blue = stored_image(engine, ids["team"]).convert("RGB").getpixel((60, 20))
    assert red > 180 and blue < 60
    assert events(engine, "team.branding.logo.set")[-1].details["format_in"] == "mpo"


@pytest.mark.parametrize("content_type", [None, "application/octet-stream", "image/png; charset=binary",
                                          "IMAGE/PNG"])
def test_missing_or_generic_content_types_are_accepted(world, client, content_type):
    engine, ids = world
    response = put(client, ids["team"], ADMIN, enc(logo(), "PNG"), content_type)
    assert response.status_code == 200, response.text
    assert stored(engine, ids["team"]) is not None


def test_a_body_over_2_mib_is_413_and_nothing_is_stored(world, client):
    engine, ids = world
    raw = enc(logo(), "PNG")
    raw += b"\0" * (logo_image.MAX_UPLOAD_BYTES + 1 - len(raw))
    response = put(client, ids["team"], ADMIN, raw)
    assert response.status_code == 413, response.text
    assert stored(engine, ids["team"]) is None
    assert refused(raw).status_code == 413  # the pure function refuses it too


def test_an_empty_body_is_422(world, client):
    _, ids = world
    response = put(client, ids["team"], ADMIN, b"")
    assert response.status_code == 422 and response.json()["detail"] == "No image was sent"


SVG = b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect/></svg>'


@pytest.mark.parametrize("name,raw,content_type", [
    ("svg", SVG, "image/svg+xml"),
    ("svg as octet-stream", SVG, "application/octet-stream"),
    ("svg without a type", SVG, None),
    ("gif", enc(logo(), "GIF"), "image/gif"),
    ("gif as octet-stream", enc(logo(), "GIF"), "application/octet-stream"),
    ("bmp", enc(logo(), "BMP"), None),
    ("jpeg claiming png", enc(logo(), "JPEG"), "image/png"),
    ("png claiming jpeg", enc(logo(), "PNG"), "image/jpeg"),
    ("png claiming webp", enc(logo(), "PNG"), "image/webp"),
    ("png sent as text", enc(logo(), "PNG"), "text/plain"),
])
def test_other_formats_and_lying_content_types_are_415(world, client, name, raw, content_type):
    engine, ids = world
    response = put(client, ids["team"], ADMIN, raw, content_type)
    assert response.status_code == 415, (name, response.text)
    assert stored(engine, ids["team"]) is None


# ------------------------------------------------------------------------------------------------ decoding

def test_a_one_bit_decompression_bomb_is_422_and_the_warning_filter_is_restored(world, client):
    _, ids = world
    bomb = enc(Image.new("1", (12000, 12000)), "PNG", optimize=True)
    assert len(bomb) < 64 * 1024  # tiny on the wire, 144 megapixels once decoded
    before = list(warnings.filters)
    response = put(client, ids["team"], ADMIN, bomb)
    assert response.status_code == 422 and "4096" in response.json()["detail"], response.text
    assert list(warnings.filters) == before  # catch_warnings was scoped: no global filter left behind


def test_a_side_over_4096_is_422_before_decoding():
    error = refused(enc(Image.new("L", (5000, 100), 0), "PNG"))
    assert error.status_code == 422 and "5000 x 100" in error.message


@pytest.mark.parametrize("fmt", ["WEBP", "PNG"])
def test_animated_webp_and_apng_are_422(fmt):
    frames = [Image.new("RGBA", (60, 20), (200, 0, 0, 255)), Image.new("RGBA", (60, 20), (0, 0, 200, 255))]
    raw = enc(frames[0], fmt, save_all=True, append_images=frames[1:])
    assert getattr(Image.open(io.BytesIO(raw)), "n_frames", 1) == 2
    error = refused(raw)
    assert error.status_code == 422 and "Animated" in error.message


def test_a_corrupt_png_is_422():
    raw = enc(logo(), "PNG")
    error = refused(raw[:60] + b"\0" * 40)
    assert error.status_code == 422 and error.message == logo_image.UNREADABLE


def test_16_bit_grey_is_scaled_not_clipped_to_white():
    raw = enc(Image.new("I;16", (80, 40), 0x4000), "PNG")
    assert Image.open(io.BytesIO(raw)).mode == "I;16"
    result = normalise(raw, "image/png")
    value = Image.open(io.BytesIO(result.png)).convert("L").getpixel((10, 10))
    assert 60 <= value <= 68  # 0x4000 / 256 = 64; a plain convert("L") would clip it to 255
    assert result.tone == "dark"


def test_an_icc_tagged_logo_is_converted_to_srgb_and_the_profile_is_dropped(monkeypatch):
    srgb = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
    raw = enc(logo(color=(200, 40, 40)), "PNG", icc_profile=srgb)
    calls = []
    real = ImageCms.profileToProfile
    monkeypatch.setattr(ImageCms, "profileToProfile", lambda *a, **k: calls.append(k) or real(*a, **k))
    result = normalise(raw)
    assert len(calls) == 1 and calls[0]["outputMode"] == "RGB"
    out = Image.open(io.BytesIO(result.png))
    assert "icc_profile" not in out.info and b"iCCP" not in result.png
    assert all(abs(a - b) <= 3 for a, b in zip(out.getpixel((5, 5)), (200, 40, 40)))


def test_a_broken_icc_profile_is_ignored_not_fatal():
    raw = enc(logo(), "PNG", icc_profile=b"not a profile at all")
    result = normalise(raw)
    assert (result.width, result.height) == (120, 40) and b"iCCP" not in result.png


def test_exif_orientation_is_applied_and_exif_is_dropped():
    image = Image.new("RGB", (200, 100), (0, 0, 220))
    image.paste((220, 0, 0), (0, 0, 100, 100))  # left half red
    exif = Image.Exif()
    exif[0x0112] = 6  # stored rotated: shown turned 90 degrees clockwise
    result = normalise(enc(image, "JPEG", quality=95, exif=exif.tobytes()), "image/jpeg")
    out = Image.open(io.BytesIO(result.png)).convert("RGB")
    assert out.size == (100, 200)
    red, _, blue = out.getpixel((50, 20))  # the left half is now on top
    assert red > 180 and blue < 60
    assert b"eXIf" not in result.png and "exif" not in Image.open(io.BytesIO(result.png)).info


def test_text_chunks_and_trailing_bytes_are_not_stored():
    from PIL import PngImagePlugin

    info = PngImagePlugin.PngInfo()
    info.add_text("Comment", "secret-ish")
    raw = enc(logo(), "PNG", pnginfo=info) + b"TRAILING-PAYLOAD"
    result = normalise(raw)
    assert b"secret-ish" not in result.png and b"TRAILING-PAYLOAD" not in result.png and b"tEXt" not in result.png


# ------------------------------------------------------------------------------------------------ geometry

def test_a_fully_transparent_logo_is_422():
    error = refused(enc(Image.new("RGBA", (100, 40), (0, 0, 0, 0)), "PNG"))
    assert error.status_code == 422 and error.message == logo_image.TRANSPARENT


def test_a_near_transparent_logo_is_422():
    error = refused(enc(Image.new("RGBA", (100, 40), (0, 0, 0, logo_image.VISIBLE_ALPHA - 1)), "PNG"))
    assert error.message == logo_image.TRANSPARENT


def test_the_logo_is_cropped_to_its_visible_pixels():
    canvas = Image.new("RGBA", (300, 300), (255, 255, 255, 0))
    canvas.paste((*NAVY, 255), (50, 100, 250, 150))  # a 200 x 50 mark in a transparent square
    canvas.putpixel((10, 10), (0, 0, 0, logo_image.VISIBLE_ALPHA - 1))  # faint speck: background
    result = normalise(enc(canvas, "PNG"))
    assert (result.width, result.height) == (200, 50) and result.has_alpha is False


@pytest.mark.parametrize("size,ok", [
    ((1200, 100), True),   # 12: the widest accepted
    ((1210, 100), False),
    ((100, 400), True),    # 0.25: the tallest accepted
    ((100, 410), False),
])
def test_aspect_ratio_bounds(size, ok):
    raw = enc(Image.new("RGB", size, NAVY), "PNG")
    if ok:
        assert normalise(raw).height <= 240
    else:
        error = refused(raw)
        assert error.status_code == 422 and "times its height" in error.message


def test_the_aspect_ratio_is_measured_after_the_crop():
    canvas = Image.new("RGBA", (400, 400), (0, 0, 0, 0))
    canvas.paste((*NAVY, 255), (0, 0, 390, 20))  # square canvas, 19.5 : 1 mark
    assert "times its height" in refused(enc(canvas, "PNG")).message


def test_large_logos_fit_800_by_240():
    wide = normalise(enc(Image.new("RGB", (2400, 300), NAVY), "PNG"))
    tall = normalise(enc(Image.new("RGB", (300, 1000), NAVY), "PNG"))
    assert (wide.width, wide.height) == (800, 100)
    assert (tall.width, tall.height) == (72, 240)


@pytest.mark.parametrize("size,ok", [((192, 16), True), ((180, 15), False), ((15, 15), False), ((16, 16), True)])
def test_minimum_side_after_scaling(size, ok):
    raw = enc(Image.new("RGB", size, NAVY), "PNG")
    if ok:
        assert min(normalise(raw).width, normalise(raw).height) >= 16
    else:
        error = refused(raw)
        assert error.status_code == 422 and "too small" in error.message


def _noise(size) -> Image.Image:
    rng = random.Random(7)
    return Image.frombytes("RGBA", size, bytes(rng.getrandbits(8) | (0 if i % 4 != 3 else 0xC0)
                                               for i in range(size[0] * size[1] * 4)))


def test_a_logo_too_detailed_for_300_kb_is_retried_at_400_by_120():
    raw = enc(_noise((800, 240)), "PNG")
    assert len(raw) > logo_image.MAX_STORED_BYTES  # 800 x 240 would not fit
    result = normalise(raw)
    assert (result.width, result.height) == (400, 120)
    assert result.size_bytes <= logo_image.MAX_STORED_BYTES and result.has_alpha is True


def test_a_logo_still_too_detailed_after_the_retry_is_422(monkeypatch):
    monkeypatch.setattr(logo_image, "MAX_STORED_BYTES", 4 * 1024)
    error = refused(enc(_noise((160, 48)), "PNG"))
    assert error.status_code == 422 and "too detailed" in error.message


def test_opaque_logos_are_stored_as_rgb_and_transparent_ones_keep_alpha(world, client):
    engine, ids = world
    assert put(client, ids["team"], ADMIN, enc(logo(mode="RGBA"), "PNG")).status_code == 200
    assert stored_image(engine, ids["team"]).mode == "RGB" and stored(engine, ids["team"]).has_alpha is False
    with_hole = logo(mode="RGBA")
    with_hole.paste((0, 0, 0, 0), (40, 10, 80, 30))
    assert put(client, ids["team"], ADMIN, enc(with_hole, "PNG")).status_code == 200
    assert stored_image(engine, ids["team"]).mode == "RGBA" and stored(engine, ids["team"]).has_alpha is True


@pytest.mark.parametrize("color,tone", [((0, 0, 0), "dark"), (NAVY, "dark"), ((128, 128, 128), "dark"),
                                        ((255, 255, 255), "light"), ((235, 235, 235), "light")])
def test_tone_is_the_mean_luminance_of_the_visible_pixels(color, tone):
    canvas = Image.new("RGBA", (200, 60), (0, 0, 0, 0))  # transparent background never counts
    canvas.paste((*color, 255), (20, 10, 180, 50))
    canvas.putpixel((100, 30), (0, 0, 0, 0))  # one transparent pixel inside the crop: the logo has alpha
    assert normalise(enc(canvas, "PNG")).tone == tone


@pytest.mark.parametrize("fmt", ["PNG", "JPEG"])
def test_an_opaque_logo_on_a_white_background_is_drawn_as_is(fmt):
    """The usual client logo: a coloured mark on its own white background. It is not "light" (no navy frame)."""
    canvas = Image.new("RGB", (300, 80), (255, 255, 255))
    canvas.paste(NAVY, (10, 20, 50, 60))
    result = normalise(enc(canvas, fmt))
    assert result.has_alpha is False and result.tone == "dark"
    assert normalise(enc(Image.new("RGB", (120, 40), (250, 250, 250)), fmt)).tone == "dark"


# ------------------------------------------------------------------------------------------------ RBAC and audit

def test_viewers_and_members_cannot_change_the_logo_but_may_read_it(world, client):
    engine, ids = world
    team = ids["team"]
    raw = enc(logo(), "PNG")
    for who in (VIEWER, MEMBER):
        response = put(client, team, who, raw)
        role = "viewer" if who == VIEWER else "member"
        assert response.status_code == 403
        assert response.json()["detail"].startswith(f"Your role ({role}) cannot change the team's report logo")
        ratelimit.reset_all()
        assert client.delete(f"/team/{team}/branding/logo", headers=bearer(who)).status_code == 403
    assert stored(engine, team) is None
    denied = [e for e in events(engine, "team.branding.manage") if e.outcome == "denied"]
    assert {e.actor_user_id for e in denied} == {ids[VIEWER], ids[MEMBER]} and len(denied) == 4

    assert put(client, team, OWNER, raw).status_code == 200
    for who in (VIEWER, MEMBER, ADMIN, OWNER):
        assert get(client, f"/team/{team}/branding", who).json()["logo_set"] is True
        assert get(client, f"/team/{team}/branding/logo", who).status_code == 200


def test_set_and_remove_are_audited_with_the_actor(world, client):
    engine, ids = world
    team = ids["team"]
    meta = put(client, team, ADMIN, enc(logo(), "PNG")).json()
    ratelimit.reset_all()
    assert client.delete(f"/team/{team}/branding/logo", headers=bearer(ADMIN)).status_code == 204
    [set_event] = events(engine, "team.branding.logo.set")
    [removed] = events(engine, "team.branding.logo.removed")
    for row in (set_event, removed):
        assert (row.actor_user_id, row.team_id, row.object_type, row.object_id, row.outcome) == (
            ids[ADMIN], team, "team", str(team), "success")
    assert removed.details == {"sha256": meta["sha256"], "bytes": meta["bytes"]}
    # the handler wrote the domain events: no generic "team.branding.manage" success row besides the attempts
    generic = [e for e in events(engine, "team.branding.manage") if e.outcome == "success"]
    assert generic == []


def test_delete_is_idempotent_and_only_audits_a_removal(world, client):
    engine, ids = world
    team = ids["team"]
    ratelimit.reset_all()
    first = client.delete(f"/team/{team}/branding/logo", headers=bearer(ADMIN))
    assert first.status_code == 204 and first.content == b""
    assert events(engine, "team.branding.logo.removed") == []
    put(client, team, ADMIN, enc(logo(), "PNG"))
    for _ in range(2):
        ratelimit.reset_all()
        assert client.delete(f"/team/{team}/branding/logo", headers=bearer(ADMIN)).status_code == 204
    assert len(events(engine, "team.branding.logo.removed")) == 1
    assert stored(engine, team) is None
    missing = get(client, f"/team/{team}/branding/logo", VIEWER)
    assert missing.status_code == 404 and missing.json()["detail"] == "No logo is set for this team"
    assert get(client, f"/team/{team}/branding", VIEWER).json() == branding.empty_metadata()


def test_a_second_upload_replaces_the_first(world, client):
    engine, ids = world
    team = ids["team"]
    first = put(client, team, ADMIN, enc(logo(color=(0, 0, 0)), "PNG")).json()
    second = put(client, team, OWNER, enc(light_mark((200, 50)), "PNG")).json()
    assert first["sha256"] != second["sha256"] and second["tone"] == "light"
    row = stored(engine, team)
    assert (row.logo_sha256, row.logo_width, row.updated_by_user_id) == (second["sha256"], 200, ids[OWNER])
    with Session(engine) as s:
        assert len(s.exec(select(TeamBranding)).all()) == 1


def test_concurrent_first_uploads_never_answer_500(world, client):
    engine, ids = world
    team = ids["team"]
    bodies = [enc(logo(color=(0, 0, 0)), "PNG"), enc(logo(color=(250, 250, 250)), "PNG")]
    ratelimit.reset_all()

    def upload(i):
        return client.put(f"/team/{team}/branding/logo", content=bodies[i % 2],
                          headers={**bearer((ADMIN, OWNER)[i % 2]), "Content-Type": "image/png"})

    with concurrent.futures.ThreadPoolExecutor(4) as pool:
        responses = list(pool.map(upload, range(4)))
    assert [r.status_code for r in responses] == [200] * 4, [r.text for r in responses]
    with Session(engine) as s:
        rows = s.exec(select(TeamBranding)).all()
    assert len(rows) == 1 and rows[0].logo_sha256 in {r.json()["sha256"] for r in responses}
    assert len(events(engine, "team.branding.logo.set")) == 4


def test_a_storage_failure_is_a_generic_500_that_stores_nothing(world, client, monkeypatch, caplog):
    engine, ids = world

    def broken(*_a, **_k):
        raise RuntimeError("password=hunter2 in a driver message")

    monkeypatch.setattr(branding, "upsert_logo", broken)
    with caplog.at_level(logging.ERROR, logger="backend.routers.team_branding"):
        response = put(client, ids["team"], ADMIN, enc(logo(), "PNG"))
    assert response.status_code == 500 and "hunter2" not in response.text
    ref = response.json()["detail"].split("ref ")[1].rstrip(")")
    [line] = [r.getMessage() for r in caplog.records if r.name == "backend.routers.team_branding"]
    assert f"ref={ref}" in line and "error=RuntimeError" in line and "hunter2" not in line
    assert stored(engine, ids["team"]) is None and events(engine, "team.branding.logo.set") == []
    assert [e.outcome for e in events(engine, "team.branding.manage")] == ["attempted", "failed"]


def test_the_upsert_itself_never_raises_on_an_existing_row(world):
    engine, ids = world
    first, second = normalise(enc(logo(), "PNG")), normalise(enc(logo(color=(255, 255, 255)), "PNG"))
    for item in (first, second):
        with Session(engine) as s:
            branding.upsert_logo(s, ids["team"], item, user_id=ids[ADMIN])
            s.commit()
    assert stored(engine, ids["team"]).logo_sha256 == second.sha256


def _no_mongo():
    class _Collection:
        def delete_many(self, *_a, **_k):
            return types.SimpleNamespace(deleted_count=0)

    class _Db(dict):
        def __getitem__(self, name):
            return _Collection()

    return _Db()


@pytest.mark.parametrize("foreign_keys", [False, True], ids=["sqlite-default", "pragma-foreign-keys-on"])
def test_team_deletion_removes_the_logo(tmp_path, monkeypatch, foreign_keys):
    from backend.routers import team as team_router

    engine = _engine(tmp_path / "delete.db", foreign_keys=foreign_keys)
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == int(foreign_keys)
    patch_all_get_db(monkeypatch, engine)
    monkeypatch.setattr(team_router, "get_mongo_client_db", _no_mongo)
    ratelimit.reset_all()
    ids = _populate(engine)
    client = TestClient(app)
    assert put(client, ids["team"], ADMIN, enc(logo(), "PNG")).status_code == 200
    assert put(client, ids["other"], OTHER_ADMIN, enc(logo(), "PNG")).status_code == 200
    ratelimit.reset_all()
    response = client.delete(f"/team/{ids['team']}", headers=bearer(OWNER))
    assert response.status_code == 200, response.text
    with Session(engine) as s:
        assert s.get(Team, ids["team"]) is None
        assert s.get(TeamBranding, ids["team"]) is None  # no orphan, whether or not the database cascades
        assert s.get(TeamBranding, ids["other"]) is not None  # the other team's logo stays
    ratelimit.reset_all()


def test_teams_never_see_or_change_each_others_logo(world, client):
    engine, ids = world
    team, other = ids["team"], ids["other"]
    mine = put(client, team, ADMIN, enc(logo(color=(0, 0, 0)), "PNG")).json()
    assert get(client, f"/team/{other}/branding", OTHER_ADMIN).json()["logo_set"] is False
    assert get(client, f"/team/{other}/branding/logo", OTHER_ADMIN).status_code == 404
    for path in (f"/team/{team}/branding", f"/team/{team}/branding/logo"):
        outsider = get(client, path, OTHER_ADMIN)
        assert outsider.status_code == 403 and outsider.json()["detail"] == NOT_IN_TEAM
    assert put(client, other, ADMIN, enc(logo(), "PNG")).json()["detail"] == NOT_IN_TEAM
    ratelimit.reset_all()
    assert client.delete(f"/team/{other}/branding/logo", headers=bearer(ADMIN)).status_code == 403
    theirs = put(client, other, OTHER_ADMIN, enc(logo(color=(255, 255, 255)), "PNG")).json()
    assert get(client, f"/team/{team}/branding", VIEWER).json()["sha256"] == mine["sha256"] != theirs["sha256"]
    with Session(engine) as s:
        assert branding.load_report_branding(s, team).sha256 == mine["sha256"]
        assert branding.load_report_branding(s, other).sha256 == theirs["sha256"]


# ------------------------------------------------------------------------------------------------ the PDF loader

def test_load_report_branding_applies_a_stored_logo(world, client):
    engine, ids = world
    meta = put(client, ids["team"], ADMIN, enc(light_mark((120, 40)), "PNG")).json()
    with Session(engine) as s:
        loaded = branding.load_report_branding(s, ids["team"])
        assert branding.load_report_branding(s, ids["other"]).status == "none"
    assert loaded.status == "applied" and loaded.applied
    assert (loaded.sha256, loaded.width, loaded.height, loaded.tone) == (meta["sha256"], 120, 40, "light")


def test_load_report_branding_skips_garbage_bytes_and_logs_once(world, caplog):
    engine, ids = world
    with Session(engine) as s:
        s.add(TeamBranding(team_id=ids["team"], logo_png=b"\x89PNG\r\n\x1a\n not really", logo_sha256="0" * 64,
                           logo_width=1, logo_height=1, logo_bytes=20, logo_tone="dark", has_alpha=False,
                           updated_at=branding._utcnow()))
        s.commit()
    with caplog.at_level(logging.WARNING), Session(engine) as s:
        loaded = branding.load_report_branding(s, ids["team"])
    assert loaded.status == "skipped" and not loaded.applied and loaded.png is None
    assert len([r for r in caplog.records if r.levelno >= logging.WARNING]) == 1


def test_load_report_branding_skips_when_the_table_is_missing(tmp_path, caplog):
    engine = create_engine(f"sqlite:///{tmp_path / 'empty.db'}")  # no tables: the migration has not run
    with caplog.at_level(logging.WARNING), Session(engine) as s:
        assert branding.load_report_branding(s, 1).status == "skipped"
    assert len([r for r in caplog.records if r.levelno >= logging.WARNING]) == 1


def test_the_metadata_read_never_selects_the_bytes(world, client):
    engine, ids = world
    put(client, ids["team"], ADMIN, enc(logo(), "PNG"))
    statements = []
    listener = lambda conn, cursor, statement, *a: statements.append(statement)  # noqa: E731
    event.listen(engine, "before_cursor_execute", listener)
    try:
        assert get(client, f"/team/{ids['team']}/branding", VIEWER).status_code == 200
    finally:
        event.remove(engine, "before_cursor_execute", listener)
    branding_selects = [s for s in statements if "teambranding" in s]
    assert len(branding_selects) == 1 and "logo_png" not in branding_selects[0]


# ------------------------------------------------------------------------------------------------ schema

def test_the_migration_creates_the_columns_the_model_declares():
    path = _REPO_ROOT / "prod_database_migrations/migrations/versions/rpdf1brand001_team_branding.py"
    spec = importlib.util.spec_from_file_location("rpdf1brand001", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    created = {}
    module.op = types.SimpleNamespace(create_table=lambda name, *items: created.setdefault(name, items))
    module.upgrade()
    assert (module.revision, module.down_revision) == ("rpdf1brand001", "r6f4rbac001")
    items = created["teambranding"]
    columns = {c.name: c for c in items if hasattr(c, "nullable") and hasattr(c, "type")}
    model = TeamBranding.__table__.columns
    assert set(columns) == {c.name for c in model}
    for name, column in columns.items():
        assert column.nullable == model[name].nullable, name
        assert type(column.type).__name__ in (type(model[name].type).__name__, "AutoString"), name
    foreign = [c for c in items if type(c).__name__ == "ForeignKeyConstraint"]
    assert len(foreign) == 1 and foreign[0].ondelete == "CASCADE"
    [model_fk] = TeamBranding.__table__.foreign_keys
    assert model_fk.target_fullname == "team.id" and model_fk.ondelete == "CASCADE"

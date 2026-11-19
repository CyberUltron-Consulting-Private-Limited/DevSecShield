"""Decode, check and normalise an uploaded team report logo (plan v2 section 5, ``PUT`` steps 1-14).

Pure: bytes in, a ``NormalizedLogo`` or a typed ``LogoError`` out; no database, no network, no global Pillow
settings (``Image.MAX_IMAGE_PIXELS`` is left alone).  The router runs ``normalize_logo`` in the threadpool.

What is stored is never the uploaded file: the image is decoded, oriented, brought to 8-bit sRGB, cropped to its
visible pixels, scaled into 800 x 240 and re-encoded as a PNG without metadata (EXIF, ICC, text chunks and any
payload appended to the upload are dropped).  Every refusal carries the HTTP status it maps to (413 / 415 / 422) and
a message a person can act on.
"""
from __future__ import annotations

import hashlib
import io
import logging
import threading
import warnings
from dataclasses import dataclass

from PIL import Image, ImageOps, ImageStat

log = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # the router reads the body with this cap (413)
ACCEPTED_CONTENT_TYPES = ("image/png", "image/jpeg", "image/webp", "application/octet-stream")
# Plan step 1 lists ["PNG", "JPEG", "MPO", "WEBP"], but Pillow 12 registers no "MPO" opener (MpoImagePlugin leaves
# it commented out; ``Image.open(formats=[..., "MPO", ...])`` raises KeyError for anything the openers before it
# refuse).  The JPEG opener itself returns an MpoImageFile for a multi-picture JPEG, so MPO is still accepted.
OPEN_FORMATS = ("PNG", "JPEG", "WEBP")
DECODED_FORMATS = ("PNG", "JPEG", "MPO", "WEBP")
MAX_SIDE = 4096
MAX_PIXELS = 16_777_216  # 4096 x 4096
VISIBLE_ALPHA = 32  # a pixel with less opacity than this is background
MIN_ASPECT, MAX_ASPECT = 0.25, 12.0  # width / height after the crop
BOX = (800, 240)
RETRY_BOX = (400, 120)
MIN_SIDE = 16  # after scaling into BOX
MAX_STORED_BYTES = 300 * 1024
LIGHT_LUMINANCE = 0.8  # mean luminance of the visible pixels above this: a light logo (drawn on navy)

_MAGIC_FORMAT = {"image/png": "PNG", "image/jpeg": "JPEG", "image/webp": "WEBP"}
# warnings.catch_warnings swaps the process-wide filter list and is not thread-safe: two decodes entering and
# leaving it interleaved could leave the "error" filter installed for good.  Uploads are rare (admins only, rate
# limited), so decodes take turns.
_WARNINGS_LOCK = threading.Lock()


class LogoError(ValueError):
    """An upload that cannot be the team's logo; ``status_code`` is the HTTP answer, ``message`` the user text."""

    status_code = 422

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class LogoTooLarge(LogoError):
    status_code = 413


class UnsupportedLogoType(LogoError):
    status_code = 415


class InvalidLogo(LogoError):
    status_code = 422


UNSUPPORTED = "The logo must be a PNG, JPEG or WebP image"
UNREADABLE = "The logo could not be read as an image; export it again as PNG, JPEG or WebP"
TRANSPARENT = "The logo is fully transparent"


@dataclass(frozen=True)
class NormalizedLogo:
    png: bytes
    sha256: str
    width: int
    height: int
    size_bytes: int
    tone: str  # "dark" | "light"
    has_alpha: bool
    format_in: str  # "png" | "jpeg" | "mpo" | "webp": what was uploaded (audit details)


def sniff_format(raw: bytes) -> str | None:
    """The format the magic bytes say, or None (GIF, SVG, BMP, anything else)."""
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if raw.startswith(b"\xff\xd8\xff"):
        return "JPEG"  # MPO files are JPEGs with extra frames
    if len(raw) >= 12 and raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "WEBP"
    return None


def check_content_type(content_type: str | None, magic: str | None) -> None:
    """Content-Type ``split(';')[0]``: png / jpeg / webp, octet-stream or none.  The magic bytes decide the format;
    an explicit image type that disagrees with them is refused (415)."""
    declared = (content_type or "").split(";")[0].strip().lower()
    if declared and declared not in ACCEPTED_CONTENT_TYPES:
        raise UnsupportedLogoType(UNSUPPORTED)
    if magic is None:
        raise UnsupportedLogoType(UNSUPPORTED)
    expected = _MAGIC_FORMAT.get(declared)
    if expected is not None and expected != magic:
        raise UnsupportedLogoType(f"The file is not the {declared} image its Content-Type says")


def normalize_logo(raw: bytes, content_type: str | None) -> NormalizedLogo:
    if len(raw) > MAX_UPLOAD_BYTES:
        raise LogoTooLarge(f"The logo is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    if not raw:
        raise InvalidLogo("No image was sent")
    magic = sniff_format(raw)
    check_content_type(content_type, magic)
    with _WARNINGS_LOCK, warnings.catch_warnings():
        # step 3, scoped to this block and this one category: a decompression bomb is an error, not a warning
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            image, format_in = _decode(raw, magic)
        except LogoError:
            raise
        except (Image.DecompressionBombWarning, Image.DecompressionBombError):
            raise InvalidLogo(f"The logo is too large: it can be at most {MAX_SIDE} x {MAX_SIDE} pixels") from None
        except Exception as exc:  # noqa: BLE001 - any decoder failure on client bytes is the client's 422
            log.info("team logo refused: %s while decoding", type(exc).__name__)
            raise InvalidLogo(UNREADABLE) from None
    return _normalise(image, format_in)


def _decode(raw: bytes, magic: str) -> tuple[Image.Image, str]:
    """Steps 1-8: an oriented, 8-bit, sRGB image (alpha kept where there is one)."""
    image = Image.open(io.BytesIO(raw), formats=list(OPEN_FORMATS))  # 1
    fmt = (image.format or "").upper()
    if fmt not in DECODED_FORMATS or (fmt == "MPO" and magic != "JPEG") or (fmt != "MPO" and fmt != magic):
        raise UnsupportedLogoType(UNSUPPORTED)
    width, height = image.size  # 2: from the header, before anything is decoded
    if width < 1 or height < 1 or width > MAX_SIDE or height > MAX_SIDE or width * height > MAX_PIXELS:
        raise InvalidLogo(f"The logo is {width} x {height} pixels; it can be at most {MAX_SIDE} x {MAX_SIDE}")
    if fmt == "MPO":  # 4: a stereo / multi-picture JPEG: its first picture
        image.seek(0)
    elif getattr(image, "n_frames", 1) > 1:
        raise InvalidLogo("Animated images can't be used as a logo")
    if fmt in ("JPEG", "MPO"):  # 5: let the JPEG decoder scale down large photos (never below what BOX needs)
        image.draft(None, (BOX[0], BOX[0]))
    image.load()
    icc = image.info.get("icc_profile")
    image = ImageOps.exif_transpose(image)  # 6
    if image.mode in ("I", "I;16", "I;16L", "I;16B", "I;16N"):  # 7: 16-bit grey to 8-bit by scaling, not clipping
        image = image.convert("I").point(lambda v: v * (1 / 256)).convert("L")
    return _to_srgb(image, icc), fmt.lower()  # 8


def _has_alpha(image: Image.Image) -> bool:
    return image.mode in ("RGBA", "LA", "PA", "La", "RGBa") or "transparency" in image.info


def _to_srgb(image: Image.Image, icc: bytes | None) -> Image.Image:
    """Step 8: RGB(A) in sRGB.  A profile that cannot be read or applied is ignored (the pixels are taken as sRGB):
    a broken ICC chunk does not make a readable logo unusable."""
    alpha = image.convert("RGBA").getchannel("A") if _has_alpha(image) else None
    color = None
    if icc:
        try:
            from PIL import ImageCms  # noqa: PLC0415 - optional in a Pillow build without littlecms

            source = ImageCms.ImageCmsProfile(io.BytesIO(icc))
            space = (source.profile.xcolor_space or "").strip().upper()
            in_mode = {"RGB": "RGB", "GRAY": "L", "CMYK": "CMYK"}.get(space)
            if in_mode is not None:
                color = ImageCms.profileToProfile(image.convert(in_mode), source, ImageCms.createProfile("sRGB"),
                                                  renderingIntent=ImageCms.Intent.PERCEPTUAL, outputMode="RGB")
        except Exception as exc:  # noqa: BLE001
            log.info("team logo: ICC profile ignored (%s)", type(exc).__name__)
            color = None
    if color is None:
        color = image.convert("RGB")
    rgba = color.convert("RGBA")
    if alpha is not None:
        rgba.putalpha(alpha)
    return rgba


def _visible_mask(rgba: Image.Image) -> Image.Image:
    return rgba.getchannel("A").point(lambda a: 255 if a >= VISIBLE_ALPHA else 0)


def _encode(image: Image.Image) -> bytes:
    image.info.clear()  # no ICC, EXIF, text or transparency chunk carried over from the upload
    out = io.BytesIO()
    image.save(out, "PNG", optimize=True)
    return out.getvalue()


def _fit(cropped: Image.Image, box: tuple[int, int]) -> Image.Image:
    scaled = cropped.copy()
    scaled.thumbnail(box, Image.Resampling.LANCZOS)
    if min(scaled.size) < MIN_SIDE:
        raise InvalidLogo(f"The logo is too small: it needs at least {MIN_SIDE} pixels on each side once scaled "
                          f"to fit {BOX[0]} x {BOX[1]}")
    return scaled


def _normalise(rgba: Image.Image, format_in: str) -> NormalizedLogo:
    """Steps 9-14."""
    bbox = _visible_mask(rgba).getbbox()  # 9
    if bbox is None:
        raise InvalidLogo(TRANSPARENT)
    cropped = rgba.crop(bbox)
    width, height = cropped.size
    if not MIN_ASPECT <= width / height <= MAX_ASPECT:  # 10
        raise InvalidLogo(f"The logo is {width} x {height} pixels once cropped; its width must be between "
                          f"{MIN_ASPECT:g} and {MAX_ASPECT:g} times its height")
    for box in (BOX, RETRY_BOX):  # 11 and 13: a logo too detailed for 300 KB gets a second try at half the size
        scaled = _fit(cropped, box)
        visible = _visible_mask(scaled)
        if visible.getbbox() is None:  # faint strokes that scaling averaged away
            raise InvalidLogo(TRANSPARENT)
        has_alpha = scaled.getchannel("A").getextrema()[0] < 255
        stored = scaled if has_alpha else scaled.convert("RGB")  # 12: opaque logos carry no alpha (no soft mask)
        png = _encode(stored)
        if len(png) <= MAX_STORED_BYTES:
            break
    else:
        raise InvalidLogo(f"The logo is too detailed to store in {MAX_STORED_BYTES // 1024} KB; simplify it or "
                          "use fewer colours")
    luminance = ImageStat.Stat(scaled.convert("L"), mask=visible).mean[0] / 255  # 14
    return NormalizedLogo(png=png, sha256=hashlib.sha256(png).hexdigest(), width=stored.width, height=stored.height,
                          size_bytes=len(png), tone="light" if luminance > LIGHT_LUMINANCE else "dark",
                          has_alpha=has_alpha, format_in=format_in)

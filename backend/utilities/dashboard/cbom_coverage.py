"""What a code scan left out, as sentences for the results page (WP8b).

The engine records every skipped or unsupported input as a ``crypto:coverage:<key>`` property in the CycloneDX
``metadata.properties`` (archives, container images, binaries, firmware, symlinks, oversized files, git history).
Until now those counts lived only in the downloaded file; ``coverage_report`` turns them into short notes the results
page shows next to the import notes of an uploaded CBOM file.  Unknown keys are kept, shown by their key, so a new
engine count is never hidden.
"""
from __future__ import annotations

from typing import Any

PREFIX = "crypto:coverage:"
MAX_NOTES = 40

# key -> (sentence with {n}, kind): "skipped" (something was not read) or "info" (what was read)
_LABELS: dict[str, tuple[str, str]] = {
    "archiveEncrypted": ("{n} encrypted archive member(s) could not be read", "skipped"),
    "archiveUnsupported": ("{n} archive(s) in an unsupported format were not opened", "skipped"),
    "archiveBudgetExceeded": ("{n} archive member(s) were skipped: the scan's unpack budget was used up", "skipped"),
    "archiveTooDeep": ("{n} archive(s) nested too deep were not opened", "skipped"),
    "archiveMembersNotScanned": ("{n} archive member(s) were not scanned", "skipped"),
    "skippedSymlinks": ("{n} symbolic link(s) were not followed", "skipped"),
    "skippedOversized": ("{n} file(s) over the size cap were skipped", "skipped"),
    "skippedBinary": ("{n} binary file(s) were skipped (turn on \"Scan binaries, container images and firmware\" to "
                      "read them)", "skipped"),
    "skippedVendoredDirs": ("{n} vendored or build director(ies) (vendor/, dist/, build/, node_modules/) were not "
                            "scanned (turn on \"Scan vendored and build directories\" to read them; packages installed "
                            "under node_modules/ are left to the dependency scan)", "skipped"),
    # the two scan options, recorded as "true" when they were on: what was read, never something skipped
    "binariesIncluded": ("\"Scan binaries, container images and firmware\" was on: binaries, container images and "
                         "firmware in the tree were read", "info"),
    "vendoredIncluded": ("\"Scan vendored and build directories\" was on: vendor/, dist/, build/ and node_modules/ "
                         "were read", "info"),
    "binariesRead": ("{n} binary file(s) were read for crypto imports, constants and embedded keys", "info"),
    "binariesTooLarge": ("{n} binary file(s) over the size cap were not read", "skipped"),
    "firmwareImagesRead": ("{n} firmware image(s) were unpacked and read", "info"),
    "firmwareSymlinksNotFollowed": ("{n} symbolic link(s) inside firmware were not followed", "skipped"),
    "symlinksNotFollowed": ("{n} symbolic link(s) inside images or archives were not followed", "skipped"),
    "layerNotTar": ("{n} image layer(s) were not tar archives and were skipped", "skipped"),
    "layersMissing": ("{n} image layer(s) named in a manifest were missing from the upload", "skipped"),
    "layersNotRead": ("{n} image layer(s) were not read", "skipped"),
    "osPackagesNotCrypto": ("{n} installed OS package(s) are not crypto-related and are not listed", "info"),
    "languagePackagesNotCrypto": ("{n} language package(s) are not crypto-related and are not listed", "info"),
    "goBuildInfoBefore118NotRead": ("{n} Go binary(ies) built before Go 1.18 have no readable build info", "skipped"),
    "rpmBerkeleyDbNotParsed": ("{n} rpm database(s) in the Berkeley DB / NDB format were not parsed (rpmdb.sqlite "
                               "only)", "skipped"),
    "rpmDatabaseTooLarge": ("{n} rpm database(s) over the size cap were not read", "skipped"),
    "rpmDatabaseUnreadable": ("{n} rpm database(s) could not be read", "skipped"),
    "trustStoreFilesCounted": ("{n} system CA trust store file(s) were counted, not listed", "info"),
    "cryptoLibrarySelfTestKeysNotReported": ("{n} crypto library self-test key(s) were recognised and not reported",
                                             "info"),
    "gitHistory": ("Git history: {n}", "skipped"),
    "gitHistoryCommits": ("{n} commit(s) of git history were read", "info"),
    "gitHistoryCommitsNotRead": ("{n} commit(s) of git history were not read", "skipped"),
    "gitHistoryBudgetExceeded": ("Git history was cut short by the scan budget", "skipped"),
    "submodulesNotScanned": ("{n} git submodule(s) were not scanned", "skipped"),
    "lfsObjectsNotScanned": ("{n} Git LFS object(s) were not scanned", "skipped"),
}
_REFUSED = {
    "pathTraversal": "a path that leaves the archive ('..')", "absolutePath": "an absolute path",
    "specialFile": "a device, FIFO or socket", "linkEscape": "a link that points outside the archive",
    "compressionBomb": "a compression bomb", "budgetExceeded": "the unpack budget", "corruptArchive": "a corrupt archive",
    "corruptHeader": "a corrupt header", "nameTooLong": "an over-long name", "nulInName": "a NUL in a name",
}


def _number(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def coverage_report(cbom_json: Any) -> dict[str, Any] | None:
    """``{"notes": [{"key", "text", "kind"}], "skipped": n}`` from a stored CycloneDX document, or None when the scan
    recorded no coverage property."""
    if not isinstance(cbom_json, dict):
        return None
    props = (cbom_json.get("metadata") or {}).get("properties") if isinstance(cbom_json.get("metadata"), dict) else None
    if not isinstance(props, list):
        return None
    notes: list[dict[str, str]] = []
    for prop in props:
        if not isinstance(prop, dict) or not str(prop.get("name") or "").startswith(PREFIX):
            continue
        key = str(prop["name"])[len(PREFIX):][:120]
        value = str(prop.get("value") or "")[:200]
        n = _number(value)
        if key.startswith("unpackRefused:"):
            reason = key.split(":", 1)[1]
            text, kind = f"{value} archive member(s) were refused: {_REFUSED.get(reason, reason)}", "skipped"
        elif key.startswith("image:"):
            sub = key.split(":", 1)[1]
            label = _LABELS.get(sub)
            text = label[0].format(n=value) if label else f"Container image: {sub} ({value})"
            kind = label[1] if label else "skipped"
        elif key.startswith("unsupportedLayerCompression:"):
            text, kind = f"{value} image layer(s) compressed with {key.split(':', 1)[1]} were not read", "skipped"
        elif key in _LABELS:
            template, kind = _LABELS[key]
            text = template.format(n=value if n is None else n)
        else:
            text, kind = f"{key}: {value}", "skipped"
        if n == 0:
            continue
        notes.append({"key": key, "text": text[:300], "kind": kind})
    if not notes:
        return None
    notes.sort(key=lambda note: (note["kind"] != "skipped", note["key"]))
    return {"notes": notes[:MAX_NOTES], "skipped": sum(1 for note in notes if note["kind"] == "skipped")}

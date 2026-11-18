"""POSIX script that keeps one server's SSH CA trust files current (F1.4).

The SSH CA page (``templates/trust-fetch``) and the fleet installers (Salt, Ansible, SSM; issue #83)
serve this same text. It contains no token, URL or group: the caller sets ``ZS_TRUST_TOKEN``,
``ZS_URL`` and ``ZS_GROUPS``.
"""
from __future__ import annotations

_TEMPLATE = r"""#!/bin/sh
# ZeroShield CBOM: keep this server's SSH CA trust current (team {team_id}). Run as root from a timer, e.g. every 5
# minutes with a random delay (systemd: OnUnitActiveSec=5min, RandomizedDelaySec=120). POSIX sh + curl + ssh-keygen.
#   ZS_TRUST_TOKEN  a trust token of this team (CBOM Sources > Fleet > SSH CA > Trust tokens); keep it in a 0600 file
#   ZS_URL          ZeroShield's API address (the one the scan nodes use, e.g. https://api.<your ZeroShield domain>)
#   ZS_GROUPS       this server's group(s), space separated (principals zs-{team_id}-<group>)
#   ZS_DIR          default /etc/ssh/zs-cbom;  ZS_RELOAD  default "systemctl reload ssh || systemctl reload sshd"
# It never installs an empty or unreadable file: on any failure it keeps the old one and exits non-zero.
set -u
umask 022
: "${{ZS_TRUST_TOKEN:?set ZS_TRUST_TOKEN}}"
URL="${{ZS_URL:?set ZS_URL to ZeroShield's API address}}"
DIR="${{ZS_DIR:-/etc/ssh/zs-cbom}}"
GROUPS_Q=""
for g in ${{ZS_GROUPS:-}}; do GROUPS_Q="${{GROUPS_Q}}${{GROUPS_Q:+&}}group=${{g}}"; done
NAME="$(hostname -f 2>/dev/null || hostname)"
mkdir -p "$DIR/principals" "$DIR/.etag" || exit 1
changed=0
fail=0

# fetch <path> <file> <check>: conditional GET (If-None-Match), atomic replace after <check> accepted the new file
fetch() {{
  path="$1"; dest="$2"; check="$3"; tag="$DIR/.etag/$(basename "$dest")"
  tmp="$(mktemp "$dest.new.XXXXXX")" || return 1
  hdr="$(mktemp "$dest.hdr.XXXXXX")" || {{ rm -f "$tmp"; return 1; }}
  set -- -sS --fail --max-time 30 -D "$hdr" -o "$tmp" -H "X-ZS-Trust-Token: $ZS_TRUST_TOKEN" -H "X-ZS-Fetcher: $NAME"
  if [ -s "$dest" ] && [ -s "$tag" ]; then set -- "$@" -H "If-None-Match: $(cat "$tag")"; fi
  code="$(curl "$@" -w '%{{http_code}}' "$URL/cbom/ssh-ca-trust$path")"  # with --fail: 4xx/5xx exit non-zero
  [ -n "$code" ] || code=000
  if [ "$code" = 304 ]; then rm -f "$tmp" "$hdr"; return 0; fi
  if [ "$code" != 200 ] || [ ! -s "$tmp" ] || ! $check "$tmp"; then
    echo "zs-trust-fetch: $path: HTTP $code or an unusable file; keeping $dest" >&2
    rm -f "$tmp" "$hdr"; return 1
  fi
  chmod 0644 "$tmp" && mv -f "$tmp" "$dest" || {{ rm -f "$tmp" "$hdr"; return 1; }}
  sed -n 's/^[Ee][Tt][Aa][Gg]: *//p' "$hdr" | tr -d '\r' > "$tag"
  rm -f "$hdr"; changed=1
}}
keys_ok() {{ grep -Eq '^(ssh-|ecdsa-|sk-)' "$1" || ! grep -qv '^#' "$1"; }}  # keys, or only comments (no CA)
krl_ok() {{ ssh-keygen -Q -l -f "$1" >/dev/null 2>&1; }}
text_ok() {{ head -c 1 "$1" >/dev/null; }}

fetch /trusted-keys "$DIR/trusted_user_ca_keys" keys_ok || fail=1
fetch /revoked "$DIR/revoked.krl" krl_ok || fail=1
fetch "/principals${{GROUPS_Q:+?}}$GROUPS_Q" "$DIR/principals/zs-cbom" text_ok || fail=1
if [ "$changed" = 1 ]; then
  if sshd -t; then
    sh -c "${{ZS_RELOAD:-systemctl reload ssh || systemctl reload sshd}}" || fail=1
  else
    echo "zs-trust-fetch: sshd -t failed; sshd was not reloaded" >&2; fail=1
  fi
fi
exit "$fail"
"""


def trust_fetch_script(team_id: int) -> str:
    """The script for one team. ``team_id`` appears only in comments (the principal prefix)."""
    if isinstance(team_id, bool) or not isinstance(team_id, int) or not 1 <= team_id <= 2_147_483_647:
        raise ValueError("team_id")
    return _TEMPLATE.format(team_id=team_id)


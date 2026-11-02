"""SIMULATED network appliance for tests and the lab proof (not a real Cisco/Fortinet device).

A paramiko SSH server that answers the commands found in a fixture file (sections headed '### <command>') with the
fixture text, refuses everything else with an IOS-style error, and records every command it receives in
``received`` (and on stdout when run as a script).  ``--shell`` mimics a device without an exec channel (Cisco
ASA): one PTY shell with a prompt, as the collector's shell mode expects.

    python sim_appliance.py --fixture fixtures/appliance/cisco_asa.txt --port 2222 --shell --password lab-only
"""
from __future__ import annotations

import argparse
import socket
import sys
import threading
from pathlib import Path

import paramiko


def load_fixture(path: str | Path) -> dict[str, str]:
    out: dict[str, str] = {}
    current = None
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.startswith("### "):
            current = line[4:].strip()
            out[current] = ""
        elif current is not None:
            out[current] += line + "\n"
    return out


class SimAppliance:
    def __init__(self, fixture: str | Path, user: str = "zs-cbom", password: str = "lab-only", shell: bool = False,
                 prompt: str = "lab-asa# ", verbose: bool = False) -> None:
        self.answers = load_fixture(fixture)
        self.user, self.password, self.shell, self.prompt, self.verbose = user, password, shell, prompt, verbose
        self.host_key = paramiko.ECDSAKey.generate()
        self.received: list[str] = []
        self.refused: list[str] = []
        self.sock: socket.socket | None = None

    def known_hosts_line(self, host: str, port: int) -> str:
        name = host if port == 22 else f"[{host}]:{port}"
        return f"{name} {self.host_key.get_name()} {self.host_key.get_base64()}"

    def _answer(self, cmd: str) -> str:
        self.received.append(cmd)
        if self.verbose:
            print(f"SIM command: {cmd}", flush=True)
        if cmd == "terminal pager 0":
            return ""
        if cmd in self.answers:
            return self.answers[cmd]
        self.refused.append(cmd)
        return "% Invalid input detected at '^' marker.\n"

    def serve(self, host: str = "127.0.0.1", port: int = 0) -> int:
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(8)
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return self.sock.getsockname()[1]

    def _accept_loop(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        sim = self
        transport = paramiko.Transport(conn)
        transport.add_server_key(self.host_key)

        class Server(paramiko.ServerInterface):
            def __init__(self) -> None:
                self.event = threading.Event()
                self.command: str | None = None
                self.want_shell = False

            def check_auth_password(self, username, password):
                ok = username == sim.user and password == sim.password
                return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

            def get_allowed_auths(self, username):
                return "password"

            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_channel_exec_request(self, channel, command):
                if sim.shell:
                    return False  # like an ASA: no exec channel
                self.command = command.decode("utf-8", "replace")
                self.event.set()
                return True

            def check_channel_pty_request(self, *args):
                return True

            def check_channel_shell_request(self, channel):
                self.want_shell = True
                self.event.set()
                return True

        server = Server()
        try:
            transport.start_server(server=server)
            while transport.is_active():
                chan = transport.accept(20)
                if chan is None:
                    break
                server.event.wait(10)
                if server.want_shell:
                    self._shell(chan)
                    break
                if server.command is not None:
                    chan.sendall(self._answer(server.command).encode())
                    chan.send_exit_status(0)
                    chan.close()
                    server.command = None
                    server.event.clear()
        except Exception:
            pass
        finally:
            transport.close()

    def _shell(self, chan: paramiko.Channel) -> None:
        chan.sendall(b"Type help or '?' for a list of available commands.\r\n" + self.prompt.encode())
        buf = b""
        while True:
            data = chan.recv(1024)
            if not data:
                return
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                cmd = line.decode("utf-8", "replace").strip("\r ")
                if not cmd:
                    chan.sendall(self.prompt.encode())
                    continue
                if cmd in ("exit", "quit"):
                    chan.close()
                    return
                text = self._answer(cmd).replace("\n", "\r\n")
                chan.sendall(cmd.encode() + b"\r\n" + text.encode() + self.prompt.encode())


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--fixture", required=True)
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--shell", action="store_true")
    p.add_argument("--password", default="lab-only")
    p.add_argument("--known-hosts-name", default="127.0.0.1")
    args = p.parse_args()
    sim = SimAppliance(args.fixture, password=args.password, shell=args.shell, verbose=True)
    port = sim.serve(args.host, args.port)
    print("SIMULATED appliance (not a real device) listening on", port, flush=True)
    print("KNOWN_HOSTS " + sim.known_hosts_line(args.known_hosts_name, port), flush=True)
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())

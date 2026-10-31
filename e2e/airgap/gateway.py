#!/usr/bin/env python3
"""Stdlib TCP forwarder for the air-gap overlay.

Listens on the ports the host publishes and copies bytes to the app containers
on the internal network. It does not inspect or modify the stream.
"""

from __future__ import annotations

import socket
import threading

FORWARDS = (
    (3000, "frontend", 3000),
    (8080, "backend", 8080),
)


def _pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _handle(client: socket.socket, host: str, port: int) -> None:
    try:
        remote = socket.create_connection((host, port), timeout=10)
    except OSError as exc:
        print(f"forward {host}:{port} failed: {exc}", flush=True)
        client.close()
        return
    remote.settimeout(None)
    threading.Thread(target=_pipe, args=(client, remote), daemon=True).start()
    _pipe(remote, client)
    client.close()
    remote.close()


def _serve(listen_port: int, host: str, port: int) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", listen_port))
    server.listen(128)
    print(f"listening {listen_port} -> {host}:{port}", flush=True)
    while True:
        client, _addr = server.accept()
        threading.Thread(target=_handle, args=(client, host, port), daemon=True).start()


def main() -> None:
    threads = []
    for listen_port, host, port in FORWARDS:
        thread = threading.Thread(target=_serve, args=(listen_port, host, port), daemon=True)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()

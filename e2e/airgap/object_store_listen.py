#!/usr/bin/env python3
"""Bind TCP 9000 and accept then close.

The air-gap overlay names this process with the MinIO tag that Docker Hub and
dl.min.io no longer publish (pull denied, release URL 410). The listener exists
so the isolated network has an object-store peer. It does not store objects.
"""

from __future__ import annotations

import socket
import sys


def main() -> None:
    del sys.argv
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 9000))
    server.listen(16)
    print("object-store listener on 9000", flush=True)
    while True:
        client, _addr = server.accept()
        client.close()


if __name__ == "__main__":
    main()

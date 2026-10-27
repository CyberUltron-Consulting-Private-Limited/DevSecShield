"""Backend air-gap helper. Blocks socket creation inside the with-block."""

from __future__ import annotations

import socket
from types import TracebackType


class NetworkBlocked(RuntimeError):
    """A posture test tried to open a socket."""


class block_network:
    """Replace socket.socket so a control that connects is caught."""

    def __enter__(self) -> "block_network":
        self._original = socket.socket

        def _refused(*_args: object, **_kwargs: object) -> socket.socket:
            raise NetworkBlocked("network is blocked")

        socket.socket = _refused  # type: ignore[assignment]
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        socket.socket = self._original

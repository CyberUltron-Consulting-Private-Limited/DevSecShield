FROM ghcr.io/astral-sh/uv:bookworm-slim

WORKDIR /app

COPY . . 

RUN uv python install 3.13.5
RUN uv init
RUN uv sync
RUN uv pip install garak 

CMD ["uv", "run", "garak_scan.py"]
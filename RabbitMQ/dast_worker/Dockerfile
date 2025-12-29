FROM ghcr.io/astral-sh/uv:bookworm-slim

WORKDIR /app

COPY . . 

RUN uv sync

ENV IS_DOCKER_CONTAINER="True"

CMD ["uv", "run", "celery","-A","dast_worker","worker","-P","threads","--loglevel=info"]
FROM ghcr.io/astral-sh/uv:bookworm-slim

WORKDIR /backend

COPY . . 

RUN uv sync

ENV IS_DOCKER_CONTAINER="True"

# Expose the port
EXPOSE 8080

# Run the FastAPI application by default
CMD ["uv", "run", "fastapi", "run", "--host", "0.0.0.0","--port", "8080", "main.py"]
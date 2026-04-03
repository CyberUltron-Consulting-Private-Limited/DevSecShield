FROM ghcr.io/astral-sh/uv:bookworm-slim

WORKDIR /backend

COPY . . 

RUN uv sync

ENV IS_DOCKER_CONTAINER="True"
ENV PYTHONPATH="/backend/.."

# Expose the port
EXPOSE 8080

# Run the Uvicorn server with Gunicorn as the worker class, using 4 workers and binding to all interfaces on port 8080. Set timeouts for better performance.
CMD ["uv", "run", "gunicorn", "main:app", "-k", "uvicorn.workers.UvicornWorker", "--workers", "4", "--bind", "0.0.0.0:8080", "--timeout", "120", "--graceful-timeout", "30", "--keep-alive", "5"]
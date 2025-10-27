FROM python:3.12-slim

WORKDIR /app

COPY . .

RUN python3 -m pip install --no-cache-dir semgrep
RUN python3 -m pip install rich
RUN python3 -m pip install gitpython

#installing git
RUN apt-get update && apt-get install -y git

ENV PYTHONUNBUFFERED=1

ENV SEMGREP_APP_TOKEN="896b59e81d3e4d0484f91a6b648804dd9f372389b32c42f2756e901b0116af0a"

CMD ["python3", "sast_runner.py"]  
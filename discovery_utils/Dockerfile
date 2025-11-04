FROM python:3.10-slim

WORKDIR /app

COPY . .

RUN pip install rich GitPython python-dotenv openai

#installing git
RUN apt-get update && apt-get install -y git



CMD ["python", "discovery_runner.py"]

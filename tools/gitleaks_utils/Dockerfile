FROM python:3.10-slim

WORKDIR /app

COPY . .

RUN pip install rich GitPython 

# True for Linux, False for Windows
ENV LINUX_GITLEAKS True 

#installing git
RUN apt-get update && apt-get install -y git



CMD ["python", "gitleaks_runner.py"]

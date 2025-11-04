FROM python:3.10-slim

WORKDIR /app

COPY . .

RUN pip install rich GitPython 

#installing git
RUN apt-get update && apt-get install -y git



CMD ["python", "gitleaks_scan.py"]

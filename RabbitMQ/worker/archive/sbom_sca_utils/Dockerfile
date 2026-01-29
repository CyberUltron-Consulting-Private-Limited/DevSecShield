FROM python:3.12-slim

WORKDIR /app

COPY . .

RUN apt-get -y update; apt-get -y install curl
RUN apt-get update && apt-get install -y git
RUN curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin
RUN pip install GitPython rich

CMD ["python3", "sbom_runner.py"]  
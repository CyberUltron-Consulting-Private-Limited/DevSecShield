FROM python:3.12-slim

WORKDIR /app

COPY . .

RUN apt-get -y update; apt-get -y install curl
RUN curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.67.2
RUN apt-get update && apt-get install -y git
RUN pip install GitPython rich


CMD ["python3", "iac_runner.py"]  
FROM ghcr.io/astral-sh/uv:bookworm-slim

WORKDIR /app

COPY . . 


# installing SBOM software  ( curl + git + grype )
RUN apt-get -y update; apt-get -y install curl
RUN apt-get update && apt-get install -y git
RUN curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin

# for SAST 
ENV PYTHONUNBUFFERED=1
ENV SEMGREP_APP_TOKEN="896b59e81d3e4d0484f91a6b648804dd9f372389b32c42f2756e901b0116af0a"

# for MCP scanning ( purposefully left out the command that installs cs certificates ) 
#installing npm
RUN  apt install -y npm 


# for iac scan
RUN curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.67.2

# for gitleaks scanning 
# True for Linux, False for Windows
ENV LINUX_GITLEAKS=True 


# installing python 3.13.5 for garak 
RUN uv python install 3.13.5
RUN uv sync

CMD ["uv", "run", "celery","-A","scan_worker","worker","-P","threads","--loglevel=info"]
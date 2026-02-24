FROM ghcr.io/astral-sh/uv:bookworm-slim

WORKDIR /app

COPY . . 

# Install Homebrew (Linuxbrew) dependencies + Chromium/rod deps for nuclei headless browser
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    file \
    git \
    procps \
    ca-certificates \
    bash \
    libglib2.0-0 \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    libx11-6 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxrandr2 \
    fonts-liberation \
    libx11-xcb1 \
    libxcursor1 \
    libgtk-3-0 \
    libpangocairo-1.0-0 \
    libcairo-gobject2 \
    libgdk-pixbuf-2.0-0 \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# create a non-root user for brew
RUN useradd -m -s /bin/bash linuxbrew \
 && echo "linuxbrew ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER linuxbrew
WORKDIR /home/linuxbrew

# install Homebrew (Linuxbrew) as non-root
RUN /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# switch back to root if you want to keep building as root
USER root

# make brew available for all users
ENV PATH="/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:${PATH}"

# install nuclei as linuxbrew user (Homebrew refuses to run as root)
RUN runuser -u linuxbrew -- env PATH="/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:$PATH" brew install nuclei

WORKDIR /app

RUN uv sync

ENV IS_DOCKER_CONTAINER="True"

RUN uv run playwright install

CMD ["uv", "run", "celery","-A","dast_worker","worker","-P","threads","--loglevel=info"]

# for testing nuclei installation ( not for production )
# CMD [ "nuclei", "-u", "https://demo.testfire.net/login.jsp", "-headless", "-t", "templates", "-me", "markdown_dir"]
FROM python:3.12-slim

# System deps for Playwright Chromium + SSH
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    curl \
    openssh-server \
    # Playwright Chromium deps
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    libatspi2.0-0 \
    libxshmfence1 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# SSH setup — pubkey only, no password auth
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh \
    && printf '%s\n' \
        'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG/jC37ZRA8gjyFqahlhn/WC9IctIJQP+0Cm5/3IilII azureuser@aet-psrdev-centralus-api0' \
        'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJS23M0/uZuDsqSwvSIcpJkplhgfixKas4tP96zVVaAE azureuser@aet-psrdev-centralus-api0' \
        'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeic3+OjyEUfsT8aEm1+kHNp5vN21B6FSk62lT+sLFo unimind-container-access' \
        > /root/.ssh/authorized_keys \
    && chmod 600 /root/.ssh/authorized_keys \
    && mkdir -p /etc/ssh/sshd_config.d \
    && printf '%s\n' \
        'PasswordAuthentication no' \
        'PermitRootLogin prohibit-password' \
        'PubkeyAuthentication yes' \
        'AuthorizedKeysFile .ssh/authorized_keys' \
        > /etc/ssh/sshd_config.d/ghostmcp.conf \
    && mkdir -p /run/sshd \
    && echo 'export PLAYWRIGHT_BROWSERS_PATH=/app/.cache/ms-playwright' >> /root/.bashrc \
    && echo 'export PYTHONPATH=/app' >> /root/.bashrc \
    && echo 'cd /app' >> /root/.bashrc

# Python deps
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Install pytest for in-container testing
RUN pip install --no-cache-dir pytest pytest-asyncio

# Ghost user for MCP runtime (non-root)
RUN groupadd -r ghost && useradd -r -g ghost -d /app -s /bin/bash ghost && \
    mkdir -p /app/.cache && chown -R ghost:ghost /app && \
    mkdir -p /tmp/ghostmcp_ratelimit && chown ghost:ghost /tmp/ghostmcp_ratelimit

# Install Playwright browsers
ENV PLAYWRIGHT_BROWSERS_PATH=/app/.cache/ms-playwright
RUN pip install --no-cache-dir playwright && \
    playwright install chromium && \
    playwright install-deps chromium && \
    chown -R ghost:ghost /app/.cache

# App code
COPY --chown=ghost:ghost src/ /app/src/
COPY --chown=ghost:ghost tests/ /app/tests/

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app
ENV GHOST_PARANOIA=cautious
ENV GHOST_MIN_DELAY=2.0

# Build metadata (injected by build-ghostmcp.sh)
ARG GIT_COMMIT=unknown
ARG GIT_BRANCH=unknown
ARG BUILD_TIME=unknown
ENV GHOST_GIT_COMMIT=$GIT_COMMIT
ENV GHOST_GIT_BRANCH=$GIT_BRANCH
ENV GHOST_BUILD_TIME=$BUILD_TIME

# Expose SSH + HTTP health
EXPOSE 22 8080

ENTRYPOINT ["tini", "--"]
CMD ["/bin/bash", "-c", "ssh-keygen -A 2>/dev/null; /usr/sbin/sshd; exec python3 -m src"]

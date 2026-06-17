FROM python:3.12-slim

# System deps for Playwright Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    curl \
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

# Python deps
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Non-root user — create BEFORE installing playwright browsers
RUN groupadd -r ghost && useradd -r -g ghost -d /app ghost && \
    mkdir -p /app/.cache && chown -R ghost:ghost /app && \
    mkdir -p /tmp/ghostmcp_ratelimit && chown ghost:ghost /tmp/ghostmcp_ratelimit

# Install Playwright browsers as the ghost user so paths match at runtime
ENV PLAYWRIGHT_BROWSERS_PATH=/app/.cache/ms-playwright
RUN pip install --no-cache-dir playwright && \
    playwright install chromium && \
    playwright install-deps chromium && \
    chown -R ghost:ghost /app/.cache

# App code
COPY --chown=ghost:ghost src/ /app/src/
COPY --chown=ghost:ghost tests/ /app/tests/

WORKDIR /app
USER ghost

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app
ENV GHOST_PARANOIA=cautious
ENV GHOST_MIN_DELAY=2.0

ENTRYPOINT ["tini", "--"]
CMD ["python3", "-m", "src"]

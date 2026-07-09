ARG ACR_SERVER=ghostmcp-base
FROM ${ACR_SERVER}:latest

# Build metadata (injected by build-ghostmcp.sh)
ARG GIT_COMMIT=unknown
ARG GIT_BRANCH=unknown
ARG BUILD_TIME=unknown
ARG CACHE_BUST=0
ENV GHOST_GIT_COMMIT=$GIT_COMMIT
ENV GHOST_GIT_BRANCH=$GIT_BRANCH
ENV GHOST_BUILD_TIME=$BUILD_TIME

# App code — this is the only layer that changes on every build
COPY --chown=ghost:ghost ghostmcp/ /app/ghostmcp/
COPY --chown=ghost:ghost tests/ /app/tests/

WORKDIR /app

ENV GHOST_PARANOIA=cautious
ENV GHOST_MIN_DELAY=2.0

# Expose SSH + HTTP health
EXPOSE 22 8080

ENTRYPOINT ["tini", "--"]
CMD ["/bin/bash", "-c", "ssh-keygen -A 2>/dev/null; /usr/sbin/sshd; exec python3 -m ghostmcp"]

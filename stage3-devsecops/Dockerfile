# Stage 3, Task 1: Hardened Security Audit Container
# Kenneth - Cloud Security & DevSecOps Apprentice

# Ubuntu 22.04 LTS base (pinned by major version for reproducibility)
FROM docker.io/library/ubuntu:22.04

LABEL maintainer="Kenneth"
LABEL purpose="SecurityAudit"
LABEL iso27001="A.8.1,A.8.9,A.8.20"
LABEL stage="3"

ENV DEBIAN_FRONTEND=noninteractive \
    IMAGE_NAME="kenneth-security-audit:v1.0.0"

# Minimal packages, explicit upgrade to patch CVEs, then clean caches
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        bash \
        iproute2 \
        net-tools \
        procps \
        findutils \
        ca-certificates && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* /tmp/* /var/tmp/*

# Non-root audit user (ISO 27001 A.5.18)
RUN groupadd -r auditor -g 10001 && \
    useradd -r -u 10001 -g auditor -s /bin/bash -d /app auditor

WORKDIR /app
RUN chown auditor:auditor /app

COPY --chown=auditor:auditor scripts/container_audit.sh ./

USER auditor

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD bash -c "echo '[OK] Audit container healthy'" || exit 1

ENTRYPOINT ["bash", "./container_audit.sh"]

# repo-guard-scanner: offline scanning image. Multi-arch (amd64/arm64).
FROM python:3.12-slim
ARG GITLEAKS_VERSION=8.30.1
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git \
 && rm -rf /var/lib/apt/lists/*
RUN set -eux; a="$(uname -m)"; case "$a" in aarch64) g=arm64;; x86_64) g=x64;; *) exit 1;; esac; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${g}.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks
RUN pip install --no-cache-dir semgrep guarddog
COPY rules /opt/repo-guard/rules
COPY repo_guard.py /opt/repo-guard/repo_guard.py
ENV HOME=/tmp SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off PYTHONDONTWRITEBYTECODE=1
RUN useradd -u 10001 -m scanner
USER 10001
WORKDIR /tmp
ENTRYPOINT ["python3", "/opt/repo-guard/repo_guard.py", "_inner"]

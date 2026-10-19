FROM python:3.13-slim

WORKDIR /app

# Install system dependencies (needed for psycopg2, git, and scanners)
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    git \
    nmap \
    wget \
    curl \
    tar \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Gitleaks
RUN curl -sL https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz -o gitleaks.tar.gz \
    && tar -xzf gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm gitleaks.tar.gz

# Keep scanner dependencies isolated from FastAPI/OpenAI (their telemetry stacks
# have incompatible version constraints). No uploaded configuration is installed.
COPY scanner-requirements.txt .
RUN python -m venv /opt/ase-semgrep \
    && /opt/ase-semgrep/bin/pip install --no-cache-dir -r scanner-requirements.txt \
    && ln -s /opt/ase-semgrep/bin/semgrep /usr/local/bin/semgrep \
    && ln -s /opt/ase-semgrep/bin/pysemgrep /usr/local/bin/pysemgrep

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

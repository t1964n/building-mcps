# Kali MCP Server — Phase 1 image.
#
# Locked decisions (CLAUDE.md §4):
#   * base = kalilinux/kali-rolling
#   * runs as a NON-ROOT user `pentester` (never root)
#   * Phase 1 installs ONLY nmap + tshark; the rest of the roster stays
#     uninstalled on purpose, so list_tools honestly reports it missing.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH

# System deps. tshark/wireshark-common is preseeded to NOT install dumpcap setuid:
# non-root capture is granted at the container level via cap_add (NET_RAW/NET_ADMIN),
# not by a setuid binary in the image.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-venv \
        python3-pip \
        nmap \
        tshark \
    && rm -rf /var/lib/apt/lists/*

# Isolated virtualenv (Kali's system Python is externally managed / PEP 668).
RUN python3 -m venv "$VIRTUAL_ENV"

# Non-root runtime user.
RUN useradd --create-home --shell /bin/bash pentester

WORKDIR /app

# Install Python deps first for layer caching.
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Then the project.
COPY . .

RUN chown -R pentester:pentester /app "$VIRTUAL_ENV"

USER pentester

# stdio MCP server. No port is opened.
CMD ["python", "server.py"]

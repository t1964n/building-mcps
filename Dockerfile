# Kali MCP Server — Phase 1 image.
#
# Locked decisions (CLAUDE.md §4):
#   * base = kalilinux/kali-rolling
#   * runs as a NON-ROOT user `pentester` (never root)
#   * installs only the tools wrapped so far (Phase 1: nmap + tshark;
#     Phase 2 Task 2.3: + masscan); the rest of the roster stays uninstalled on
#     purpose, so list_tools honestly reports it missing.
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
        libcap2-bin \
        nmap \
        tshark \
        masscan \
    && rm -rf /var/lib/apt/lists/*
# libcap2-bin is pulled in transitively today, but we install it EXPLICITLY: the
# raw-socket-caps step below depends on `setcap`, and a transitive dep can vanish
# on any base-image refresh. Make the dependency we rely on visible, not implicit.

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

# --- Grant effective raw-socket caps to tools that ship WITHOUT file-caps -----
# WHY: the container is granted CAP_NET_RAW/CAP_NET_ADMIN in the bounding set
# (docker-compose cap_add, CLAUDE.md §4), but a non-root process only actually
# RECEIVES a cap if the binary's file-caps ask for it (+eip). nmap works non-root
# for free because /usr/lib/nmap/nmap already ships `cap_net_raw=eip`; dumpcap
# (which tshark forks to do the real capture) ships with NO file-caps, so tshark
# capture FAILED for `pentester` in Phase 1. This step closes that gap and is the
# general pattern for every raw-socket tool that lacks file-caps.
#
# CRITICAL — setcap the REAL ELF, not a wrapper (the nmap lesson): /usr/bin/nmap
# is a shell script that execs /usr/lib/nmap/nmap, so the cap must live on the
# ELF, not the shim. dumpcap is itself a real ELF at /usr/bin/dumpcap (verified:
# readlink -f resolves to itself), but we still `readlink -f` every entry so this
# stays correct if a future tool turns out to be a symlink/wrapper. getcap is
# printed BEFORE and AFTER so the change is proven in the build log, not assumed.
#
# REUSABLE: Tasks 2.3/2.4 add masscan/arp-scan — just append their binary paths
# to the list below; do NOT rediscover this caps gap per tool.
#
# DECISION (CLAUDE.md §4): we use DIRECT `setcap ...+eip` on the binary. This is
# acceptable ONLY because this is a SINGLE-USER container — `pentester` is the
# only non-root user, so "any non-root user may raw-capture" == "pentester may
# raw-capture". A MULTI-user image must NOT do this; it would instead restrict
# capture to a `wireshark` group (chgrp wireshark dumpcap && chmod 750 dumpcap)
# so not every account silently inherits CAP_NET_RAW. If this image ever grows
# additional non-root users, switch to the group-restricted approach.
RUN set -eux; \
    for bin in \
        /usr/bin/dumpcap \
        /usr/bin/masscan \
    ; do \
        real="$(readlink -f "$bin")"; \
        before="$(getcap "$real" 2>/dev/null || true)"; \
        echo "raw-socket-caps BEFORE: ${before:-<none> $real}"; \
        setcap cap_net_raw,cap_net_admin+eip "$real"; \
        echo "raw-socket-caps AFTER:  $(getcap "$real")"; \
    done

USER pentester

# stdio MCP server. No port is opened.
CMD ["python", "server.py"]

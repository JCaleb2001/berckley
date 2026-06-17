# berckley dashboard container.
# Uses a Kali base so the scanner's CLI tools (nmap, dig, masscan, nuclei, etc.)
# are available inside the same container that runs the dashboard.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PENTEST_ROOT=/workspace \
    SCANNER_PATH=/workspace/extpentest.sh \
    MGMT_REPORT_PATH=/workspace/nw_report_mgmt.sh \
    SOC_REPORT_PATH=/workspace/nw_report_soc.sh

# Core scanner deps. The scanner gracefully skips tools that are missing,
# so this is a "best-effort" core set — extend as needed.
# Pin to kali.download (CloudFlare-fronted, more reliable than http.kali.org
# round-robin which occasionally serves 404s mid-mirror-sync).
RUN echo 'deb https://kali.download/kali kali-rolling main contrib non-free non-free-firmware' \
      > /etc/apt/sources.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends --fix-missing \
      python3 python3-pip python3-venv \
      bash curl wget jq ca-certificates \
      dnsutils whois nmap masscan snmp \
      openssl libssl-dev \
      git unzip \
      golang-go \
 && apt-get install -y --no-install-recommends --fix-missing \
      sslscan testssl.sh ssh-audit \
      wafw00f ffuf nikto \
 && apt-get install -y --no-install-recommends --fix-missing \
      chromium \
 && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery toolchain: nuclei + subfinder (passive subdomain enum) +
# httpx (live host probe). All compiled from source via go install; binaries
# end up in /root/go/bin and we promote them to /usr/local/bin for PATH.
RUN set -eux; \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest    || echo "nuclei skipped"; \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || echo "subfinder skipped"; \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest         || echo "httpx skipped"; \
    for b in nuclei subfinder httpx; do \
      [ -f "/root/go/bin/$b" ] && cp "/root/go/bin/$b" "/usr/local/bin/$b" || true; \
    done; \
    nuclei -version  2>/dev/null | head -1 || true; \
    subfinder -version 2>/dev/null | head -1 || true; \
    httpx -version   2>/dev/null | head -1 || true

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY app.py validator.py ownership.py suppressions.py diff.py report_extras.py intake.py risk.py asset_tags.py screenshots.py taxonomy.py scorecard.py ./
COPY static ./static

EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]

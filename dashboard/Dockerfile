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
 && apt-get install -y --no-install-recommends --fix-missing \
      seclists \
 && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery toolchain + discovery extras: nuclei, subfinder (passive
# subdomain enum), httpx (live host probe), dnsx (DNS brute/resolve with a
# resolver pool + wildcard filtering), gotator (subdomain permutations), and
# gau (historical URLs from wayback/otx/commoncrawl). All compiled via go
# install into /root/go/bin and promoted to /usr/local/bin for PATH.
RUN set -eux; \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest    || echo "nuclei skipped"; \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || echo "subfinder skipped"; \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest         || echo "httpx skipped"; \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest           || echo "dnsx skipped"; \
    go install -v github.com/Josue87/gotator@latest                         || echo "gotator skipped"; \
    go install -v github.com/lc/gau/v2/cmd/gau@latest                       || echo "gau skipped"; \
    for b in nuclei subfinder httpx dnsx gotator gau; do \
      [ -f "/root/go/bin/$b" ] && cp "/root/go/bin/$b" "/usr/local/bin/$b" || true; \
    done; \
    nuclei -version  2>/dev/null | head -1 || true; \
    subfinder -version 2>/dev/null | head -1 || true; \
    httpx -version   2>/dev/null | head -1 || true; \
    dnsx -version    2>/dev/null | head -1 || true; \
    gau --version    2>/dev/null | head -1 || true

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY app.py auth.py validator.py ownership.py suppressions.py diff.py report_extras.py intake.py risk.py asset_tags.py screenshots.py taxonomy.py scorecard.py confidence.py evidence.py ./
COPY static ./static

EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]

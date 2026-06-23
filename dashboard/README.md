# Berckley Dashboard

A hacker-styled, single-page console for the `extpentest.sh` scanner. It
reads every `pentest_*` directory in the repo root, parses
`report/findings.tsv` and `assets/discovered.log`, and gives you:

- **Suppliers tab** — passive, outside-in assessment of third parties/vendors.
  Launches the scanner in passive mode (`extpentest.sh -P`): OSINT, DNS/email,
  certificate transparency, passive discovery and browser-level TLS/header checks
  only — **no** brute-force, port-scan, webapp fuzzing, nuclei or auth tests.
  Shows a portfolio table of suppliers with their posture grade (A–F), security
  domains of risk and findings count. `GET /api/suppliers` powers it.
- Severity overview with top categories and most-hit scopes
- **Security-posture score** — a 0–100 grade (A–F) for the whole scan, derived
  from the validated severity profile (`100 − (45·C + 18·H + 6·M + 1.5·L)`,
  floored at 0; ≥1 CRITICAL caps the grade at D, ≥1 HIGH at B). Shown as the
  Overview headline and as a section in the exported reports. The model lives in
  `scorecard.py` (single source of truth for dashboard *and* reports).
- **Security-domain classification** — every finding is grouped into one main
  domain (Network, Cryptography/TLS, Web App, Email/DNS, Cloud, Secrets, Access
  Control); shown as Overview cards, Findings filter chips + row badges, and a
  dedicated section in the exported reports. See [CATEGORIES.md](CATEGORIES.md)
  for the full domain → finding-type distribution. The classifier lives in
  `taxonomy.py` (single source of truth for dashboard *and* reports).
- Filterable findings table
- Asset explorer (subdomains, IPs, Azure tenants, GitHub orgs, etc.)
- Live tail of `report/master.log` over Server-Sent Events
- One-click generation of the management + SOC HTML reports
- "New Scan" form that launches `extpentest.sh` inside the container

## Run with Docker

```bash
cd dashboard
docker compose up --build -d
# → http://127.0.0.1:8080
```

The compose file mounts the repo root at `/workspace`, so:

- Existing scans (`../pentest_*`) appear immediately.
- New scans launched from the UI are written back to the host.
- The scanner script (`../extpentest.sh`) and the two report generators
  are executed inside the container.

The Kali base image ships with the bulk of the scanner's CLI tools
(`nmap`, `masscan`, `dig`, `whois`, `curl`, `jq`, `openssl`, `nuclei`).
The scanner gracefully skips anything it can't find on `PATH`, so the
dashboard works even with a partial toolchain.

## Run without Docker (dev mode)

```bash
cd dashboard
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
PENTEST_ROOT=$(realpath ..) \
SCANNER_PATH=$(realpath ../extpentest.sh) \
MGMT_REPORT_PATH=$(realpath ../nw_report_mgmt.sh) \
SOC_REPORT_PATH=$(realpath ../nw_report_soc.sh) \
uvicorn app:app --host 127.0.0.1 --port 8080 --reload
```

## Tests

A regression corpus guards the false-positive logic (confidence bands, the
security-domain taxonomy, the posture score, and the validator re-probe rules).
Network is mocked, so the suite is offline and fast:

```bash
cd dashboard
pip install -r requirements-dev.txt
pytest            # tests/
```

## API surface

| Method | Path                                       | Purpose                          |
|--------|--------------------------------------------|----------------------------------|
| GET    | `/api/health`                              | Backend status                   |
| GET    | `/api/scans`                               | List of scans + severity counts  |
| GET    | `/api/scans/{name}/summary`                | Severity counts, top cats/scopes, `domain_counts`, `scorecard` (score + grade) |
| GET    | `/api/scans/{name}/findings`               | Filtered findings (`q`, `severity`, `owner_class`, `domain`); each row carries its `domain`, plus `domains_available` |
| GET    | `/api/scans/{name}/assets`                 | Discovered assets (by type)      |
| GET    | `/api/scans/{name}/log?tail=N`             | Snapshot of `master.log` tail    |
| GET    | `/api/scans/{name}/log/stream`             | SSE — live `master.log` lines    |
| POST   | `/api/scans`                               | Launch a new scan                |
| POST   | `/api/scans/{name}/stop`                   | Send SIGTERM to scan process     |
| POST   | `/api/scans/{name}/reports/{mgmt|soc}`     | Generate HTML report             |
| GET    | `/api/scans/{name}/reports/{mgmt|soc}`     | View generated report            |

# Dashboard finding categories (security domains)

Every finding the scanner emits is classified into exactly **one** top-level *security domain* by `dashboard/taxonomy.py` — the single source of truth used by both the live dashboard (Overview cards, Findings filter chips + badges) and the exported HTML/PDF reports ("Findings by Security Domain" section).

Membership is single and deterministic: domains are evaluated in the order below and the **first** one whose keyword rules match wins. `Network & Infrastructure` is the catch-all default; `Other` only appears if a finding matches nothing (it never does for current scanner output).

_Distribution below covers all 261 distinct finding titles the scanner can emit (regenerate after editing the rules — see the snippet at the bottom)._

| # | Domain | Color | Finding types |
|---|--------|-------|---------------|
| 1 | ✉ **Email & DNS Security** | `#c792ea` | 20 |
| 2 | ☁ **Cloud & Storage Exposure** | `#4fc3f7` | 13 |
| 3 | 🔑 **Secrets & Info Disclosure** | `#ffb74d` | 29 |
| 4 | 🔒 **Cryptography & TLS** | `#69f0ae` | 42 |
| 5 | 🛡 **Access Control & Auth** | `#ff5fa2` | 39 |
| 6 | 🌐 **Web Application Security** | `#5c9dff` | 43 |
| 7 | 🖧 **Network & Infrastructure** | `#b0bec5` | 75 |

## ✉ Email & DNS Security  ·  `#c792ea`  ·  20 types

- BIMI Record Missing VMC Authority Tag
- CAA Missing iodef Contact
- CAA Missing issuewild Restriction
- CAA Uses Wildcard Issuer
- DMARC Policy Not Enforced
- DMARC Subdomain Policy Too Lax
- DNS CAA Record Missing
- DNS Zone Transfer
- DNSSEC NSEC Zone Walk Possible
- DNSSEC Not Enabled
- Dangling DNS / Subdomain Takeover
- Lookalike/Typosquatting Domains Registered
- MX Points to Cloud Provider
- MX Record Points to Unresolvable Host
- No DMARC Record
- No SPF Record
- Open DNS Resolver
- Permissive SPF
- Subdomain Takeover
- Wildcard DNS

## ☁ Cloud & Storage Exposure  ·  `#4fc3f7`  ·  13 types

- Azure AD User Enumeration Possible
- Azure Blob Storage Account Listable
- Azure SAS Token Exposed in Page Source
- Azure Storage Account Exists
- Cloud Storage Reference in Page Source
- DigitalOcean Space Publicly Listable
- Firebase Realtime Database Publicly Readable
- GCP Storage Reference in Page Source
- GCS Bucket Exists (Private)
- GCS Bucket Publicly Listable
- S3 Bucket Exists (Private)
- S3 Bucket Publicly Listable
- SSRF to Cloud Metadata

## 🔑 Secrets & Info Disclosure  ·  `#ffb74d`  ·  29 types

- API Documentation Exposed
- AWS Access Key Leaked in JavaScript
- Analytics Tracking ID Found
- Database/Backup File Exposed
- Debug/OIDC Endpoint Exposed
- Dependency Confusion Risk
- Dependency Manifest Exposed
- Directory Listing Enabled
- Domain Found in Breach Database (HIBP)
- Domain Referenced in Paste Sites
- GitHub Personal Access Token in JavaScript
- Google API Key in JavaScript
- Historical Sensitive URLs
- IIS .Trace.axd Exposed
- IPv6 Address Exposed
- Infrastructure File Exposed
- JWT Token Embedded in JavaScript
- JavaScript Source Map Exposed
- PHP Info / Adminer Exposed
- Potential Secret Reference in JavaScript
- Potential Secrets in GitHub Public Repos
- Sensitive Config Exposed
- Sensitive File Exposed
- Sensitive Path Found by Crawler
- Slack Token Leaked in JavaScript
- Stripe Live Secret Key in JavaScript
- Technology Disclosure via Response Headers
- Verbose Error / Stack Trace Disclosure
- robots.txt Reveals Sensitive Paths

## 🔒 Cryptography & TLS  ·  `#69f0ae`  ·  42 types

- 3DES Cipher Accepted (Sweet32)
- Anonymous Diffie-Hellman Cipher Accepted
- Certificate Expiring Soon
- Certificate Hostname Mismatch
- Certificate Lifetime Exceeds CABForum Limit
- Cipher Uses MD5 MAC
- EXPORT-Grade Cipher Accepted
- Expired TLS Certificate
- Heartbleed (CVE-2014-0160)
- JWT Algorithm Deserves Review
- JWT Algorithm None
- JWT No Signature Algorithm
- JWT Using Symmetric Algorithm
- Legacy TLS Protocol Accepted
- NULL Cipher Accepted
- No Certificate Revocation
- OCSP Must-Staple Not Set
- OCSP Stapling Not Configured
- Only CBC Ciphers Accepted (no AEAD)
- RC4 Cipher Accepted
- SSH Configuration Failures (ssh-audit)
- SSH Protocol v1 Enabled
- SSLv2 Protocol Enabled
- SSLv3 Protocol Enabled (POODLE)
- Self-Signed Certificate
- Single-DES Cipher Accepted
- TLS 1.0 Enabled (PCI / BEAST)
- TLS 1.1 Enabled (deprecated)
- TLS 1.3 Not Supported
- TLS Compression Enabled (CRIME)
- TLS Fallback SCSV Not Supported
- Untrusted Certificate Chain
- Weak Certificate Signature Algorithm
- Weak DH Parameters (${_dhlow}-bit)
- Weak EC Key Size
- Weak RSA Key Size
- Weak SSH Cipher Advertised
- Weak SSH Host Key Algorithm
- Weak SSH Key Exchange (SHA1 / Group1)
- Weak SSH MAC Algorithm
- Weak TLS Cipher Suite
- Wildcard Certificate Covers Public Suffix

## 🛡 Access Control & Auth  ·  `#ff5fa2`  ·  39 types

- 403 Access Control Bypass
- 403 Header Injection Bypass
- Admin Panel Exposed (No Auth)
- CouchDB Database List Anonymously Readable
- Default Credentials Accepted
- Default Credentials: Grafana
- Default Credentials: Portainer
- Docker API Unauthenticated
- Docker Registry Catalog Anonymously Listable
- Docker Registry Unauthenticated
- Elasticsearch Exposed (No Auth)
- Elasticsearch Unauthenticated
- FTP Anonymous Login
- Jenkins User Enumeration
- Kibana Unauthenticated Access
- Kubernetes API Anonymously Accessible
- Kubernetes API Server Unauthenticated
- Kubernetes Kubelet Unauthenticated
- LDAP Anonymous Bind Allowed
- Memcached Exposed (No Auth)
- Memcached Unauthenticated
- No Rate Limiting on Login Endpoint
- Open SMTP Relay
- Outdated OpenSSH (CVE-2018-15473 user enum + EoL)
- Portainer Uninitialized
- RD Web Access Login Exposed with Internal AD Disclosure
- Redis Exposed (No Auth)
- Redis Unauthenticated
- SMB Null Session
- SMB Null Session — Share List Exposed
- SMTP EXPN Enabled
- SMTP VRFY User Enumeration
- SNMP Community 'public' Accessible
- SNMP Community String Accessible
- SNMP v3 NoAuth Accepted
- User Account Enumeration via Login Error
- VNC No Authentication
- WebSocket Endpoint Detected (No Auth in URL)
- etcd Cluster Unauthenticated

## 🌐 Web Application Security  ·  `#5c9dff`  ·  43 types

- CORS Credentials + Wildcard
- CORS Null Origin Reflected
- CORS Null Origin with Credentials
- CORS Origin Reflection with Credentials
- CSP Missing default-src Directive
- CSP unsafe-inline / unsafe-eval
- Cookie Missing HttpOnly Flag
- Cookie Missing SameSite Attribute
- Cookie Missing Secure Flag
- Cookie SameSite=None Without Secure
- GraphQL Endpoint Exposed
- GraphQL Introspection Enabled
- HSTS Missing includeSubDomains
- HSTS Missing preload Directive
- HSTS max-age Below 1 Year
- HTTP DELETE Method Allowed
- HTTP PUT Method Allowed
- HTTP TRACE Enabled
- Host Header Injection
- Missing Content-Security-Policy
- Missing Cross-Origin-Opener-Policy
- Missing HSTS (HTTP Strict Transport Security)
- Missing Permissions-Policy
- Missing Referrer-Policy
- Missing Subresource Integrity (SRI)
- Missing X-Content-Type-Options
- Missing X-Frame-Options
- Missing security.txt
- Mixed Content: HTTP Script on HTTPS Page
- No HTTP to HTTPS Redirect
- Open Redirect
- Path Traversal / Directory Traversal
- Permissive Cross-Domain Policy
- Potentially Cacheable Authenticated Response
- Prototype Pollution
- Reflected XSS Indicator
- SQL Injection Indicator
- Server-Side Template Injection (SSTI)
- Virtual Hosts Discovered
- WAF Detected
- Web Cache Poisoning
- XML-Consuming Endpoint Detected
- security.txt Missing Contact Field

## 🖧 Network & Infrastructure  ·  `#b0bec5`  ·  75 types

- ActiveMQ Exposed
- Apache 2.2.x End-of-Life
- Apache 2.4.49/50 RCE (CVE-2021-41773 / 42013)
- Apache Tomcat EoL Series (<9)
- Apache httpd Outdated
- Check Point SSL VPN Detected
- Cisco IOS XE Web UI Exposed
- Citrix Gateway Detected
- Confirmed CVE: $_dcve
- CouchDB Welcome Endpoint Exposed
- Docker Daemon Socket Exposed (2375)
- Docker Registry Detected (Auth Required)
- Docker Registry v2 Exposed
- Domain Behind CloudFlare
- Domain Expiry
- Elasticsearch Exposed
- Exim Below 4.92 (CVE-2019-10149)
- FTP Exposed
- Fortinet FortiGate SSL-VPN Exposed
- GitLab Instance Exposed
- GitLab Public Projects API
- HTTP Proxy Exposed
- Harbor Registry API Reachable
- IIS Tilde (~) Enumeration Possible
- IIS aspnet_client Folder Exposed
- IKE/IPsec VPN Endpoint Exposed
- Ivanti Connect Secure VPN Exposed
- Jenkins Script Console Exposed
- JetBrains TeamCity Exposed
- Juniper SSL VPN Detected
- Kibana Dashboard Exposed
- Kubelet Read-only API Exposed (10255)
- Kubelet Write API Exposed (10250)
- Kubernetes API Exposed to Internet
- Kubernetes API Server Exposed (Auth Required)
- Legacy / End-of-Life Microsoft IIS
- MOVEit Transfer Exposed
- Microsoft Dynamics NAV / BC Web Server Exposed
- Microsoft Exchange OWA Exposed
- Microsoft IIS End-of-Life Version
- MongoDB Exposed
- MongoDB Exposed on Default Port
- MySQL/MariaDB Exposed
- NFS Export World-Readable
- NFS Exports Visible
- NFS Exposed
- Nuclei: ${_label}
- OpenSSH 8.x Below 8.7
- OpenSSL 1.0.x End-of-Life
- OpenSSL 1.1.x End-of-Life
- PHP End-of-Life Branch
- Palo Alto GlobalProtect VPN Exposed
- Panel Redirects to Unknown External Auth
- PaperCut NG/MF Exposed
- PostgreSQL Exposed
- ProFTPD Version Detected
- RPC Portmapper Exposed
- RabbitMQ AMQP Exposed
- RabbitMQ Management UI Exposed
- Redis Exposed
- RethinkDB Admin UI Exposed
- SAP Fiori Launchpad Detected
- SAP ICM Ping Accessible
- SAP SOAP RFC Service Exposed
- SMB Insecure Configuration
- Searchsploit Exploit Matches
- Shodan CVE
- SonicWall SSL-VPN Detected
- Spring Boot Actuator Exposed
- Telnet Exposed
- VNC Exposed
- Version Match: $_dcve
- etcd Client API Exposed (2379)
- nginx Below 1.20 (mainline EoL)
- vsftpd 2.3.4 Backdoor

## Regenerating this table

```bash
cd dashboard
python3 - <<'PY'
import subprocess, collections, taxonomy
out = subprocess.run(r'''grep -oE 'finding +(CRITICAL|HIGH|MEDIUM|LOW|INFO) +"[^"]+"' ../extpentest.sh | sed -E 's/finding +[A-Z]+ +"([^"]+)"/\1/' ''', shell=True, capture_output=True, text=True).stdout
by = collections.defaultdict(list)
for t in sorted(set(out.split(chr(10)))):
    if t.strip(): by[taxonomy.classify(t)].append(t)
for d in taxonomy.iter_domains():
    if by.get(d['slug']): print(d['label'], len(by[d['slug']]))
PY
```
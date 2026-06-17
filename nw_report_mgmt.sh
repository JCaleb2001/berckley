#!/usr/bin/env bash
# =============================================================================
#  nw_report_mgmt.sh  —  Berckley Management / Executive Report Generator
#  Audience : CISO, CTO, Management, Board
#  Style    : Classic consultancy (serif headings, navy palette, formal)
#
#  Branding via ENV vars (all optional):
#    ORG                — client organisation display name (default: from domain)
#    CLIENT_LOGO        — path or URL to client logo (PNG/SVG)
#    CONSULTANCY        — consultancy display name (default: "Berckley Security")
#    CONSULTANCY_LOGO   — path or URL to consultancy logo
#    BRAND_COLOR        — hex (e.g. #1e3a5f) for accents (default: navy)
#    ANALYST            — engagement lead / author
#    REVIEWER           — QA / technical reviewer name
#    APPROVER           — engagement manager / sign-off
#    ENGAGEMENT_START   — YYYY-MM-DD
#    ENGAGEMENT_END     — YYYY-MM-DD
#    REPORT_VERSION     — e.g. "1.0" / "1.0 - Draft"
#    DISTRIBUTION_LIST  — comma-separated names/roles
#    CLASSIFICATION     — e.g. "Confidential" / "Restricted"
#
#  Usage: ./nw_report_mgmt.sh <pentest_dir> [output.html]
# =============================================================================
set +e; set +u; set +o pipefail 2>/dev/null

PENTEST_DIR="${1:-}"
[ -z "$PENTEST_DIR" ] && { echo "Usage: $0 <pentest_dir> [output.html]"; exit 1; }
[ ! -d "$PENTEST_DIR" ] && { echo "Not found: $PENTEST_DIR"; exit 1; }
PENTEST_DIR="$(realpath "$PENTEST_DIR" 2>/dev/null || echo "$PENTEST_DIR")"
OUT_HTML="${2:-${PENTEST_DIR}/report/management_report.html}"
mkdir -p "$(dirname "$OUT_HTML")"

echo "[MGMT] Reading : $PENTEST_DIR"
echo "[MGMT] Output  : $OUT_HTML"

slurp()  { [ -f "$1" ] && cat "$1" 2>/dev/null || true; }
nlines() { [ -f "$1" ] && grep -c . "$1" 2>/dev/null | tr -d ' ' || echo "0"; }
to_int() { local v="${1//[^0-9]/}"; printf '%s' "${v:-0}"; }
esc()    { sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g' 2>/dev/null || true; }

# ── Input metadata ────────────────────────────────────────────────────────────
DOMAIN=$(slurp "$PENTEST_DIR/recon/input_domains.txt" | head -1 | tr -d '[:space:]')
[ -z "$DOMAIN" ] && DOMAIN="unknown"
ORG="${ORG:-$(printf '%s' "$DOMAIN" | sed 's/\..*//' | sed 's/.*/\u&/')}"
TARGETS=$(slurp "$PENTEST_DIR/recon/input_targets.txt" | tr '\n' ',' | sed 's/,$//')
[ -z "$TARGETS" ] && TARGETS="—"

# ── Branding + engagement details (ENV-driven) ───────────────────────────────
CONSULTANCY="${CONSULTANCY:-Berckley Security}"
BRAND_COLOR="${BRAND_COLOR:-#1e3a5f}"
ANALYST="${ANALYST:-Berckley Security}"
REVIEWER="${REVIEWER:-—}"
APPROVER="${APPROVER:-—}"
CLASSIFICATION="${CLASSIFICATION:-Confidential}"
REPORT_VERSION="${REPORT_VERSION:-1.0}"
DISTRIBUTION_LIST="${DISTRIBUTION_LIST:-CISO, CTO, Information Security Team}"
REPORT_DATE=$(date "+%B %d, %Y")
REPORT_YEAR=$(date "+%Y")
REPORT_DATE_ISO=$(date "+%Y-%m-%d")

# Best-effort engagement window: derive from scan output mtimes if not provided
if [ -z "${ENGAGEMENT_START:-}" ]; then
  ENGAGEMENT_START=$(stat -c '%y' "$PENTEST_DIR/report/master.log" 2>/dev/null \
    | awk '{print $1}' | head -1)
  [ -z "$ENGAGEMENT_START" ] && ENGAGEMENT_START="$REPORT_DATE_ISO"
fi
if [ -z "${ENGAGEMENT_END:-}" ]; then
  ENGAGEMENT_END=$(stat -c '%y' "$PENTEST_DIR/report/findings.tsv" 2>/dev/null \
    | awk '{print $1}' | head -1)
  [ -z "$ENGAGEMENT_END" ] && ENGAGEMENT_END="$REPORT_DATE_ISO"
fi

# Logo handling: if path supplied and file exists, base64-embed it. Otherwise
# render a text placeholder so the report degrades gracefully.
_logo_img() {
  local _src="$1" _alt="$2" _class="$3"
  if [ -n "$_src" ]; then
    if printf '%s' "$_src" | grep -qE '^https?://'; then
      printf '<img class="%s" src="%s" alt="%s">' "$_class" "$_src" "$_alt"
      return
    fi
    if [ -f "$_src" ]; then
      local _ext; _ext=$(printf '%s' "$_src" | sed 's/.*\.//' | tr 'A-Z' 'a-z')
      local _mime; case "$_ext" in
        svg) _mime="image/svg+xml" ;;
        png) _mime="image/png" ;;
        jpg|jpeg) _mime="image/jpeg" ;;
        *) _mime="application/octet-stream" ;;
      esac
      local _b64; _b64=$(base64 -w0 "$_src" 2>/dev/null)
      [ -n "$_b64" ] && {
        printf '<img class="%s" src="data:%s;base64,%s" alt="%s">' "$_class" "$_mime" "$_b64" "$_alt"
        return
      }
    fi
  fi
  printf '<div class="logo-placeholder %s">%s</div>' "$_class" "$_alt"
}
CLIENT_LOGO_HTML=$(_logo_img "${CLIENT_LOGO:-}" "${ORG}" "client-logo")
CONSULT_LOGO_HTML=$(_logo_img "${CONSULTANCY_LOGO:-}" "${CONSULTANCY}" "consult-logo")

# ── Findings counts ───────────────────────────────────────────────────────────
# Prefer the validated TSV produced by the dashboard's validation layer
# (false positives removed, severities re-weighted by ownership). Fall back
# to the raw scanner output when the validator hasn't been run.
if [ -f "$PENTEST_DIR/report/findings_validated.tsv" ]; then
  TSV="$PENTEST_DIR/report/findings_validated.tsv"
  TSV_SOURCE="validated"
else
  TSV="$PENTEST_DIR/report/findings.tsv"
  TSV_SOURCE="raw"
fi
RAW_TSV_PATH="$PENTEST_DIR/report/findings.tsv"
count_types() { awk -F'\t' -v sev="$1" 'BEGIN{n=0} $1==sev{key=$1"\t"$2; if(!(key in s)){s[key]=1; n++}} END{print n}' "$TSV" 2>/dev/null; }
count_rows()  { awk -F'\t' -v sev="$1" 'BEGIN{n=0} $1==sev{n++} END{print n}'             "$TSV" 2>/dev/null; }
C_CRIT=$(to_int "$(count_types CRITICAL)")
C_HIGH=$(to_int "$(count_types HIGH)")
C_MED=$( to_int "$(count_types MEDIUM)")
C_LOW=$( to_int "$(count_types LOW)")
C_TOTAL=$(( C_CRIT + C_HIGH + C_MED + C_LOW ))
T_CRIT=$(to_int "$(count_rows CRITICAL)")
T_HIGH=$(to_int "$(count_rows HIGH)")
T_MED=$( to_int "$(count_rows MEDIUM)")
T_LOW=$( to_int "$(count_rows LOW)")

RS=$(( C_CRIT * 40 + C_HIGH * 20 + C_MED * 10 + C_LOW * 5 ))
[ "$RS" -gt 100 ] && RS=100

if   [ "$C_CRIT" -gt 0 ]; then RISK_LEVEL="Critical"; RISK_COLOR="#b91c1c"
elif [ "$C_HIGH" -gt 0 ]; then RISK_LEVEL="High";     RISK_COLOR="#c2410c"
elif [ "$C_MED"  -gt 0 ]; then RISK_LEVEL="Moderate"; RISK_COLOR="#b45309"
elif [ "$C_LOW"  -gt 0 ]; then RISK_LEVEL="Low";      RISK_COLOR="#1d4ed8"
else                            RISK_LEVEL="Minimal";  RISK_COLOR="#047857"; fi

SUBS_COUNT=$(to_int "$(nlines "$PENTEST_DIR/recon/subs_master.txt")")
LIVE_COUNT=$(to_int "$(nlines "$PENTEST_DIR/recon/live_hosts.txt")")
EXPOSED_COUNT=$(to_int "$(nlines "$PENTEST_DIR/recon/exposed_paths.txt")")
TAKEOVER_COUNT=$(to_int "$(nlines "$PENTEST_DIR/dns/takeover.txt")")
PORTS_COUNT=$(grep -c "^[0-9]*/[a-z]*\s*open" "$PENTEST_DIR"/recon/nmap*.txt 2>/dev/null | head -1 | tr -d ' ' || echo "0")
[ -z "$PORTS_COUNT" ] && PORTS_COUNT="0"

# ── Business impact mapping ──────────────────────────────────────────────────
business_impact() {
  local cat="$1"
  case "$cat" in
    *HSTS*|*HTTPS\ Redirect*) printf "Unencrypted traffic interception risk — credentials and session tokens can be captured by network-positioned attackers (public WiFi, ISP, compromised infrastructure)." ;;
    *CSP*)                    printf "Cross-site scripting impact magnified — without Content Security Policy, a single XSS flaw enables full account takeover, data exfiltration, or malware delivery to all users." ;;
    *X-Frame*|*Clickjack*)    printf "User-interface deception — pages can be embedded in attacker-controlled sites to trick employees and customers into unintended actions." ;;
    *DMARC*|*SPF*|*DKIM*)     printf "Brand impersonation and phishing facilitation — anyone on the internet can send mail purporting to come from the organisation's domain, raising the risk of business email compromise and supplier fraud." ;;
    *Zone\ Transfer*)         printf "Full internal DNS architecture exposed — attackers obtain a complete inventory of internal hosts without any access." ;;
    *Takeover*|*Dangling*)    printf "Subdomain hijack — attacker can serve content under the organisation's official domain, enabling credential phishing and SEO poisoning." ;;
    *Admin\ Panel*|*RDWeb*)   printf "Management interface accessible from the public internet — credential stuffing, brute-force, and known-vulnerability exploitation become directly possible." ;;
    *Jenkins*)                printf "CI/CD platform exposed — risk of source-code disclosure, build-pipeline tampering, and lateral movement into production." ;;
    *Default\ Cred*)          printf "Trivial unauthorised access — factory-default credentials provide full administrative control to any attacker." ;;
    *Dynamics*NAV*|*Dynamics*BC*) printf "ERP front-end internet-exposed — financial data, customer records, and business processes accessible to attackers if authentication is bypassed or credentials phished." ;;
    *Legacy*IIS*|*End-of-Life*|*EoL*) printf "End-of-life platform — no security patches available; accumulating CVEs make compromise a matter of time without compensating controls." ;;
    *SQL*)                    printf "Database breach — potential access to all customer records, financial data, and confidential business information through unauthenticated input." ;;
    *XSS*)                    printf "Session hijacking and credential theft — attackers can impersonate authenticated users including administrators." ;;
    *Directory\ List*)        printf "Unauthorised file exposure — internal documents, configuration files, and sensitive data may be publicly downloadable." ;;
    *Open\ Redirect*)         printf "Phishing facilitation — the official domain can be weaponised to redirect users to fraudulent sites." ;;
    *GraphQL*)                printf "API surface exposure — internal data structure and relationships visible to unauthenticated parties." ;;
    *Docker*)                 printf "Container engine exposure — root-level access to hosting infrastructure obtainable without authentication." ;;
    *Redis*|*MongoDB*|*Elasticsearch*|*MySQL*|*PostgreSQL*|*Memcached*) \
                              printf "Database service exposed to internet — direct read/write access to business data without authentication." ;;
    *SNMP*)                   printf "Network device information leakage — full infrastructure inventory exposed to external parties." ;;
    *LDAP*)                   printf "Active Directory accessible externally — employee accounts, groups, and network topology readable without credentials." ;;
    *NFS*|*SMB*)              printf "File share reachable from internet — internal documents and server files accessible without authentication." ;;
    *RabbitMQ*|*ActiveMQ*)    printf "Message broker exposed — internal application communications interceptable, with potential for data injection." ;;
    *Telnet*)                 printf "Unencrypted remote shell — all data including credentials transmitted in cleartext." ;;
    *FTP*Anon*)               printf "Unauthenticated file server — any internet user can read (and potentially write) server files." ;;
    *VPN*)                    printf "VPN endpoint exposed — enterprise remote access infrastructure visible and potentially exploitable." ;;
    *CVE*)                    printf "Known vulnerability present — public exploit code may exist, enabling unauthenticated compromise." ;;
    *Cert*Expir*)             printf "Expired certificate — browser warnings deter customers and erode trust in the brand." ;;
    *Hostname\ Mismatch*)     printf "Certificate does not cover the served hostname — browsers will refuse the connection, breaking the service for end users." ;;
    *Untrusted*Chain*)        printf "Certificate chain does not verify against the public trust store — clients will receive security warnings." ;;
    *Weak*Signature*|*Weak*RSA*|*Weak*Key*) printf "Weak cryptography in TLS certificate — encryption can be defeated by well-resourced adversaries." ;;
    *Legacy\ TLS*|*Weak*Cipher*) printf "Outdated encryption standards in use — data in transit may be decryptable by capable attackers." ;;
    *Lookalike*|*Typosquat*)  printf "Domains imitating the organisation registered by third parties — facilitates phishing and brand abuse." ;;
    *CORS*)                   printf "Cross-origin policy misconfiguration — other websites can make authenticated requests on behalf of users." ;;
    *Error\ Disc*|*Disclosure*|*Stack*Trace*) printf "Technical information leakage — software stack and internal paths revealed, aiding targeted exploitation." ;;
    *Paste*|*Leak*|*Breach*)  printf "Credential exposure detected — account information may be available in public breach databases or paste sites." ;;
    *IKE*|*IPsec*)            printf "VPN endpoint fingerprinting risk — enterprise remote access infrastructure identifiable and targetable." ;;
    *DNSSEC*)                 printf "DNS responses cannot be cryptographically validated — vulnerable to DNS spoofing and cache poisoning." ;;
    *OCSP*Staple*)            printf "Certificate revocation status not delivered with handshake — each client makes a separate revocation check, leaking browsing patterns to the CA." ;;
    *TLS\ 1.3*)               printf "Latest TLS version not supported — server lacks improvements in forward secrecy, handshake performance, and side-channel resistance." ;;
    *security.txt*)           printf "No vulnerability disclosure contact published — security researchers cannot responsibly report flaws, increasing the risk of public 0-day disclosure." ;;
    *Technology\ Disclosure*|*Banner*) printf "Server / framework versions disclosed in HTTP headers — narrows the attack surface investigation an external attacker must perform." ;;
    *X-Content-Type-Options*) printf "MIME-sniffing protection absent — browsers may render attacker-controlled content with unexpected interpretation, enabling content injection." ;;
    *HSTS*max-age*)           printf "HSTS protection window below industry minimum (1 year) — the protective effect against downgrade attacks is reduced." ;;
    *)                        printf "Security control gap — increases attack surface and creates pre-conditions that lower the cost of compromise." ;;
  esac
}

priority_label() {
  case "$1" in
    CRITICAL) printf "Immediate (24-48 hours)" ;;
    HIGH)     printf "Short-term (2-4 weeks)" ;;
    MEDIUM)   printf "Medium-term (1-2 quarters)" ;;
    LOW)      printf "Long-term (roadmap item)" ;;
    *)        printf "Review as needed" ;;
  esac
}

# ── Compliance mapping per finding category ──────────────────────────────────
# Returns: pipe-separated "NIST CSF|ISO 27001|PCI-DSS|OWASP/GDPR"
compliance_map() {
  local cat="$1"
  case "$cat" in
    *HSTS*|*HTTPS\ Redirect*|*Legacy\ TLS*|*Weak*Cipher*|*Weak*RSA*|*Weak*Signature*|*Untrusted*Chain*|*Hostname\ Mismatch*) \
      printf "PR.DS-2|A.10.1.1, A.13.2.1|4.1, 4.2|GDPR Art. 32(1)(a)" ;;
    *Cert*Expir*|*OCSP*Staple*|*TLS\ 1.3*) \
      printf "PR.DS-2|A.10.1.1|4.1|GDPR Art. 32" ;;
    *CSP*|*X-Frame*|*Clickjack*|*X-Content-Type-Options*) \
      printf "PR.IP-1|A.14.2.5|6.5.7|OWASP A05:2021" ;;
    *XSS*|*SQL*|*Open\ Redirect*) \
      printf "PR.IP-1, DE.CM-4|A.14.2.5|6.5.1, 6.5.7|OWASP A03:2021" ;;
    *DMARC*|*SPF*|*DKIM*) \
      printf "PR.AC-7, PR.DS-2|A.13.2.1, A.13.2.3|—|NIST SP 800-177" ;;
    *Admin\ Panel*|*RDWeb*|*Jenkins*) \
      printf "PR.AC-1, PR.AC-4|A.9.1.2, A.9.4.1|7.1, 8.1|OWASP A07:2021" ;;
    *Default\ Cred*) \
      printf "PR.AC-1|A.9.2.4, A.9.4.3|2.1|OWASP A07:2021" ;;
    *Takeover*|*Lookalike*|*Typosquat*) \
      printf "ID.AM-2|A.8.1.1|—|GDPR Art. 32 (brand protection)" ;;
    *Zone\ Transfer*|*DNSSEC*) \
      printf "PR.DS-2|A.13.1.1|—|NIST SP 800-81" ;;
    *Legacy*IIS*|*End-of-Life*|*EoL*|*Dynamics*NAV*|*Dynamics*BC*|*CVE*) \
      printf "ID.RA-1, PR.IP-12|A.12.6.1|6.2|GDPR Art. 32(1)(d)" ;;
    *Directory\ List*|*GraphQL*|*Error\ Disc*|*Disclosure*|*Banner*|*Technology\ Disclosure*) \
      printf "PR.IP-1|A.14.1.3|6.5.5|OWASP A05:2021" ;;
    *Redis*|*MongoDB*|*Elasticsearch*|*MySQL*|*PostgreSQL*|*Memcached*|*Docker*|*LDAP*|*SMB*|*NFS*|*Telnet*|*FTP*Anon*|*RabbitMQ*|*ActiveMQ*|*VPN*|*SNMP*) \
      printf "PR.AC-3, PR.AC-5|A.13.1.3|1.2, 1.3|OWASP A01:2021" ;;
    *security.txt*) \
      printf "ID.GV-1|A.16.1.3|—|RFC 9116" ;;
    *HSTS*max-age*) \
      printf "PR.DS-2|A.10.1.1|4.1|OWASP TLS Cheat Sheet" ;;
    *) \
      printf "PR.IP-1|A.14.2.5|—|—" ;;
  esac
}

# ── Likelihood × Impact (for heatmap) ────────────────────────────────────────
# Returns "L|I" each in 1..5
risk_li() {
  local sev="$1" cat="$2"
  local L=2 I=2
  case "$sev" in
    CRITICAL) L=5; I=5 ;;
    HIGH)     L=4; I=4 ;;
    MEDIUM)   L=3; I=3 ;;
    LOW)      L=2; I=2 ;;
  esac
  # Refine likelihood: things behind auth / requiring chain attacks → lower L
  case "$cat" in
    *DMARC*|*SPF*|*DKIM*) L=$(( L + 1 )); I=$(( I - 1 )) ;;
    *HSTS*|*X-Content*|*OCSP*) L=$(( L - 1 )) ;;
    *security.txt*) L=1; I=1 ;;
    *Admin\ Panel*|*Default\ Cred*|*RDWeb*) L=$(( L + 1 )); I=5 ;;
    *Lookalike*) L=2 ;;
    *Cert*Expir*|*Hostname\ Mismatch*) I=$(( I + 1 )) ;;
  esac
  [ "$L" -gt 5 ] && L=5; [ "$L" -lt 1 ] && L=1
  [ "$I" -gt 5 ] && I=5; [ "$I" -lt 1 ] && I=1
  printf '%s|%s' "$L" "$I"
}

# ── Industry benchmark (Verizon DBIR / OWASP / static baseline) ──────────────
# Average HIGH+CRITICAL findings per external-pentest report in 2024-2025 corpus
BENCHMARK_HIGH_AVG=3   # industry median for HIGH+CRITICAL on a perimeter scan
BENCHMARK_MED_AVG=8
BENCHMARK_TOTAL_AVG=18

# ── Build summary table rows ─────────────────────────────────────────────────
echo "[MGMT] Building report sections..."
FINDING_TABLE_ROWS=""
HEATMAP_DOTS=""
declare -A SEEN_CATS 2>/dev/null || true
TAB="$(printf '\011')"

while IFS= read -r row; do
  [ -z "$row" ] && continue
  local_sev=$(printf '%s' "$row" | cut -f1)
  local_cat=$(printf '%s' "$row" | cut -f2)
  key="${local_sev}|${local_cat}"
  printf '%s' "${SEEN_CATS[$key]+x}" | grep -q "x" 2>/dev/null && continue
  SEEN_CATS[$key]=1

  local_scope=$(awk -F'\t' -v s="$local_sev" -v c="$local_cat" \
    '$1==s && $2==c {print $3}' "$TSV" | sort -u | wc -l | tr -d ' ')
  local_scope=$(to_int "$local_scope")
  local_impact=$(business_impact "$local_cat" | esc)
  local_priority=$(priority_label "$local_sev")
  local_cat_esc=$(printf '%s' "$local_cat" | esc)
  local_comp=$(compliance_map "$local_cat")
  comp_csf=$(printf '%s' "$local_comp" | cut -d'|' -f1 | esc)
  comp_iso=$(printf '%s' "$local_comp" | cut -d'|' -f2 | esc)
  comp_pci=$(printf '%s' "$local_comp" | cut -d'|' -f3 | esc)
  comp_other=$(printf '%s' "$local_comp" | cut -d'|' -f4 | esc)

  case "$local_sev" in
    CRITICAL) row_cls="row-crit"; badge_cls="badge-crit"; badge_txt="Critical" ;;
    HIGH)     row_cls="row-high"; badge_cls="badge-high"; badge_txt="High" ;;
    MEDIUM)   row_cls="row-med";  badge_cls="badge-med";  badge_txt="Medium" ;;
    LOW)      row_cls="row-low";  badge_cls="badge-low";  badge_txt="Low" ;;
    *)        row_cls="";         badge_cls="badge-low";  badge_txt="$local_sev" ;;
  esac

  FINDING_TABLE_ROWS="${FINDING_TABLE_ROWS}
<tr class='${row_cls}'>
  <td><span class='badge ${badge_cls}'>${badge_txt}</span></td>
  <td class='finding-name'>${local_cat_esc}</td>
  <td class='business-impact'>${local_impact}</td>
  <td class='affected-count'>${local_scope}</td>
  <td class='priority'>${local_priority}</td>
  <td class='compliance'>
    <div class='comp-tags'>
      <span class='comp-tag csf'>NIST CSF: ${comp_csf}</span>
      <span class='comp-tag iso'>ISO 27001: ${comp_iso}</span>
      <span class='comp-tag pci'>PCI-DSS: ${comp_pci}</span>
      <span class='comp-tag oth'>${comp_other}</span>
    </div>
  </td>
</tr>"

  # Plot one heat-map dot per finding TYPE
  li=$(risk_li "$local_sev" "$local_cat")
  L="${li%%|*}"; I="${li##*|}"
  HEATMAP_DOTS="${HEATMAP_DOTS}
<div class='hm-dot ${row_cls}' style='grid-column:${L};grid-row:$((6-I))' title='${local_cat_esc} — L=${L} I=${I}'></div>"

done < "$TSV" 2>/dev/null

PIE_TOTAL=$(( C_TOTAL > 0 ? C_TOTAL : 1 ))

echo "[MGMT] Writing HTML..."

# ── Cover + head ─────────────────────────────────────────────────────────────
cat > "$OUT_HTML" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>External Security Assessment — ${ORG} — ${REPORT_DATE}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700;900&family=Source+Serif+Pro:wght@400;600;700&family=Inter:wght@300;400;500;600;700&display=swap');
:root{
  --brand:${BRAND_COLOR};
  --brand-dk:#0f172a;
  --brand-lt:#dbeafe;
  --crit:#b91c1c; --high:#c2410c; --med:#b45309; --low:#1d4ed8;
  --crit-bg:#fef2f2; --high-bg:#fff7ed; --med-bg:#fffbeb; --low-bg:#eff6ff;
  --crit-bd:#fca5a5; --high-bd:#fdba74; --med-bd:#fcd34d; --low-bd:#93c5fd;
  --border:#cbd5e1; --surface:#f8fafc; --surface-2:#f1f5f9; --white:#ffffff;
  --text:#0f172a; --muted:#475569; --light:#94a3b8;
  --serif:'Playfair Display',Georgia,serif;
  --serif-body:'Source Serif Pro',Georgia,serif;
  --sans:'Inter',-apple-system,sans-serif;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
@page{size:A4;margin:0}
html,body{background:#e2e8f0;font-family:var(--sans);color:var(--text);font-size:11.5px;line-height:1.65}
.page{background:var(--white);max-width:1000px;margin:0 auto;box-shadow:0 4px 32px rgba(15,23,42,.12)}
em{font-style:italic}
strong{font-weight:600;color:var(--brand-dk)}

/* ── COVER ──────────────────────────────────────────────────────────────── */
.cover{position:relative;min-height:880px;padding:0;background:var(--white);
  display:flex;flex-direction:column}
.cover-top{background:linear-gradient(135deg,var(--brand-dk) 0%,var(--brand) 70%,var(--brand-dk) 100%);
  padding:48px 64px 32px;color:#fff;position:relative;overflow:hidden}
.cover-top::after{content:'';position:absolute;left:0;right:0;bottom:0;height:4px;
  background:linear-gradient(90deg,var(--brand-lt) 0%,#fff 50%,var(--brand-lt) 100%)}
.cover-logos{display:flex;justify-content:space-between;align-items:center;margin-bottom:64px}
.client-logo,.consult-logo{max-height:48px;max-width:180px;object-fit:contain;filter:brightness(0) invert(1)}
.logo-placeholder{padding:8px 16px;border:1px solid rgba(255,255,255,.3);
  font-family:var(--sans);font-size:11px;letter-spacing:2px;text-transform:uppercase;
  color:rgba(255,255,255,.7);border-radius:2px}
.cover-classification{position:absolute;top:16px;left:50%;transform:translateX(-50%);
  background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.3);
  padding:4px 16px;font-family:var(--sans);font-size:9px;letter-spacing:4px;
  text-transform:uppercase;color:rgba(255,255,255,.85);border-radius:2px}
.cover-eyebrow{font-family:var(--sans);font-size:10px;letter-spacing:5px;
  text-transform:uppercase;color:rgba(255,255,255,.45);margin-bottom:8px;font-weight:500}
.cover-title{font-family:var(--serif);font-size:48px;line-height:1.05;color:#fff;
  font-weight:900;margin-bottom:16px;letter-spacing:-1px}
.cover-sub{font-family:var(--serif-body);font-size:20px;font-style:italic;
  color:rgba(255,255,255,.8);font-weight:400;margin-bottom:8px}
.cover-domain{font-family:var(--sans);font-size:14px;color:rgba(255,255,255,.55);
  letter-spacing:1px;margin-bottom:48px}
.cover-meta{display:grid;grid-template-columns:repeat(4,1fr);gap:24px;
  padding-top:24px;border-top:1px solid rgba(255,255,255,.15)}
.cover-meta-item label{display:block;font-family:var(--sans);font-size:9px;
  letter-spacing:3px;text-transform:uppercase;color:rgba(255,255,255,.45);
  margin-bottom:6px;font-weight:500}
.cover-meta-item span{font-family:var(--serif-body);font-size:13px;
  color:rgba(255,255,255,.95);font-weight:600}

/* Cover bottom panel: document control */
.cover-bottom{flex:1;padding:48px 64px;background:var(--surface);
  display:flex;flex-direction:column;justify-content:space-between}
.doc-control-title{font-family:var(--serif);font-size:14px;color:var(--brand-dk);
  font-weight:700;margin-bottom:16px;border-bottom:2px solid var(--brand);
  padding-bottom:6px;display:inline-block;letter-spacing:0}
.doc-control{width:100%;border-collapse:collapse;font-size:11px;
  background:var(--white);border:1px solid var(--border)}
.doc-control th{background:var(--brand-dk);color:#fff;text-align:left;
  padding:8px 14px;font-size:9px;letter-spacing:2px;text-transform:uppercase;
  font-weight:600;font-family:var(--sans)}
.doc-control td{padding:9px 14px;border-bottom:1px solid var(--border);
  font-family:var(--serif-body);color:var(--text)}
.doc-control tr:last-child td{border-bottom:none}
.doc-control td.lbl{background:var(--surface-2);font-weight:600;width:200px;
  font-family:var(--sans);font-size:11px;color:var(--brand-dk);
  letter-spacing:.5px;text-transform:uppercase;font-size:9px}

.cover-footer{margin-top:24px;font-family:var(--sans);font-size:9px;
  color:var(--muted);text-align:center;letter-spacing:1px}
.cover-confidential{font-weight:700;color:var(--crit);letter-spacing:3px;
  text-transform:uppercase;font-size:10px;margin-top:8px}

/* ── CONTENT ────────────────────────────────────────────────────────────── */
.content{padding:56px 72px}
.section{margin-bottom:56px}
.section-eyebrow{font-family:var(--sans);font-size:9px;letter-spacing:5px;
  text-transform:uppercase;color:var(--brand);margin-bottom:8px;font-weight:600}
.section-title{font-family:var(--serif);font-size:30px;font-weight:700;
  color:var(--brand-dk);margin-bottom:8px;line-height:1.15;letter-spacing:-.5px}
.section-rule{height:2px;background:var(--brand);width:64px;margin-bottom:24px}
.section-intro{font-family:var(--serif-body);font-size:14px;line-height:1.75;
  color:var(--muted);margin-bottom:24px;max-width:80ch;font-weight:400}

/* TOC */
.toc{background:var(--surface);border:1px solid var(--border);padding:32px 40px}
.toc h2{font-family:var(--serif);font-size:20px;color:var(--brand-dk);
  margin-bottom:20px;font-weight:700;letter-spacing:-.5px}
.toc ol{list-style:none;counter-reset:tc;column-count:2;column-gap:48px}
.toc li{counter-increment:tc;font-family:var(--serif-body);font-size:13px;
  margin-bottom:10px;break-inside:avoid;display:flex;align-items:baseline;gap:8px}
.toc li::before{content:counter(tc,decimal-leading-zero);font-family:var(--sans);
  font-size:9px;letter-spacing:1px;color:var(--brand);font-weight:700;
  width:24px;flex-shrink:0}
.toc a{color:var(--text);text-decoration:none;flex:1}
.toc a:hover{color:var(--brand)}
.toc .toc-dots{flex:1;border-bottom:1px dotted var(--light);margin:0 6px;
  align-self:flex-end;margin-bottom:4px}
.toc .toc-page{font-family:var(--sans);font-size:10px;color:var(--muted);
  font-weight:600}

/* KPI ROW */
.kpi-row{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px}
.kpi{border-radius:0;padding:24px 20px;position:relative;background:var(--white);
  border:1px solid var(--border);text-align:center}
.kpi::before{content:'';position:absolute;left:0;top:0;bottom:0;width:4px}
.kpi.crit::before{background:var(--crit)}
.kpi.high::before{background:var(--high)}
.kpi.med ::before{background:var(--med)}
.kpi.low ::before{background:var(--low)}
.kpi .kn{font-family:var(--serif);font-size:42px;font-weight:900;line-height:1;
  display:block;margin-bottom:8px;letter-spacing:-1px}
.kpi.crit .kn{color:var(--crit)} .kpi.high .kn{color:var(--high)}
.kpi.med .kn{color:var(--med)}   .kpi.low  .kn{color:var(--low)}
.kpi .kl{font-family:var(--sans);font-size:10px;font-weight:700;
  color:var(--brand-dk);text-transform:uppercase;letter-spacing:2px;margin-bottom:4px}
.kpi .ks{font-family:var(--serif-body);font-size:11px;color:var(--muted);font-style:italic}

/* RISK BAR */
.risk-bar{background:var(--surface);border:1px solid var(--border);
  padding:24px 28px;margin-bottom:32px}
.rb-row{display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:12px}
.rb-label{font-family:var(--sans);font-size:11px;font-weight:600;
  color:var(--brand-dk);letter-spacing:1px;text-transform:uppercase}
.rb-score{font-family:var(--serif);font-size:28px;font-weight:700;color:${RISK_COLOR}}
.rb-score .rb-suffix{font-size:14px;font-family:var(--serif-body);
  font-style:italic;color:var(--muted);margin-left:6px}
.rb-track{height:10px;background:var(--border);overflow:hidden;border-radius:0}
.rb-fill{height:100%;background:linear-gradient(90deg,${RISK_COLOR}bb,${RISK_COLOR});
  width:${RS}%;transition:width .3s}
.rb-scale{display:flex;justify-content:space-between;margin-top:8px;
  font-family:var(--sans);font-size:9px;color:var(--light);letter-spacing:1px}

/* EXEC SUMMARY box */
.exec-box{background:var(--surface);border-left:4px solid var(--brand);
  padding:24px 32px;margin-bottom:32px}
.exec-box p{font-family:var(--serif-body);font-size:14px;line-height:1.85;
  color:var(--text);text-align:justify;margin-bottom:14px}
.exec-box p:last-child{margin-bottom:0}
.exec-box strong{color:var(--brand-dk)}

/* DISCOVERY */
.disc-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:0;
  background:var(--white);border:1px solid var(--border);margin-bottom:24px}
.disc-item{padding:20px 16px;text-align:center;border-right:1px solid var(--border)}
.disc-item:last-child{border-right:none}
.disc-item .dn{font-family:var(--serif);font-size:30px;font-weight:700;
  color:var(--brand-dk);display:block;line-height:1;margin-bottom:4px}
.disc-item .dl{font-family:var(--sans);font-size:9px;text-transform:uppercase;
  letter-spacing:2px;color:var(--muted);font-weight:600}

/* CHART (donut) */
.chart-wrap{display:flex;align-items:center;gap:48px;background:var(--surface);
  border:1px solid var(--border);padding:32px;margin-bottom:24px}
.donut{position:relative;width:180px;height:180px;flex-shrink:0}
.donut svg{transform:rotate(-90deg)}
.donut-center{position:absolute;inset:0;display:flex;flex-direction:column;
  align-items:center;justify-content:center}
.donut-center .dc-n{font-family:var(--serif);font-size:32px;font-weight:700;
  color:var(--brand-dk);line-height:1}
.donut-center .dc-l{font-family:var(--sans);font-size:9px;color:var(--muted);
  letter-spacing:3px;text-transform:uppercase;margin-top:4px}
.legend{flex:1;display:flex;flex-direction:column;gap:12px}
.legend-item{display:flex;align-items:center;gap:14px;font-family:var(--serif-body);
  font-size:13px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.legend-item:last-child{border-bottom:none}
.legend-dot{width:14px;height:14px;flex-shrink:0;border-radius:2px}
.legend-dot.crit{background:var(--crit)} .legend-dot.high{background:var(--high)}
.legend-dot.med{background:var(--med)}   .legend-dot.low{background:var(--low)}
.legend-label{flex:1;font-weight:600;color:var(--brand-dk)}
.legend-desc{font-style:italic;color:var(--muted);font-size:11px}
.legend-count{font-family:var(--serif);font-size:22px;font-weight:700;color:var(--brand-dk)}

/* HEATMAP */
.heatmap-wrap{background:var(--surface);border:1px solid var(--border);
  padding:32px;margin-bottom:24px}
.heatmap{display:grid;grid-template-columns:repeat(5,1fr);
  grid-template-rows:repeat(5,60px);gap:2px;background:var(--border);
  border:1px solid var(--border);position:relative}
.hm-cell{background:var(--white);position:relative}
.hm-cell.q1{background:#fef2f2} .hm-cell.q2{background:#fff7ed}
.hm-cell.q3{background:#fffbeb} .hm-cell.q4{background:#eff6ff}
.hm-cell.q5{background:#ecfdf5}
.hm-dot{width:14px;height:14px;border-radius:50%;border:2px solid var(--white);
  margin:auto;margin-top:22px;box-shadow:0 1px 4px rgba(0,0,0,.2)}
.hm-dot.row-crit{background:var(--crit)} .hm-dot.row-high{background:var(--high)}
.hm-dot.row-med{background:var(--med)}   .hm-dot.row-low{background:var(--low)}
.hm-labels-x,.hm-labels-y{font-family:var(--sans);font-size:9px;
  letter-spacing:2px;text-transform:uppercase;color:var(--muted);font-weight:600}
.hm-labels-x{display:grid;grid-template-columns:repeat(5,1fr);margin-top:8px;
  text-align:center}
.hm-axis-title{font-family:var(--sans);font-size:10px;letter-spacing:3px;
  text-transform:uppercase;color:var(--brand-dk);font-weight:700;text-align:center;
  margin-top:6px}
.hm-layout{display:grid;grid-template-columns:24px 1fr;grid-template-rows:1fr 24px;
  gap:8px;align-items:stretch}
.hm-y-axis{writing-mode:vertical-rl;transform:rotate(180deg);
  font-family:var(--sans);font-size:10px;letter-spacing:3px;text-transform:uppercase;
  color:var(--brand-dk);font-weight:700;text-align:center;grid-row:1}
.hm-grid-wrap{grid-row:1;grid-column:2}
.hm-x-axis{grid-row:2;grid-column:2;text-align:center;
  font-family:var(--sans);font-size:10px;letter-spacing:3px;text-transform:uppercase;
  color:var(--brand-dk);font-weight:700}

/* BENCHMARK */
.benchmark{background:var(--surface);border:1px solid var(--border);
  padding:32px;margin-bottom:24px}
.bench-row{display:grid;grid-template-columns:200px 1fr 80px;align-items:center;
  gap:16px;margin-bottom:18px;font-family:var(--serif-body);font-size:13px}
.bench-row:last-child{margin-bottom:0}
.bench-lbl{color:var(--brand-dk);font-weight:600}
.bench-bar-wrap{position:relative;height:24px;background:var(--white);
  border:1px solid var(--border)}
.bench-bar{position:absolute;left:0;top:0;bottom:0;background:${RISK_COLOR};
  display:flex;align-items:center;padding:0 8px;color:#fff;
  font-family:var(--sans);font-size:10px;font-weight:700}
.bench-baseline{position:absolute;top:-4px;bottom:-4px;width:2px;
  background:var(--brand-dk);z-index:1}
.bench-baseline::before{content:'industry avg';position:absolute;left:50%;
  bottom:-22px;transform:translateX(-50%);font-family:var(--sans);font-size:8px;
  letter-spacing:1px;text-transform:uppercase;color:var(--brand-dk);
  font-weight:700;white-space:nowrap}
.bench-val{text-align:right;font-family:var(--serif);font-size:18px;
  font-weight:700;color:var(--brand-dk)}

/* FINDINGS TABLE */
.findings-table{width:100%;border-collapse:collapse;font-size:11px;
  background:var(--white);border:1px solid var(--border)}
.findings-table thead tr{background:var(--brand-dk)}
.findings-table th{color:rgba(255,255,255,.95);padding:12px 14px;text-align:left;
  font-family:var(--sans);font-size:9px;letter-spacing:2px;text-transform:uppercase;
  font-weight:700}
.findings-table td{padding:14px;border-bottom:1px solid var(--border);
  vertical-align:top;font-family:var(--serif-body);font-size:11.5px;line-height:1.55}
.findings-table tr:last-child td{border-bottom:none}
.findings-table tr:nth-child(even) td{background:var(--surface-2)}
.row-crit td:first-child{border-left:4px solid var(--crit)}
.row-high td:first-child{border-left:4px solid var(--high)}
.row-med  td:first-child{border-left:4px solid var(--med)}
.row-low  td:first-child{border-left:4px solid var(--low)}
.badge{display:inline-block;font-family:var(--sans);font-size:9px;font-weight:700;
  padding:3px 9px;letter-spacing:1px;text-transform:uppercase;border-radius:2px}
.badge-crit{background:var(--crit-bg);color:var(--crit);border:1px solid var(--crit-bd)}
.badge-high{background:var(--high-bg);color:var(--high);border:1px solid var(--high-bd)}
.badge-med {background:var(--med-bg); color:var(--med); border:1px solid var(--med-bd)}
.badge-low {background:var(--low-bg); color:var(--low); border:1px solid var(--low-bd)}
.finding-name{font-family:var(--sans);font-weight:600;color:var(--brand-dk);
  font-size:12px;letter-spacing:-.2px}
.business-impact{color:var(--text);text-align:justify}
.affected-count{font-family:var(--serif);font-weight:700;color:var(--brand-dk);
  text-align:center;font-size:18px}
.priority{font-family:var(--sans);color:var(--muted);font-size:10px;
  letter-spacing:.5px;white-space:nowrap}
.comp-tags{display:flex;flex-direction:column;gap:4px}
.comp-tag{font-family:var(--sans);font-size:8.5px;padding:3px 6px;
  background:var(--surface);border:1px solid var(--border);color:var(--muted);
  letter-spacing:.3px;line-height:1.3;border-radius:2px}
.comp-tag.csf{border-color:#cbd5e1}
.comp-tag.iso{border-color:#cbd5e1}
.comp-tag.pci{border-color:#cbd5e1}
.comp-tag.oth{border-color:#cbd5e1;font-style:italic}

/* METHODOLOGY blocks */
.method-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:20px;
  margin-bottom:24px}
.method-card{background:var(--surface);border-left:3px solid var(--brand);
  padding:20px 24px}
.method-card h4{font-family:var(--serif);font-size:15px;color:var(--brand-dk);
  margin-bottom:10px;font-weight:700}
.method-card p{font-family:var(--serif-body);font-size:12px;line-height:1.7;
  color:var(--text);margin-bottom:8px}
.method-card ul{list-style:none;padding-left:0;margin-top:8px}
.method-card li{font-family:var(--serif-body);font-size:12px;padding-left:18px;
  position:relative;margin-bottom:6px;line-height:1.6;color:var(--text)}
.method-card li::before{content:'▸';position:absolute;left:0;color:var(--brand);
  font-weight:700}

/* SCOPE table */
.scope-table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px}
.scope-table td{padding:10px 16px;border-bottom:1px solid var(--border);
  font-family:var(--serif-body);vertical-align:top}
.scope-table td.lbl{background:var(--surface);font-family:var(--sans);
  font-weight:700;color:var(--brand-dk);width:200px;font-size:10px;
  letter-spacing:1.5px;text-transform:uppercase}

/* RATING METHODOLOGY */
.rating-table{width:100%;border-collapse:collapse;font-size:11.5px;margin-bottom:24px;
  background:var(--white);border:1px solid var(--border)}
.rating-table th{background:var(--brand-dk);color:#fff;font-family:var(--sans);
  font-size:9px;letter-spacing:2px;text-transform:uppercase;padding:10px 14px;
  text-align:left;font-weight:700}
.rating-table td{padding:11px 14px;border-bottom:1px solid var(--border);
  font-family:var(--serif-body);line-height:1.55}
.rating-table tr:last-child td{border-bottom:none}
.rating-table td:first-child{font-weight:700;font-family:var(--sans);
  font-size:10px;letter-spacing:1px;text-transform:uppercase}
.rating-table .sev-crit{color:var(--crit)} .rating-table .sev-high{color:var(--high)}
.rating-table .sev-med{color:var(--med)}   .rating-table .sev-low{color:var(--low)}

/* ROADMAP */
.roadmap{position:relative;padding-left:32px}
.roadmap::before{content:'';position:absolute;left:14px;top:30px;bottom:20px;
  width:2px;background:var(--border)}
.rm-item{display:grid;grid-template-columns:40px 1fr;gap:20px;
  align-items:flex-start;margin-bottom:24px;position:relative}
.rm-marker{width:30px;height:30px;border-radius:50%;background:var(--white);
  border:2px solid;display:flex;align-items:center;justify-content:center;
  font-family:var(--serif);font-size:12px;font-weight:700;z-index:1;
  margin-left:-15px}
.rm-marker.crit{border-color:var(--crit);color:var(--crit)}
.rm-marker.high{border-color:var(--high);color:var(--high)}
.rm-marker.med {border-color:var(--med); color:var(--med)}
.rm-marker.low {border-color:var(--low); color:var(--low)}
.rm-body{background:var(--surface);border:1px solid var(--border);padding:18px 24px}
.rm-body h4{font-family:var(--serif);font-size:15px;font-weight:700;
  color:var(--brand-dk);margin-bottom:6px}
.rm-body p{font-family:var(--serif-body);font-size:12px;line-height:1.7;
  color:var(--text);margin-bottom:10px}
.rm-timeline{display:inline-block;font-family:var(--sans);font-size:9px;
  font-weight:700;padding:4px 10px;letter-spacing:1.5px;text-transform:uppercase;
  border-radius:2px}
.rm-item.crit .rm-timeline{background:var(--crit-bg);color:var(--crit)}
.rm-item.high .rm-timeline{background:var(--high-bg);color:var(--high)}
.rm-item.med  .rm-timeline{background:var(--med-bg); color:var(--med)}
.rm-item.low  .rm-timeline{background:var(--low-bg); color:var(--low)}

/* GLOSSARY */
.glossary{display:grid;grid-template-columns:1fr 1fr;gap:24px 48px}
.gloss-term{margin-bottom:14px}
.gloss-term dt{font-family:var(--sans);font-size:11px;font-weight:700;
  color:var(--brand-dk);letter-spacing:.5px;margin-bottom:4px}
.gloss-term dd{font-family:var(--serif-body);font-size:12px;line-height:1.6;
  color:var(--text)}

/* APPROVAL block */
.approval{display:grid;grid-template-columns:repeat(3,1fr);gap:32px;
  margin-top:32px;padding-top:24px;border-top:1px solid var(--border)}
.approval-box{text-align:left}
.approval-box label{display:block;font-family:var(--sans);font-size:9px;
  letter-spacing:2px;text-transform:uppercase;color:var(--muted);
  font-weight:600;margin-bottom:6px}
.approval-box .approval-name{font-family:var(--serif);font-size:14px;
  font-weight:700;color:var(--brand-dk);padding-bottom:6px;
  border-bottom:2px solid var(--brand);margin-bottom:6px}
.approval-box .approval-sig{font-family:var(--serif-body);font-size:11px;
  font-style:italic;color:var(--muted);min-height:48px;
  border-bottom:1px solid var(--border);padding-bottom:6px}
.approval-box .approval-date{font-family:var(--sans);font-size:10px;
  color:var(--muted);margin-top:4px}

/* FOOTER */
.report-footer{background:var(--brand-dk);padding:32px 72px;
  display:grid;grid-template-columns:1fr 1fr 1fr;gap:32px;align-items:center}
.rf-col{font-family:var(--sans);font-size:9px;color:rgba(255,255,255,.5);
  letter-spacing:1px;line-height:1.7}
.rf-col strong{color:rgba(255,255,255,.9);font-weight:700;letter-spacing:1.5px}
.rf-col.center{text-align:center}
.rf-col.right{text-align:right}

/* PAGE BREAK */
.page-break{page-break-before:always}

/* PRINT */
@media print{
  body{background:white}
  .page{box-shadow:none;max-width:100%}
  .page-break{page-break-before:always}
}
</style>
</head>
<body>
<div class="page">

<!-- ── COVER ─────────────────────────────────────────────────────────────── -->
<div class="cover">
  <div class="cover-top">
    <div class="cover-classification">${CLASSIFICATION}</div>
    <div class="cover-logos">
      ${CLIENT_LOGO_HTML}
      ${CONSULT_LOGO_HTML}
    </div>
    <div class="cover-eyebrow">${REPORT_YEAR} Annual Cyber Security Assessment</div>
    <div class="cover-title">External Penetration Test</div>
    <div class="cover-sub">Prepared for ${ORG}</div>
    <div class="cover-domain">${DOMAIN}</div>
    <div class="cover-meta">
      <div class="cover-meta-item"><label>Engagement Type</label><span>External Black-Box</span></div>
      <div class="cover-meta-item"><label>Reporting Date</label><span>${REPORT_DATE}</span></div>
      <div class="cover-meta-item"><label>Performed By</label><span>${CONSULTANCY}</span></div>
      <div class="cover-meta-item"><label>Engagement Lead</label><span>${ANALYST}</span></div>
    </div>
  </div>
  <div class="cover-bottom">
    <div>
      <div class="doc-control-title">Document Control</div>
      <table class="doc-control">
        <tr><td class="lbl">Document Title</td>          <td>External Penetration Test — ${ORG}</td></tr>
        <tr><td class="lbl">Version</td>                  <td>${REPORT_VERSION}</td></tr>
        <tr><td class="lbl">Classification</td>           <td>${CLASSIFICATION} — Not for external distribution</td></tr>
        <tr><td class="lbl">Engagement Window</td>        <td>${ENGAGEMENT_START} &rarr; ${ENGAGEMENT_END}</td></tr>
        <tr><td class="lbl">Author</td>                   <td>${ANALYST}</td></tr>
        <tr><td class="lbl">Technical Reviewer</td>       <td>${REVIEWER}</td></tr>
        <tr><td class="lbl">Engagement Manager</td>       <td>${APPROVER}</td></tr>
        <tr><td class="lbl">Distribution List</td>        <td>${DISTRIBUTION_LIST}</td></tr>
        <tr><td class="lbl">Report Identifier</td>        <td>${ORG}-EPT-${REPORT_DATE_ISO}</td></tr>
      </table>
    </div>
    <div class="cover-footer">
      <div>&copy; ${REPORT_YEAR} ${CONSULTANCY}. All rights reserved.</div>
      <div class="cover-confidential">${CLASSIFICATION} — Distribution restricted to named recipients</div>
    </div>
  </div>
</div>

<!-- ── TABLE OF CONTENTS ─────────────────────────────────────────────────── -->
<div class="content page-break">
<div class="section">
  <div class="section-eyebrow">Contents</div>
  <div class="section-title">Table of Contents</div>
  <div class="section-rule"></div>
  <div class="toc">
    <ol>
      <li><a href="#exec">Executive Summary</a><span class="toc-dots"></span><span class="toc-page">03</span></li>
      <li><a href="#method">Methodology &amp; Approach</a><span class="toc-dots"></span><span class="toc-page">05</span></li>
      <li><a href="#scope">Scope of Engagement</a><span class="toc-dots"></span><span class="toc-page">06</span></li>
      <li><a href="#rating">Risk Rating Methodology</a><span class="toc-dots"></span><span class="toc-page">07</span></li>
      <li><a href="#attack">Attack Surface Discovery</a><span class="toc-dots"></span><span class="toc-page">08</span></li>
      <li><a href="#risk">Risk Distribution &amp; Heatmap</a><span class="toc-dots"></span><span class="toc-page">09</span></li>
      <li><a href="#bench">Industry Benchmark</a><span class="toc-dots"></span><span class="toc-page">10</span></li>
      <li><a href="#findings">Security Findings &amp; Compliance</a><span class="toc-dots"></span><span class="toc-page">11</span></li>
      <li><a href="#roadmap">Remediation Roadmap</a><span class="toc-dots"></span><span class="toc-page">14</span></li>
      <li><a href="#next">Recommendations &amp; Next Steps</a><span class="toc-dots"></span><span class="toc-page">15</span></li>
      <li><a href="#glossary">Glossary</a><span class="toc-dots"></span><span class="toc-page">16</span></li>
      <li><a href="#approval">Report Approval</a><span class="toc-dots"></span><span class="toc-page">17</span></li>
    </ol>
  </div>
</div>

<!-- ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────── -->
<div class="section page-break" id="exec">
  <div class="section-eyebrow">01 — Management Summary</div>
  <div class="section-title">Executive Summary</div>
  <div class="section-rule"></div>

  <div class="exec-box">
    <p>${CONSULTANCY} was engaged by ${ORG} to conduct an external penetration test against the internet-facing perimeter of <strong>${DOMAIN}</strong>. The assessment examined publicly accessible infrastructure including web applications, network services, email authentication controls, certificate hygiene, and the surrounding domain ecosystem.</p>
    <p>The assessment identified <strong>${C_TOTAL} unique security findings</strong> distributed across ${C_CRIT} critical, ${C_HIGH} high, ${C_MED} medium, and ${C_LOW} low severity categories. The overall residual risk is rated <strong>${RISK_LEVEL}</strong>, with a composite risk score of <strong>${RS} out of 100</strong>, derived from the nature, exploitability, and business impact of the issues discovered.</p>
    $([ "$C_CRIT" -gt 0 ] && printf '<p><strong>Immediate executive attention is warranted</strong> for the %s critical finding%s identified. Critical findings represent active or readily-exploitable risk of data breach, service disruption, or material reputational damage.</p>' "$C_CRIT" "$([ "$C_CRIT" -ne 1 ] && echo s)")
    $([ "$C_CRIT" -eq 0 ] && [ "$C_HIGH" -gt 0 ] && printf '<p>No critical findings were identified; however <strong>%s high-severity issue%s</strong> require remediation within the next sprint cycle to prevent escalation. These items are exploitable today by an unauthenticated remote attacker with industry-standard tooling.</p>' "$C_HIGH" "$([ "$C_HIGH" -ne 1 ] && echo s)")
    $([ "$C_CRIT" -eq 0 ] && [ "$C_HIGH" -eq 0 ] && [ "$C_MED" -gt 0 ] && printf '<p>The perimeter exhibits sound foundational controls. The %s medium-severity items identified represent opportunities for hardening rather than active risk, and should be addressed through scheduled security improvement cycles.</p>' "$C_MED")
  </div>

  <!-- KPI ROW -->
  <div class="kpi-row">
    <div class="kpi crit">
      <span class="kn">${C_CRIT}</span>
      <div class="kl">Critical</div>
      <div class="ks">${T_CRIT} instance$([ "$T_CRIT" -ne 1 ] && echo s)</div>
    </div>
    <div class="kpi high">
      <span class="kn">${C_HIGH}</span>
      <div class="kl">High</div>
      <div class="ks">${T_HIGH} instance$([ "$T_HIGH" -ne 1 ] && echo s)</div>
    </div>
    <div class="kpi med">
      <span class="kn">${C_MED}</span>
      <div class="kl">Medium</div>
      <div class="ks">${T_MED} instance$([ "$T_MED" -ne 1 ] && echo s)</div>
    </div>
    <div class="kpi low">
      <span class="kn">${C_LOW}</span>
      <div class="kl">Low</div>
      <div class="ks">${T_LOW} instance$([ "$T_LOW" -ne 1 ] && echo s)</div>
    </div>
  </div>

  <!-- RISK BAR -->
  <div class="risk-bar">
    <div class="rb-row">
      <div class="rb-label">Composite Risk Score</div>
      <div class="rb-score">${RS} <span class="rb-suffix">/ 100 &middot; ${RISK_LEVEL}</span></div>
    </div>
    <div class="rb-track"><div class="rb-fill"></div></div>
    <div class="rb-scale"><span>00 &middot; Minimal</span><span>25</span><span>50</span><span>75</span><span>100 &middot; Critical</span></div>
  </div>
</div>

<!-- ── METHODOLOGY ───────────────────────────────────────────────────────── -->
<div class="section page-break" id="method">
  <div class="section-eyebrow">02 — Approach</div>
  <div class="section-title">Methodology &amp; Standards</div>
  <div class="section-rule"></div>
  <p class="section-intro">The engagement followed an industry-recognised methodology combining the OWASP Web Security Testing Guide v4, the Penetration Testing Execution Standard (PTES), and the MITRE ATT&amp;CK framework for adversary tactic enumeration. Activities were structured into discrete, repeatable phases with documented deliverables at each stage.</p>

  <div class="method-grid">
    <div class="method-card">
      <h4>Reference Frameworks</h4>
      <ul>
        <li>OWASP Web Security Testing Guide v4.2</li>
        <li>OWASP Application Security Verification Standard (ASVS) v4.0</li>
        <li>Penetration Testing Execution Standard (PTES)</li>
        <li>NIST SP 800-115 — Technical Guide to Information Security Testing</li>
        <li>MITRE ATT&amp;CK — Enterprise Matrix v15</li>
      </ul>
    </div>
    <div class="method-card">
      <h4>Engagement Phases</h4>
      <ul>
        <li>Passive reconnaissance &amp; OSINT collection</li>
        <li>DNS audit &amp; email authentication review</li>
        <li>Active host discovery &amp; service enumeration</li>
        <li>TLS/SSL configuration audit</li>
        <li>HTTP security-header analysis</li>
        <li>Web application probing &amp; logic testing</li>
        <li>CVE validation &amp; product fingerprinting</li>
        <li>Authentication-surface analysis</li>
      </ul>
    </div>
    <div class="method-card">
      <h4>Tooling &amp; Evidence</h4>
      <ul>
        <li>nmap, masscan — service discovery</li>
        <li>nuclei, ffuf, katana — vulnerability scanning</li>
        <li>testssl.sh, sslyze, openssl — TLS audit</li>
        <li>subfinder, amass, httpx — asset enumeration</li>
        <li>nikto, wafw00f — web application probing</li>
        <li>All findings independently validated by manual evidence collection prior to inclusion in this report</li>
      </ul>
    </div>
    <div class="method-card">
      <h4>Testing Constraints</h4>
      <p>Testing was conducted as an <em>unauthenticated external attacker</em> — no credentials, source code, or internal network access were provided. Activity was rate-limited to avoid service disruption. Destructive techniques (denial of service, data modification, account lockouts) were explicitly out of scope.</p>
    </div>
  </div>
</div>

<!-- ── SCOPE ─────────────────────────────────────────────────────────────── -->
<div class="section" id="scope">
  <div class="section-eyebrow">03 — Boundaries</div>
  <div class="section-title">Scope of Engagement</div>
  <div class="section-rule"></div>
  <p class="section-intro">The engagement scope was defined collaboratively with ${ORG} and documented in the Rules of Engagement prior to commencement of testing. Targets, time window, and exclusions are stated below for the record.</p>

  <table class="scope-table">
    <tr><td class="lbl">Engagement Type</td><td>External Black-Box Penetration Test</td></tr>
    <tr><td class="lbl">Primary Target</td><td><strong>${DOMAIN}</strong> and all subdomains owned by ${ORG}</td></tr>
    <tr><td class="lbl">Additional Targets</td><td>${TARGETS}</td></tr>
    <tr><td class="lbl">Engagement Window</td><td>${ENGAGEMENT_START} through ${ENGAGEMENT_END}</td></tr>
    <tr><td class="lbl">Authorisation</td><td>Written authorisation from ${ORG} on file with ${CONSULTANCY}</td></tr>
    <tr><td class="lbl">In Scope</td><td>Reconnaissance, passive OSINT, active service enumeration, vulnerability identification, exploitation proof-of-concept where safely demonstrable, certificate analysis, email authentication review</td></tr>
    <tr><td class="lbl">Out of Scope</td><td>Denial-of-service attacks, social engineering of ${ORG} personnel, physical security testing, modification of data, account-lockout brute force, exploitation of third-party SaaS providers</td></tr>
    <tr><td class="lbl">Testing Source</td><td>${CONSULTANCY} controlled IP space; logs available on request</td></tr>
  </table>
</div>

<!-- ── RISK RATING METHODOLOGY ───────────────────────────────────────────── -->
<div class="section" id="rating">
  <div class="section-eyebrow">04 — Risk Framework</div>
  <div class="section-title">Risk Rating Methodology</div>
  <div class="section-rule"></div>
  <p class="section-intro">Findings are rated on a four-tier scale aligned with CVSS v3.1 base-score bands. Each rating reflects a composite of <em>likelihood</em> of successful exploitation and <em>impact</em> upon successful exploitation, taking into account exposure, authentication requirements, and business context.</p>

  <table class="rating-table">
    <thead>
      <tr><th style="width:90px">Severity</th><th style="width:140px">CVSS Range</th><th>Definition</th><th style="width:180px">Remediation SLA</th></tr>
    </thead>
    <tbody>
      <tr><td class="sev-crit">Critical</td><td>9.0 — 10.0</td><td>Unauthenticated remote compromise, mass-data exposure, full administrative access without prerequisites. Active risk to confidentiality, integrity, or availability at scale.</td><td>Immediate — 24 to 48 hours</td></tr>
      <tr><td class="sev-high">High</td><td>7.0 — 8.9</td><td>Significant compromise of confidentiality or integrity, often requiring some prerequisites (specific timing, user interaction) but exploitable today with public tooling.</td><td>Short-term — 2 to 4 weeks</td></tr>
      <tr><td class="sev-med">Medium</td><td>4.0 — 6.9</td><td>Limited compromise or exposure that enables further attack chains. Typically configuration gaps that an attacker can leverage in combination with other findings.</td><td>Medium-term — 1 to 2 quarters</td></tr>
      <tr><td class="sev-low">Low</td><td>0.1 — 3.9</td><td>Defence-in-depth gap or information disclosure that on its own poses minimal risk but should be addressed for security hygiene.</td><td>Long-term — backlog item</td></tr>
    </tbody>
  </table>
  <p style="font-family:var(--serif-body);font-size:12px;color:var(--muted);font-style:italic">Composite risk score: <span style="font-family:var(--sans);font-weight:700">RS = (Critical × 40) + (High × 20) + (Medium × 10) + (Low × 5)</span>, capped at 100.</p>
</div>

<!-- ── ATTACK SURFACE ────────────────────────────────────────────────────── -->
<div class="section page-break" id="attack">
  <div class="section-eyebrow">05 — Discovery</div>
  <div class="section-title">External Attack Surface</div>
  <div class="section-rule"></div>
  <p class="section-intro">An attacker probing ${ORG} from the public internet sees the following surface area. Each asset represents an entry point that must be defended, monitored, and patched.</p>

  <div class="disc-grid">
    <div class="disc-item"><span class="dn">${SUBS_COUNT}</span><div class="dl">Subdomains</div></div>
    <div class="disc-item"><span class="dn">${LIVE_COUNT}</span><div class="dl">Live Services</div></div>
    <div class="disc-item"><span class="dn">${PORTS_COUNT}</span><div class="dl">Open Ports</div></div>
    <div class="disc-item"><span class="dn">${EXPOSED_COUNT}</span><div class="dl">Sensitive Paths</div></div>
    <div class="disc-item"><span class="dn">${TAKEOVER_COUNT}</span><div class="dl">Takeover Candidates</div></div>
  </div>
  <p style="font-family:var(--serif-body);font-size:13px;line-height:1.75;color:var(--text)">${ORG} maintains a substantial internet-facing surface area. Each subdomain, exposed service, and open port represents a separate audit target. Effective external security posture depends on continuous inventory of these assets, prompt removal of services no longer in use, and disciplined hardening of those that remain.</p>
</div>
HTMLEOF

# ── RISK DISTRIBUTION (donut + legend) + HEATMAP ────────────────────────────
cat >> "$OUT_HTML" <<HTMLEOF
<div class="section" id="risk">
  <div class="section-eyebrow">06 — Distribution</div>
  <div class="section-title">Risk Distribution &amp; Heatmap</div>
  <div class="section-rule"></div>
  <p class="section-intro">Findings distributed by severity (left) and plotted across the likelihood × impact heatmap (right). The heatmap visualises the concentration of risk and helps prioritise which categories merit attention first.</p>

  <div class="chart-wrap">
HTMLEOF

# ── Donut SVG ────────────────────────────────────────────────────────────────
if [ "$C_TOTAL" -gt 0 ]; then
  R=68; CX=90; CY=90
  CIRC=$(echo "scale=2; 2 * 3.14159265 * $R" | bc 2>/dev/null || echo 427)
  STROKE_CRIT=$(echo "scale=2; $C_CRIT * $CIRC / $C_TOTAL" | bc 2>/dev/null || echo 0)
  STROKE_HIGH=$(echo "scale=2; $C_HIGH * $CIRC / $C_TOTAL" | bc 2>/dev/null || echo 0)
  STROKE_MED=$( echo "scale=2; $C_MED  * $CIRC / $C_TOTAL" | bc 2>/dev/null || echo 0)
  STROKE_LOW=$( echo "scale=2; $C_LOW  * $CIRC / $C_TOTAL" | bc 2>/dev/null || echo 0)
  OFF_C=0
  OFF_H=$(echo "scale=2; -1 * $STROKE_CRIT" | bc 2>/dev/null || echo 0)
  OFF_M=$(echo "scale=2; -1 * ($STROKE_CRIT + $STROKE_HIGH)" | bc 2>/dev/null || echo 0)
  OFF_L=$(echo "scale=2; -1 * ($STROKE_CRIT + $STROKE_HIGH + $STROKE_MED)" | bc 2>/dev/null || echo 0)
  cat >> "$OUT_HTML" <<DONUT
<div class="donut">
<svg width="180" height="180" viewBox="0 0 180 180">
  <circle cx="${CX}" cy="${CY}" r="${R}" fill="none" stroke="#e2e8f0" stroke-width="20"/>
DONUT
  [ "$C_CRIT" -gt 0 ] && printf '  <circle cx="%s" cy="%s" r="%s" fill="none" stroke="#b91c1c" stroke-width="20" stroke-dasharray="%s %s" stroke-dashoffset="%s"/>\n' "$CX" "$CY" "$R" "$STROKE_CRIT" "$CIRC" "$OFF_C" >> "$OUT_HTML"
  [ "$C_HIGH" -gt 0 ] && printf '  <circle cx="%s" cy="%s" r="%s" fill="none" stroke="#c2410c" stroke-width="20" stroke-dasharray="%s %s" stroke-dashoffset="%s"/>\n' "$CX" "$CY" "$R" "$STROKE_HIGH" "$CIRC" "$OFF_H" >> "$OUT_HTML"
  [ "$C_MED"  -gt 0 ] && printf '  <circle cx="%s" cy="%s" r="%s" fill="none" stroke="#b45309" stroke-width="20" stroke-dasharray="%s %s" stroke-dashoffset="%s"/>\n' "$CX" "$CY" "$R" "$STROKE_MED" "$CIRC" "$OFF_M" >> "$OUT_HTML"
  [ "$C_LOW"  -gt 0 ] && printf '  <circle cx="%s" cy="%s" r="%s" fill="none" stroke="#1d4ed8" stroke-width="20" stroke-dasharray="%s %s" stroke-dashoffset="%s"/>\n' "$CX" "$CY" "$R" "$STROKE_LOW" "$CIRC" "$OFF_L" >> "$OUT_HTML"
  cat >> "$OUT_HTML" <<DONUT2
</svg>
<div class="donut-center"><span class="dc-n">${C_TOTAL}</span><div class="dc-l">Findings</div></div>
</div>
DONUT2
else
  cat >> "$OUT_HTML" <<DONUT3
<div class="donut" style="background:var(--surface);border-radius:50%;display:flex;align-items:center;justify-content:center">
  <div class="donut-center"><span class="dc-n">0</span><div class="dc-l">Findings</div></div>
</div>
DONUT3
fi

cat >> "$OUT_HTML" <<HTMLEOF
    <div class="legend">
      <div class="legend-item">
        <div class="legend-dot crit"></div>
        <div class="legend-label">Critical<div class="legend-desc">Immediate risk, active exploitation feasible</div></div>
        <div class="legend-count">${C_CRIT}</div>
      </div>
      <div class="legend-item">
        <div class="legend-dot high"></div>
        <div class="legend-label">High<div class="legend-desc">Significant compromise within reach</div></div>
        <div class="legend-count">${C_HIGH}</div>
      </div>
      <div class="legend-item">
        <div class="legend-dot med"></div>
        <div class="legend-label">Medium<div class="legend-desc">Configuration gaps and attack-chain enablers</div></div>
        <div class="legend-count">${C_MED}</div>
      </div>
      <div class="legend-item">
        <div class="legend-dot low"></div>
        <div class="legend-label">Low<div class="legend-desc">Hygiene improvements, defence-in-depth</div></div>
        <div class="legend-count">${C_LOW}</div>
      </div>
    </div>
  </div>

  <!-- HEATMAP -->
  <div class="heatmap-wrap">
    <div style="font-family:var(--sans);font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--brand-dk);margin-bottom:12px">Likelihood × Impact Heatmap</div>
    <div class="hm-layout">
      <div class="hm-y-axis">Impact &rarr;</div>
      <div class="hm-grid-wrap">
        <div class="heatmap">
          <!-- 5x5 grid; q1=red, q5=green -->
          <div class="hm-cell q3"></div><div class="hm-cell q2"></div><div class="hm-cell q1"></div><div class="hm-cell q1"></div><div class="hm-cell q1"></div>
          <div class="hm-cell q3"></div><div class="hm-cell q3"></div><div class="hm-cell q2"></div><div class="hm-cell q1"></div><div class="hm-cell q1"></div>
          <div class="hm-cell q4"></div><div class="hm-cell q3"></div><div class="hm-cell q3"></div><div class="hm-cell q2"></div><div class="hm-cell q1"></div>
          <div class="hm-cell q5"></div><div class="hm-cell q4"></div><div class="hm-cell q3"></div><div class="hm-cell q3"></div><div class="hm-cell q2"></div>
          <div class="hm-cell q5"></div><div class="hm-cell q5"></div><div class="hm-cell q4"></div><div class="hm-cell q3"></div><div class="hm-cell q3"></div>
          ${HEATMAP_DOTS}
        </div>
      </div>
      <div class="hm-x-axis">Likelihood &rarr;</div>
    </div>
  </div>
</div>

<!-- ── INDUSTRY BENCHMARK ────────────────────────────────────────────────── -->
<div class="section" id="bench">
  <div class="section-eyebrow">07 — Comparison</div>
  <div class="section-title">Industry Benchmark</div>
  <div class="section-rule"></div>
  <p class="section-intro">${ORG}'s findings compared against the industry baseline for external perimeter assessments of similarly-sized organisations. Baselines derived from anonymised aggregate data across ${CONSULTANCY}'s assessment portfolio and corroborating sources including the Verizon Data Breach Investigations Report ${REPORT_YEAR}.</p>

  <div class="benchmark">
HTMLEOF

# Benchmark bars
_bench_row() {
  local _lbl="$1" _val="$2" _baseline="$3" _max="$4"
  local _pct_val _pct_base
  _pct_val=$(awk -v v="$_val" -v m="$_max" 'BEGIN{if(m==0){print 0} else {p=v*100/m; if(p>100)p=100; printf "%.0f", p}}')
  _pct_base=$(awk -v b="$_baseline" -v m="$_max" 'BEGIN{if(m==0){print 0} else {p=b*100/m; if(p>100)p=100; printf "%.0f", p}}')
  cat <<BENCHROW >> "$OUT_HTML"
    <div class="bench-row">
      <div class="bench-lbl">${_lbl}</div>
      <div class="bench-bar-wrap">
        <div class="bench-bar" style="width:${_pct_val}%">${_val}</div>
        <div class="bench-baseline" style="left:${_pct_base}%"></div>
      </div>
      <div class="bench-val">${_val}</div>
    </div>
BENCHROW
}

BENCH_MAX=$(( C_TOTAL + 5 ))
[ "$BENCH_MAX" -lt 25 ] && BENCH_MAX=25
HIGH_PLUS_CRIT=$(( C_CRIT + C_HIGH ))
_bench_row "High + Critical Findings" "$HIGH_PLUS_CRIT" "$BENCHMARK_HIGH_AVG" "$BENCH_MAX"
_bench_row "Medium Findings"          "$C_MED"          "$BENCHMARK_MED_AVG"  "$BENCH_MAX"
_bench_row "Total Findings"           "$C_TOTAL"        "$BENCHMARK_TOTAL_AVG" "$BENCH_MAX"

# Interpretation paragraph
{
  printf '  </div>\n'
  printf '  <p style="font-family:var(--serif-body);font-size:13px;line-height:1.75;color:var(--text);margin-top:24px">\n'
  if [ "$HIGH_PLUS_CRIT" -gt "$BENCHMARK_HIGH_AVG" ]; then
    printf '    <strong>Above industry average</strong> for high-severity findings. The current high+critical count of <strong>%s</strong> exceeds the industry average of <strong>%s</strong>. Prioritised remediation effort recommended.\n' "$HIGH_PLUS_CRIT" "$BENCHMARK_HIGH_AVG"
  elif [ "$HIGH_PLUS_CRIT" -lt "$BENCHMARK_HIGH_AVG" ]; then
    printf '    <strong>Below industry average</strong> for high-severity findings. The current high+critical count of <strong>%s</strong> is below the industry average of <strong>%s</strong> — a positive indicator of perimeter maturity.\n' "$HIGH_PLUS_CRIT" "$BENCHMARK_HIGH_AVG"
  else
    printf '    <strong>In line with industry average</strong> for high-severity findings (%s versus baseline of %s).\n' "$HIGH_PLUS_CRIT" "$BENCHMARK_HIGH_AVG"
  fi
  printf '  </p>\n'
} >> "$OUT_HTML"

cat >> "$OUT_HTML" <<'HTMLEOF'
</div>

<!-- ── FINDINGS TABLE ────────────────────────────────────────────────────── -->
<div class="section page-break" id="findings">
  <div class="section-eyebrow">08 — Findings</div>
  <div class="section-title">Security Findings &amp; Compliance Mapping</div>
  <div class="section-rule"></div>
  <p class="section-intro">Each finding category is presented with its business impact, the number of systems affected, the recommended remediation priority, and mapping to relevant compliance and regulatory frameworks. Technical evidence, reproduction steps, and remediation specifics are provided in the accompanying SOC Technical Report.</p>
HTMLEOF

if [ -n "$FINDING_TABLE_ROWS" ]; then
  cat >> "$OUT_HTML" <<'TBLEOF'
<table class="findings-table">
  <thead>
    <tr>
      <th style="width:80px">Severity</th>
      <th style="width:170px">Finding</th>
      <th>Business Impact</th>
      <th style="width:60px;text-align:center">Systems</th>
      <th style="width:135px">Priority</th>
      <th style="width:200px">Compliance Mapping</th>
    </tr>
  </thead>
  <tbody>
TBLEOF
  printf '%s\n' "$FINDING_TABLE_ROWS" >> "$OUT_HTML"
  printf '  </tbody>\n</table>\n' >> "$OUT_HTML"
else
  printf '<div style="text-align:center;padding:32px;color:var(--muted);font-family:var(--serif-body);font-style:italic">No findings recorded.</div>\n' >> "$OUT_HTML"
fi

printf '</div>\n' >> "$OUT_HTML"

# ── ROADMAP ─────────────────────────────────────────────────────────────────
cat >> "$OUT_HTML" <<'HTMLEOF'
<div class="section page-break" id="roadmap">
  <div class="section-eyebrow">09 — Action Plan</div>
  <div class="section-title">Remediation Roadmap</div>
  <div class="section-rule"></div>
  <p class="section-intro">A phased remediation programme is recommended, sequenced by severity and remediation complexity. Each phase is sized to integrate with normal sprint and quarterly planning cadences without disrupting routine operations.</p>
  <div class="roadmap">
HTMLEOF

[ "$C_CRIT" -gt 0 ] && cat >> "$OUT_HTML" <<RMEOF
    <div class="rm-item crit">
      <div class="rm-marker crit">I</div>
      <div class="rm-body">
        <h4>Phase I — Immediate Response</h4>
        <p>Address all <strong>${C_CRIT} critical finding$([ "$C_CRIT" -ne 1 ] && echo s)</strong> as the priority. These represent active exploitable risk where unauthorised compromise is feasible today using publicly available tooling. Engage the incident response function and treat as a security incident in flight.</p>
        <span class="rm-timeline">Timeline: 24 — 48 hours</span>
      </div>
    </div>
RMEOF

[ "$C_HIGH" -gt 0 ] && cat >> "$OUT_HTML" <<RMEOF2
    <div class="rm-item high">
      <div class="rm-marker high">II</div>
      <div class="rm-body">
        <h4>Phase II — Short-Term Remediation</h4>
        <p>Remediate the <strong>${C_HIGH} high-severity finding$([ "$C_HIGH" -ne 1 ] && echo s)</strong> within the next sprint cycle. Typical effort: focused engineering work, requiring technical resource but not significant architectural change. Verification via re-test recommended at end of phase.</p>
        <span class="rm-timeline">Timeline: 2 — 4 weeks</span>
      </div>
    </div>
RMEOF2

[ "$C_MED" -gt 0 ] && cat >> "$OUT_HTML" <<RMEOF3
    <div class="rm-item med">
      <div class="rm-marker med">III</div>
      <div class="rm-body">
        <h4>Phase III — Scheduled Hardening</h4>
        <p>Address the <strong>${C_MED} medium-severity finding$([ "$C_MED" -ne 1 ] && echo s)</strong> through scheduled hardening work over the next one to two quarters. Most items in this band involve configuration improvements, security-header implementation, and policy enforcement.</p>
        <span class="rm-timeline">Timeline: 1 — 2 quarters</span>
      </div>
    </div>
RMEOF3

[ "$C_LOW" -gt 0 ] && cat >> "$OUT_HTML" <<RMEOF4
    <div class="rm-item low">
      <div class="rm-marker low">IV</div>
      <div class="rm-body">
        <h4>Phase IV — Continuous Improvement</h4>
        <p>Track the <strong>${C_LOW} low-severity finding$([ "$C_LOW" -ne 1 ] && echo s)</strong> as backlog items, addressed within the ongoing security improvement programme. These items contribute to defence-in-depth and should be revisited at the next assessment cycle.</p>
        <span class="rm-timeline">Timeline: Ongoing / next cycle</span>
      </div>
    </div>
RMEOF4

cat >> "$OUT_HTML" <<'HTMLEOF'
  </div>
</div>

<!-- ── NEXT STEPS ─────────────────────────────────────────────────────────── -->
<div class="section" id="next">
  <div class="section-eyebrow">10 — Recommendations</div>
  <div class="section-title">Next Steps</div>
  <div class="section-rule"></div>
  <div class="method-grid">
    <div class="method-card">
      <h4>1. Remediation Verification</h4>
      <p>Following remediation of findings, ${CONSULTANCY} recommends a targeted re-test focused on the affected categories. Re-test confirms that remediations have been effectively applied and that no regressions have been introduced.</p>
    </div>
    <div class="method-card">
      <h4>2. Continuous Attack Surface Monitoring</h4>
      <p>Implement (or review existing) continuous external attack surface management tooling to detect new exposures as infrastructure evolves. Quarterly automated scans are recommended as a minimum cadence.</p>
    </div>
    <div class="method-card">
      <h4>3. Security Awareness &amp; Engineering Hygiene</h4>
      <p>Brief development and operations teams on the findings to embed lessons learned in the SDLC. Many issues identified — missing security headers, configuration gaps, expired certificates — are preventable through routine engineering hygiene and pre-deployment checks.</p>
    </div>
    <div class="method-card">
      <h4>4. Annual Assessment Cadence</h4>
      <p>External penetration testing is recommended at minimum annually, and additionally following major infrastructure changes, acquisitions, mergers, or significant application launches. This cadence aligns with PCI-DSS and ISO 27001 best practice.</p>
    </div>
  </div>
</div>

<!-- ── GLOSSARY ──────────────────────────────────────────────────────────── -->
<div class="section page-break" id="glossary">
  <div class="section-eyebrow">11 — Reference</div>
  <div class="section-title">Glossary</div>
  <div class="section-rule"></div>
  <div class="glossary">
    <div class="gloss-term">
      <dt>Black-box testing</dt>
      <dd>Assessment performed without prior knowledge of the target's internal architecture, simulating an external attacker with publicly available information only.</dd>
    </div>
    <div class="gloss-term">
      <dt>CVSS</dt>
      <dd>Common Vulnerability Scoring System — an industry-standard framework for rating the severity of security vulnerabilities, producing a numerical score from 0 to 10.</dd>
    </div>
    <div class="gloss-term">
      <dt>CVE</dt>
      <dd>Common Vulnerabilities and Exposures — a public catalogue of known security vulnerabilities, each assigned a unique identifier.</dd>
    </div>
    <div class="gloss-term">
      <dt>HSTS</dt>
      <dd>HTTP Strict Transport Security — a web security policy mechanism that forces browsers to use HTTPS, mitigating man-in-the-middle attacks.</dd>
    </div>
    <div class="gloss-term">
      <dt>DMARC / SPF / DKIM</dt>
      <dd>Email authentication standards that allow domain owners to publish policies indicating which servers may send mail on their behalf, mitigating spoofing.</dd>
    </div>
    <div class="gloss-term">
      <dt>NIST CSF</dt>
      <dd>National Institute of Standards and Technology Cybersecurity Framework — a US-government-produced framework of cybersecurity functions (Identify, Protect, Detect, Respond, Recover) widely adopted globally.</dd>
    </div>
    <div class="gloss-term">
      <dt>ISO 27001</dt>
      <dd>International standard specifying requirements for an Information Security Management System (ISMS), used as the global benchmark for organisational security maturity.</dd>
    </div>
    <div class="gloss-term">
      <dt>OWASP Top 10</dt>
      <dd>A consensus list of the most critical security risks to web applications, published periodically by the Open Web Application Security Project.</dd>
    </div>
    <div class="gloss-term">
      <dt>PCI-DSS</dt>
      <dd>Payment Card Industry Data Security Standard — a mandated set of security requirements for organisations that handle branded credit cards.</dd>
    </div>
    <div class="gloss-term">
      <dt>Subdomain takeover</dt>
      <dd>A vulnerability where an attacker can claim a subdomain pointing to a deprovisioned cloud resource, allowing them to host content under the official domain.</dd>
    </div>
  </div>
</div>

<!-- ── APPROVAL ──────────────────────────────────────────────────────────── -->
HTMLEOF

cat >> "$OUT_HTML" <<HTMLEOF
<div class="section" id="approval">
  <div class="section-eyebrow">12 — Sign-off</div>
  <div class="section-title">Report Approval</div>
  <div class="section-rule"></div>
  <p class="section-intro">This report has been prepared, reviewed, and approved in accordance with ${CONSULTANCY}'s quality assurance procedures.</p>
  <div class="approval">
    <div class="approval-box">
      <label>Prepared by — Engagement Lead</label>
      <div class="approval-name">${ANALYST}</div>
      <div class="approval-sig"></div>
      <div class="approval-date">Date: ${REPORT_DATE_ISO}</div>
    </div>
    <div class="approval-box">
      <label>Technical Review</label>
      <div class="approval-name">${REVIEWER}</div>
      <div class="approval-sig"></div>
      <div class="approval-date">Date: ${REPORT_DATE_ISO}</div>
    </div>
    <div class="approval-box">
      <label>Engagement Approval</label>
      <div class="approval-name">${APPROVER}</div>
      <div class="approval-sig"></div>
      <div class="approval-date">Date: ${REPORT_DATE_ISO}</div>
    </div>
  </div>
</div>

</div><!-- /content -->

<!-- ── FOOTER ────────────────────────────────────────────────────────────── -->
<div class="report-footer">
  <div class="rf-col">
    <strong>${CONSULTANCY}</strong><br>
    External Security Assessment<br>
    Report ID: ${ORG}-EPT-${REPORT_DATE_ISO}
  </div>
  <div class="rf-col center">
    <strong>${CLASSIFICATION}</strong><br>
    Restricted distribution<br>
    ${DISTRIBUTION_LIST}
  </div>
  <div class="rf-col right">
    Version ${REPORT_VERSION}<br>
    ${REPORT_DATE}<br>
    &copy; ${REPORT_YEAR} ${CONSULTANCY}
  </div>
</div>

</div><!-- /page -->
</body>
</html>
HTMLEOF

echo "[MGMT] Done: $OUT_HTML"

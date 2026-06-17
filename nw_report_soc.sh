#!/usr/bin/env bash
# =============================================================================
#  nw_report_soc.sh  —  Berckley SOC Technical Report Generator
#  Audience : Security Operations Center / Incident Response / Red Team
#  Format   : Dark terminal aesthetic, raw evidence, verify commands,
#             remediation steps, IOCs, full scope per finding
#
#  Usage: ./nw_report_soc.sh <pentest_dir> [output.html]
# =============================================================================
set +e; set +u; set +o pipefail 2>/dev/null

PENTEST_DIR="${1:-}"
[ -z "$PENTEST_DIR" ] && { echo "Usage: $0 <pentest_dir> [output.html]"; exit 1; }
[ ! -d "$PENTEST_DIR" ] && { echo "Not found: $PENTEST_DIR"; exit 1; }
PENTEST_DIR="$(realpath "$PENTEST_DIR" 2>/dev/null || echo "$PENTEST_DIR")"
OUT_HTML="${2:-${PENTEST_DIR}/report/soc_report.html}"
mkdir -p "$(dirname "$OUT_HTML")"

echo "[SOC] Reading : $PENTEST_DIR"
echo "[SOC] Output  : $OUT_HTML"

slurp()  { [ -f "$1" ] && cat "$1" 2>/dev/null || true; }
nlines() { [ -f "$1" ] && grep -c . "$1" 2>/dev/null | tr -d ' ' || echo "0"; }
to_int() { local v="${1//[^0-9]/}"; printf '%s' "${v:-0}"; }
esc()    { sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g' 2>/dev/null || true; }

DOMAIN=$(slurp "$PENTEST_DIR/recon/input_domains.txt" | head -1 | tr -d '[:space:]')
[ -z "$DOMAIN" ] && DOMAIN="unknown"
TARGETS=$(slurp "$PENTEST_DIR/recon/input_targets.txt" | tr '\n' ',' | sed 's/,$//' || true)
[ -z "$TARGETS" ] && TARGETS="—"
SCAN_DATE=$(date "+%Y-%m-%d %H:%M UTC")
ANALYST="${ANALYST:-@nightwing}"
# Prefer validated TSV (false positives removed, severities adjusted by
# ownership). Fall back to raw scanner output if not validated yet.
if [ -f "$PENTEST_DIR/report/findings_validated.tsv" ]; then
  TSV="$PENTEST_DIR/report/findings_validated.tsv"
  TSV_SOURCE="validated"
else
  TSV="$PENTEST_DIR/report/findings.tsv"
  TSV_SOURCE="raw"
fi
RAW_TSV_PATH="$PENTEST_DIR/report/findings.tsv"

# Locate + base64-embed the brand logo if it exists in the project root.
# Walk up from the pentest dir looking for logo.png.
_find_logo() {
  local d="$PENTEST_DIR"
  for _ in 1 2 3 4 5; do
    [ -f "$d/logo.png" ] && { echo "$d/logo.png"; return; }
    d="$(dirname "$d")"
    [ "$d" = "/" ] && return
  done
}
LOGO_PATH="$(_find_logo)"
if [ -n "$LOGO_PATH" ] && command -v base64 >/dev/null 2>&1; then
  LOGO_DATA_URI="data:image/png;base64,$(base64 -w0 "$LOGO_PATH" 2>/dev/null)"
  LOGO_TAG="<img src=\"$LOGO_DATA_URI\" alt=\"Berckley\">"
else
  LOGO_TAG="<span class=\"lg-fallback\">B</span>"
fi

# Counts — unique finding TYPES. Use awk so a 0-match never produces "0\n0\n"
# (which the previous `grep -c … || echo 0` chain did, since `grep -c` exits
# 1 on no matches; the OR fallback then appended an extra "0" and to_int
# rendered "00" in the report header).
count_types() { awk -F'\t' -v sev="$1" 'BEGIN{n=0} $1==sev{key=$1"\t"$2; if(!(key in s)){s[key]=1; n++}} END{print n}' "$TSV" 2>/dev/null; }
count_rows()  { awk -F'\t' -v sev="$1" 'BEGIN{n=0} $1==sev{n++} END{print n}'             "$TSV" 2>/dev/null; }
C_CRIT=$(to_int "$(count_types CRITICAL)")
C_HIGH=$(to_int "$(count_types HIGH)")
C_MED=$( to_int "$(count_types MEDIUM)")
C_LOW=$( to_int "$(count_types LOW)")
C_TOTAL=$(( C_CRIT + C_HIGH + C_MED + C_LOW ))

# Target counts (rows = instances)
T_CRIT=$(to_int "$(count_rows CRITICAL)")
T_HIGH=$(to_int "$(count_rows HIGH)")
T_MED=$( to_int "$(count_rows MEDIUM)")
T_LOW=$( to_int "$(count_rows LOW)")

# ── Remediation command lookup ─────────────────────────────────────────────────
# Returns a shell command/tool for verifying or remediating a finding category
remediation_cmd() {
  local cat="$1" scope="$2"
  case "$cat" in
    *HSTS*)           printf 'curl -sI %s | grep -i strict\ncurl -sI http://%s' "$scope" "$scope" ;;
    *CSP*)            printf 'curl -sI %s | grep -i content-security-policy' "$scope" ;;
    *X-Frame*)        printf 'curl -sI %s | grep -i x-frame-options' "$scope" ;;
    *SPF*)            printf 'dig TXT %s | grep spf\nnmap --script dns-check-zone %s' "$scope" "$scope" ;;
    *DMARC*)          printf 'dig TXT _dmarc.%s' "$scope" ;;
    *Takeover*|*Dangling*) printf 'dig CNAME %s\ncurl -sk https://%s | head -20' "$scope" "$scope" ;;
    *Zone.Transfer*)  printf 'dig axfr %s @<nameserver>' "$scope" ;;
    *SQL.Injection*)  printf 'sqlmap -u "%s" --level 3 --risk 2 --batch' "$scope" ;;
    *XSS*)            printf '# Manual: inject <script>alert(1)</script> in reflected params\ncurl -sk "%s"' "$scope" ;;
    *Directory.List*) printf 'curl -sk %s | grep -i "index of"' "$scope" ;;
    *Open.Redirect*)  printf 'curl -skiL "%s" -w "%%{redirect_url}"' "$scope" ;;
    *GraphQL*)        printf 'curl -sk -X POST %s -H "Content-Type: application/json" -d '"'"'{"query":"{__schema{types{name}}}"}'"'"'' "$scope" ;;
    *Source.Map*)     printf 'curl -sk %s | head -5\ncurl -sk %s.map | head -5' "$scope" "$scope" ;;
    *FTP.Anon*)       printf 'ftp -n %s <<EOF\nuser anonymous anon@test.com\nls\nEOF' "$scope" ;;
    *Redis*)          printf 'redis-cli -h %s ping\nredis-cli -h %s info server' "${scope%%:*}" "${scope%%:*}" ;;
    *Docker.API*)     printf 'curl -sk http://%s/v1.41/info | jq .Name\ncurl -sk http://%s/v1.41/containers/json' "$scope" "$scope" ;;
    *Elasticsearch*)  printf 'curl -sk http://%s/_cluster/health\ncurl -sk http://%s/_cat/indices' "$scope" "$scope" ;;
    *MongoDB*)        printf 'mongosh --host %s --eval "db.adminCommand({listDatabases:1})"' "${scope%%:*}" ;;
    *SNMP*)           printf 'snmpwalk -v2c -c public %s 1.3.6.1.2.1.1\nonesixtyone -c /usr/share/doc/onesixtyone/dict.txt %s' "${scope%%:*}" "${scope%%:*}" ;;
    *LDAP*)           printf 'ldapsearch -x -H ldap://%s -b "" -s base\nldapsearch -x -H ldap://%s -b "dc=domain,dc=com"' "${scope%%:*}" "${scope%%:*}" ;;
    *NFS*)            printf 'showmount -e %s\nmount -t nfs %s:/share /tmp/nfsmount' "${scope%%:*}" "${scope%%:*}" ;;
    *SMB*)            printf 'smbclient -N -L //%s\ncrackmap exec smb %s -u "" -p ""' "${scope%%:*}" "${scope%%:*}" ;;
    *Admin.Panel*)    printf 'curl -sk %s | grep -i "login\|password\|admin"' "$scope" ;;
    *Default.Cred*)   printf '# Try: admin:admin, admin:password, root:root, test:test' ;;
    *CVE*)            local cve; cve=$(printf '%s' "$cat" | grep -oE 'CVE-[0-9-]+' | head -1)
                      [ -n "$cve" ] && printf 'nuclei -u %s -t cves/%s.yaml\n# NVD: https://nvd.nist.gov/vuln/detail/%s' "$scope" "$(echo "$cve" | tr '[:upper:]' '[:lower:]')" "$cve" \
                                    || printf 'nuclei -u %s -tags cve -severity critical,high' "$scope" ;;
    *TLS*Cert*Expir*) printf 'echo | openssl s_client -connect %s -servername %s 2>/dev/null | openssl x509 -noout -dates' "$scope" "${scope%%:*}" ;;
    *Legacy.TLS*)     printf 'nmap --script ssl-enum-ciphers -p %s %s\ntestssl.sh %s' "${scope##*:}" "${scope%%:*}" "$scope" ;;
    *Weak.Cipher*)    printf 'testssl.sh --severity MEDIUM %s\nnmap --script ssl-enum-ciphers -p 443 %s' "$scope" "${scope%%:*}" ;;
    *Memcached*)      printf 'echo "stats" | nc -w 2 %s 11211\necho "version" | nc -w 2 %s 11211' "${scope%%:*}" "${scope%%:*}" ;;
    *IKE*|*IPsec*)    printf 'ike-scan --aggressive %s\nike-scan --multiline %s' "${scope%%:*}" "${scope%%:*}" ;;
    *VNC*)            printf 'nmap --script vnc-info,vnc-brute -p 5900 %s' "${scope%%:*}" ;;
    *)                printf 'nuclei -u %s -tags misconfig,exposure -severity critical,high,medium' "$scope" ;;
  esac
}

# ── Remediation guidance lookup ────────────────────────────────────────────────
remediation_fix() {
  local cat="$1"
  case "$cat" in
    *HSTS*)        printf 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' ;;
    *CSP*)         printf 'Define restrictive CSP — avoid "unsafe-inline"/"unsafe-eval". Start with: Content-Security-Policy: default-src '"'"'self'"'"'; script-src '"'"'self'"'"'' ;;
    *X-Frame*)     printf 'Add header: X-Frame-Options: DENY (or SAMEORIGIN for embedded content)' ;;
    *X-Content*)   printf 'Add header: X-Content-Type-Options: nosniff' ;;
    *SPF*)         printf 'Create TXT record: "v=spf1 ip4:<mailserver-ip> include:<provider> -all" — use -all not ~all' ;;
    *DMARC*)       printf 'Create TXT record on _dmarc.<domain>: "v=DMARC1; p=reject; rua=mailto:dmarc@<domain>; pct=100"' ;;
    *Zone.Transfer*) printf 'Restrict AXFR to authorised IPs only. In BIND: allow-transfer { <secondary-ns-ip>; };' ;;
    *Takeover*)    printf 'Remove stale CNAME record or re-claim the service. Audit all CNAMEs quarterly.' ;;
    *SQL*)         printf 'Use parameterised queries / prepared statements. Apply input validation and WAF rules. Run sqlmap to confirm scope.' ;;
    *XSS*)         printf 'HTML-encode all user input on output. Implement strict CSP. Use framework auto-escaping.' ;;
    *Directory.List*) printf 'Disable directory listing: Apache: Options -Indexes | Nginx: autoindex off; | IIS: disable Directory Browsing' ;;
    *Open.Redirect*) printf 'Whitelist allowed redirect targets. Reject or sanitise external URLs. Use relative paths where possible.' ;;
    *GraphQL*)     printf 'Disable introspection in production: Apollo: introspection: false | Yoga: disableIntrospection plugin' ;;
    *FTP.Anon*)    printf 'Disable anonymous FTP login. Migrate to SFTP/SCP. If FTP required, enforce authentication.' ;;
    *Redis*)       printf 'Bind Redis to 127.0.0.1 only. Set requirepass in redis.conf. Use firewall rules to block port 6379 externally.' ;;
    *Docker.API*)  printf 'Remove -H tcp:// from Docker daemon. Use Unix socket only. If remote API required, enable TLS mutual auth.' ;;
    *Elasticsearch*) printf 'Enable X-Pack security. Set xpack.security.enabled: true. Bind to localhost or VPN only.' ;;
    *MongoDB*)     printf 'Enable --auth flag. Create admin user. Bind to 127.0.0.1 or VPN. Disable --smallfiles.' ;;
    *SNMP*)        printf 'Disable SNMPv1/v2c. Migrate to SNMPv3 with authPriv. Change community strings from defaults. Firewall UDP 161.' ;;
    *LDAP.Anon*)   printf 'Disable anonymous bind in AD: dSHeuristics = 0000002. Require LDAP signing and channel binding.' ;;
    *NFS*)         printf 'Restrict exports: use /etc/exports with specific host IPs, not *. Add no_root_squash only if required.' ;;
    *SMB*)         printf 'Disable SMBv1. Require SMB signing. Block port 445 externally. Audit null session access: net config server' ;;
    *Memcached*)   printf 'Bind to 127.0.0.1 only (-l 127.0.0.1). Block port 11211 externally. Upgrade to version with SASL auth.' ;;
    *IKE*)         printf 'Disable IKEv1 aggressive mode. Require IKEv2 with certificate auth. Restrict access to known peer IPs.' ;;
    *VNC*)         printf 'Enable VNC authentication and set strong password. Prefer NLA/SSH tunnel. Block port 5900 externally.' ;;
    *Default.Cred*) printf 'Change all default credentials immediately. Implement password policy. Consider MFA for admin interfaces.' ;;
    *CVE*)         printf 'Apply vendor security patch. Check https://nvd.nist.gov for affected versions and patch availability.' ;;
    *TLS*Expir*)   printf 'Renew certificate before expiry. Consider Let'\''s Encrypt with auto-renewal or Certificate Manager.' ;;
    *Legacy.TLS*)  printf 'Disable TLS 1.0/1.1 and SSLv3. Config: ssl_protocols TLSv1.2 TLSv1.3; (nginx) or SSLProtocol TLSv1.2+ (Apache)' ;;
    *Weak.Cipher*) printf 'Remove RC4, 3DES, EXPORT ciphers. Use: ssl_ciphers HIGH:!aNULL:!MD5:!RC4:!3DES (nginx)' ;;
    *CORS*)        printf 'Set explicit origin whitelist. Never use wildcard (*) with credentials. Remove Access-Control-Allow-Origin: * on authenticated endpoints.' ;;
    *Admin.Panel*) printf 'Restrict admin paths to VPN/internal network via firewall or nginx geo-restriction. Require MFA.' ;;
    *Error.Disc*)  printf 'Set DEBUG=False in production. Configure custom error pages. Suppress stack traces externally.' ;;
    *Mixed.Content*) printf 'Update all resource URLs to https://. Check Content-Security-Policy: upgrade-insecure-requests directive.' ;;
    *)             printf 'Review finding, apply principle of least privilege, update to latest version, and verify with re-test.' ;;
  esac
}

echo "[SOC] Building findings cards..."

# ── Build finding cards ────────────────────────────────────────────────────────
CARDS_CRIT="" CARDS_HIGH="" CARDS_MED="" CARDS_LOW=""

build_soc_cards() {
  local sev_filter="$1" out_var="$2"
  [ ! -f "$TSV" ] && { eval "$out_var=\"\""; return; }
  local cats; cats=$(grep "^${sev_filter}" "$TSV" 2>/dev/null | cut -f2 | sort -u || true)
  [ -z "$cats" ] && { eval "$out_var=\"\""; return; }
  local html="" TAB; TAB="$(printf '\011')"
  local card_num=0

  while IFS= read -r cat; do
    [ -z "$cat" ] && continue
    card_num=$(( card_num + 1 ))
    # Use awk with literal field-equality compare instead of grep BRE — the
    # previous sed-escape over-escaped `(` and `)` which in BRE become group
    # markers, so any finding whose name contained parens (e.g. "Missing
    # HSTS (HTTP Strict Transport Security)") matched zero rows.
    local first_row; first_row=$(awk -F'\t' -v s="$sev_filter" -v c="$cat" \
      '$1==s && $2==c {print; exit}' "$TSV")
    [ -z "$first_row" ] && continue

    local fsev; fsev=$(printf '%s' "$first_row" | cut -f1)
    local fdesc; fdesc=$(printf '%s' "$first_row" | cut -f4 | esc)
    local cls; case "$fsev" in CRITICAL) cls="crit";; HIGH) cls="high";; MEDIUM) cls="med";; LOW) cls="low";; *) cls="low";; esac

    # All affected scopes for this category
    local scopes; scopes=$(awk -F'\t' -v s="$sev_filter" -v c="$cat" \
      '$1==s && $2==c {print $3}' "$TSV" | sort -u)
    local scope_count; scope_count=$(printf '%s' "$scopes" | grep -c . || echo 0)

    # Build scope list (pills + copy-friendly list)
    local scope_pills="" scope_list_text=""
    while IFS= read -r sc; do
      [ -z "$sc" ] && continue
      local se; se=$(printf '%s' "$sc" | esc)
      scope_pills="${scope_pills}<span class='scope-pill ${cls}'>${se}</span>"
      scope_list_text="${scope_list_text}${sc}\n"
    done <<< "$scopes"

    # First scope for commands
    local first_scope; first_scope=$(printf '%s' "$scopes" | head -1)
    local verify_cmd; verify_cmd=$(remediation_cmd "$cat" "$first_scope" | esc)
    local fix_guidance; fix_guidance=$(remediation_fix "$cat" | esc)

    local cat_esc; cat_esc=$(printf '%s' "$cat" | esc)
    local card_id; card_id="${fsev}_$(printf '%s' "$cat" | tr -cs 'a-zA-Z0-9' '_' | sed 's/_*$//')_${card_num}"

    html="${html}
<div class='fc ${cls}' id='${card_id}'>
  <div class='fc-header'>
    <div class='fc-header-left'>
      <span class='sev-badge ${cls}'>${fsev}</span>
      <div class='fc-title-block'>
        <div class='fc-title'>${cat_esc}</div>
        <div class='fc-desc'>${fdesc}</div>
      </div>
    </div>
    <div class='fc-meta'>
      <span class='meta-chip'>${scope_count} target$([ "$scope_count" -ne 1 ] && echo s || true)</span>
    </div>
  </div>
  <div class='fc-body'>
    <div class='fc-section'>
      <div class='section-label'>Affected Scope</div>
      <div class='scope-pills'>${scope_pills}</div>
    </div>
    <div class='fc-row2'>
      <div class='fc-section'>
        <div class='section-label'>Verification Command</div>
        <pre class='cmd-block'>${verify_cmd}</pre>
      </div>
      <div class='fc-section'>
        <div class='section-label'>Remediation</div>
        <div class='fix-text'>${fix_guidance}</div>
      </div>
    </div>
  </div>
</div>"
  done <<< "$cats"
  eval "$out_var=\"\$html\""
}

build_soc_cards CRITICAL CARDS_CRIT
build_soc_cards HIGH     CARDS_HIGH
build_soc_cards MEDIUM   CARDS_MED
build_soc_cards LOW      CARDS_LOW

# Discovery data
LIVE_COUNT=$(to_int "$(nlines "$PENTEST_DIR/recon/live_hosts.txt")")
SUBS_COUNT=$(to_int "$(nlines "$PENTEST_DIR/recon/subs_master.txt")")
EXPOSED_COUNT=$(to_int "$(nlines "$PENTEST_DIR/recon/exposed_paths.txt")")
NUCLEI_COUNT=$(to_int "$(nlines "$PENTEST_DIR/cve/nuclei_results.txt")")
TAKEOVER_COUNT=$(to_int "$(nlines "$PENTEST_DIR/dns/takeover.txt")")

echo "[SOC] Writing HTML..."
{
cat << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Report — ${DOMAIN} — ${SCAN_DATE}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
:root{
  /* aligned with the berckley dashboard design system */
  --bg:#050608;
  --bg-1:#0a0d11;
  --bg-2:#0e1217;
  --bg-3:#141921;
  --s1:#0a0d11;
  --s2:#0e1217;
  --b1:#1c232c;
  --b2:#27313d;

  --crit:#ff3b5c; --high:#ff8c1a; --med:#ffd400; --low:#6ec1ff;
  --cyan:#00d8ff; --cyan2:#66e3ff; --cyan3:#00a3c4;
  --grn:#3ddc97;
  --txt:#e6ecf2; --hd:#f3f7fb; --dim:#4d5965; --soft:#8694a3;

  --mono:'JetBrains Mono','Fira Code',ui-monospace,monospace;
  --bd:'Inter',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  --disp:'Space Grotesk','Inter',sans-serif;

  --r:6px;
  --shadow-card:0 1px 0 rgba(255,255,255,.025) inset,0 0 0 1px var(--b1),0 12px 32px rgba(0,0,0,.55);
  --shadow-glow:0 0 1px rgba(0,216,255,.5),0 0 14px rgba(0,216,255,.08);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{
  background-color:var(--bg); color:var(--txt);
  font-family:var(--bd); font-size:13.5px; line-height:1.55;
  display:flex; min-height:100vh;
  -webkit-font-smoothing:antialiased;
  text-rendering:optimizeLegibility;
  background-image:
    radial-gradient(1100px 700px at 12% -10%, rgba(0,216,255,.055), transparent 55%),
    radial-gradient(900px 600px at 110% 110%, rgba(102,227,255,.030), transparent 55%),
    url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='28' height='32' viewBox='0 0 28 32'><path d='M14 0l14 8v16L14 32 0 24V8z' fill='none' stroke='%23005a78' stroke-opacity='0.085' stroke-width='0.6'/></svg>"),
    repeating-linear-gradient(0deg, rgba(255,255,255,0.007) 0 1px, transparent 1px 3px);
  background-attachment:fixed;
}
::selection{background:rgba(0,216,255,.28); color:#fff}

/* SIDEBAR */
.sidebar{
  width:240px; flex-shrink:0;
  background:linear-gradient(180deg, var(--bg-1), #03050a 80%);
  border-right:1px solid var(--b1);
  display:flex; flex-direction:column;
  position:sticky; top:0; height:100vh; overflow-y:auto;
}
.sb-logo{padding:20px 18px 14px; border-bottom:1px solid var(--b1); display:flex; align-items:center; gap:12px}
.sb-logo .lg-frame{
  width:40px; height:40px; flex-shrink:0;
  display:grid; place-items:center;
  border:1px solid var(--b2); border-radius:8px;
  background:radial-gradient(circle at 30% 30%, rgba(0,216,255,.1), transparent 60%), #060809;
  box-shadow:0 0 0 1px rgba(0,216,255,.10), 0 4px 12px rgba(0,0,0,.6);
}
.sb-logo .lg-frame img{width:32px; height:32px; object-fit:contain;
  filter:drop-shadow(0 0 6px rgba(0,216,255,.4))}
.sb-logo .lg-frame .lg-fallback{
  font-family:var(--disp); font-weight:700; color:var(--cyan); font-size:13px;
}
.sb-logo .title{
  font-family:var(--disp); font-size:15px; font-weight:700;
  letter-spacing:-.01em; color:var(--hd);
  background:linear-gradient(180deg, #fff, #b9d8e6);
  -webkit-background-clip:text; background-clip:text;
  -webkit-text-fill-color:transparent;
}
.sb-logo .sub{font-size:10.5px; color:var(--soft); margin-top:2px;
  font-family:var(--bd); font-weight:500; letter-spacing:.02em}
.sb-section{
  font-family:var(--bd); font-size:10px; letter-spacing:.12em; text-transform:uppercase;
  color:var(--dim); padding:18px 18px 8px; font-weight:600;
}
.sb-item{
  display:flex; align-items:center; gap:8px; padding:8px 18px;
  font-size:12px; cursor:pointer; color:var(--soft);
  border-left:2px solid transparent;
  transition:all .15s cubic-bezier(.2,.8,.2,1);
  text-decoration:none;
  font-family:var(--bd); font-weight:500;
}
.sb-item:hover{background:rgba(0,216,255,.04); color:var(--hd); border-left-color:rgba(0,216,255,.35)}
.sb-item.active{background:linear-gradient(90deg, rgba(0,216,255,.08), transparent 60%);
  color:var(--cyan); border-left-color:var(--cyan);
  box-shadow:inset 0 0 30px rgba(0,216,255,.04)}
.sb-item .sbi-cnt{
  margin-left:auto;
  font-family:var(--mono); font-size:10px; font-weight:700;
  padding:1px 7px; border-radius:4px;
  font-variant-numeric:tabular-nums;
}
.sb-item.has-crit .sbi-cnt{background:rgba(255,59,92,.12); color:var(--crit); border:1px solid rgba(255,59,92,.3)}
.sb-item.has-high .sbi-cnt{background:rgba(255,140,26,.12); color:var(--high); border:1px solid rgba(255,140,26,.3)}
.sb-item.has-med  .sbi-cnt{background:rgba(255,212,0,.10); color:var(--med); border:1px solid rgba(255,212,0,.25)}
.sb-item.has-low  .sbi-cnt{background:rgba(110,193,255,.10); color:var(--low); border:1px solid rgba(110,193,255,.25)}
.sb-divider{height:1px; background:var(--b1); margin:10px 0}

/* MAIN */
.main{flex:1; min-width:0; padding:0}

/* HEADER BAR */
.hbar{
  background:linear-gradient(180deg, rgba(10,13,17,.92), rgba(5,6,8,.88));
  backdrop-filter:blur(12px) saturate(140%);
  -webkit-backdrop-filter:blur(12px) saturate(140%);
  border-bottom:1px solid var(--b1);
  padding:16px 32px;
  display:flex; align-items:center; gap:18px;
  position:sticky; top:0; z-index:50;
}
.hbar-title{
  font-family:var(--disp); font-size:13px; font-weight:600;
  color:var(--cyan); letter-spacing:.02em;
  text-shadow:0 0 8px rgba(0,216,255,.3);
  text-transform:uppercase;
}
.hbar-domain{font-family:var(--mono); font-size:12px; color:var(--hd); font-weight:500}
.hbar-sep{color:var(--b2); font-size:16px}
.hbar-meta{
  font-family:var(--mono); font-size:11px; color:var(--soft);
  margin-left:auto; display:flex; gap:18px;
  font-variant-numeric:tabular-nums;
}
.hbar-meta span{display:flex; align-items:center; gap:5px}

/* SECTIONS — match dashboard's panel-head pattern */
.section{padding:32px 32px; border-bottom:1px solid var(--b1)}
.sec-hdr{
  font-family:var(--disp);
  font-size:18px; font-weight:700;
  letter-spacing:-.015em;
  color:var(--hd);
  margin-bottom:18px;
  display:flex; align-items:center; gap:12px;
  padding-bottom:10px;
  border-bottom:1px solid var(--b1);
  position:relative;
}
.sec-hdr::before{
  content:"›"; color:var(--cyan); font-weight:700; font-size:20px;
  text-shadow:0 0 10px var(--cyan); font-family:var(--mono);
}
.sec-hdr::after{content:''; flex:1}
.sec-hdr span{
  background:var(--bg-2); padding:3px 10px; border-radius:999px;
  font-size:10.5px; color:var(--soft); font-weight:500;
  border:1px solid var(--b1);
  font-family:var(--bd); letter-spacing:0; text-transform:none;
}

/* STAT GRID — cards matching the dashboard sev-grid */
.stat-grid{
  display:grid; grid-template-columns:repeat(4,1fr) 1px repeat(4,1fr);
  gap:10px; margin-bottom:24px;
}
.stat-div{display:none}
.stat{
  position:relative;
  background:linear-gradient(180deg, var(--bg-2), var(--bg-1));
  border:1px solid var(--b1); border-radius:10px;
  padding:18px 16px; text-align:left;
  box-shadow:var(--shadow-card);
  overflow:hidden;
  transition:transform .18s cubic-bezier(.2,.8,.2,1), border-color .2s;
}
.stat::before{content:''; position:absolute; left:0; top:0; bottom:0; width:3px; background:var(--cyan); opacity:.8}
.stat::after{content:''; position:absolute; left:0; right:0; top:0; height:1px;
  background:linear-gradient(90deg, transparent, rgba(255,255,255,.06), transparent)}
.stat:hover{transform:translateY(-2px); border-color:rgba(0,216,255,.20)}
.stat.crit::before{background:var(--crit)}
.stat.high::before{background:var(--high)}
.stat.med::before{background:var(--med)}
.stat.low::before{background:var(--low)}
.stat.disc::before{background:var(--cyan)}
.stat .n{
  font-family:var(--disp); font-size:34px; font-weight:700;
  line-height:1; display:block; letter-spacing:-.03em;
  font-variant-numeric:tabular-nums;
}
.stat.crit .n{color:var(--crit); text-shadow:0 0 16px rgba(255,59,92,.40)}
.stat.high .n{color:var(--high); text-shadow:0 0 14px rgba(255,140,26,.30)}
.stat.med  .n{color:var(--med);  text-shadow:0 0 14px rgba(255,212,0,.25)}
.stat.low  .n{color:var(--low);  text-shadow:0 0 14px rgba(110,193,255,.30)}
.stat.disc .n{color:var(--cyan); text-shadow:0 0 14px rgba(0,216,255,.35)}
.stat .l{
  font-family:var(--bd); font-size:10.5px; font-weight:600;
  letter-spacing:.12em; text-transform:uppercase;
  color:var(--soft); margin-top:8px; display:block;
}
.stat .sub{
  font-size:11px; color:var(--soft); font-family:var(--mono);
  margin-top:4px; font-variant-numeric:tabular-nums;
}

/* FINDING CARD */
.fc{
  border:1px solid var(--b1); border-radius:8px; margin-bottom:14px;
  overflow:hidden;
  background:linear-gradient(180deg, var(--bg-2), var(--bg-1));
  box-shadow:var(--shadow-card);
  transition:border-color .2s, box-shadow .2s;
}
.fc:hover{border-color:rgba(0,216,255,.18)}
.fc.crit{border-left:3px solid var(--crit)}
.fc.high{border-left:3px solid var(--high)}
.fc.med {border-left:3px solid var(--med)}
.fc.low {border-left:3px solid var(--low)}
.fc-header{
  padding:14px 16px; display:flex;
  align-items:flex-start; justify-content:space-between;
  border-bottom:1px solid var(--b1);
  background:linear-gradient(180deg, rgba(255,255,255,.015), transparent);
}
.fc-header-left{display:flex; align-items:flex-start; gap:12px; flex:1}
.sev-badge{
  font-family:var(--bd); font-size:10px; font-weight:700;
  letter-spacing:.06em; padding:3px 9px;
  border-radius:4px; white-space:nowrap;
  flex-shrink:0; margin-top:2px;
  text-transform:uppercase;
}
.sev-badge.crit{background:rgba(255,59,92,.10); color:var(--crit); border:1px solid rgba(255,59,92,.35)}
.sev-badge.high{background:rgba(255,140,26,.10); color:var(--high); border:1px solid rgba(255,140,26,.35)}
.sev-badge.med {background:rgba(255,212,0,.08); color:var(--med); border:1px solid rgba(255,212,0,.30)}
.sev-badge.low {background:rgba(110,193,255,.08); color:var(--low); border:1px solid rgba(110,193,255,.30)}
.fc-title{
  font-family:var(--disp); font-size:14.5px; font-weight:600;
  color:var(--hd); line-height:1.3; letter-spacing:-.01em;
}
.fc-desc{
  font-family:var(--bd); font-size:13px;
  color:var(--soft); margin-top:6px; line-height:1.55;
}
.fc-meta{flex-shrink:0; display:flex; gap:6px; align-items:center}
.meta-chip{
  font-family:var(--mono); font-size:10.5px; padding:2px 8px;
  border-radius:999px; background:var(--bg-2);
  color:var(--soft); border:1px solid var(--b1);
  font-variant-numeric:tabular-nums;
}
.fc-body{padding:14px 16px; background:rgba(0,0,0,.18)}
.fc-section{margin-bottom:14px}
.fc-section:last-child{margin-bottom:0}
.fc-row2{display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-top:12px}
.section-label{
  font-family:var(--bd); font-size:10.5px; font-weight:600;
  letter-spacing:.08em; text-transform:uppercase;
  color:var(--soft); margin-bottom:8px;
  display:flex; align-items:center; gap:6px;
}
.section-label::before{
  content:""; width:4px; height:4px; border-radius:50%;
  background:var(--cyan); box-shadow:0 0 6px var(--cyan);
}
.scope-pills{display:flex; flex-wrap:wrap; gap:6px}
.scope-pill{
  font-family:var(--mono); font-size:11px; padding:3px 10px;
  border-radius:4px; white-space:nowrap; word-break:break-all;
  font-weight:500;
}
.scope-pill.crit{background:rgba(255,59,92,.06); border:1px solid rgba(255,59,92,.28); color:var(--crit)}
.scope-pill.high{background:rgba(255,140,26,.06); border:1px solid rgba(255,140,26,.28); color:var(--high)}
.scope-pill.med {background:rgba(255,212,0,.05); border:1px solid rgba(255,212,0,.25); color:var(--med)}
.scope-pill.low {background:rgba(110,193,255,.05); border:1px solid rgba(110,193,255,.25); color:var(--low)}
.cmd-block{
  font-family:var(--mono); font-size:11px;
  background:#02060a; border:1px solid var(--b1); border-radius:6px;
  padding:10px 12px; white-space:pre-wrap; word-break:break-all;
  color:var(--cyan2); line-height:1.65;
  cursor:pointer; transition:border-color .15s, box-shadow .2s;
  position:relative;
}
.cmd-block::before{
  content:"$"; color:var(--dim); margin-right:8px; font-weight:700;
}
.cmd-block:hover{border-color:var(--cyan); box-shadow:var(--shadow-glow)}
.fix-text{
  font-size:12.5px; color:var(--txt); line-height:1.6;
  background:var(--bg-2); border:1px solid var(--b1);
  border-radius:6px; padding:10px 12px;
  font-family:var(--bd);
}

/* PRE (raw data) */
pre.raw{
  font-family:var(--mono); font-size:11.5px; line-height:1.65;
  color:var(--soft);
  background:#02060a; border:1px solid var(--b1); border-radius:6px;
  padding:14px 16px; overflow-x:auto;
  white-space:pre-wrap; word-break:break-all;
  max-height:420px; overflow-y:auto;
  box-shadow:inset 0 0 30px rgba(0,216,255,.03);
}

/* TABLE */
.dtbl{
  width:100%; border-collapse:collapse;
  font-family:var(--mono); font-size:12px;
  background:linear-gradient(180deg, var(--bg-2), var(--bg-1));
  border:1px solid var(--b1); border-radius:8px; overflow:hidden;
}
.dtbl th{
  font-family:var(--bd); font-size:10.5px; font-weight:600;
  letter-spacing:.06em; text-transform:uppercase;
  color:var(--soft);
  padding:9px 14px; text-align:left;
  border-bottom:1px solid var(--b1);
  background:rgba(10,13,17,.55);
}
.dtbl td{padding:9px 14px; border-bottom:1px solid var(--line-soft, #131820); vertical-align:top}
.dtbl tr:hover{background:rgba(0,216,255,.03)}
.dtbl td.url{color:var(--cyan2); word-break:break-all}
.dtbl td.hi{color:var(--hd); font-weight:500}

/* EMPTY */
.empty{
  text-align:center; padding:36px;
  color:var(--dim); font-family:var(--bd); font-size:12px;
  font-style:italic; letter-spacing:.04em;
  border:1px dashed var(--b1); border-radius:8px;
}

/* TABS */
.tabs{
  display:flex; border-bottom:1px solid var(--b1);
  margin-bottom:14px; flex-wrap:wrap; gap:0;
}
.tab{
  font-family:var(--bd); font-size:12px; font-weight:500;
  letter-spacing:-.005em;
  padding:10px 16px; cursor:pointer;
  color:var(--soft); border-bottom:2px solid transparent;
  margin-bottom:-1px; transition:color .15s;
  background:transparent; border-top:0; border-left:0; border-right:0;
  text-transform:none;
}
.tab:hover{color:var(--hd)}
.tab.active{color:var(--cyan); border-bottom-color:var(--cyan); font-weight:600;
  box-shadow:0 2px 12px rgba(0,216,255,.25)}
.tp{display:none}
.tp.active{display:block}

/* ALERT */
.alert{
  padding:12px 14px; border-radius:6px;
  font-family:var(--bd); font-size:12.5px; font-weight:500;
  margin-bottom:14px; border-left:3px solid;
  line-height:1.5;
}
.alert.crit{background:rgba(255,59,92,.06); border-color:var(--crit); color:var(--crit)}
.alert.high{background:rgba(255,140,26,.06); border-color:var(--high); color:var(--high)}
.alert.info{background:rgba(0,216,255,.05); border-color:var(--cyan); color:var(--cyan2)}

/* COPY TOAST */
.toast{
  position:fixed; bottom:20px; right:20px;
  background:linear-gradient(180deg, #093, #062);
  color:#fff; font-family:var(--bd); font-weight:600; font-size:12px;
  padding:10px 16px; border-radius:6px;
  opacity:0; transform:translateY(10px);
  transition:opacity .25s, transform .25s;
  pointer-events:none; z-index:999;
  box-shadow:0 8px 24px rgba(0,0,0,.5), 0 0 20px rgba(61,220,151,.3);
}
.toast.show{opacity:1; transform:translateY(0)}

/* FOOTER */
footer{
  padding:18px 32px; border-top:1px solid var(--b1);
  font-family:var(--mono); font-size:11px; color:var(--dim);
  display:flex; justify-content:space-between;
  background:linear-gradient(180deg, transparent, rgba(10,13,17,.5));
}
footer b{color:var(--cyan); font-weight:700}

/* SCROLLBAR */
::-webkit-scrollbar{width:10px; height:10px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:#0c1820; border:1px solid var(--b1); border-radius:1px}
::-webkit-scrollbar-thumb:hover{background:#103040}
</style>
</head>
<body>

<!-- SIDEBAR -->
<div class="sidebar">
  <div class="sb-logo">
    <div class="lg-frame">${LOGO_TAG}</div>
    <div>
      <div class="title">Berckley</div>
      <div class="sub">SOC · Technical</div>
    </div>
  </div>
  <div class="sb-section">Findings</div>
  <a class="sb-item has-crit" href="#crit">
    <span>&#9679; Critical</span><span class="sbi-cnt">${C_CRIT}</span>
  </a>
  <a class="sb-item has-high" href="#high">
    <span>&#9679; High</span><span class="sbi-cnt">${C_HIGH}</span>
  </a>
  <a class="sb-item has-med" href="#medium">
    <span>&#9679; Medium</span><span class="sbi-cnt">${C_MED}</span>
  </a>
  <a class="sb-item has-low" href="#low">
    <span>&#9679; Low</span><span class="sbi-cnt">${C_LOW}</span>
  </a>
  <div class="sb-divider"></div>
  <div class="sb-section">Intelligence</div>
  <a class="sb-item" href="#discovery">&#9656; Discovery</a>
  <a class="sb-item" href="#dns">&#9656; DNS Audit</a>
  <a class="sb-item" href="#ports">&#9656; Port Scan</a>
  <a class="sb-item" href="#tls">&#9656; TLS/SSL</a>
  <a class="sb-item" href="#nuclei">&#9656; Nuclei</a>
  <a class="sb-item" href="#raw">&#9656; Raw Findings</a>
</div>

<!-- MAIN -->
<div class="main">

<!-- HEADER -->
<div class="hbar">
  <span class="hbar-title">SOC // External Pentest</span>
  <span class="hbar-sep">|</span>
  <span class="hbar-domain">${DOMAIN}</span>
  <div class="hbar-meta">
    <span>📅 ${SCAN_DATE}</span>
    <span>👤 ${ANALYST}</span>
  </div>
</div>

<!-- OVERVIEW -->
<div class="section">
  <div class="sec-hdr">Overview <span>${C_TOTAL} finding types</span></div>
  <div class="stat-grid">
    <div class="stat crit"><span class="n">${C_CRIT}</span><span class="l">Critical</span><span class="sub">${T_CRIT} instance$([ "$T_CRIT" -ne 1 ] && echo s)</span></div>
    <div class="stat high"><span class="n">${C_HIGH}</span><span class="l">High</span><span class="sub">${T_HIGH} instance$([ "$T_HIGH" -ne 1 ] && echo s)</span></div>
    <div class="stat med"><span class="n">${C_MED}</span><span class="l">Medium</span><span class="sub">${T_MED} instance$([ "$T_MED" -ne 1 ] && echo s)</span></div>
    <div class="stat low"><span class="n">${C_LOW}</span><span class="l">Low</span><span class="sub">${T_LOW} instance$([ "$T_LOW" -ne 1 ] && echo s)</span></div>
    <div class="stat-div"></div>
    <div class="stat disc"><span class="n">${SUBS_COUNT}</span><span class="l">Subdomains</span></div>
    <div class="stat disc"><span class="n">${LIVE_COUNT}</span><span class="l">Live Hosts</span></div>
    <div class="stat disc"><span class="n">${EXPOSED_COUNT}</span><span class="l">Exposed Paths</span></div>
    <div class="stat disc"><span class="n">${NUCLEI_COUNT}</span><span class="l">Nuclei Hits</span></div>
  </div>
</div>
HTMLEOF

# ── CRITICAL ──
printf '<div class="section" id="crit">\n'
printf '<div class="sec-hdr">Critical Findings <span>immediate action required</span></div>\n'
if [ -n "$CARDS_CRIT" ]; then
  [ "$TAKEOVER_COUNT" -gt 0 ] && \
    printf '<div class="alert crit">!! %s subdomain takeover candidate(s) — verify immediately</div>\n' "$TAKEOVER_COUNT"
  printf '%s\n' "$CARDS_CRIT"
else
  printf '<div class="empty">No Critical findings</div>\n'
fi
printf '</div>\n'

# ── HIGH ──
printf '<div class="section" id="high">\n'
printf '<div class="sec-hdr">High Findings <span>remediate within sprint</span></div>\n'
[ -n "$CARDS_HIGH" ] && printf '%s\n' "$CARDS_HIGH" || printf '<div class="empty">No High findings</div>\n'
printf '</div>\n'

# ── MEDIUM ──
printf '<div class="section" id="medium">\n'
printf '<div class="sec-hdr">Medium Findings <span>remediate within quarter</span></div>\n'
[ -n "$CARDS_MED" ] && printf '%s\n' "$CARDS_MED" || printf '<div class="empty">No Medium findings</div>\n'
printf '</div>\n'

# ── LOW ──
printf '<div class="section" id="low">\n'
printf '<div class="sec-hdr">Low Findings <span>track and remediate</span></div>\n'
[ -n "$CARDS_LOW" ] && printf '%s\n' "$CARDS_LOW" || printf '<div class="empty">No Low findings</div>\n'
printf '</div>\n'

# ── DISCOVERY ──
LIVE_DATA=$(slurp "$PENTEST_DIR/recon/live_hosts.txt" | esc)
SUBS_DATA=$(slurp "$PENTEST_DIR/recon/subs_master.txt" | esc)
EXPOSED_DATA=$(slurp "$PENTEST_DIR/recon/exposed_paths.txt" | esc)
printf '<div class="section" id="discovery">\n'
printf '<div class="sec-hdr">Discovery <span>full scan data</span></div>\n'
printf '<div class="tabs">\n'
printf '<div class="tab active" onclick="sw('"'"'disc'"'"','"'"'lh'"'"',this)">Live Hosts (%s)</div>\n' "$LIVE_COUNT"
printf '<div class="tab" onclick="sw('"'"'disc'"'"','"'"'sb'"'"',this)">Subdomains (%s)</div>\n' "$SUBS_COUNT"
printf '<div class="tab" onclick="sw('"'"'disc'"'"','"'"'ep'"'"',this)">Exposed Paths (%s)</div>\n' "$EXPOSED_COUNT"
printf '</div>\n'
printf '<div id="pdiscslh" class="tp active">%s</div>\n' \
  "$( [ -n "$LIVE_DATA" ] && printf '<pre class="raw">%s</pre>' "$LIVE_DATA" || printf '<div class="empty">No live hosts</div>')"
printf '<div id="pdiscsb" class="tp">%s</div>\n' \
  "$( [ -n "$SUBS_DATA" ] && printf '<pre class="raw">%s</pre>' "$SUBS_DATA" || printf '<div class="empty">No subdomains</div>')"
printf '<div id="pdiscep" class="tp">%s</div>\n' \
  "$( [ -n "$EXPOSED_DATA" ] && printf '<pre class="raw">%s</pre>' "$EXPOSED_DATA" || printf '<div class="empty">No exposed paths</div>')"
printf '</div>\n'

# ── DNS ──
DNS_REC=$(slurp "$PENTEST_DIR/dns/records_${DOMAIN}.txt" | head -80 | esc)
EMAIL_SEC=$(slurp "$PENTEST_DIR/dns/email_security_${DOMAIN}.txt" | esc)
TAKEOVER_D=$(slurp "$PENTEST_DIR/dns/takeover.txt" | esc)
printf '<div class="section" id="dns">\n'
printf '<div class="sec-hdr">DNS Audit <span>%s</span></div>\n' "$DOMAIN"
printf '<div class="tabs"><div class="tab active" onclick="sw('"'"'dns'"'"','"'"'r'"'"',this)">Records</div>'
printf '<div class="tab" onclick="sw('"'"'dns'"'"','"'"'e'"'"',this)">Email Security</div>'
printf '<div class="tab" onclick="sw('"'"'dns'"'"','"'"'t'"'"',this)">Takeover Candidates</div></div>\n'
printf '<div id="pdnsr" class="tp active">%s</div>\n' "$( [ -n "$DNS_REC" ] && printf '<pre class="raw">%s</pre>' "$DNS_REC" || printf '<div class="empty">No data</div>')"
printf '<div id="pdnse" class="tp">%s</div>\n'        "$( [ -n "$EMAIL_SEC" ] && printf '<pre class="raw">%s</pre>' "$EMAIL_SEC" || printf '<div class="empty">No data</div>')"
printf '<div id="pdnst" class="tp">%s</div>\n'        "$( [ -n "$TAKEOVER_D" ] && printf '<pre class="raw">%s</pre>' "$TAKEOVER_D" || printf '<div class="empty">None</div>')"
printf '</div>\n'

# ── PORT SCAN ──
NMAP_DATA=$(slurp "$PENTEST_DIR/recon/nmap_scan.nmap" | head -200 | esc)
MASSCAN_DATA=$(slurp "$PENTEST_DIR/recon/masscan_results.txt" | head -100 | esc)
SPLOIT_DATA=$(slurp "$PENTEST_DIR/recon/searchsploit_results.txt" | head -100 | esc)
printf '<div class="section" id="ports">\n'
printf '<div class="sec-hdr">Port Scan <span>nmap + masscan</span></div>\n'
printf '<div class="tabs"><div class="tab active" onclick="sw('"'"'ps'"'"','"'"'nm'"'"',this)">Nmap</div>'
printf '<div class="tab" onclick="sw('"'"'ps'"'"','"'"'ms'"'"',this)">Masscan</div>'
printf '<div class="tab" onclick="sw('"'"'ps'"'"','"'"'sp'"'"',this)">Searchsploit</div></div>\n'
printf '<div id="ppsnm" class="tp active">%s</div>\n' "$( [ -n "$NMAP_DATA" ] && printf '<pre class="raw">%s</pre>' "$NMAP_DATA" || printf '<div class="empty">No nmap results</div>')"
printf '<div id="ppsms" class="tp">%s</div>\n'        "$( [ -n "$MASSCAN_DATA" ] && printf '<pre class="raw">%s</pre>' "$MASSCAN_DATA" || printf '<div class="empty">No masscan results</div>')"
printf '<div id="ppssp" class="tp">%s</div>\n'        "$( [ -n "$SPLOIT_DATA" ] && printf '<pre class="raw">%s</pre>' "$SPLOIT_DATA" || printf '<div class="empty">No searchsploit matches</div>')"
printf '</div>\n'

# ── TLS ──
HSTS_DATA=$(slurp "$PENTEST_DIR/tls/hsts_audit.txt" | esc)
printf '<div class="section" id="tls">\n'
printf '<div class="sec-hdr">TLS / SSL Audit</div>\n'
[ -n "$HSTS_DATA" ] && printf '<pre class="raw">%s</pre>\n' "$HSTS_DATA" \
                     || printf '<div class="empty">No TLS data</div>\n'
printf '</div>\n'

# ── NUCLEI ──
NUCLEI_DATA=$(slurp "$PENTEST_DIR/cve/nuclei_results.txt" | head -100 | esc)
printf '<div class="section" id="nuclei">\n'
printf '<div class="sec-hdr">Nuclei Results <span>%s findings</span></div>\n' "$NUCLEI_COUNT"
[ -n "$NUCLEI_DATA" ] && printf '<pre class="raw">%s</pre>\n' "$NUCLEI_DATA" \
                       || printf '<div class="empty">No nuclei results</div>\n'
printf '</div>\n'

# ── RAW FINDINGS TSV ──
# This section always shows the SCANNER's raw output (pre-validation) so
# analysts can audit what the auto-rules suppressed. The rest of the report
# above is rendered from $TSV (validated when available).
RAW_TSV=$(slurp "$RAW_TSV_PATH" | esc)
printf '<div class="section" id="raw">\n'
printf '<div class="sec-hdr">Raw Findings TSV <span>scanner output, pre-validation</span></div>\n'
[ -n "$RAW_TSV" ] && printf '<pre class="raw">%s</pre>\n' "$RAW_TSV" \
                   || printf '<div class="empty">No findings recorded</div>\n'
printf '</div>\n'

cat << 'FOOTEOF'
<footer>
  <span>Berckley External Pentest // SOC Technical Report</span>
  <span><b id="fdom"></b> // <b id="fdate"></b></span>
</footer>

<div class="toast" id="toast">Copied to clipboard</div>

<script>
document.getElementById('fdom').textContent = document.querySelector('.hbar-domain').textContent;
document.getElementById('fdate').textContent = document.querySelector('.hbar-meta').textContent.trim().split('\n')[0].trim();

function sw(sec,id,el){
  var pfx='p'+sec;
  document.querySelectorAll('[id^="'+pfx+'"]').forEach(function(p){p.classList.remove('active');});
  var t=document.getElementById(pfx+id); if(t) t.classList.add('active');
  if(el){el.parentElement.querySelectorAll('.tab').forEach(function(tb){tb.classList.remove('active');}); el.classList.add('active');}
}

// Click on command block to copy
document.querySelectorAll('.cmd-block').forEach(function(el){
  el.title = 'Click to copy';
  el.addEventListener('click', function(){
    var txt = this.textContent;
    if(navigator.clipboard){ navigator.clipboard.writeText(txt); }
    else { var ta=document.createElement('textarea'); ta.value=txt; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); }
    var t=document.getElementById('toast'); t.classList.add('show');
    setTimeout(function(){ t.classList.remove('show'); }, 1800);
  });
});

// Syntax highlight
document.querySelectorAll('pre').forEach(function(p){
  p.innerHTML=p.innerHTML
    .replace(/(CVE-\d{4}-\d+)/g,'<span style="color:#ff9e64;font-weight:bold">$1</span>')
    .replace(/\b(CRITICAL)\b/g,'<span style="color:#ff2d55;font-weight:bold">$1</span>')
    .replace(/\b(HIGH)\b/g,'<span style="color:#ff6b2b;font-weight:bold">$1</span>')
    .replace(/\b(MEDIUM)\b/g,'<span style="color:#fbbf24;font-weight:bold">$1</span>')
    .replace(/\b(open)\b/g,'<span style="color:#00e676">$1</span>')
    .replace(/(https?:\/\/[^\s&<>"]+)/g,'<a href="$1" target="_blank" rel="noopener" style="color:#38bdf8">$1</a>');
});
</script>
</body></html>
FOOTEOF

} > "$OUT_HTML"

echo "[SOC] Done: $OUT_HTML"

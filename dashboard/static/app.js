// berckley dashboard — UI logic
const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => Array.from(ctx.querySelectorAll(sel));

const state = {
  scans: [],
  selected: null,
  stream: null,
  pollTimer: null,
  showRaw: false,   // findings tab: show raw (pre-validation) data
  ownerFilter: new Set(),  // active ownership-class chips on findings tab
  domainFilter: new Set(), // active security-domain chips on findings tab
  domainMeta: {},          // slug -> {label,icon,color} from the API
  confidenceFilter: new Set(), // active confidence-band chips on findings tab
  groupDupes: false,       // collapse same finding across many hosts
  intake: null,            // last intake result for the modal
};

const OWNER_CLASSES = ["OWNED", "SAAS", "CLOUD_SHARED", "CDN", "INTERNAL", "EXTERNAL", "UNKNOWN"];

// ─── Boot ────────────────────────────────────────────────────────────────────
window.addEventListener("DOMContentLoaded", () => {
  bindTabs();
  bindHeader();
  bindModal();
  bindSuppliers();
  bindFindings();
  bindAudit();
  bindOwnership();
  bindSuppressions();
  bindDiff();
  bindLive();
  bindReports();
  bindValidate();
  bindExtract();
  bindTriage();
  bindDeleteScan();
  bindScreenshots();
  startClock();
  bindHashRouter();
  refresh(true);
  state.pollTimer = setInterval(() => refresh(false), 5000);
});

// Tabs are shareable via URL hash: #findings, #ownership, #reports, etc.
function bindHashRouter() {
  const apply = () => {
    const h = (location.hash || "").replace("#", "").trim();
    if (h && document.getElementById(`panel-${h}`)) switchPanel(h);
  };
  window.addEventListener("hashchange", apply);
  setTimeout(apply, 80);
}

function startClock() {
  const el = document.getElementById("sb-clock");
  if (!el) return;
  const tick = () => {
    const d = new Date();
    el.textContent = d.toISOString().slice(11, 19) + "Z";
  };
  tick();
  setInterval(tick, 1000);
}

// ─── API helpers ─────────────────────────────────────────────────────────────
async function api(path, opts = {}) {
  const r = await fetch(path, opts);
  if (!r.ok) {
    let detail = "";
    try { detail = (await r.json()).detail || ""; } catch {}
    throw new Error(detail || `${r.status} ${r.statusText}`);
  }
  const ct = r.headers.get("content-type") || "";
  return ct.includes("application/json") ? r.json() : r.text();
}

// ─── Sidebar + overview ──────────────────────────────────────────────────────
async function refresh(initial) {
  try {
    const health = await api("/api/health");
    $("#health-line").innerHTML =
      `<span class="online-dot"></span> Connected` +
      `  ·  Scanner <span style="color:${health.scanner_present ? 'var(--accent-2)' : 'var(--crit)'}">${health.scanner_present ? "ready" : "missing"}</span>` +
      `  ·  Running <span style="color:var(--fg)">${health.running.length}</span>`;
    setStatusBar({ connected: true, running: health.running.length });
  } catch {
    $("#health-line").textContent = "backend unreachable";
    setStatusBar({ connected: false });
  }
  try {
    const data = await api("/api/scans");
    state.scans = data.scans;
    renderSidebar();
    setStatusBar({ scans: data.scans.length });
    if (initial && state.scans.length && !state.selected) {
      selectScan(state.scans[0].name);
    } else if (state.selected) {
      const cur = state.scans.find(s => s.name === state.selected);
      if (cur) refreshOverview();
    }
  } catch (e) { /* swallow */ }
}

function setStatusBar(p) {
  const conn = document.getElementById("sb-conn");
  if (conn && "connected" in p) {
    conn.className = "sb-pill" + (p.connected ? "" : " crit");
    conn.textContent = p.connected ? "● connected" : "● offline";
  }
  if ("running" in p) {
    const el = document.getElementById("sb-running");
    if (el) {
      el.textContent = p.running;
      el.style.color = p.running > 0 ? "var(--accent)" : "var(--fg)";
    }
  }
  if ("scans" in p) {
    const el = document.getElementById("sb-scans");
    if (el) el.textContent = p.scans;
  }
  if ("scan" in p) {
    const el = document.getElementById("sb-scan");
    if (el) el.textContent = p.scan || "—";
  }
}

function renderSidebar() {
  const list = $("#scan-list");
  list.innerHTML = "";
  $("#scan-count").textContent = state.scans.length;
  for (const s of state.scans) {
    const li = document.createElement("li");
    if (s.name === state.selected) li.classList.add("active");
    const target = [...(s.domains || []), ...(s.targets || [])].slice(0, 3).join(", ") || "(no target file)";
    const display = s.display || {};
    const heading = display.label || s.name;
    // Running scans get no delete button (you must stop them first)
    const delBtn = s.running ? "" : `
      <button class="scan-del" title="Delete this scan"
              aria-label="Delete ${escapeHtml(s.name)}">✕</button>`;
    // Severity mini-bar: 4-segment colored bar showing CRIT/HIGH/MED/LOW proportions
    const total = (s.severity.CRITICAL || 0) + (s.severity.HIGH || 0)
                + (s.severity.MEDIUM || 0) + (s.severity.LOW || 0);
    const sevBar = total > 0 ? `
      <div class="sev-minibar" title="C${s.severity.CRITICAL} H${s.severity.HIGH} M${s.severity.MEDIUM} L${s.severity.LOW}">
        ${s.severity.CRITICAL ? `<span class="seg crit" style="flex:${s.severity.CRITICAL}"></span>` : ''}
        ${s.severity.HIGH ? `<span class="seg high" style="flex:${s.severity.HIGH}"></span>` : ''}
        ${s.severity.MEDIUM ? `<span class="seg med" style="flex:${s.severity.MEDIUM}"></span>` : ''}
        ${s.severity.LOW ? `<span class="seg low" style="flex:${s.severity.LOW}"></span>` : ''}
      </div>` : '';
    li.innerHTML = `
      <div class="scan-row-top">
        <div class="scan-name" title="${escapeHtml(s.name)}">${escapeHtml(heading)}</div>
        ${delBtn}
      </div>
      <div class="scan-target" title="${escapeHtml(target)}">${escapeHtml(target)}</div>
      ${sevBar}
      <div class="badges">
        ${s.running ? '<span class="badge live">live</span>' : ''}
        ${s.validated ? '<span class="badge val">validated</span>' : ''}
        ${total > 0 ? `<span class="badge total">${total}</span>` : ''}
      </div>`;
    li.onclick = () => selectScan(s.name);
    const delEl = li.querySelector(".scan-del");
    if (delEl) {
      delEl.onclick = e => {
        e.stopPropagation();           // don't trigger selectScan
        openDeleteModal(s.name, heading);
      };
    }
    list.appendChild(li);
  }
}

function selectScan(name) {
  state.selected = name;
  detachStream();
  state.ownerFilter.clear();
  ownTabState.activeClass = "";
  $("#f-owner").dataset.rendered = "";
  $("#f-owner").innerHTML = "";
  const meta = state.scans.find(s => s.name === name) || {};
  const heading = (meta.display && meta.display.label) || name;
  $$(".scan-list li").forEach(li => li.classList.toggle("active", li.querySelector(".scan-name").textContent === heading));
  setStatusBar({ scan: (meta.display && meta.display.label) || name });
  refreshOverview();
  const activeTab = $(".tab.active").dataset.tab;
  if (activeTab === "findings") loadFindings();
  if (activeTab === "audit") loadAudit();
  if (activeTab === "ownership") loadOwnership();
  if (activeTab === "assets") loadAssets();
  if (activeTab === "triage") loadTriage();
  if (activeTab === "live") loadLogSnapshot();
}

async function refreshOverview() {
  if (!state.selected) return;
  $("#overview-empty").classList.add("hidden");
  $("#overview-body").classList.remove("hidden");
  try {
    const s = await api(`/api/scans/${state.selected}/summary`);
    const meta = state.scans.find(x => x.name === state.selected) || {};
    $("#ov-target").textContent = [...(meta.domains || []), ...(meta.targets || [])].join(", ") || "—";
    $("#ov-started").textContent = meta.mtime_iso || "—";
    $("#ov-status").innerHTML = s.running
      ? '<span style="color:var(--accent)">● running</span>'
      : '<span style="color:var(--fg-soft)">○ idle</span>';

    if (s.validated_available) {
      $("#ov-val-state").textContent = "validated";
      $("#ov-val-state").classList.add("done");
      $("#btn-validate").textContent = "↻ Re-run Validation";
    } else {
      $("#ov-val-state").textContent = "Not yet run";
      $("#ov-val-state").classList.remove("done");
      $("#btn-validate").textContent = "▶ Run Validation";
    }
    // Screenshots state: query stats
    try {
      const ss = await api(`/api/scans/${state.selected}/screenshots`);
      const el = $("#shots-state");
      if (el) {
        if (ss.total > 0) {
          el.textContent = `${ss.total} captured`;
          el.classList.add("done");
        } else {
          el.textContent = "no screenshots yet";
          el.classList.remove("done");
        }
      }
    } catch { /* silent */ }

    // banner
    const banner = $("#ov-source-banner");
    if (s.validated_available) {
      const before = sumSev(s.severity_counts_raw);
      const after = sumSev(s.severity_counts);
      banner.classList.remove("hidden");
      banner.innerHTML = `
        <span>showing <span class="accent">validated</span> data — false positives filtered
        (raw ${before} → ${after}, −${before - after})</span>`;
    } else {
      banner.classList.add("hidden");
    }

    setSev("crit", s.severity_counts.CRITICAL, s.severity_counts_raw?.CRITICAL);
    setSev("high", s.severity_counts.HIGH,     s.severity_counts_raw?.HIGH);
    setSev("med",  s.severity_counts.MEDIUM,   s.severity_counts_raw?.MEDIUM);
    setSev("low",  s.severity_counts.LOW,      s.severity_counts_raw?.LOW);

    renderCharts(s);

    // Risk-weighted top hosts
    const riskBody = $("#tbl-risk-hosts tbody"); riskBody.innerHTML = "";
    if (s.top_hosts_by_risk && s.top_hosts_by_risk.length) {
      for (const h of s.top_hosts_by_risk) {
        const cls = riskCls(h.total_risk);
        const own = h.owner_class
          ? `<span class="own-tag ${h.owner_class}">${h.owner_class}</span>`
          : '<span class="dim">—</span>';
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td style="width:64px"><span class="risk-tag ${cls}">${h.total_risk.toFixed(1)}</span></td>
          <td><span class="sev-tag ${sevClass(h.max_severity)}">${h.max_severity}</span></td>
          <td>${own}</td>
          <td class="scope">${escapeHtml(h.scope)}</td>
          <td class="dim" style="text-align:right">${h.n} finding${h.n === 1 ? "" : "s"}</td>
          <td class="dim">${escapeHtml(h.criticality_label || "")}</td>`;
        riskBody.appendChild(tr);
      }
    } else {
      riskBody.innerHTML = `<tr><td colspan="6" class="dim" style="padding:10px">no risk-weighted hosts (validation/ownership not yet run)</td></tr>`;
    }

    renderScorecard(s.scorecard);
    renderDomainCards(s.domain_counts || []);

    const catBody = $("#tbl-cats tbody"); catBody.innerHTML = "";
    s.top_categories.forEach(r => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td><span class="sev-tag ${sevClass(r.severity)}">${r.severity}</span></td>
                      <td class="cat">${escapeHtml(r.category)}</td>
                      <td style="text-align:right">${r.count}</td>`;
      catBody.appendChild(tr);
    });
    const scopeBody = $("#tbl-scopes tbody"); scopeBody.innerHTML = "";
    s.top_scopes.forEach(r => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td class="scope">${escapeHtml(r.scope)}</td>
                      <td style="text-align:right">${r.count}</td>`;
      scopeBody.appendChild(tr);
    });
  } catch (e) {
    console.warn("summary failed", e);
  }
}

function renderScorecard(sc) {
  const el = $("#scorecard");
  if (!el) return;
  if (!sc) { el.classList.add("hidden"); return; }
  el.classList.remove("hidden");
  el.style.setProperty("--gc", sc.color || "#90a4ae");
  const c = sc.counts || {};
  const ceiling = sc.ceiling_applied
    ? `<span class="sc-ceiling" title="Grade capped because open ${sc.ceiling_applied} findings exist">▾ capped at ${sc.grade} by open ${sc.ceiling_applied}</span>`
    : "";
  el.innerHTML = `
    <div class="sc-grade">${escapeHtml(sc.grade)}</div>
    <div class="sc-body">
      <div class="sc-top">
        <span class="sc-score">${sc.score}<span class="sc-out">/100</span></span>
        <span class="sc-label">Security Posture</span>
        ${ceiling}
      </div>
      <div class="sc-bar"><span style="width:${sc.score}%"></span></div>
      <div class="sc-deduct">−${sc.deduction} pts from
        <span class="sev-tag crit">${c.CRITICAL || 0} C</span>
        <span class="sev-tag high">${c.HIGH || 0} H</span>
        <span class="sev-tag med">${c.MEDIUM || 0} M</span>
        <span class="sev-tag low">${c.LOW || 0} L</span>
      </div>
    </div>`;
}

function renderDomainCards(domains) {
  const wrap = $("#domain-cards");
  if (!wrap) return;
  wrap.innerHTML = "";
  if (!domains.length) {
    wrap.innerHTML = '<span class="dim" style="font-size:12px">no findings to classify</span>';
    return;
  }
  const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  domains.forEach(d => {
    const card = document.createElement("div");
    card.className = "domain-card";
    card.style.setProperty("--dc", d.color || "#90a4ae");
    const segs = sevOrder
      .filter(s => (d.severity || {})[s] > 0)
      .map(s => `<span class="seg ${sevClass(s)}" style="flex:${d.severity[s]}" title="${s} ${d.severity[s]}"></span>`)
      .join("");
    const pills = sevOrder
      .filter(s => (d.severity || {})[s] > 0)
      .map(s => `<span class="dc-sev ${sevClass(s)}">${d.severity[s]}</span>`)
      .join("");
    card.innerHTML = `
      <div class="dc-top">
        <span class="dc-icon">${d.icon || "•"}</span>
        <span class="dc-label">${escapeHtml(d.label)}</span>
        <span class="dc-count">${d.count}</span>
      </div>
      <div class="dc-bar">${segs}</div>
      <div class="dc-pills">${pills || '<span class="dim">—</span>'}</div>`;
    // Click a card → jump to Findings filtered by that domain
    card.onclick = () => filterByDomain(d.slug);
    wrap.appendChild(card);
  });
}

function filterByDomain(slug) {
  state.domainFilter = new Set([slug]);
  // re-render chips to reflect the active selection, then switch tabs
  const group = $("#f-domain");
  if (group) group.dataset.rendered = "";
  switchPanel("findings");
}

function setSev(slot, val, rawVal) {
  const el = $(`#ov-${slot}`);
  if (el) el.textContent = String(val ?? 0);
  const delta = $(`#ov-${slot}-d`);
  if (rawVal == null || rawVal === val) { delta.textContent = ""; return; }
  const diff = val - rawVal;
  const sign = diff > 0 ? "+" : "";
  delta.textContent = `raw ${rawVal} (${sign}${diff})`;
}
function sumSev(o) { return o ? (o.CRITICAL + o.HIGH + o.MEDIUM + o.LOW) : 0; }

// ─── Tabs ────────────────────────────────────────────────────────────────────
// Asset-group sub-views live under the single "Assets" primary tab.
const ASSET_GROUP = ["assets", "ownership", "extract", "triage"];
// Panels that don't need a scan selected to render.
const NO_SELECT = ["suppliers"];

function _loadFor(tab) {
  if (tab === "suppliers") { loadSuppliers(); return; }
  if (!state.selected) return;
  ({
    findings: loadFindings, audit: loadAudit, ownership: loadOwnership,
    suppressions: loadSuppressions, diff: loadDiffOptions, assets: loadAssets,
    extract: loadExtract, triage: loadTriage, live: loadLogSnapshot,
  })[tab]?.();
}

// Switch to a panel by name, updating primary-nav highlight, the Assets
// sub-nav, and closing the More menu. This is the single entry point for all
// navigation (primary tabs, More menu, sub-pills, deep links).
function switchPanel(tab) {
  $$(".panel").forEach(x => x.classList.remove("active"));
  const panel = $(`#panel-${tab}`);
  if (panel) panel.classList.add("active");

  const inAssets = ASSET_GROUP.includes(tab);
  const inMore = ["audit", "suppressions", "diff", "live"].includes(tab);
  // Primary-nav highlight: the Assets group always lights the "Assets" tab.
  const primaryFor = inAssets ? "assets" : tab;
  $$(".tabs > .tab, #assets-subnav .subpill").forEach(x => x.classList.remove("active"));
  $$(".tabs > .tab").forEach(x => { if (x.dataset.tab === primaryFor) x.classList.add("active"); });
  $("#more-btn")?.classList.toggle("active", inMore);
  $$("#more-menu .tab").forEach(x => x.classList.toggle("active", x.dataset.tab === tab));
  // Assets sub-nav: visible only within the group, with the right pill active.
  const sub = $("#assets-subnav");
  if (sub) {
    sub.classList.toggle("hidden", !inAssets);
    $$("#assets-subnav .subpill").forEach(p => p.classList.toggle("active", p.dataset.tab === tab));
  }
  $("#more-menu")?.classList.add("hidden");
  _loadFor(tab);
}

function bindTabs() {
  // Primary tabs + More-menu items (all carry data-tab).
  $$(".tabs .tab[data-tab], #more-menu .tab[data-tab]").forEach(t => {
    // The Assets primary tab defaults to the Inventory sub-view.
    t.onclick = () => switchPanel(t.dataset.group === "assets" ? "assets" : t.dataset.tab);
  });
  // Assets sub-pills.
  $$("#assets-subnav .subpill").forEach(p => {
    p.onclick = () => switchPanel(p.dataset.tab);
  });
  // "More ▾" dropdown toggle.
  const moreBtn = $("#more-btn"), moreMenu = $("#more-menu");
  if (moreBtn && moreMenu) {
    moreBtn.onclick = e => { e.stopPropagation(); moreMenu.classList.toggle("hidden"); };
    document.addEventListener("click", () => moreMenu.classList.add("hidden"));
  }
}

function bindHeader() {
  $("#btn-refresh").onclick = () => refresh(false);
  $("#btn-new").onclick = () => $("#modal").classList.remove("hidden");
}

// ─── New-scan modal ──────────────────────────────────────────────────────────
function bindModal() {
  const m = $("#modal");
  const close = () => {
    m.classList.add("hidden");
    state.intake = null;
    $("#scope-tree-wrap").classList.add("hidden");
    $("#scope-tree").innerHTML = "";
    $("#scope-count").textContent = "";
    $("#discover-state").textContent = "passive enum + light classification before scan";
  };
  $("#modal-close").onclick = close;
  $("#form-cancel").onclick = close;
  $("#btn-discover").onclick = runDiscover;
  // Preset profile buttons pre-fill phase + rate
  $$(".profile-btn").forEach(b => {
    b.onclick = () => {
      $$(".profile-btn").forEach(x => x.classList.remove("active"));
      b.classList.add("active");
      const form = $("#new-form");
      const presets = {
        quick:    { phase: "3", rate: 200, threads: 30 },  // recon-light: subdomains + ports + sensitive paths
        standard: { phase: "all", rate: 50, threads: 20 },
        deep:     { phase: "all", rate: 30, threads: 10 },
      };
      const p = presets[b.dataset.profile] || presets.standard;
      form.elements["phase"].value = p.phase;
      form.elements["rate"].value  = p.rate;
      form.elements["threads"].value = p.threads;
    };
  });

  $("#new-form").onsubmit = async e => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target).entries());
    data.threads = parseInt(data.threads || 20);
    data.rate = parseInt(data.rate || 50);

    // If discovery was run, use the curated checkbox state as scope_hosts.
    if (state.intake) {
      const scope = collectScopeFromTree();
      if (scope.length === 0) {
        if (!confirm("no hosts selected from the discovered scope — launch with just the typed domains?")) return;
      } else {
        data.scope_hosts = scope;
      }
    }

    $("#form-msg").textContent = "launching...";
    try {
      const r = await api("/api/scans", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(data),
      });
      $("#form-msg").textContent = `▶ launched: ${r.name}`;
      setTimeout(async () => {
        close();
        $("#form-msg").textContent = "";
        await refresh(false);
        selectScan(r.name);
        switchPanel("live");
        attachStream();
      }, 600);
    } catch (err) {
      $("#form-msg").textContent = `launch failed: ${err.message}`;
    }
  };
}

// ─── Suppliers (passive third-party assessment) ──────────────────────────────
function bindSuppliers() {
  const btn = $("#sup-add");
  if (!btn) return;
  btn.onclick = async () => {
    const name = $("#sup-name").value.trim();
    const domain = $("#sup-domain").value.trim();
    if (!domain) { $("#sup-add-state").textContent = "enter a domain"; return; }
    btn.disabled = true;
    $("#sup-add-state").textContent = "launching passive assessment...";
    try {
      const r = await api("/api/scans", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({domains: domain, passive: true, supplier_name: name}),
      });
      $("#sup-add-state").textContent = `▶ assessing: ${r.name}`;
      $("#sup-name").value = ""; $("#sup-domain").value = "";
      setTimeout(async () => {
        await refresh(false);
        selectScan(r.name);
        switchPanel("live");
        attachStream();
        $("#sup-add-state").textContent = "";
      }, 600);
    } catch (err) {
      $("#sup-add-state").textContent = `failed: ${err.message}`;
    } finally {
      btn.disabled = false;
    }
  };
}

async function loadSuppliers() {
  const body = $("#sup-body");
  if (!body) return;
  let data;
  try { data = await api("/api/suppliers"); }
  catch (e) { return; }
  const sups = data.suppliers || [];
  $("#sup-empty").style.display = sups.length ? "none" : "";
  $("#sup-wrap").style.display = sups.length ? "" : "none";
  body.innerHTML = "";
  for (const s of sups) {
    const sc = s.scorecard || {grade: "?", score: 0, color: "#90a4ae"};
    // Per-domain sub-grade chips (e.g. "✉ B", "🔒 D") — vendor risk at a glance.
    const doms = (s.subscores || s.domain_counts || [])
      .map(d => `<span class="dom-tag" style="--dc:${d.color}" title="${escapeHtml(d.label)} — grade ${d.grade || ''} (${d.count} findings)">${d.icon || "•"} ${d.grade || d.count}</span>`)
      .join(" ") || '<span class="dim">—</span>';
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="grade-pill" style="--gc:${sc.color}">${escapeHtml(sc.grade)}</span></td>
      <td><span class="risk-tag">${sc.score}</span></td>
      <td>${escapeHtml(s.supplier_name)}${s.running ? ' <span class="badge live">live</span>' : ''}</td>
      <td class="scope">${escapeHtml(s.domains || "—")}</td>
      <td>${doms}</td>
      <td class="dim">${s.total_findings}</td>
      <td class="dim">${escapeHtml(s.mtime_iso || "")}</td>
      <td><button class="btn-mini sup-open" title="Open in Overview/Findings">open ↗</button></td>`;
    tr.querySelector(".sup-open").onclick = () => {
      selectScan(s.name);
      switchPanel("overview");
    };
    body.appendChild(tr);
  }
}

async function runDiscover() {
  const domains = ($("#new-form [name=domains]").value || "")
    .split(",").map(s => s.trim()).filter(Boolean);
  if (!domains.length) {
    $("#discover-state").innerHTML = '<span style="color:var(--high)">enter at least one domain first</span>';
    return;
  }
  $("#btn-discover").disabled = true;
  $("#discover-state").textContent = `discovering (${domains.join(", ")}) — DNS + crt.sh, ~10-30s...`;
  try {
    const res = await api("/api/intake", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({domains}),
    });
    state.intake = res;
    renderScopeTree(res);
    $("#discover-state").innerHTML =
      `✓ discovery in ${res.duration_sec}s — source: ${res.discovery_source}`;
  } catch (e) {
    $("#discover-state").innerHTML =
      `<span style="color:var(--crit)">discovery failed: ${e.message}</span>`;
  } finally {
    $("#btn-discover").disabled = false;
  }
}

function renderScopeTree(res) {
  const wrap = $("#scope-tree-wrap");
  const tree = $("#scope-tree");
  tree.innerHTML = "";
  wrap.classList.remove("hidden");

  for (const root of res.roots) {
    const rootEl = document.createElement("div");
    rootEl.className = "scope-root";
    rootEl.dataset.root = root.root;
    const rootCb = `<input type="checkbox" class="scope-root-cb" checked>`;
    const meta = [
      root.resolves ? '<span style="color:var(--accent)">resolves</span>' : '<span style="color:var(--crit)">no DNS</span>',
      root.mx ? "mx" : null,
      root.whois_org ? `whois: ${escapeHtml(root.whois_org)}` : null,
      `${root.discovered_count} discovered`,
    ].filter(Boolean).join(" · ");

    rootEl.innerHTML = `
      <div class="scope-root-head">
        ${rootCb}
        <div class="scope-root-name">${escapeHtml(root.root)}</div>
        <div class="scope-root-stats">${meta}</div>
        <div class="scope-root-chev">▼</div>
      </div>
      ${root.error ? `<div class="scope-root-error">discovery error: ${escapeHtml(root.error)} — scan will still run with just the root</div>` : ""}
      <div class="scope-children"></div>
    `;

    const children = rootEl.querySelector(".scope-children");
    // Root itself is always part of the scope when its checkbox is on.
    children.appendChild(scopeRowEl(root.root, "OWNED", "", "input root", true, true));

    for (const h of root.discovered) {
      const ctx = [
        h.owner_class !== "OWNED" ? h.owner_class : "",
        h.provider,
        h.note,
      ].filter(Boolean).join(" · ");
      children.appendChild(scopeRowEl(
        h.host, h.owner_class, h.provider, ctx,
        h.include_default, h.resolves, false
      ));
    }

    // "+ add custom" footer
    const add = document.createElement("div");
    add.className = "scope-add";
    add.innerHTML = `
      <input placeholder="add custom subdomain (e.g. internal.${root.root})">
      <button type="button" class="ghost">+</button>
    `;
    add.querySelector("button").onclick = () => {
      const v = add.querySelector("input").value.trim().toLowerCase();
      if (!v) return;
      children.appendChild(scopeRowEl(v, "OWNED", "", "user-added", true, true, false));
      add.querySelector("input").value = "";
      updateScopeCount();
    };
    children.appendChild(add);

    // Toggle children visibility / select-all-in-group
    const head = rootEl.querySelector(".scope-root-head");
    head.addEventListener("click", e => {
      if (e.target.tagName === "INPUT") return;  // checkbox handles itself
      rootEl.classList.toggle("collapsed");
    });
    head.querySelector(".scope-root-cb").addEventListener("change", e => {
      e.stopPropagation();
      const on = e.target.checked;
      rootEl.querySelectorAll(".scope-row input[type=checkbox]")
        .forEach(cb => { cb.checked = on; cb.dispatchEvent(new Event("change")); });
    });

    tree.appendChild(rootEl);
  }

  updateScopeCount();
}

function scopeRowEl(host, ownerClass, provider, ctx, checked, resolves, isRoot) {
  const row = document.createElement("div");
  row.className = "scope-row";
  row.dataset.host = host;
  const ownTag = ownerClass
    ? `<span class="own-tag ${ownerClass}">${ownerClass}</span>` : "";
  row.innerHTML = `
    <input type="checkbox" ${checked ? "checked" : ""}>
    <div class="host ${resolves ? "" : "dim"}">${escapeHtml(host)}</div>
    <div class="ctx">${escapeHtml(ctx)}</div>
    <div>${ownTag}</div>
  `;
  row.querySelector("input").addEventListener("change", updateScopeCount);
  return row;
}

function collectScopeFromTree() {
  const hosts = new Set();
  $$(".scope-row").forEach(row => {
    const cb = row.querySelector("input[type=checkbox]");
    if (cb && cb.checked) hosts.add(row.dataset.host);
  });
  return Array.from(hosts);
}

function updateScopeCount() {
  const total = $$(".scope-row").length;
  const selected = collectScopeFromTree().length;
  $("#scope-count").textContent =
    total ? `${selected} of ${total} hosts in scope` : "";
}

// ─── Findings ────────────────────────────────────────────────────────────────
function bindFindings() {
  let t;
  $("#f-search").addEventListener("input", () => {
    clearTimeout(t); t = setTimeout(loadFindings, 200);
  });
  $$('#f-sev input').forEach(cb => cb.addEventListener("change", loadFindings));
  $("#f-raw").addEventListener("change", e => { state.showRaw = e.target.checked; loadFindings(); });
  $("#f-sort-risk").addEventListener("change", loadFindings);
  $("#f-group").addEventListener("change", e => { state.groupDupes = e.target.checked; loadFindings(); });
}

async function loadFindings() {
  if (!state.selected) return;
  const sevs = $$('#f-sev input').filter(c => c.checked).map(c => c.value).join(",");
  const q = $("#f-search").value;
  const owners = Array.from(state.ownerFilter).join(",");
  const domains = Array.from(state.domainFilter).join(",");
  const confidences = Array.from(state.confidenceFilter).join(",");
  const params = new URLSearchParams();
  if (sevs) params.set("severity", sevs);
  if (q) params.set("q", q);
  if (owners) params.set("owner_class", owners);
  if (domains) params.set("domain", domains);
  if (confidences) params.set("confidence", confidences);
  if (state.showRaw) params.set("source", "raw");
  if ($("#f-sort-risk").checked) params.set("sort", "risk");
  const data = await api(`/api/scans/${state.selected}/findings?${params}`);
  // Results-first: show the validated (real) findings; the audit of what was
  // filtered lives behind a discreet link, not a primary tab.
  const auditLink = (data.source === "validated")
    ? ` · <a href="#" class="audit-link">why filtered?</a>`
    : "";
  $("#f-count").innerHTML =
    `${data.count} finding${data.count === 1 ? "" : "s"} (${escapeHtml(data.source)}) · total risk ${data.total_risk}${auditLink}`;
  const al = $("#f-count .audit-link");
  if (al) al.onclick = e => { e.preventDefault(); switchPanel("audit"); };
  renderOwnerChips(data.ownership_available);
  // Cache domain metadata (label/icon/color) for badges + render the chips.
  state.domainMeta = {};
  (data.domains_available || []).forEach(d => { state.domainMeta[d.slug] = d; });
  renderDomainChips(data.domains_available || []);
  renderConfidenceChips(data.confidences_available || []);
  const body = $("#findings-body"); body.innerHTML = "";
  if (state.groupDupes) {
    const groups = groupFindings(data.findings);
    for (const g of groups) body.appendChild(groupRow(g));
    $("#f-count").textContent =
      `${groups.length} group${groups.length === 1 ? "" : "s"} · ${data.count} finding${data.count === 1 ? "" : "s"} (${data.source})`;
    return;
  }
  for (const f of data.findings) {
    const owner = f.owner_class
      ? `<span class="own-tag ${f.owner_class}" title="${escapeHtml(f.owner_provider || '')}">${f.owner_class}${f.owner_provider ? ' · ' + escapeHtml(f.owner_provider) : ''}</span>`
      : '<span class="dim">—</span>';
    // Sub-line shown directly under the scope URL with all the row metadata
    // (owner tag from triage + screenshot icon + future per-row indicators)
    const subBits = [];
    if (f.owner_tag) {
      subBits.push(`<span class="owner-tag-pill" title="From Triage tab">🏷 ${escapeHtml(f.owner_tag)}</span>`);
    }
    if (f.has_screenshot) {
      subBits.push(`<span class="shot-icon" data-shot="${escapeHtml(f.screenshot_url)}" data-scope="${escapeHtml(f.scope)}" title="Click to view screenshot">📸 screenshot</span>`);
    }
    if (f.has_evidence) {
      subBits.push(`<a class="evidence-icon" href="${escapeHtml(f.evidence_url)}" target="_blank" rel="noopener" title="Captured HTTP response (status, headers, body snippet)">📄 evidence</a>`);
    }
    const subLine = subBits.length
      ? `<div class="finding-sub">${subBits.join("")}</div>`
      : '';
    const conf = f.confidence || {band: "MEDIUM", color: "#ffb300"};
    const tr = document.createElement("tr");
    if (conf.band === "LOW") tr.classList.add("low-confidence");
    tr.innerHTML = `<td><span class="sev-tag ${sevClass(f.severity)}">${f.severity}</span></td>
                    <td>${riskCellHTML(f)}</td>
                    <td><span class="conf-tag" style="--cc:${conf.color}" title="Confidence: ${conf.band} (score ${conf.score})">${conf.band}</span></td>
                    <td>${domainBadgeHTML(f.domain)}</td>
                    <td class="cat">${escapeHtml(f.category)}</td>
                    <td class="scope">${escapeHtml(f.scope)}${subLine}</td>
                    <td>${owner}</td>
                    <td class="desc">${escapeHtml(f.description)}</td>
                    <td><button class="btn-mini" title="suppress this finding">✕</button></td>`;
    tr.querySelector("button").onclick = () => openSuppressModal(f.category, f.scope);
    const shotEl = tr.querySelector(".shot-icon");
    if (shotEl) {
      shotEl.onclick = e => {
        e.stopPropagation();
        openShotModal(shotEl.dataset.shot, shotEl.dataset.scope, f.category);
      };
    }
    body.appendChild(tr);
  }
}

// Collapse findings that share (severity, category, description) — the same
// issue repeated across many hosts — into one group, keeping every scope.
function groupFindings(findings) {
  const map = new Map();
  for (const f of findings) {
    const key = `${f.severity} ${f.category} ${f.description}`;
    let g = map.get(key);
    if (!g) {
      g = { severity: f.severity, category: f.category, description: f.description,
            domain: f.domain, confidence: f.confidence, maxRisk: 0, members: [] };
      map.set(key, g);
    }
    g.members.push(f);
    g.maxRisk = Math.max(g.maxRisk, Number(f.risk_score || 0));
  }
  const groups = [...map.values()];
  // Mirror the active sort so grouped view stays ordered sensibly.
  if ($("#f-sort-risk").checked) groups.sort((a, b) => b.maxRisk - a.maxRisk);
  return groups;
}

function groupRow(g) {
  const conf = g.confidence || {band: "MEDIUM", color: "#ffb300"};
  const tr = document.createElement("tr");
  if (conf.band === "LOW") tr.classList.add("low-confidence");
  const n = g.members.length;
  const scopeCell = n === 1
    ? `<span class="scope">${escapeHtml(g.members[0].scope)}</span>`
    : `<details class="scope-group"><summary><span class="grp-count">${n} hosts</span></summary>` +
      g.members.map(m => {
        const own = m.owner_class ? ` <span class="own-tag ${m.owner_class}" style="border:0;padding:0">${m.owner_class}</span>` : "";
        const ev = m.has_evidence ? ` <a class="evidence-icon" href="${escapeHtml(m.evidence_url)}" target="_blank" rel="noopener">📄</a>` : "";
        return `<div class="scope-line">${escapeHtml(m.scope)} <span class="dim">· risk ${Number(m.risk_score||0).toFixed(1)}</span>${own}${ev}</div>`;
      }).join("") + `</details>`;
  const riskCell = `<span class="risk-tag ${riskCls(g.maxRisk)}" title="highest risk across ${n} host(s)">${g.maxRisk.toFixed(1)}</span>`;
  tr.innerHTML = `<td><span class="sev-tag ${sevClass(g.severity)}">${g.severity}</span></td>
                  <td>${riskCell}</td>
                  <td><span class="conf-tag" style="--cc:${conf.color}" title="Confidence: ${conf.band}">${conf.band}</span></td>
                  <td>${domainBadgeHTML(g.domain)}</td>
                  <td class="cat">${escapeHtml(g.category)}</td>
                  <td>${scopeCell}</td>
                  <td class="dim">${n > 1 ? "various" : (g.members[0].owner_class || "—")}</td>
                  <td class="desc">${escapeHtml(g.description)}</td>
                  <td><button class="btn-mini" title="suppress this category on all hosts">✕</button></td>`;
  tr.querySelector("button").onclick = () => openSuppressModal(g.category, n > 1 ? "*" : g.members[0].scope);
  return tr;
}

function riskCellHTML(f) {
  const s = Number(f.risk_score || 0);
  const cls = riskCls(s);
  const b = f.risk_breakdown || {};
  const tip = `sev ${b.severity} × expl ${b.exploitability}` +
              (b.exploit_label ? ` (${b.exploit_label})` : "") +
              ` × own ${b.ownership}` +
              ` × crit ${b.host_criticality}` +
              (b.criticality_label ? ` (${b.criticality_label})` : "");
  return `<span class="risk-tag ${cls}" title="${escapeHtml(tip)}">${s.toFixed(1)}</span>`;
}

function riskCls(s) {
  if (s >= 80) return "r-crit";
  if (s >= 30) return "r-high";
  if (s >= 8)  return "r-med";
  if (s >  0)  return "r-low";
  return "r-zero";
}

function domainBadgeHTML(slug) {
  if (!slug) return '<span class="dim">—</span>';
  const m = state.domainMeta[slug] || { label: slug, icon: "•", color: "#90a4ae" };
  return `<span class="dom-tag" style="--dc:${m.color}" title="${escapeHtml(m.label)}">` +
         `${m.icon || "•"} ${escapeHtml(m.label)}</span>`;
}

function renderDomainChips(domains) {
  const group = $("#f-domain");
  if (!group) return;
  if (!domains.length) {
    group.innerHTML = '<span class="dim" style="font-size:11px">no findings to classify</span>';
    group.dataset.rendered = "";
    return;
  }
  // Re-render when the set of present domains changes or selection was reset.
  const sig = domains.map(d => d.slug).join(",");
  if (group.dataset.rendered === sig) {
    // keep DOM, just sync checkbox state to state.domainFilter
    $$('#f-domain input').forEach(cb => { cb.checked = state.domainFilter.has(cb.value); });
    return;
  }
  group.dataset.rendered = sig;
  group.innerHTML = "";
  domains.forEach(d => {
    const el = document.createElement("label");
    el.innerHTML = `<input type="checkbox" value="${d.slug}" ${state.domainFilter.has(d.slug) ? "checked" : ""}>` +
      `<span class="dom-tag" style="--dc:${d.color};border:0;padding:0 2px">${d.icon || "•"} ${escapeHtml(d.label)}</span>`;
    el.querySelector("input").addEventListener("change", e => {
      if (e.target.checked) state.domainFilter.add(d.slug);
      else state.domainFilter.delete(d.slug);
      loadFindings();
    });
    group.appendChild(el);
  });
}

function renderConfidenceChips(bands) {
  const group = $("#f-confidence");
  if (!group) return;
  if (!bands.length) { group.innerHTML = ""; group.dataset.rendered = ""; return; }
  const sig = bands.map(b => b.band).join(",");
  if (group.dataset.rendered === sig) {
    $$('#f-confidence input').forEach(cb => { cb.checked = state.confidenceFilter.has(cb.value); });
    return;
  }
  group.dataset.rendered = sig;
  group.innerHTML = "";
  bands.forEach(b => {
    const el = document.createElement("label");
    el.innerHTML = `<input type="checkbox" value="${b.band}" ${state.confidenceFilter.has(b.band) ? "checked" : ""}>` +
      `<span class="conf-tag" style="--cc:${b.color};border:0;padding:0 2px">${b.band}</span>`;
    el.querySelector("input").addEventListener("change", e => {
      if (e.target.checked) state.confidenceFilter.add(b.band);
      else state.confidenceFilter.delete(b.band);
      loadFindings();
    });
    group.appendChild(el);
  });
}

function renderOwnerChips(available) {
  const group = $("#f-owner");
  if (!available) {
    group.innerHTML = '<span class="dim" style="font-size:11px">ownership not classified yet — run validation</span>';
    return;
  }
  if (group.dataset.rendered === "1") return;
  group.dataset.rendered = "1";
  group.innerHTML = "";
  OWNER_CLASSES.forEach(cls => {
    const el = document.createElement("label");
    el.innerHTML = `<input type="checkbox" value="${cls}"><span class="own-tag ${cls}" style="border:0;padding:0">${cls}</span>`;
    el.querySelector("input").addEventListener("change", e => {
      if (e.target.checked) state.ownerFilter.add(cls);
      else state.ownerFilter.delete(cls);
      loadFindings();
    });
    group.appendChild(el);
  });
}

// ─── Validation / audit ──────────────────────────────────────────────────────
function bindValidate() {
  $("#btn-validate").onclick = runValidation;
  $("#btn-validate-2").onclick = runValidation;
}

async function runValidation() {
  if (!state.selected) return;
  const btns = [$("#btn-validate"), $("#btn-validate-2")];
  const labels = btns.map(b => b.textContent);
  btns.forEach(b => { b.disabled = true; b.textContent = "validating..."; });
  try {
    const stats = await api(`/api/scans/${state.selected}/validate`, {method: "POST"});
    btns.forEach(b => { b.textContent = `✓ ${stats.suppressed} suppressed, ${stats.downgraded} downgraded`; });
    await refresh(false);
    // if currently on audit tab, reload it
    if ($(".tab.active").dataset.tab === "audit") loadAudit();
    setTimeout(() => btns.forEach((b, i) => { b.textContent = labels[i]; b.disabled = false; }), 2200);
  } catch (e) {
    btns.forEach(b => { b.textContent = "✘ failed"; b.disabled = false; });
    setTimeout(() => btns.forEach((b, i) => b.textContent = labels[i]), 2200);
    alert(e.message);
  }
}

// ─── Ownership tab ───────────────────────────────────────────────────────────
const ownTabState = { activeClass: "" };

function bindOwnership() {
  // chips are rendered dynamically once data arrives
}

async function loadOwnership() {
  if (!state.selected) return;
  const params = new URLSearchParams();
  if (ownTabState.activeClass) params.set("owner_class", ownTabState.activeClass);
  const data = await api(`/api/scans/${state.selected}/ownership?${params}`);
  $("#o-count").textContent = `${data.count} of ${data.total} host${data.total === 1 ? "" : "s"}`;

  if (data.total === 0) {
    $("#ownership-empty").classList.remove("hidden");
    $("#ownership-wrap").classList.add("hidden");
    $("#o-classes").innerHTML = "";
    return;
  }
  $("#ownership-empty").classList.add("hidden");
  $("#ownership-wrap").classList.remove("hidden");

  // chips
  const chips = $("#o-classes"); chips.innerHTML = "";
  chips.appendChild(mkOwnChip("ALL", "", !ownTabState.activeClass));
  data.by_class.forEach(c => {
    chips.appendChild(mkOwnChip(`${c.class} (${c.count})`, c.class, ownTabState.activeClass === c.class));
  });

  const body = $("#ownership-body"); body.innerHTML = "";
  for (const r of data.hosts) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="scope">${escapeHtml(r.host)}</td>
                    <td><span class="own-tag ${r.class}">${r.class}</span></td>
                    <td class="cat">${escapeHtml(r.provider || "")}</td>
                    <td class="reason">${escapeHtml(r.ip || "")}</td>
                    <td class="rule">${escapeHtml(r.asn || "")}</td>
                    <td class="reason">${escapeHtml(r.evidence || "")}</td>`;
    body.appendChild(tr);
  }
}

function mkOwnChip(label, cls, active) {
  const el = document.createElement("label");
  el.innerHTML = `<input type="radio" name="ownclass" ${active ? "checked" : ""}>
                  <span class="own-tag ${cls || ''}" style="border:0;padding:0">${escapeHtml(label)}</span>`;
  el.onclick = e => {
    e.preventDefault();
    ownTabState.activeClass = cls;
    loadOwnership();
  };
  return el;
}

function bindAudit() {
  $$('#a-verdict input').forEach(cb => cb.addEventListener("change", loadAudit));
}

async function loadAudit() {
  if (!state.selected) return;
  const verdicts = $$('#a-verdict input').filter(c => c.checked).map(c => c.value).join(",");
  const data = await api(`/api/scans/${state.selected}/audit?verdict=${verdicts}`);
  $("#audit-count").textContent = `${data.count} row${data.count === 1 ? "" : "s"}`;
  if (data.count === 0) {
    $("#audit-empty").classList.remove("hidden");
    $("#audit-wrap").classList.add("hidden");
    return;
  }
  $("#audit-empty").classList.add("hidden");
  $("#audit-wrap").classList.remove("hidden");
  const body = $("#audit-body"); body.innerHTML = "";
  for (const r of data.audit) {
    const tr = document.createElement("tr");
    const trans = r.verdict === "SUPPRESS"
      ? `<span class="sev-tag ${sevClass(r.orig_severity)}">${r.orig_severity}</span> <span class="dim">→ ✕</span>`
      : r.verdict === "DOWNGRADE"
      ? `<span class="sev-tag ${sevClass(r.orig_severity)}">${r.orig_severity}</span> <span class="dim">→</span> <span class="sev-tag ${sevClass(r.new_severity)}">${r.new_severity}</span>`
      : `<span class="sev-tag ${sevClass(r.orig_severity)}">${r.orig_severity}</span>`;
    tr.innerHTML = `<td class="verdict"><span class="verdict-tag ${r.verdict}">${r.verdict}</span></td>
                    <td>${trans}</td>
                    <td class="cat">${escapeHtml(r.category)}</td>
                    <td class="scope">${escapeHtml(r.scope)}</td>
                    <td class="rule">${escapeHtml(r.rule)}</td>
                    <td class="reason">${escapeHtml(r.reason)}</td>`;
    body.appendChild(tr);
  }
}

// ─── Assets ──────────────────────────────────────────────────────────────────
async function loadAssets(type) {
  if (!state.selected) return;
  const params = new URLSearchParams();
  if (type) params.set("type", type);
  const data = await api(`/api/scans/${state.selected}/assets?${params}`);
  $("#a-count").textContent = `${data.count} row${data.count === 1 ? "" : "s"}`;
  const chips = $("#a-types"); chips.innerHTML = "";
  chips.appendChild(mkChip("ALL", !type, () => loadAssets()));
  data.types.forEach(t => {
    chips.appendChild(mkChip(`${t.type} (${t.count})`, type === t.type, () => loadAssets(t.type)));
  });
  const body = $("#assets-body"); body.innerHTML = "";
  for (const r of data.assets) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="cat">${escapeHtml(r.type)}</td>
                    <td class="scope">${escapeHtml(r.value)}</td>`;
    body.appendChild(tr);
  }
}

function mkChip(label, active, onClick) {
  const el = document.createElement("label");
  el.innerHTML = `<input type="radio" name="atype" ${active ? "checked" : ""}><span>${escapeHtml(label)}</span>`;
  el.onclick = e => { e.preventDefault(); onClick(); };
  return el;
}

// ─── Live log ────────────────────────────────────────────────────────────────
function bindLive() {
  $("#btn-attach").onclick = attachStream;
  $("#btn-detach").onclick = detachStream;
  $("#btn-stop").onclick = async () => {
    if (!state.selected) return;
    try {
      await api(`/api/scans/${state.selected}/stop`, {method: "POST"});
      $("#stream-state").textContent = "stop signal sent";
    } catch (e) { $("#stream-state").textContent = `stop failed: ${e.message}`; }
  };
}

async function loadLogSnapshot() {
  if (!state.selected) return;
  try {
    const txt = await api(`/api/scans/${state.selected}/log?tail=500`);
    const pre = $("#live-log");
    pre.innerHTML = "";
    txt.split("\n").forEach(line => pre.appendChild(formatLine(line)));
    pre.scrollTop = pre.scrollHeight;
  } catch { /* */ }
}

function attachStream() {
  if (!state.selected) return;
  detachStream();
  $("#stream-state").textContent = "connecting...";
  const es = new EventSource(`/api/scans/${state.selected}/log/stream`);
  state.stream = es;
  const pre = $("#live-log"); pre.innerHTML = "";
  es.onopen = () => $("#stream-state").textContent = "● streaming";
  es.onmessage = ev => {
    let msg; try { msg = JSON.parse(ev.data); } catch { return; }
    if (msg.event === "eof") {
      $("#stream-state").textContent = "scan finished";
      return;
    }
    if (typeof msg.line === "string") {
      const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 40;
      pre.appendChild(formatLine(msg.line));
      if (atBottom) pre.scrollTop = pre.scrollHeight;
    }
  };
  es.onerror = () => { $("#stream-state").textContent = "stream error / disconnected"; };
}

function detachStream() {
  if (state.stream) { state.stream.close(); state.stream = null; }
  $("#stream-state").textContent = "idle";
}

function formatLine(line) {
  const clean = line.replace(/\x1b\[[0-9;]*m/g, "");
  const span = document.createElement("span");
  let cls = "";
  if (/\[CRITICAL\]/.test(clean)) cls = "l-crit";
  else if (/\[HIGH\]/.test(clean)) cls = "l-high";
  else if (/\[MEDIUM\]/.test(clean)) cls = "l-med";
  else if (/\[LOW\]/.test(clean)) cls = "l-low";
  else if (/^\[\+\]|\[OK\]/.test(clean)) cls = "l-ok";
  else if (/^\[\!\]/.test(clean)) cls = "l-warn";
  else if (/^\[\-\]/.test(clean)) cls = "l-err";
  else if (/^\[\*\]|\[>\]/.test(clean)) cls = "l-info";
  span.className = cls;
  span.textContent = clean + "\n";
  return span;
}

// ─── Reports ─────────────────────────────────────────────────────────────────
function bindReports() {
  $("#btn-gen-mgmt").onclick = () => genReport("mgmt");
  $("#btn-gen-soc").onclick = () => genReport("soc");
  $("#btn-view-mgmt").onclick = () => viewReport("mgmt");
  $("#btn-view-soc").onclick = () => viewReport("soc");
  $("#btn-pdf-mgmt").onclick = () => downloadPdf("mgmt");
  $("#btn-pdf-soc").onclick = () => downloadPdf("soc");
}

async function downloadPdf(kind) {
  if (!state.selected) return alert("Select a scan first");
  const btn = $(`#btn-pdf-${kind}`);
  const orig = btn.textContent;
  btn.textContent = "rendering…"; btn.disabled = true;
  try {
    // GET the endpoint; if it errors, the API returns JSON we surface.
    const resp = await fetch(`/api/scans/${state.selected}/reports/${kind}/pdf`);
    if (!resp.ok) {
      let detail = "";
      try { detail = (await resp.json()).detail || ""; } catch {}
      throw new Error(detail || `${resp.status} ${resp.statusText}`);
    }
    // Stream into a blob → download via temporary <a> click
    const blob = await resp.blob();
    const cd = resp.headers.get("content-disposition") || "";
    const m = cd.match(/filename="([^"]+)"/);
    const fname = m ? m[1] : `report-${kind}.pdf`;
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement("a"),
                            { href: url, download: fname });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    btn.textContent = "✓ downloaded";
  } catch (e) {
    btn.textContent = "✘ failed";
    alert(`PDF failed: ${e.message}`);
  } finally {
    setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 1500);
  }
}

async function genReport(kind) {
  if (!state.selected) return alert("select a scan first");
  const btn = $(`#btn-gen-${kind}`);
  const original = btn.textContent;
  btn.textContent = "generating..."; btn.disabled = true;
  try {
    await api(`/api/scans/${state.selected}/reports/${kind}`, {method: "POST"});
    btn.textContent = "✔ generated";
    setTimeout(() => { btn.textContent = original; btn.disabled = false; }, 1400);
  } catch (e) {
    btn.textContent = "✘ failed"; btn.disabled = false;
    setTimeout(() => btn.textContent = original, 1800);
    alert(e.message);
  }
}

function viewReport(kind) {
  if (!state.selected) return alert("select a scan first");
  window.open(`/api/scans/${state.selected}/reports/${kind}`, "_blank");
}

// ─── Suppressions tab ────────────────────────────────────────────────────────
function bindSuppressions() {
  $("#sup-modal-close").onclick = closeSuppressModal;
  $("#sup-cancel").onclick = closeSuppressModal;
  $("#sup-form").onsubmit = async e => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target).entries());
    $("#sup-msg").textContent = "saving...";
    try {
      const r = await api("/api/suppressions", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(data),
      });
      $("#sup-msg").textContent = `✓ added (id ${r.id}). re-run validation to apply.`;
      setTimeout(() => { closeSuppressModal(); loadSuppressions(); }, 900);
    } catch (err) {
      $("#sup-msg").textContent = `failed: ${err.message}`;
    }
  };
}

function openSuppressModal(category, scope) {
  $("#sup-cat").value = category;
  $("#sup-scope").value = scope;
  $("#sup-msg").textContent = "";
  $("#sup-modal").classList.remove("hidden");
}
function closeSuppressModal() {
  $("#sup-modal").classList.add("hidden");
  $("#sup-form").reset();
}

async function loadSuppressions() {
  const data = await api("/api/suppressions");
  $("#sup-count").textContent = `${data.active} active / ${data.count} total`;
  $("#sup-file").textContent = data.file;
  if (data.count === 0) {
    $("#sup-empty").classList.remove("hidden");
    $("#sup-wrap").classList.add("hidden");
    return;
  }
  $("#sup-empty").classList.add("hidden");
  $("#sup-wrap").classList.remove("hidden");
  const body = $("#sup-body"); body.innerHTML = "";
  for (const s of data.suppressions) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${s.active
                      ? '<span class="own-tag OWNED">ACTIVE</span>'
                      : '<span class="dim">expired</span>'}</td>
                    <td class="cat">${escapeHtml(s.category)}</td>
                    <td class="scope">${escapeHtml(s.scope)}</td>
                    <td class="reason">${escapeHtml(s.reason)}</td>
                    <td class="dim">${escapeHtml(s.created_at)}</td>
                    <td class="dim">${escapeHtml(s.expires_at || "—")}</td>
                    <td><button class="btn-mini" data-id="${s.id}" title="remove">✕</button></td>`;
    tr.querySelector("button").onclick = async () => {
      if (!confirm("remove this suppression?")) return;
      try {
        await api(`/api/suppressions/${s.id}`, {method: "DELETE"});
        loadSuppressions();
      } catch (e) { alert(e.message); }
    };
    body.appendChild(tr);
  }
}

// ─── Diff tab ────────────────────────────────────────────────────────────────
function bindDiff() {
  $("#btn-diff").onclick = runDiff;
}

function loadDiffOptions() {
  // Populate the dropdown from state.scans (excluding the current one).
  const sel = $("#diff-against");
  const cur = sel.value;
  sel.innerHTML = '<option value="">— auto: previous run with same target —</option>';
  for (const s of state.scans) {
    if (s.name === state.selected) continue;
    const opt = document.createElement("option");
    opt.value = s.name;
    const dom = (s.domains || []).slice(0, 2).join(",");
    opt.textContent = `${s.name}${dom ? `  (${dom})` : ""}`;
    sel.appendChild(opt);
  }
  sel.value = cur || "";
}

async function runDiff() {
  if (!state.selected) return alert("select a scan first");
  const against = $("#diff-against").value;
  $("#diff-state").textContent = "computing...";
  try {
    const params = new URLSearchParams();
    if (against) params.set("against", against);
    const d = await api(`/api/scans/${state.selected}/diff?${params}`);
    if (!d.b) {
      $("#diff-state").textContent = d.message || "no comparison available";
      $("#diff-empty").classList.remove("hidden");
      $("#diff-body").classList.add("hidden");
      return;
    }
    $("#diff-state").textContent = `${d.a} vs ${d.b}`;
    $("#diff-empty").classList.add("hidden");
    $("#diff-body").classList.remove("hidden");
    $("#diff-new-n").textContent = d.totals.new;
    $("#diff-fixed-n").textContent = d.totals.fixed;
    $("#diff-changed-n").textContent = d.totals.changed;
    $("#diff-same-n").textContent = d.totals.unchanged;
    renderDiffRows("#diff-new-body", d.new, "new");
    renderDiffRows("#diff-fixed-body", d.fixed, "fixed");
    renderDiffChanged("#diff-changed-body", d.changed);
  } catch (e) {
    $("#diff-state").textContent = `failed: ${e.message}`;
  }
}

function renderDiffRows(sel, rows, kind) {
  const body = $(sel); body.innerHTML = "";
  if (!rows.length) {
    body.innerHTML = `<tr><td class="dim" colspan="4" style="padding:8px;font-style:italic">none</td></tr>`;
    return;
  }
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td><span class="sev-tag ${sevClass(r.severity)}">${r.severity}</span></td>
                    <td class="cat">${escapeHtml(r.category)}</td>
                    <td class="scope">${escapeHtml(r.scope)}</td>
                    <td class="desc">${escapeHtml(r.description)}</td>`;
    body.appendChild(tr);
  }
}

function renderDiffChanged(sel, rows) {
  const body = $(sel); body.innerHTML = "";
  if (!rows.length) {
    body.innerHTML = `<tr><td class="dim" colspan="4" style="padding:8px;font-style:italic">none</td></tr>`;
    return;
  }
  for (const r of rows) {
    const arrow = r.drift === "worse" ? "↑" : r.drift === "better" ? "↓" : "·";
    const tr = document.createElement("tr");
    tr.innerHTML = `<td><span class="sev-tag ${sevClass(r.previous_severity)}">${r.previous_severity}</span>
                        <span class="drift-${r.drift}">${arrow}</span>
                        <span class="sev-tag ${sevClass(r.severity)}">${r.severity}</span></td>
                    <td class="cat">${escapeHtml(r.category)}</td>
                    <td class="scope">${escapeHtml(r.scope)}</td>
                    <td class="desc">${escapeHtml(r.description)}</td>`;
    body.appendChild(tr);
  }
}

// ─── Extract tab ─────────────────────────────────────────────────────────────
const extractState = { activeClasses: new Set(), withFindings: false, format: "txt" };

function bindExtract() {
  $$('#x-format-group input').forEach(r => r.addEventListener("change", e => {
    extractState.format = e.target.value;
    loadExtract();
  }));
  $("#x-with-findings").addEventListener("change", e => {
    extractState.withFindings = e.target.checked;
    loadExtract();
  });
  $("#x-copy").onclick = async () => {
    try {
      await navigator.clipboard.writeText($("#extract-preview").textContent);
      flashButton($("#x-copy"), "✓ copied");
    } catch { flashButton($("#x-copy"), "✘ failed"); }
  };
  $("#x-download").onclick = () => {
    if (!state.selected) return;
    const url = buildExtractUrl({ download: true });
    window.open(url, "_blank");
  };
}

function buildExtractUrl({ download = false } = {}) {
  const params = new URLSearchParams();
  params.set("format", extractState.format);
  if (extractState.activeClasses.size)
    params.set("owner_class", Array.from(extractState.activeClasses).join(","));
  if (extractState.withFindings)
    params.set("only_with_findings", "true");
  if (download) params.set("download", "true");
  return `/api/scans/${state.selected}/extract?${params}`;
}

async function loadExtract() {
  if (!state.selected) return;
  // Always fetch JSON for the chip counts + preview metadata, then a second
  // request in the chosen format for the preview body.
  const meta = await api(`/api/scans/${state.selected}/extract?format=json`);
  const previewBody = await fetch(buildExtractUrl()).then(r => r.text());
  renderExtractChips(meta);
  $("#x-count").textContent =
    `${(await countAfterFilter(meta))} hosts (of ${meta.count} identified)` +
    `  ·  sources: ownership ${meta.sources.ownership} · findings ${meta.sources.findings} · enum ${meta.sources.enum_files}`;
  if (!meta.count) {
    $("#extract-empty").classList.remove("hidden");
    $("#extract-preview").classList.add("hidden");
    return;
  }
  $("#extract-empty").classList.add("hidden");
  $("#extract-preview").classList.remove("hidden");
  $("#extract-preview").textContent = previewBody;
}

function countAfterFilter(meta) {
  // Re-apply the JS-side filters on the meta payload to compute the live
  // post-filter count without a second JSON round-trip.
  return new Promise(res => {
    let rows = meta.rows;
    if (extractState.activeClasses.size) {
      rows = rows.filter(r => extractState.activeClasses.has(r.owner_class));
    }
    if (extractState.withFindings) {
      rows = rows.filter(r => (r.findings || 0) > 0);
    }
    res(rows.length);
  });
}

function renderExtractChips(meta) {
  const group = $("#x-classes");
  if (group.dataset.rendered === "1") return;
  group.dataset.rendered = "1";
  group.innerHTML = "";
  // ALL chip: clear filter
  const all = document.createElement("label");
  all.innerHTML = `<input type="checkbox" ${extractState.activeClasses.size === 0 ? "checked" : ""}><span class="own-tag" style="border:0;padding:0">ALL</span>`;
  all.onclick = e => {
    e.preventDefault();
    extractState.activeClasses.clear();
    group.dataset.rendered = "";
    loadExtract();
  };
  group.appendChild(all);
  OWNER_CLASSES.forEach(cls => {
    const el = document.createElement("label");
    el.innerHTML = `<input type="checkbox" value="${cls}" ${extractState.activeClasses.has(cls) ? "checked" : ""}><span class="own-tag ${cls}" style="border:0;padding:0">${cls}</span>`;
    el.querySelector("input").addEventListener("change", e => {
      if (e.target.checked) extractState.activeClasses.add(cls);
      else extractState.activeClasses.delete(cls);
      group.dataset.rendered = "";
      loadExtract();
    });
    group.appendChild(el);
  });
}

function flashButton(btn, msg, ms = 1200) {
  const orig = btn.textContent;
  btn.textContent = msg;
  setTimeout(() => { btn.textContent = orig; }, ms);
}

// ─── Delete scan flow ────────────────────────────────────────────────────────
const delState = { name: null };

function bindDeleteScan() {
  const close = () => {
    $("#del-modal").classList.add("hidden");
    $("#del-confirm").checked = false;
    $("#del-confirm-btn").disabled = true;
    $("#del-msg").textContent = "";
    delState.name = null;
  };
  $("#del-modal-close").onclick = close;
  $("#del-cancel").onclick = close;
  $("#del-confirm").addEventListener("change", e => {
    $("#del-confirm-btn").disabled = !e.target.checked;
  });
  $("#del-confirm-btn").onclick = async () => {
    if (!delState.name) return;
    const btn = $("#del-confirm-btn");
    btn.disabled = true; btn.textContent = "deleting...";
    try {
      await api(`/api/scans/${encodeURIComponent(delState.name)}`, { method: "DELETE" });
      $("#del-msg").textContent = "✓ deleted";
      const wasSelected = state.selected === delState.name;
      setTimeout(async () => {
        close();
        // If we just deleted the currently selected scan, reset selection
        if (wasSelected) {
          state.selected = null;
          $("#overview-body").classList.add("hidden");
          $("#overview-empty").classList.remove("hidden");
          setStatusBar({ scan: null });
        }
        await refresh(false);
      }, 500);
    } catch (e) {
      $("#del-msg").innerHTML = `<span style="color:var(--crit)">delete failed: ${escapeHtml(e.message)}</span>`;
      btn.disabled = false; btn.textContent = "✕ Delete Scan";
    }
  };
}

function openDeleteModal(name, label) {
  delState.name = name;
  $("#del-name").textContent = label || name;
  $("#del-confirm").checked = false;
  $("#del-confirm-btn").disabled = true;
  $("#del-confirm-btn").textContent = "✕ Delete Scan";
  $("#del-msg").textContent = "";
  $("#del-modal").classList.remove("hidden");
}

// ─── Screenshots — capture + lightbox ────────────────────────────────────────
function bindScreenshots() {
  $("#btn-capture-shots")?.addEventListener("click", captureScreenshots);
  // Close lightbox on backdrop click or × button
  $("#shot-modal-close")?.addEventListener("click", () =>
    $("#shot-modal").classList.add("hidden"));
  $("#shot-modal")?.addEventListener("click", e => {
    if (e.target.id === "shot-modal") $("#shot-modal").classList.add("hidden");
  });
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") $("#shot-modal")?.classList.add("hidden");
  });
}

async function captureScreenshots() {
  if (!state.selected) return;
  const btn = $("#btn-capture-shots");
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = "capturing… (this can take 1-2 min)";
  try {
    const r = await api(`/api/scans/${state.selected}/screenshots/capture`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({severity_floor: "HIGH", max_findings: 50}),
    });
    btn.textContent = `✓ ${r.captured} new / ${r.cached} cached / ${r.failed} failed`;
    $("#shots-state").textContent =
      `${r.captured + r.cached} screenshots ready — viewable in Findings tab`;
    // Refresh findings table so the 📸 icons appear
    if ($(".tab.active").dataset.tab === "findings") loadFindings();
  } catch (e) {
    btn.textContent = `✘ ${e.message.slice(0, 40)}`;
  } finally {
    setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 2400);
  }
}

function openShotModal(url, scope, category) {
  if (!url) return;
  $("#shot-modal-title").textContent = category || "Screenshot";
  $("#shot-modal-img").src = url;
  $("#shot-modal-img").alt = scope || "";
  $("#shot-modal-meta").textContent = scope || "";
  $("#shot-modal").classList.remove("hidden");
}

// ─── Triage tab — verify identified assets + tag owners ─────────────────────
const triageState = {
  statusFilter: new Set(),
  onlyTagged: false,
  query: "",
  loaded: false,
};
const TRIAGE_STATUSES = ["alive", "dead", "unknown"];

function bindTriage() {
  let t;
  const search = $("#t-search");
  if (search) {
    search.addEventListener("input", () => {
      clearTimeout(t); t = setTimeout(() => {
        triageState.query = search.value;
        loadTriage();
      }, 250);
    });
  }
  $("#t-only-tagged")?.addEventListener("change", e => {
    triageState.onlyTagged = e.target.checked;
    loadTriage();
  });
  $("#t-verify-all")?.addEventListener("click", verifyAllUnchecked);
}

async function loadTriage() {
  // Explicit message when there's no scan to triage against
  if (!state.selected) {
    $("#triage-empty").classList.remove("hidden");
    $("#triage-empty").textContent =
      "Select a scan from the left sidebar first.";
    $("#triage-wrap").classList.add("hidden");
    $("#t-count").textContent = "";
    return;
  }
  // Loading indicator
  $("#t-count").textContent = "loading…";
  $("#triage-empty").classList.add("hidden");

  const params = new URLSearchParams();
  if (triageState.statusFilter.size)
    params.set("status", Array.from(triageState.statusFilter).join(","));
  if (triageState.onlyTagged) params.set("only_with_tag", "true");
  if (triageState.query) params.set("q", triageState.query);

  let data;
  try {
    data = await api(`/api/scans/${state.selected}/triage?${params}`);
  } catch (e) {
    $("#triage-empty").classList.remove("hidden");
    $("#triage-empty").innerHTML =
      `<span style="color:var(--crit)">Triage request failed: ${escapeHtml(e.message)}</span>`;
    $("#triage-wrap").classList.add("hidden");
    $("#t-count").textContent = "error";
    return;
  }

  const ctr = data.counters;
  renderTriageChips(ctr);
  $("#t-count").textContent =
    `${data.count} of ${ctr.total} hosts  ·  alive ${ctr.alive}  ·  dead ${ctr.dead}  ·  unknown ${ctr.unknown}  ·  tagged ${ctr.tagged}`;

  // No hosts at all — scan probably hasn't done recon yet
  if (ctr.total === 0) {
    $("#triage-empty").classList.remove("hidden");
    $("#triage-empty").textContent =
      "No subdomains or domains discovered yet for this scan. Re-run with phase 3 (recon) or use Discover Scope in New Scan.";
    $("#triage-wrap").classList.add("hidden");
    return;
  }

  // Hosts exist but the current filters hide all of them
  if (data.count === 0) {
    $("#triage-empty").classList.remove("hidden");
    const totalNote = `${ctr.total} hosts available — adjust filters above to see them.`;
    $("#triage-empty").textContent = totalNote;
    $("#triage-wrap").classList.add("hidden");
    return;
  }

  $("#triage-empty").classList.add("hidden");
  $("#triage-wrap").classList.remove("hidden");
  renderTriageBody(data.rows);
  triageState.loaded = true;
}

function renderTriageChips(ctr) {
  const group = $("#t-status-chips");
  if (!group) return;
  // Render only once; preserve state via class toggles
  if (!group.dataset.built) {
    group.innerHTML = "";
    TRIAGE_STATUSES.forEach(s => {
      const el = document.createElement("label");
      el.innerHTML = `<input type="checkbox" value="${s}"><span class="t-status ${s}">${s}</span>`;
      el.querySelector("input").addEventListener("change", e => {
        if (e.target.checked) triageState.statusFilter.add(s);
        else triageState.statusFilter.delete(s);
        loadTriage();
      });
      group.appendChild(el);
    });
    group.dataset.built = "1";
  }
}

function renderTriageBody(rows) {
  const body = $("#triage-body");
  body.innerHTML = "";
  for (const r of rows) {
    const tr = document.createElement("tr");
    if (r.has_tag) tr.classList.add("tagged");
    const ownClass = r.owner_class
      ? `<span class="own-tag ${r.owner_class}" title="${escapeHtml(r.owner_provider || '')}">${r.owner_class}</span>`
      : '<span class="dim">—</span>';
    const lastTs = r.verified_at
      ? `<div class="t-ts">${escapeHtml(r.verified_at.slice(0,16).replace('T',' '))}${r.verification_code ? ` · ${r.verification_code}` : ''}</div>`
      : "";
    const apexBadge = r.is_apex
      ? ' <span class="apex-badge" title="Apex input domain">APEX</span>' : '';
    tr.innerHTML = `
      <td class="scope">${escapeHtml(r.host)}${apexBadge}</td>
      <td>${ownClass}</td>
      <td>
        <span class="t-status ${r.verification_status}">${r.verification_status}</span>
        ${lastTs}
      </td>
      <td><button class="t-verify" title="Re-verify this host">↻</button></td>
      <td><input class="triage-input t-tag" type="text"
                 placeholder="e.g. Marketing Team"
                 value="${escapeHtml(r.tag || '')}"></td>
      <td><input class="triage-input t-notes" type="text"
                 placeholder="Optional notes"
                 value="${escapeHtml(r.notes || '')}"></td>
      <td>${r.has_tag ? '<button class="t-clear" title="Remove tag">×</button>' : ''}</td>
    `;
    // Verify button → single host
    tr.querySelector(".t-verify").onclick = () => verifyOne(r.host, tr);
    // Tag + notes auto-save on blur (or Enter)
    const tagInput = tr.querySelector(".t-tag");
    const notesInput = tr.querySelector(".t-notes");
    const markDirty = el => el.classList.add("dirty");
    tagInput.addEventListener("input", () => markDirty(tagInput));
    notesInput.addEventListener("input", () => markDirty(notesInput));
    const save = async () => {
      const newTag = tagInput.value.trim();
      const newNotes = notesInput.value.trim();
      if (newTag === (r.tag || "") && newNotes === (r.notes || "")) return;
      try {
        await api("/api/asset_tags", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({host: r.host, tag: newTag, notes: newNotes}),
        });
        r.tag = newTag; r.notes = newNotes; r.has_tag = !!newTag;
        tagInput.classList.remove("dirty");
        notesInput.classList.remove("dirty");
        tagInput.classList.add("saved");
        notesInput.classList.add("saved");
        setTimeout(() => {
          tagInput.classList.remove("saved");
          notesInput.classList.remove("saved");
        }, 900);
        if (newTag) tr.classList.add("tagged");
        else tr.classList.remove("tagged");
      } catch (e) {
        alert(`Save failed: ${e.message}`);
      }
    };
    tagInput.addEventListener("blur", save);
    notesInput.addEventListener("blur", save);
    tagInput.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); tagInput.blur(); } });
    notesInput.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); notesInput.blur(); } });
    // Clear tag button
    const clearBtn = tr.querySelector(".t-clear");
    if (clearBtn) {
      clearBtn.onclick = async () => {
        if (!confirm(`Remove tag and notes for ${r.host}?`)) return;
        try {
          await api(`/api/asset_tags/${encodeURIComponent(r.host)}`, {method: "DELETE"});
          loadTriage();
        } catch (e) { alert(e.message); }
      };
    }
    body.appendChild(tr);
  }
}

async function verifyOne(host, tr) {
  const btn = tr.querySelector(".t-verify");
  btn.classList.add("busy");
  try {
    const r = await api(`/api/scans/${state.selected}/triage/verify`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({hosts: [host]}),
    });
    // Mutate the visible row instead of full reload (less flicker)
    const res = r.results[0];
    const statusCell = tr.children[2];
    statusCell.innerHTML = `
      <span class="t-status ${res.status}">${res.status}</span>
      <div class="t-ts">${(res.verified_at || '').slice(0,16).replace('T',' ')}${res.code ? ` · ${res.code}` : ''}</div>`;
  } catch (e) {
    alert(`Verify failed: ${e.message}`);
  } finally {
    btn.classList.remove("busy");
  }
}

async function verifyAllUnchecked() {
  if (!state.selected) return;
  const btn = $("#t-verify-all");
  const orig = btn.textContent;
  btn.disabled = true;
  // Grab hosts currently unknown from the rendered table
  const rows = $$("#triage-body tr");
  const targets = rows
    .filter(r => r.children[2].querySelector(".t-status.unknown"))
    .map(r => r.children[0].textContent.trim());
  if (targets.length === 0) {
    btn.textContent = "✓ nothing to verify";
    setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 1400);
    return;
  }
  btn.textContent = `verifying ${targets.length}...`;
  // Batch in chunks of 20 to keep requests reasonable
  const chunk = (arr, n) => Array.from({length: Math.ceil(arr.length/n)}, (_, i) => arr.slice(i*n, (i+1)*n));
  let done = 0;
  for (const batch of chunk(targets, 20)) {
    try {
      await api(`/api/scans/${state.selected}/triage/verify`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({hosts: batch}),
      });
      done += batch.length;
      btn.textContent = `verifying ${done}/${targets.length}...`;
    } catch { /* keep going */ }
  }
  btn.textContent = `✓ verified ${done}`;
  setTimeout(() => { btn.textContent = orig; btn.disabled = false; loadTriage(); }, 1200);
}

// ─── Overview charts — vanilla SVG, no external deps ─────────────────────────
const SEV_COLORS = {
  CRITICAL: "#ff3b5c", HIGH: "#ff8c1a", MEDIUM: "#ffd400", LOW: "#6ec1ff",
};
const OWN_COLORS = {
  OWNED: "#00d8ff", SAAS: "#b47bff", CLOUD_SHARED: "#ffb86c",
  CDN: "#ff8cce", INTERNAL: "#8694a3", EXTERNAL: "#ff6b6b", UNKNOWN: "#4d5965",
};

function renderCharts(summary) {
  // ── Severity donut ──
  const sc = summary.severity_counts || {};
  const sevData = [
    { label: "Critical", value: sc.CRITICAL || 0, color: SEV_COLORS.CRITICAL },
    { label: "High",     value: sc.HIGH     || 0, color: SEV_COLORS.HIGH     },
    { label: "Medium",   value: sc.MEDIUM   || 0, color: SEV_COLORS.MEDIUM   },
    { label: "Low",      value: sc.LOW      || 0, color: SEV_COLORS.LOW      },
  ];
  document.getElementById("chart-sev").innerHTML =
    svgDonut(sevData, "Total");

  // ── Ownership donut ──
  const own = summary.ownership_by_class || {};
  const ownOrder = ["OWNED", "SAAS", "CLOUD_SHARED", "CDN", "INTERNAL", "EXTERNAL", "UNKNOWN"];
  const ownData = ownOrder
    .filter(c => own[c] > 0)
    .map(c => ({ label: c, value: own[c], color: OWN_COLORS[c] }));
  const ownEl = document.getElementById("chart-own");
  if (ownData.length === 0) {
    ownEl.innerHTML =
      `<div class="chart-empty">Run Validation to classify hosts.</div>`;
  } else {
    ownEl.innerHTML = svgDonut(ownData, "Hosts");
  }

  // ── Top hosts by risk — horizontal bar ──
  const tops = (summary.top_hosts_by_risk || []).slice(0, 10).map(t => ({
    label: t.scope,
    value: t.total_risk,
    color: SEV_COLORS[t.max_severity] || SEV_COLORS.LOW,
    tooltip: `${t.n} findings · max ${t.max_severity}`,
  }));
  const riskEl = document.getElementById("chart-risk");
  riskEl.innerHTML = tops.length === 0
    ? `<div class="chart-empty">No risk data yet — run Validation on a completed scan.</div>`
    : svgHBar(tops);
}

// Build a donut + side legend in plain SVG. Data: [{label, value, color}].
function svgDonut(data, sublabel, size = 200) {
  const total = data.reduce((a, d) => a + d.value, 0);
  const cx = size / 2, cy = size / 2;
  const r  = size * 0.40;
  const sw = size * 0.13;
  const circ = 2 * Math.PI * r;
  let offset = 0;
  const segs = total === 0
    ? `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none"
        stroke="#1c232c" stroke-width="${sw}"/>`
    : data.map(d => {
        if (d.value === 0) return "";
        const len = (d.value / total) * circ;
        const seg = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none"
          stroke="${d.color}" stroke-width="${sw}"
          stroke-dasharray="${len} ${circ - len}"
          stroke-dashoffset="${-offset}"
          transform="rotate(-90 ${cx} ${cy})"
          stroke-linecap="butt"/>`;
        offset += len;
        return seg;
      }).join("");

  const legend = data.map(d =>
    d.value === 0 ? "" : `
      <div class="lg-row">
        <span class="lg-dot" style="background:${d.color}"></span>
        <span class="lg-lbl">${escapeHtml(d.label)}</span>
        <span class="lg-val">${d.value}</span>
        <span class="lg-pct">${total ? Math.round(d.value*100/total) : 0}%</span>
      </div>`).join("");

  return `
    <div class="svg-chart svg-donut">
      <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
        ${segs}
        <text x="${cx}" y="${cy - 2}" text-anchor="middle"
          fill="#f3f7fb" font-family="JetBrains Mono, monospace"
          font-size="28" font-weight="700">${total}</text>
        <text x="${cx}" y="${cy + 18}" text-anchor="middle"
          fill="#8694a3" font-family="Inter, sans-serif"
          font-size="10" font-weight="600"
          letter-spacing="1.5">${sublabel.toUpperCase()}</text>
      </svg>
      <div class="svg-legend">${legend}</div>
    </div>`;
}

// Horizontal bar chart. Data: [{label, value, color, tooltip?}].
function svgHBar(data) {
  const max = Math.max(...data.map(d => d.value), 1);
  const rows = data.map((d, i) => {
    const pct = (d.value / max) * 100;
    return `
      <div class="hb-row" title="${escapeHtml(d.tooltip || '')}">
        <span class="hb-label" title="${escapeHtml(d.label)}">${escapeHtml(d.label)}</span>
        <span class="hb-track">
          <span class="hb-bar" style="width:${pct.toFixed(1)}%;background:${d.color}"></span>
        </span>
        <span class="hb-val">${d.value.toFixed(1)}</span>
      </div>`;
  }).join("");
  return `<div class="svg-chart svg-hbar">${rows}</div>`;
}

// ─── Utils ───────────────────────────────────────────────────────────────────
function sevClass(s) {
  return s === "CRITICAL" ? "crit"
       : s === "HIGH"     ? "high"
       : s === "MEDIUM"   ? "med"
       : s === "LOW"      ? "low" : "muted";
}
function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

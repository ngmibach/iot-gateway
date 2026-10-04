/* Native Monitoring tabs — talks to control-service via wizard /api/v1 proxy. */
(function () {
  const TABS = [
    { id: "gateway", label: "Gateway" },
    { id: "raspi", label: "Host" },
    { id: "sensors", label: "Sensors" },
  ];
  const WIZARD_MONITORING = "http://127.0.0.1:9138/monitoring.html";
  let tab = "gateway";
  let timer = null;
  let lastWarnings = [];

  const $ = (id) => document.getElementById(id);

  /** Wizard shell proxies /api/v1 and injects IOTGW_API_TOKEN — not Tauri asset origin. */
  function onWizardOrigin() {
    if (location.protocol !== "http:" && location.protocol !== "https:") {
      return false;
    }
    const host = location.hostname;
    return host === "127.0.0.1" || host === "localhost";
  }

  async function control(path, opts) {
    if (!onWizardOrigin()) {
      throw new Error(
        "Open Monitoring from the Setup Wizard at " +
          WIZARD_MONITORING +
          " (same-origin /api/v1 proxy)."
      );
    }
    const headers = { "Content-Type": "application/json", ...(opts && opts.headers) };
    const res = await fetch(path, { ...opts, headers });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = data.detail || data.error || res.statusText;
      throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    }
    return data;
  }

  function showWarnings(warnings) {
    lastWarnings = Array.isArray(warnings) ? warnings : [];
    const banner = $("warn-banner");
    if (!banner) return;
    if (!lastWarnings.length) {
      banner.classList.add("hidden");
      banner.textContent = "";
      return;
    }
    banner.classList.remove("hidden");
    banner.textContent =
      "Backend warnings (" +
      lastWarnings.length +
      "): " +
      String(lastWarnings[0]).slice(0, 240);
  }

  function setStatusBadge(kind, text) {
    $("hdr-status").innerHTML =
      `<span class="badge ${kind}">${escapeHtml(text)}</span>`;
  }

  function sparkSvg(values, opts) {
    const w = (opts && opts.w) || 96;
    const h = (opts && opts.h) || 28;
    if (!values || !values.length) {
      return `<svg viewBox="0 0 ${w} ${h}" class="spark"><text x="4" y="${h / 2 + 3}" fill="#8b9bb4" font-size="10">—</text></svg>`;
    }
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = max - min || 1;
    const pts = values
      .map((v, i) => {
        const x = (i / Math.max(values.length - 1, 1)) * (w - 2) + 1;
        const y = h - 2 - ((v - min) / span) * (h - 4);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
    return `<svg viewBox="0 0 ${w} ${h}" class="spark" preserveAspectRatio="none"><polyline fill="none" stroke="#4da3ff" stroke-width="1.5" points="${pts}" /></svg>`;
  }

  function fmtBytes(n) {
    if (n == null || !isFinite(n)) return "—";
    const u = ["B", "KB", "MB", "GB", "TB"];
    let v = Number(n);
    let i = 0;
    while (v >= 1024 && i < u.length - 1) {
      v /= 1024;
      i++;
    }
    return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${u[i]}`;
  }

  function metricCards(el, items) {
    el.innerHTML = items
      .map(
        ([label, value]) =>
          `<div class="metric-card"><div class="label">${escapeHtml(label)}</div><div class="value">${escapeHtml(value)}</div></div>`
      )
      .join("");
  }

  function fillTable(table, headers, rows) {
    const thead = table.querySelector("thead");
    const tbody = table.querySelector("tbody");
    thead.innerHTML = `<tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr>`;
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="${headers.length}" class="muted">No data</td></tr>`;
      return;
    }
    tbody.innerHTML = rows
      .map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`)
      .join("");
  }

  function buildTabs() {
    const nav = $("mon-tabs");
    nav.innerHTML = "";
    TABS.forEach((t) => {
      const b = document.createElement("button");
      b.textContent = t.label;
      b.dataset.tab = t.id;
      b.classList.toggle("active", t.id === tab);
      b.addEventListener("click", () => showTab(t.id));
      nav.appendChild(b);
    });
  }

  function showTab(id) {
    tab = id;
    document.querySelectorAll(".mon-panel").forEach((el) => {
      el.classList.toggle("hidden", el.dataset.tab !== tab);
    });
    document.querySelectorAll("#mon-tabs button").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.tab === tab);
    });
  }

  async function loadGateways() {
    const sel = $("gateway-id");
    try {
      const rows = await control("/api/v1/gateways");
      sel.innerHTML = "";
      (rows || []).forEach((g) => {
        const opt = document.createElement("option");
        opt.value = g.id;
        opt.textContent = `${g.id} (${g.host})`;
        sel.appendChild(opt);
      });
      if (!rows || !rows.length) {
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "(no gateways in registry)";
        sel.appendChild(opt);
      }
    } catch (e) {
      sel.innerHTML = `<option value="">control API offline</option>`;
      $("hdr-status").innerHTML = `<span class="badge bad">${escapeHtml(e.message)}</span>`;
      throw e;
    }
  }

  async function refreshGateway() {
    const range = $("range").value;
    const data = await control(`/api/v1/query/summaries/gateway?range=${encodeURIComponent(range)}`);
    const m = data.metrics || {};
    metricCards($("gw-metrics"), [
      ["Sensor msgs", String(m.total_sensor_messages ?? "—")],
      ["Msgs / min", String(m.messages_per_minute ?? "—")],
      ["Denied", String(m.denied_publishes ?? "—")],
      ["IDS", String(m.ids_detections ?? "—")],
      ["Allowed IPs", String(m.allowed_ips ?? "—")],
    ]);
    fillTable(
      $("gw-connected"),
      ["Device", "Client", "Source IP"],
      (data.connected_sensors || []).map((r) => [
        escapeHtml(r.device_id),
        escapeHtml(r.client_id),
        escapeHtml(r.source_ip),
      ])
    );
    fillTable(
      $("gw-delay"),
      ["Device", "Latest", "Sparkline"],
      (data.delay_by_device || []).map((r) => [
        escapeHtml(r.device_id),
        r.latest == null ? "—" : Number(r.latest).toFixed(4),
        sparkSvg(r.sparkline || []),
      ])
    );
    $("gw-msg").textContent = `range=${data.range}`;
    showWarnings(data.warnings);
  }

  async function refreshRaspi() {
    const data = await control("/api/v1/query/summaries/raspi");
    const m = data.metrics || {};
    metricCards($("raspi-metrics"), [
      ["Status", data.up ? "up" : "down"],
      ["CPU busy (cores)", String(m.cpu_cores_busy ?? "—")],
      ["Cores", String(m.cpu_cores ?? "—")],
      ["Mem used", `${m.mem_used_pct ?? "—"}%`],
      ["Mem", `${fmtBytes(m.mem_used_bytes)} / ${fmtBytes(m.mem_total_bytes)}`],
      ["Load1", String(m.load1 ?? "—")],
      ["Disk used", `${m.fs_used_pct ?? "—"}%`],
      ["Containers", String(m.active_containers ?? "—")],
    ]);
    $("raspi-spark").innerHTML = sparkSvg(data.cpu_sparkline_pct || [], { w: 600, h: 56 });
    $("raspi-msg").textContent = `node=${data.node} job=${data.job}`;
    showWarnings(data.warnings);
  }

  async function refreshSensors() {
    const gid = $("gateway-id").value;
    const range = $("range").value;
    const showAll = $("show-all").checked;
    const q = new URLSearchParams({ range, show_all: showAll ? "true" : "false" });
    if (gid) q.set("gateway_id", gid);
    const data = await control(`/api/v1/query/summaries/sensors?${q}`);
    $("sensors-filter-note").textContent = data.filter_active
      ? `Filtered to monitor_enabled devices: ${(data.monitored_device_ids || []).join(", ") || "(none enabled — empty view)"}`
      : showAll
        ? "Showing all Loki deviceIds (filter off)."
        : "No devices in registry — showing all (first-run explore).";
    metricCards(
      $("sensors-stages"),
      (data.stages || []).map((s) => [s.device_id, String(s.stage)])
    );
    if (!(data.stages || []).length) {
      $("sensors-stages").innerHTML = `<div class="muted">No stage data</div>`;
    }
    fillTable(
      $("sensors-temp"),
      ["Device", "Series", "Latest", "Sparkline"],
      (data.temperatures || []).map((r) => [
        escapeHtml(r.device_id),
        escapeHtml(r.series),
        r.latest == null ? "—" : Number(r.latest).toFixed(2),
        sparkSvg(r.sparkline || []),
      ])
    );
    fillTable(
      $("sensors-pressure"),
      ["Device", "Series", "Latest", "Sparkline"],
      (data.pressures || []).map((r) => [
        escapeHtml(r.device_id),
        escapeHtml(r.series),
        r.latest == null ? "—" : Number(r.latest).toFixed(2),
        sparkSvg(r.sparkline || []),
      ])
    );
    $("sensors-msg").textContent = `range=${data.range}`;
    showWarnings(data.warnings);
  }

  async function refresh() {
    setStatusBadge("warn", "loading…");
    try {
      if (tab === "gateway") await refreshGateway();
      else if (tab === "raspi") await refreshRaspi();
      else await refreshSensors();
      if (lastWarnings.length) {
        setStatusBadge("warn", "degraded");
      } else {
        setStatusBadge("ok", "live");
      }
    } catch (e) {
      showWarnings([]);
      setStatusBadge("bad", e.message);
    }
  }

  function scheduleAuto() {
    if (timer) clearInterval(timer);
    timer = null;
    if ($("auto-refresh").checked) {
      timer = setInterval(() => refresh().catch(() => {}), 15000);
    }
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function wire() {
    buildTabs();
    showTab("gateway");
    const originBanner = $("origin-banner");
    if (!onWizardOrigin() && originBanner) {
      originBanner.classList.remove("hidden");
      originBanner.innerHTML =
        `Monitoring must be opened from the Setup Wizard shell so <code>/api/v1</code> is proxied ` +
        `(with optional <code>IOTGW_API_TOKEN</code>). Use ` +
        `<a class="link" href="${WIZARD_MONITORING}">${WIZARD_MONITORING}</a>.`;
      setStatusBadge("bad", "wrong origin");
    }
    $("btn-refresh").addEventListener("click", () => refresh().catch(console.error));
    $("auto-refresh").addEventListener("change", scheduleAuto);
    $("show-all").addEventListener("change", () => {
      if (tab === "sensors") refresh().catch(console.error);
    });
    $("range").addEventListener("change", () => refresh().catch(console.error));
    $("gateway-id").addEventListener("change", () => {
      if (tab === "sensors") refresh().catch(console.error);
    });
    $("mon-tabs").addEventListener("click", () => refresh().catch(console.error));
    if (!onWizardOrigin()) return;
    loadGateways()
      .catch(() => {})
      .finally(() => {
        refresh().catch(console.error);
        scheduleAuto();
      });
  }

  wire();
})();

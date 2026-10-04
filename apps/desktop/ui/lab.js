/* Lab panel — talks to wizard /api/lab/fake-sensors/* (optional demos). */
(function () {
  const $ = (id) => document.getElementById(id);

  async function api(path, opts) {
    const res = await fetch(path, {
      headers: { "Content-Type": "application/json", ...(opts && opts.headers) },
      ...opts,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || data.detail || res.statusText || "request failed");
    return data;
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function showStatus(data) {
    $("status-json").textContent = JSON.stringify(data, null, 2);
    const running = !!data.running;
    $("hdr-status").innerHTML = running
      ? '<span class="badge warn">lab running</span>'
      : '<span class="badge ok">lab stopped</span>';
    if (data.warning) {
      $("warn-box").innerHTML = escapeHtml(data.warning);
    }
  }

  async function loadDefaults() {
    try {
      const s = await api("/api/lab/defaults");
      if (s.gateway_ip) $("gateway-ip").value = s.gateway_ip;
      if (s.duration_minutes) $("duration").value = String(s.duration_minutes);
    } catch (_) {
      /* ignore */
    }
  }

  async function refresh() {
    const data = await api("/api/lab/fake-sensors/status");
    showStatus(data);
    $("msg").innerHTML = data.running
      ? `<div class="okmsg">Running until ${data.stops_at ? new Date(data.stops_at * 1000).toLocaleTimeString() : "?"}</div>`
      : `<div class="okmsg">Not running.</div>`;
  }

  async function start() {
    const mins = Number($("duration").value);
    if (!Number.isFinite(mins) || mins < 1 || mins > 60) {
      throw new Error("duration_minutes must be 1..60");
    }
    if (mins > 30) {
      const ok = confirm(
        `Duration is ${mins} minutes. Prolonged fake_sensor runs can overflow storage. Continue?`
      );
      if (!ok) return;
    }
    const sensors = $("sensors")
      .value.split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    $("msg").textContent = "Starting (always rebuilds images for HOST)…";
    const data = await api("/api/lab/fake-sensors/start", {
      method: "POST",
      body: JSON.stringify({
        gateway_ip: $("gateway-ip").value.trim(),
        duration_minutes: mins,
        sensors,
      }),
    });
    showStatus(data);
    $("msg").innerHTML = `<div class="okmsg">Started. Auto-stop scheduled — keep this app open. ${escapeHtml(data.warning || "")}</div>`;
  }

  async function stop() {
    const data = await api("/api/lab/fake-sensors/stop", {
      method: "POST",
      body: "{}",
    });
    showStatus(data);
    $("msg").innerHTML = `<div class="okmsg">Stopped.</div>`;
  }

  function showErr(e) {
    console.error(e);
    $("msg").innerHTML = `<div class="err">${escapeHtml(e.message || String(e))}</div>`;
  }

  $("btn-start").addEventListener("click", () => start().catch(showErr));
  $("btn-stop").addEventListener("click", () => stop().catch(showErr));
  $("btn-refresh").addEventListener("click", () => refresh().catch(showErr));
  loadDefaults().then(() => refresh().catch(() => {}));
})();

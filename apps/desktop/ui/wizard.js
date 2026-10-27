/* First-run installer — Install monitoring only. Network and gateways come later in-app. */
(function () {
  const $ = (id) => document.getElementById(id);

  async function api(path, opts) {
    let res;
    try {
      res = await fetch(path, {
        headers: { "Content-Type": "application/json", ...(opts && opts.headers) },
        ...opts,
      });
    } catch (e) {
      throw new Error(
        "Cannot reach the local app server (Failed to fetch). " +
          "Close this window and start IoT Gateway Monitor again."
      );
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.statusText || "request failed");
    return data;
  }

  function badge(el, ok, text) {
    el.innerHTML = `<span class="badge ${ok ? "ok" : "bad"}">${text}</span>`;
  }

  function setTelemetryReadyUi(ready, detail) {
    badge($("telemetry-badge"), !!ready, ready ? "Ready" : "Not installed");
    $("telemetry-hint").textContent =
      detail ||
      (ready
        ? "Loki, Prometheus, and Grafana are running."
        : "Click Install monitoring to continue.");
    $("hdr-status").innerHTML = ready
      ? '<span class="badge ok">Ready</span>'
      : '<span class="badge warn">Setup</span>';
    const early = $("btn-open-mon-early");
    if (early) early.disabled = !ready;
  }

  async function refreshEnv() {
    const data = await api("/api/wizard/env");
    if (data.setup_complete) {
      window.location.replace("monitoring.html#metric");
      return;
    }
    const t = data.telemetry || {};
    const job = t.job || {};
    if (job.state === "running") {
      badge($("telemetry-badge"), false, "Installing…");
      $("telemetry-hint").textContent =
        t.progress || job.detail || "Installing…";
      $("hdr-status").innerHTML = '<span class="badge warn">Setup</span>';
      return;
    }
    setTelemetryReadyUi(
      !!t.ready,
      t.ready
        ? t.detail || "Loki, Prometheus, and Grafana are running."
        : t.progress || t.detail || "Click Install monitoring to continue."
    );
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async function prepareTelemetry() {
    $("telemetry-hint").textContent = "Installing…";
    badge($("telemetry-badge"), false, "Installing…");
    const early = $("btn-open-mon-early");
    if (early) early.disabled = true;
    try {
      await api("/api/wizard/telemetry/ensure", {
        method: "POST",
        body: JSON.stringify({ background: true }),
      });
      const deadline = Date.now() + 15 * 60 * 1000;
      let last = null;
      while (Date.now() < deadline) {
        last = await api("/api/wizard/telemetry/status");
        const job = last.job || {};
        $("telemetry-hint").textContent =
          last.progress || job.detail || "Installing…";
        if (job.state === "ok") {
          setTelemetryReadyUi(
            true,
            last.detail || job.detail || "Loki, Prometheus, and Grafana are running."
          );
          return;
        }
        if (job.state === "error") {
          throw new Error(job.detail || last.detail || "Install failed");
        }
        await sleep(900);
      }
      throw new Error(
        (last && (last.detail || (last.job && last.job.detail))) ||
          "Install timed out while downloading or starting monitoring."
      );
    } catch (e) {
      badge($("telemetry-badge"), false, "Failed");
      $("telemetry-hint").textContent = String(e.message || e);
      if (early) early.disabled = true;
    }
  }

  async function markSetupComplete() {
    if (typeof window.iotgwMarkSetupComplete === "function") {
      await window.iotgwMarkSetupComplete();
      return;
    }
    try {
      await api("/api/wizard/setup/complete", {
        method: "POST",
        body: "{}",
      });
    } catch (_) {}
  }

  async function enterApp(path) {
    await markSetupComplete();
    window.location.href = path;
  }

  async function startServices() {
    await api("/api/wizard/services/start", {
      method: "POST",
      body: "{}",
    });
  }

  async function openMonitoring() {
    const hint = $("telemetry-hint");
    const prev = hint ? hint.textContent : "";
    if (hint) hint.textContent = "Starting control service…";
    try {
      await startServices();
    } catch (_) {}
    if (hint && prev) hint.textContent = prev;
    await enterApp("monitoring.html#metric");
  }

  function showErr(e) {
    console.error(e);
    alert(e.message || String(e));
  }

  function wire() {
    $("btn-prepare-telemetry").addEventListener("click", () =>
      prepareTelemetry().catch(showErr)
    );
    const early = $("btn-open-mon-early");
    if (early) {
      early.addEventListener("click", () => openMonitoring().catch(showErr));
    }
    refreshEnv().catch(showErr);
  }

  wire();
})();

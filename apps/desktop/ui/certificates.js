/* Settings → Certificates — Grafana HTTPS trust cert + open system browser. */
(function () {
  const $ = (id) => document.getElementById(id);
  const GRAFANA_URL = "https://127.0.0.1:9140/";

  let lastStatus = {
    running: false,
    cert: { present: false, not_after: null, fingerprint_sha256: null },
  };

  async function api(path, opts) {
    let res;
    try {
      res = await fetch(path, {
        headers: { "Content-Type": "application/json", ...(opts && opts.headers) },
        ...opts,
      });
    } catch (e) {
      throw new Error(
        "Cannot reach the local app server. Close this window and start IoT Gateway Monitor again."
      );
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.statusText || "request failed");
    return data;
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function formatExpiry(iso) {
    if (!iso) return "—";
    try {
      const d = new Date(iso);
      if (Number.isNaN(d.getTime())) return String(iso);
      return d.toISOString().replace(/\.\d{3}Z$/, "Z");
    } catch (_) {
      return String(iso);
    }
  }

  function applyStatus(st) {
    lastStatus = st || lastStatus;
    const cert = (st && st.cert) || {};
    const present = !!cert.present;
    const running = !!(st && st.running);

    $("cert-expiry").textContent =
      "Valid until: " + (present ? formatExpiry(cert.not_after) : "—");
    $("cert-fp").textContent =
      "SHA-256: " + (present && cert.fingerprint_sha256 ? cert.fingerprint_sha256 : "—");
    $("grafana-state").textContent =
      "Grafana: " + (running ? "running" : "not running");

    $("btn-cert-download").disabled = !present;

    if (!running) {
      $("hdr-status").innerHTML = '<span class="badge warn">Grafana down</span>';
      $("cert-msg").innerHTML =
        '<div class="err">' +
        escapeHtml(
          "Grafana is not running. Use Install monitoring / Retry on the Certificates page."
        ) +
        "</div>";
    } else {
      $("hdr-status").innerHTML = '<span class="badge ok">Ready</span>';
      if ($("cert-msg").querySelector(".err")) {
        $("cert-msg").innerHTML = "";
      }
    }
  }

  async function refreshStatus() {
    const st = await api("/api/wizard/grafana/status");
    applyStatus(st);
    return st;
  }

  async function downloadCert() {
    const res = await fetch("/api/wizard/grafana/cert");
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || res.statusText || "download failed");
    }
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "iot-gateway-grafana.crt";
    a.click();
    URL.revokeObjectURL(a.href);
    $("cert-msg").innerHTML =
      '<div class="okmsg">' + escapeHtml("Certificate downloaded.") + "</div>";
  }

  async function regenerateCert() {
    $("cert-msg").textContent = "Regenerating…";
    $("btn-cert-regen").disabled = true;
    try {
      await api("/api/wizard/grafana/cert/regenerate", {
        method: "POST",
        body: "{}",
      });
      await refreshStatus();
      $("cert-msg").innerHTML =
        '<div class="okmsg">' +
        escapeHtml("Certificate regenerated. Re-download and re-trust if needed.") +
        "</div>";
    } finally {
      $("btn-cert-regen").disabled = false;
    }
  }

  async function openGrafana() {
    await api("/api/wizard/open-url", {
      method: "POST",
      body: JSON.stringify({ url: GRAFANA_URL }),
    });
  }

  async function retryInstall() {
    $("cert-msg").textContent = "Starting install…";
    $("btn-grafana-retry").disabled = true;
    try {
      await api("/api/wizard/telemetry/ensure", {
        method: "POST",
        body: JSON.stringify({ background: true }),
      });
      $("cert-msg").innerHTML =
        '<div class="okmsg">' +
        escapeHtml(
          "Install started in the background. Wait a minute, then refresh this page."
        ) +
        "</div>";
      // Brief poll so a fast ensure can clear the degraded banner.
      for (let i = 0; i < 6; i++) {
        await new Promise((r) => setTimeout(r, 2500));
        try {
          const st = await refreshStatus();
          if (st.running && st.cert && st.cert.present) {
            $("cert-msg").innerHTML =
              '<div class="okmsg">' +
              escapeHtml("Grafana is running.") +
              "</div>";
            break;
          }
        } catch (_) {
          /* keep waiting */
        }
      }
    } finally {
      $("btn-grafana-retry").disabled = false;
    }
  }

  function wire() {
    $("btn-cert-download").addEventListener("click", () =>
      downloadCert().catch((e) => {
        $("cert-msg").innerHTML =
          '<div class="err">' + escapeHtml(e.message || e) + "</div>";
      })
    );
    $("btn-cert-regen").addEventListener("click", () =>
      regenerateCert().catch((e) => {
        $("cert-msg").innerHTML =
          '<div class="err">' + escapeHtml(e.message || e) + "</div>";
        $("btn-cert-regen").disabled = false;
      })
    );
    $("btn-open-grafana").addEventListener("click", () =>
      openGrafana().catch((e) => {
        $("cert-msg").innerHTML =
          '<div class="err">' + escapeHtml(e.message || e) + "</div>";
      })
    );
    $("btn-grafana-retry").addEventListener("click", () =>
      retryInstall().catch((e) => {
        $("cert-msg").innerHTML =
          '<div class="err">' + escapeHtml(e.message || e) + "</div>";
        $("btn-grafana-retry").disabled = false;
      })
    );
    refreshStatus().catch((e) => {
      $("hdr-status").innerHTML =
        '<span class="badge bad">' + escapeHtml(e.message || e) + "</span>";
      $("cert-msg").innerHTML =
        '<div class="err">' + escapeHtml(e.message || e) + "</div>";
      $("btn-cert-download").disabled = true;
    });
  }

  wire();
})();

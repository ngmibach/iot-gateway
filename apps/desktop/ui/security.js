/* Gateway IDS controls and Loki-backed alert view. */
(function () {
  const $ = (id) => document.getElementById(id);
  const IDS_BASE = "/api/v1";
  const POLL_MS = 15000;
  let gatewayId = "";
  let gatewayStatus = null;
  let busy = false;

  async function control(path, options) {
    let response;
    try {
      response = await fetch(path, {
        headers: { "Content-Type": "application/json", ...(options && options.headers) },
        ...options,
      });
    } catch (error) {
      throw new Error("Gateway or control service is unreachable.");
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = data.detail || data.error || response.statusText;
      throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    }
    return data;
  }

  function setMessage(id, message, error) {
    const element = $(id);
    element.textContent = message || "";
    element.classList.toggle("error", !!error);
  }

  function setBadge(text, kind) {
    const badge = $("ids-header-state");
    badge.textContent = text;
    badge.className = "ids-badge" + (kind ? " " + kind : "");
  }

  function setText(id, value) {
    $(id).textContent = value == null || value === "" ? "—" : String(value);
  }

  function setFormEnabled(enabled) {
    ["enable-button", "disable-button", "save-button"].forEach((id) => {
      $(id).disabled = busy || !enabled;
    });
  }

  function renderStatus(status) {
    gatewayStatus = status;
    const installed = !!status.installed;
    setText("installation-state", installed ? "Installed" : "Not installed");
    setText("configured-state", status.configured_enabled ? "Enabled" : "Disabled");
    setText("service-state", status.service_state);
    setText("model-state", status.model_ready ? "Ready" : "Missing");
    setText("runtime-state", status.runtime_ready ? "Ready" : "Missing");
    const config = status.config || {};
    const rules = config.behavioral_rules || {};
    $("rules-enabled").checked = !!rules.enabled;
    $("ml-enabled").checked = config.ml_enabled !== false;
    $("threshold").value = config.suspicious_threshold == null
      ? "0.05" : String(config.suspicious_threshold);
    $("message-rate").value = String(rules.max_message_rate_per_sec || 1.5);
    $("clock-skew").value = String(rules.max_clock_skew_seconds == null
      ? 2.5 : rules.max_clock_skew_seconds);
    $("connect-ratio").value = String(rules.max_connect_publish_ratio || 1.15);
    $("alert-cooldown").value = String(rules.alert_cooldown_seconds == null
      ? 60 : rules.alert_cooldown_seconds);
    setFormEnabled(installed);
    $("enable-button").disabled = busy || !installed || status.configured_enabled;
    $("disable-button").disabled = busy || !installed || !status.configured_enabled;
    if (!installed) {
      setBadge("Not installed", "warn");
      setMessage("gateway-message", "Provision or update this gateway to install its IDS.");
    } else if (status.service_state === "failed") {
      setBadge("Service failed", "bad");
      setMessage("gateway-message", "IDS service failed: " + (status.result || "check the gateway service logs."), true);
    } else if (status.configured_enabled && status.service_state !== "running") {
      setBadge("Not running", "warn");
      setMessage("gateway-message", "IDS is configured as enabled but the gateway service is not running.", true);
    } else if (!status.configured_enabled) {
      setBadge("Disabled", "warn");
      setMessage("gateway-message", "IDS is installed but disabled. Enable it to start gateway-side detection.");
    } else {
      setBadge("Running", "ok");
      setMessage("gateway-message", "IDS is running on the gateway; detection continues when this app is closed.");
    }
  }

  async function loadStatus() {
    if (!gatewayId) return null;
    const data = await control(
      IDS_BASE + "/gateways/" + encodeURIComponent(gatewayId) + "/ids/status"
    );
    renderStatus(data);
    return data;
  }

  function alertTime(value) {
    if (typeof value === "number" || /^\d{15,}$/.test(String(value || ""))) {
      const numeric = Number(value);
      const millis = numeric > 1e15 ? numeric / 1e6 : numeric > 1e12 ? numeric / 1e3 : numeric;
      const date = new Date(millis);
      return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
    }
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value || "—") : date.toLocaleString();
  }

  function appendCell(row, value) {
    const cell = document.createElement("td");
    cell.textContent = value == null ? "" : String(value);
    row.appendChild(cell);
  }

  function renderAlerts(alerts) {
    const body = $("alerts-body");
    body.replaceChildren();
    const filter = $("alert-search").value.trim().toLowerCase();
    const visible = alerts.filter((alert) => {
      const text = [
        alert.device_id,
        alert.suspicion,
        alert.detection,
        alert.message,
      ].join(" ").toLowerCase();
      return !filter || text.includes(filter);
    });
    visible.forEach((alert) => {
      const row = document.createElement("tr");
      appendCell(row, alertTime(alert.timestamp || alert["@timestamp"]));
      appendCell(row, alert.severity || "—");
      appendCell(row, alert.device_id || "—");
      appendCell(row, alert.suspicion || alert.detection || "—");
      appendCell(row, alert.message || alert.reason || "—");
      const score = Number(alert.score);
      appendCell(row, Number.isFinite(score) ? score.toFixed(4) : "—");
      body.appendChild(row);
    });
    if (!visible.length && gatewayStatus && !gatewayStatus.installed) {
      setMessage("alerts-message", "IDS is not installed on this gateway.");
    } else if (!visible.length && gatewayStatus && !gatewayStatus.configured_enabled) {
      setMessage("alerts-message", "IDS is disabled. Enable it to collect new alerts.");
    } else if (!visible.length) {
      setMessage("alerts-message", "No IDS alerts in this range.");
    } else {
      setMessage("alerts-message", visible.length + " alert(s).");
    }
  }

  async function loadAlerts() {
    if (!gatewayId) {
      $("alerts-body").replaceChildren();
      setMessage("alerts-message", "Select a registered gateway.");
      return;
    }
    const params = new URLSearchParams({
      gateway_id: gatewayId,
      range: $("alert-range").value,
      limit: "500",
    });
    if ($("alert-severity").value) params.set("severity", $("alert-severity").value);
    try {
      const data = await control(IDS_BASE + "/ids/alerts?" + params.toString());
      renderAlerts(Array.isArray(data.alerts) ? data.alerts : []);
    } catch (error) {
      $("alerts-body").replaceChildren();
      setMessage("alerts-message", "Loki error: " + error.message, true);
    }
  }

  async function refresh() {
    if (!gatewayId) return;
    try {
      const status = await loadStatus();
      if (status && !status.installed) {
        $("alerts-body").replaceChildren();
        setMessage("alerts-message", "IDS is not installed on this gateway.");
        return;
      }
    } catch (error) {
      setBadge("Unreachable", "bad");
      setMessage("gateway-message", "Gateway unreachable: " + error.message, true);
    }
    await loadAlerts();
  }

  async function changeEnabled(enabled) {
    if (busy || !gatewayId) return;
    busy = true;
    setFormEnabled(!!(gatewayStatus && gatewayStatus.installed));
    setMessage("gateway-message", enabled ? "Enabling IDS…" : "Disabling IDS…");
    try {
      const password = $("sudo-password").value;
      const data = await control(
        IDS_BASE + "/gateways/" + encodeURIComponent(gatewayId) + "/ids/config",
        {
          method: "POST",
          body: JSON.stringify({ enabled, ...(password ? { sudo_password: password } : {}) }),
        }
      );
      $("sudo-password").value = "";
      renderStatus(data);
      setMessage("settings-message", enabled ? "IDS enabled." : "IDS disabled.");
      await loadAlerts();
    } catch (error) {
      setMessage("gateway-message", error.message, true);
    } finally {
      busy = false;
      setFormEnabled(!!(gatewayStatus && gatewayStatus.installed));
      if (gatewayStatus) renderStatus(gatewayStatus);
    }
  }

  function numberValue(id, label) {
    const value = Number($(id).value);
    if (!Number.isFinite(value)) throw new Error(label + " must be a number.");
    return value;
  }

  async function saveSettings(event) {
    event.preventDefault();
    if (busy || !gatewayId) return;
    let values;
    try {
      values = {
        rules_enabled: $("rules-enabled").checked,
        ml_enabled: $("ml-enabled").checked,
        threshold: numberValue("threshold", "Threshold"),
        max_message_rate_per_sec: numberValue("message-rate", "Max message rate"),
        max_clock_skew_seconds: numberValue("clock-skew", "Max clock skew"),
        max_connect_publish_ratio: numberValue("connect-ratio", "Connect/publish ratio"),
        alert_cooldown_seconds: numberValue("alert-cooldown", "Alert cooldown"),
      };
    } catch (error) {
      setMessage("settings-message", error.message, true);
      return;
    }
    const password = $("sudo-password").value;
    if (password) values.sudo_password = password;
    busy = true;
    setFormEnabled(!!(gatewayStatus && gatewayStatus.installed));
    setMessage("settings-message", "Saving settings…");
    try {
      const data = await control(
        IDS_BASE + "/gateways/" + encodeURIComponent(gatewayId) + "/ids/config",
        { method: "POST", body: JSON.stringify(values) }
      );
      $("sudo-password").value = "";
      renderStatus(data);
      setMessage("settings-message", "Settings saved.");
    } catch (error) {
      setMessage("settings-message", error.message, true);
    } finally {
      busy = false;
      if (gatewayStatus) renderStatus(gatewayStatus);
    }
  }

  async function loadGateways() {
    try {
      const data = await control(IDS_BASE + "/gateways");
      const gateways = Array.isArray(data) ? data : [];
      const select = $("gateway-select");
      select.replaceChildren();
      gateways.forEach((gateway) => {
        const option = document.createElement("option");
        option.value = gateway.id;
        option.textContent = gateway.id + " (" + gateway.host + ")";
        select.appendChild(option);
      });
      if (!gateways.length) {
        gatewayId = "";
        setBadge("No gateways", "warn");
        setMessage("gateway-message", "Register a gateway before configuring IDS.");
        setMessage("alerts-message", "No registered gateway selected.");
        setFormEnabled(false);
        return;
      }
      gatewayId = gateways[0].id;
      await refresh();
    } catch (error) {
      setBadge("Unavailable", "bad");
      setMessage("gateway-message", error.message, true);
      setMessage("alerts-message", "Unable to load IDS alerts.", true);
    }
  }

  $("gateway-select").addEventListener("change", async (event) => {
    gatewayId = event.target.value;
    gatewayStatus = null;
    await refresh();
  });
  $("refresh-button").addEventListener("click", refresh);
  $("enable-button").addEventListener("click", () => changeEnabled(true));
  $("disable-button").addEventListener("click", () => changeEnabled(false));
  $("settings-form").addEventListener("submit", saveSettings);
  ["alert-range", "alert-severity"].forEach((id) => {
    $(id).addEventListener("change", loadAlerts);
  });
  $("alert-search").addEventListener("input", loadAlerts);
  loadGateways();
  window.setInterval(refresh, POLL_MS);
})();

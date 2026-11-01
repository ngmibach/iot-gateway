/* Gateway IDS controls and live alert refresh. */
(function () {
  const $ = (id) => document.getElementById(id);
  const POLL_MS = 15000;
  let gateways = [];
  let alerts = [];
  let selectedGateway = "";
  let refreshing = false;
  let installed = false;
  let gatewayStatus = null;
  let gatewayStatusError = "";
  let configDirty = false;
  let applying = false;

  async function api(path, options) {
    let response;
    try {
      response = await fetch(path, {
        headers: { "Content-Type": "application/json", ...(options?.headers || {}) },
        ...options,
      });
    } catch (error) {
      throw new Error("Cannot reach the local control service. " + String(error.message || error));
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = data.detail || data.error || response.statusText;
      throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    }
    return data;
  }

  function showMessage(message, isError) {
    const node = $("security-message");
    node.textContent = message || "";
    node.classList.toggle("hidden", !message);
    node.style.borderLeftColor = isError ? "var(--bad)" : "var(--ok)";
  }

  function setBadge(kind, text) {
    const badge = document.createElement("span");
    badge.className = "badge " + kind;
    badge.textContent = text;
    $("ids-status-badge").replaceChildren(badge);
  }

  function configureControls(config) {
    $("ids-enabled").checked = Boolean(config.enabled);
    $("rules-enabled").checked = Boolean(config.rules_enabled);
    $("ml-enabled").checked = Boolean(config.ml_enabled);
    $("ml-threshold").value = config.threshold;
    $("rate-threshold").value = config.max_message_rate_per_sec;
    $("clock-threshold").value = config.max_clock_skew_seconds;
    $("connect-ratio").value = config.max_connect_publish_ratio;
    $("cooldown").value = config.alert_cooldown_seconds;
  }

  function setControlAvailability(available) {
    document.querySelectorAll(
      "#ids-enabled, #rules-enabled, #ml-enabled, #ml-threshold, " +
      "#rate-threshold, #clock-threshold, #connect-ratio, #cooldown, #btn-apply-ids"
    ).forEach((node) => {
      node.disabled = !available || (node.id === "btn-apply-ids" && applying);
    });
  }

  async function refreshStatus() {
    if (!selectedGateway) return;
    try {
      const status = await api(
        `/api/v1/gateways/${encodeURIComponent(selectedGateway)}/ids/status`
      );
      gatewayStatus = status;
      gatewayStatusError = "";
      installed = Boolean(status.installed);
      $("ids-configured").textContent = status.configured_enabled == null
        ? "Not installed"
        : status.configured_enabled ? "Enabled" : "Disabled";
      $("ids-service").textContent = status.service_state || "Unknown";
      $("ids-model").textContent = status.model_ready
        ? (status.runtime_ready ? "Ready" : "Assets ready; service not running")
        : "Not ready";
      if (!installed) {
        setBadge("warn", "Not installed");
        showMessage("IDS is not installed. Provision or update this gateway to deploy the IDS service and model.", true);
        setControlAvailability(false);
        return;
      }
      if (!configDirty) configureControls(status.config);
      setControlAvailability(true);
      if (!status.configured_enabled) {
        setBadge("warn", "Disabled");
        showMessage("", false);
      } else if (status.runtime_ready) {
        setBadge("ok", "Enabled · Running");
        showMessage("", false);
      } else {
        setBadge("bad", "Runtime unavailable");
        showMessage(
          `IDS is configured as enabled, but its service is ${status.service_state} ` +
          `(systemd result: ${status.result}).`,
          true
        );
      }
    } catch (error) {
      gatewayStatus = null;
      gatewayStatusError = error.message;
      installed = false;
      setBadge("bad", "Gateway unreachable");
      $("ids-configured").textContent = "Unavailable";
      $("ids-service").textContent = "Unavailable";
      $("ids-model").textContent = "Unavailable";
      setControlAvailability(false);
      showMessage("Could not read IDS status: " + error.message, true);
    }
  }

  function makeCell(value) {
    const cell = document.createElement("td");
    cell.textContent = value == null || value === "" ? "—" : String(value);
    return cell;
  }

  function renderAlerts() {
    const severityFilter = $("severity-filter").value;
    const search = $("alert-search").value.trim().toLowerCase();
    const filtered = alerts.filter((alert) => {
      if (severityFilter && String(alert.severity || "").toLowerCase() !== severityFilter) return false;
      const haystack = [
        alert.device_id, alert.detection, alert.suspicion, alert.message,
      ].join(" ").toLowerCase();
      return !search || haystack.includes(search);
    });
    const rows = filtered.map((alert) => {
      const row = document.createElement("tr");
      const when = alert.occurred_at || alert["@timestamp"];
      const parsed = Date.parse(when || "");
      row.appendChild(makeCell(Number.isNaN(parsed) ? when : new Date(parsed).toLocaleString()));
      const severity = String(alert.severity || "info").toLowerCase();
      const severityCell = makeCell(severity);
      if (["critical", "warning", "info"].includes(severity)) {
        severityCell.classList.add("severity-" + severity);
      }
      row.appendChild(severityCell);
      row.appendChild(makeCell(alert.device_id));
      row.appendChild(makeCell(alert.detection || alert.suspicion));
      row.appendChild(makeCell(alert.message || alert.suspicion_category));
      const score = Number(alert.score);
      row.appendChild(makeCell(alert.score == null || !Number.isFinite(score) ? "—" : score.toFixed(3)));
      return row;
    });
    $("security-alert-rows").replaceChildren(...rows);
    $("alert-empty").classList.toggle("hidden", filtered.length !== 0);
    $("alert-empty").textContent = alerts.length
      ? "No alerts match the selected filters."
      : "No IDS alerts in this time range.";
  }

  function alertStatusNote() {
    if (gatewayStatusError) {
      return "Gateway IDS status is unavailable; displayed alert history may be stale. ";
    }
    if (!gatewayStatus) return "Gateway IDS status has not been checked. ";
    if (!gatewayStatus.installed) {
      return "IDS is not installed on this gateway. ";
    }
    if (!gatewayStatus.configured_enabled) {
      return "IDS is disabled on this gateway; showing any previously recorded alerts. ";
    }
    if (!gatewayStatus.runtime_ready) {
      return `IDS service is ${gatewayStatus.service_state}; alerts may not be current. `;
    }
    return "";
  }

  async function refreshAlerts() {
    if (!selectedGateway) return;
    $("alerts-message").textContent = "Loading alerts…";
    $("alert-empty").classList.add("hidden");
    try {
      const params = new URLSearchParams({
        range: $("alert-range").value,
        limit: "500",
        gateway_id: selectedGateway,
      });
      const result = await api(`/api/v1/ids/alerts?${params}`);
      alerts = Array.isArray(result.alerts) ? result.alerts : [];
      $("alerts-message").textContent =
        `${alertStatusNote()}${result.count} alert${result.count === 1 ? "" : "s"} · updated ${new Date().toLocaleTimeString()}`;
      renderAlerts();
    } catch (error) {
      alerts = [];
      $("security-alert-rows").replaceChildren();
      $("alert-empty").classList.add("hidden");
      $("alerts-message").textContent =
        `${alertStatusNote()}Alerts unavailable: ${error.message}`;
    }
  }

  async function refreshAll() {
    if (refreshing || !selectedGateway) return;
    refreshing = true;
    $("btn-refresh").disabled = true;
    try {
      await refreshStatus();
      await refreshAlerts();
    } finally {
      refreshing = false;
      $("btn-refresh").disabled = false;
    }
  }

  async function applySettings() {
    if (!selectedGateway || !installed) return;
    const button = $("btn-apply-ids");
    const gatewayId = selectedGateway;
    applying = true;
    button.disabled = true;
    $("gateway-id").disabled = true;
    $("config-status").textContent = "Applying settings on gateway…";
    try {
      const payload = {
        enabled: $("ids-enabled").checked,
        rules_enabled: $("rules-enabled").checked,
        ml_enabled: $("ml-enabled").checked,
        threshold: Number($("ml-threshold").value),
        max_message_rate_per_sec: Number($("rate-threshold").value),
        max_clock_skew_seconds: Number($("clock-threshold").value),
        max_connect_publish_ratio: Number($("connect-ratio").value),
        alert_cooldown_seconds: Number($("cooldown").value),
      };
      const password = $("sudo-password").value;
      if (password) payload.sudo_password = password;
      const result = await api(
        `/api/v1/gateways/${encodeURIComponent(gatewayId)}/ids/config`,
        { method: "POST", body: JSON.stringify(payload) }
      );
      $("sudo-password").value = "";
      configDirty = false;
      $("config-status").textContent = result.ok
        ? (payload.enabled ? "IDS enabled and running on the gateway." : "IDS disabled and stopped on the gateway.")
        : "Gateway did not confirm the IDS operation.";
      await refreshAll();
    } catch (error) {
      $("config-status").textContent = "IDS operation failed: " + error.message;
      setBadge("bad", "Update failed");
    } finally {
      applying = false;
      $("gateway-id").disabled = false;
      setControlAvailability(installed);
    }
  }

  async function loadGateways() {
    gateways = await api("/api/v1/gateways");
    const select = $("gateway-id");
    select.replaceChildren();
    gateways.forEach((gateway) => {
      const option = document.createElement("option");
      option.value = gateway.id;
      option.textContent = `${gateway.id} (${gateway.host})`;
      select.appendChild(option);
    });
    if (!gateways.length) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "No registered gateways";
      select.appendChild(option);
      setBadge("warn", "No gateway");
      showMessage("Register and provision a gateway to control IDS.", true);
      setControlAvailability(false);
      return;
    }
    selectedGateway = gateways[0].id;
    select.value = selectedGateway;
    await refreshAll();
  }

  $("gateway-id").addEventListener("change", () => {
    selectedGateway = $("gateway-id").value;
    alerts = [];
    $("security-alert-rows").replaceChildren();
    $("alert-empty").classList.add("hidden");
    gatewayStatus = null;
    gatewayStatusError = "";
    configDirty = false;
    $("config-status").textContent = "";
    refreshAll();
  });
  document.querySelectorAll(
    "#ids-enabled, #rules-enabled, #ml-enabled, #ml-threshold, " +
    "#rate-threshold, #clock-threshold, #connect-ratio, #cooldown"
  ).forEach((node) => {
    node.addEventListener("input", () => { configDirty = true; });
    node.addEventListener("change", () => { configDirty = true; });
  });
  $("btn-refresh").addEventListener("click", refreshAll);
  $("btn-apply-ids").addEventListener("click", applySettings);
  $("alert-range").addEventListener("change", refreshAlerts);
  $("severity-filter").addEventListener("change", renderAlerts);
  $("alert-search").addEventListener("input", renderAlerts);

  loadGateways().catch((error) => {
    setBadge("bad", "Unavailable");
    showMessage("Could not load registered gateways: " + error.message, true);
  });
  window.setInterval(() => {
    if (selectedGateway) refreshAll();
  }, POLL_MS);
})();

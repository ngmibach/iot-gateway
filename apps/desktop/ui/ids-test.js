/* Live test observes real IDS alerts; the operator controls the fake sensor. */
(function () {
  const $ = (id) => document.getElementById(id);
  const durationMs = 150000;
  const pollMs = 3000;
  let running = false;
  let sensorGateway = "";

  function message(text, error) {
    const node = $("ids-test-message");
    node.textContent = text;
    node.classList.toggle("error", !!error);
  }

  async function request(path) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetch(path, { signal: controller.signal });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || body.error || response.statusText);
      }
      return await response.json();
    } finally {
      window.clearTimeout(timer);
    }
  }

  async function refreshSensors() {
    const gateway = $("gateway-select").value;
    const select = $("ids-test-device");
    select.replaceChildren();
    sensorGateway = "";
    if (!gateway) {
      message("Select a gateway first.", true);
      return;
    }
    try {
      const devices = await request("/api/v1/gateways/" + encodeURIComponent(gateway) + "/devices?is_fake=true");
      if (gateway !== $("gateway-select").value) return;
      if (!Array.isArray(devices)) throw new Error("Invalid sensor list.");
      devices.forEach((device) => {
        if (!device.is_fake) return;
        const option = document.createElement("option");
        option.value = device.id;
        option.textContent = device.id;
        select.appendChild(option);
      });
      sensorGateway = gateway;
      message(select.value ? "Select the dedicated test sensor, then run the test." : "No fake sensors found. Create one in Control Plane.");
    } catch (error) {
      message("Could not load fake sensors: " + error.message, true);
    }
  }

  async function alerts(gateway) {
    const query = new URLSearchParams({ gateway_id: gateway, range: "15m", limit: "2000" });
    const result = await request("/api/v1/ids/alerts?" + query.toString());
    if (!Array.isArray(result.alerts)) throw new Error("Invalid IDS alerts response.");
    return result.alerts;
  }

  function alertKey(alert) {
    return JSON.stringify([alert.timestamp || alert["@timestamp"], alert.device_id,
      alert.alert_type, alert.score_type, alert.score, alert.message]);
  }

  function isModelAlert(alert, device) {
    return alert.device_id === device && alert.alert_type === "ml_anomaly" &&
      alert.score_type === "ml_probability";
  }

  async function runTest() {
    if (running) return;
    const gateway = $("gateway-select").value;
    const device = $("ids-test-device").value;
    if (!gateway || !device || sensorGateway !== gateway) {
      message("Select a gateway and refresh its fake sensors first.", true);
      return;
    }
    running = true;
    $("ids-test-start").disabled = true;
    $("ids-test-refresh").disabled = true;
    $("ids-test-device").disabled = true;
    $("gateway-select").disabled = true;
    try {
      message("Checking IDS and fake sensor settings…");
      const base = "/api/v1/gateways/" + encodeURIComponent(gateway);
      const status = await request(base + "/ids/status");
      const config = status.config || {};
      if (!status.installed || !status.configured_enabled || status.service_state !== "running" ||
          !status.model_ready || !status.runtime_ready) {
        throw new Error("IDS must be installed, enabled and running with its model and runtime ready.");
      }
      if (config.ml_enabled === false || !config.behavioral_rules || config.behavioral_rules.enabled !== false) {
        throw new Error("Enable ML and disable behavioral rules, then save settings before the test.");
      }
      const fake = await request(base + "/devices/" + encodeURIComponent(device) + "/fake");
      if (fake.status !== "running") throw new Error("Start the dedicated fake sensor in Control Plane first.");
      if (Number(fake.send_interval_ms) !== 100) throw new Error("Set the fake sensor interval to 100 ms.");
      const behaviors = fake.behaviors || {};
      if (behaviors.ids_test_alternate_order !== true ||
          Object.keys(behaviors).some((key) => key !== "ids_test_alternate_order" && behaviors[key])) {
        throw new Error("Enable only the IDS test order option; disable all other simulated behaviors.");
      }
      const previous = new Set((await alerts(gateway)).filter((item) => isModelAlert(item, device)).map(alertKey));
      const started = Date.now();
      message("Waiting for a new ML alert from " + device + " (up to 150 seconds)…");
      while (Date.now() - started < durationMs) {
        await new Promise((resolve) => window.setTimeout(resolve, pollMs));
        const found = (await alerts(gateway)).find((item) =>
          isModelAlert(item, device) && !previous.has(alertKey(item)) &&
          Date.parse(item.timestamp || item["@timestamp"]) >= started
        );
        if (found) {
          message("PASS: a new ML alert for " + device + " reached the app. Stop the fake sensor and restore IDS settings.");
          return;
        }
      }
      message("INCONCLUSIVE: no new ML alert arrived within 150 seconds. Check sensor, IDS, Loki and clock synchronization; stop the fake sensor and restore IDS settings.", true);
    } catch (error) {
      message("Test could not be completed: " + error.message + " Stop the fake sensor if it is running and restore IDS settings.", true);
    } finally {
      running = false;
      $("ids-test-start").disabled = false;
      $("ids-test-refresh").disabled = false;
      $("ids-test-device").disabled = false;
      $("gateway-select").disabled = false;
    }
  }

  $("ids-test-refresh").addEventListener("click", refreshSensors);
  $("ids-test-start").addEventListener("click", runTest);
  $("gateway-select").addEventListener("change", () => {
    sensorGateway = "";
    $("ids-test-device").replaceChildren();
    message("Refresh sensors for the selected gateway.");
  });
})();

/* Control Plane — progressive Registration + View (same-origin /api/v1 wizard proxy). */
(function () {
  const $ = (id) => document.getElementById(id);

  let devices = [];
  let fakeDevices = [];
  let baseline = null;
  let selectedSensorIp = "";
  let caWaiters = null;
  let pendingSimDeviceId = "";

  const SIM_BEHAVIOR_IDS = {
    omit_client_cert: "sim-omit-cert",
    wrong_client_cert: "sim-wrong-cert",
    skip_encryption: "sim-skip-enc",
    bad_encryption: "sim-bad-enc",
    wrong_password: "sim-wrong-pass",
    wrong_topic: "sim-wrong-topic",
  };

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function onWizardOrigin() {
    if (location.protocol !== "http:" && location.protocol !== "https:") {
      return false;
    }
    const host = location.hostname;
    return host === "127.0.0.1" || host === "localhost";
  }

  async function control(method, path, { body, query } = {}) {
    if (!onWizardOrigin()) {
      throw new Error(
        "Open Control Plane from the app shell so /api/v1 is proxied."
      );
    }
    let url = path;
    if (query) {
      const qs = new URLSearchParams(query);
      url += "?" + qs.toString();
    }
    const res = await fetch(url, {
      method,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: body != null ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { detail: text };
    }
    if (!res.ok) {
      const detail = data.detail || data.error;
      const msg =
        typeof detail === "string"
          ? detail
          : detail != null
            ? JSON.stringify(detail)
            : res.statusText || "request failed";
      const err = new Error(msg);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  async function wizardApi(method, path, { body, query } = {}) {
    let url = path;
    if (query) {
      const qs = new URLSearchParams(query);
      url += "?" + qs.toString();
    }
    const res = await fetch(url, {
      method,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: body != null ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { error: text };
    }
    if (!res.ok) {
      const msg = data.error || data.detail || res.statusText || "request failed";
      const err = new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  function selectedGateway() {
    return ($("gw-select") && $("gw-select").value) || "";
  }

  function requireGateway() {
    const gid = selectedGateway();
    if (!gid) throw new Error("Select a gateway first.");
    return gid;
  }

  function showTab(id) {
    document.querySelectorAll(".action-panel").forEach((el) => {
      el.classList.toggle("hidden", el.dataset.action !== id);
    });
    document.querySelectorAll("#action-tabs button").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.action === id);
    });
    if (id === "view") {
      refreshDevices().catch(showErr);
    } else if (id === "simulate") {
      refreshFakeDevices().catch(showErr);
    }
  }

  function formatEpoch(ts) {
    if (ts == null || ts === "") return "—";
    const n = Number(ts);
    if (!Number.isFinite(n) || n <= 0) return String(ts);
    try {
      return new Date(n * 1000).toLocaleString();
    } catch {
      return String(ts);
    }
  }

  function statusBadgeClass(status) {
    const s = String(status || "").toLowerCase();
    if (s === "running") return "ok";
    if (s === "stopped") return "warn";
    if (s === "error") return "bad";
    return "warn";
  }

  function wireTabs() {
    document.querySelectorAll("#action-tabs button").forEach((btn) => {
      btn.addEventListener("click", () => showTab(btn.dataset.action));
    });
  }

  function topicOne(value) {
    if (value == null) return "";
    if (Array.isArray(value)) return value.length ? String(value[0]) : "";
    return String(value);
  }

  function isCaFailure(err) {
    const msg = String((err && err.message) || err || "").toLowerCase();
    return (
      msg.includes("ca_passphrase") ||
      msg.includes("ca passphrase") ||
      msg.includes("passphrase") ||
      msg.includes("bad decrypt") ||
      msg.includes("mac verify") ||
      msg.includes("unable to load") ||
      msg.includes("wrong password") ||
      msg.includes("password required")
    );
  }

  function openCaModal() {
    return new Promise((resolve, reject) => {
      caWaiters = { resolve, reject };
      $("ca-modal-pass").value = "";
      $("ca-modal-msg").innerHTML = "";
      $("ca-modal").classList.remove("hidden");
      setTimeout(() => $("ca-modal-pass").focus(), 50);
    });
  }

  function closeCaModal(ok, value) {
    $("ca-modal").classList.add("hidden");
    const waiters = caWaiters;
    caWaiters = null;
    if (!waiters) return;
    if (ok) waiters.resolve(value);
    else waiters.reject(new Error("CA passphrase entry cancelled."));
  }

  async function ensureCaPassphrase(gid) {
    const status = await wizardApi("GET", "/api/wizard/secrets/ca-status", {
      query: { gateway_id: gid },
    });
    if (status.present) return;
    const passphrase = await openCaModal();
    await wizardApi("PUT", "/api/wizard/secrets/ca", {
      body: { gateway_id: gid, ca_passphrase: passphrase },
    });
  }

  async function clearStoredCa(gid) {
    try {
      await wizardApi("DELETE", "/api/wizard/secrets/ca", {
        query: { gateway_id: gid },
      });
    } catch {
      /* ignore */
    }
  }

  async function withCaRetry(gid, fn) {
    await ensureCaPassphrase(gid);
    try {
      return await fn();
    } catch (err) {
      if (!isCaFailure(err)) throw err;
      await clearStoredCa(gid);
      const passphrase = await openCaModal();
      await wizardApi("PUT", "/api/wizard/secrets/ca", {
        body: { gateway_id: gid, ca_passphrase: passphrase },
      });
      return await fn();
    }
  }

  function renderDownloadCards(container, gatewayId, items) {
    container.classList.remove("hidden");
    const ttlNote =
      '<div class="note-box">One-time download (≤5 min). Download now to keep a copy for the sensor.</div>';
    const cards = (items || [])
      .map((it) => {
        const url =
          `/api/v1/gateways/${encodeURIComponent(gatewayId)}/devices/${encodeURIComponent(it.device_id)}/cert-bundle?token=${encodeURIComponent(it.cert_bundle_token)}`;
        const fp = it.fingerprint_sha256
          ? `<div class="mono">fp ${escapeHtml(it.fingerprint_sha256)}</div>`
          : "";
        return `<div class="download-card">
          <strong>${escapeHtml(it.device_id)}</strong>
          ${fp}
          <div><a class="btn-dl" href="${url}" download="${escapeHtml(it.device_id)}-cert-bundle.zip">Download cert bundle</a></div>
        </div>`;
      })
      .join("");
    container.innerHTML = ttlNote + (cards || "<p>No bundles.</p>");
  }

  async function refreshGateways() {
    const rows = await control("GET", "/api/v1/gateways");
    const sel = $("gw-select");
    const prev = sel.value;
    sel.innerHTML = "";
    (rows || []).forEach((gw) => {
      const opt = document.createElement("option");
      opt.value = gw.id;
      opt.textContent = `${gw.id} — ${gw.host}`;
      sel.appendChild(opt);
    });
    if (prev && [...sel.options].some((o) => o.value === prev)) sel.value = prev;
    if (!(rows || []).length) {
      $("ctrl-msg").innerHTML =
        '<div class="err">No gateways in registry. Register a gateway first.</div>';
      $("hdr-status").innerHTML = '<span class="badge warn">no gateway</span>';
      return;
    }
    $("ctrl-msg").innerHTML = "";
    $("hdr-status").innerHTML = '<span class="badge ok">Ready</span>';
  }

  function hideFakeForm() {
    if (!$("fake-form")) return;
    $("fake-form").classList.add("hidden");
    $("fake-download").classList.add("hidden");
    if ($("fake-msg")) $("fake-msg").innerHTML = "";
  }

  function hideRegForm() {
    selectedSensorIp = "";
    $("reg-form").classList.add("hidden");
    $("reg-download").classList.add("hidden");
    if ($("reg-msg")) $("reg-msg").innerHTML = "";
  }

  function showRegForm(ip, { editable } = {}) {
    hideFakeForm();
    selectedSensorIp = ip || "";
    $("reg-ip").value = selectedSensorIp;
    $("reg-ip").readOnly = !editable;
    if (!$("reg-user").value.trim() && selectedSensorIp) {
      /* leave Device ID for the operator */
    }
    const uid = $("reg-user").value.trim();
    if (uid && !$("reg-topic-rw").value.trim()) {
      $("reg-topic-rw").value = `sensors/${uid}/#`;
    }
    $("reg-form").classList.remove("hidden");
    $("reg-download").classList.add("hidden");
    if ($("reg-msg")) $("reg-msg").innerHTML = "";
  }

  function showFakeForm() {
    hideRegForm();
    $("reg-results").classList.add("hidden");
    $("scan-badge").innerHTML = "";
    $("scan-msg").textContent =
      "Neighbor lists only show devices the gateway has recently talked to.";
    $("fake-form").classList.remove("hidden");
    $("fake-download").classList.add("hidden");
    if ($("fake-msg")) $("fake-msg").innerHTML = "";
    setTimeout(() => $("fake-user").focus(), 50);
  }

  function renderHostList(hosts) {
    const list = $("host-list");
    const results = $("reg-results");
    list.innerHTML = "";
    results.classList.remove("hidden");

    if (!hosts.length) {
      const li = document.createElement("li");
      li.className = "host-list-empty";
      li.textContent =
        "No neighbors found. Sensors appear after they talk to the gateway; or enter an IP manually.";
      list.appendChild(li);
      hideRegForm();
      return;
    }

    hosts.forEach((h) => {
      const ip = h.ip || h;
      const mac = h.mac ? ` · ${h.mac}` : "";
      const state = h.state ? ` (${h.state})` : "";
      const li = document.createElement("li");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "host-list-item";
      btn.dataset.ip = ip;
      btn.textContent = `${ip}${mac}${state}`;
      btn.addEventListener("click", () => {
        list.querySelectorAll(".host-list-item").forEach((el) => {
          el.classList.toggle("selected", el === btn);
        });
        showRegForm(ip);
      });
      li.appendChild(btn);
      list.appendChild(li);
    });
  }

  async function findSensors() {
    const gid = requireGateway();
    hideFakeForm();
    $("scan-msg").textContent = "Looking for sensors on the gateway…";
    $("scan-badge").innerHTML = '<span class="badge warn">Scanning…</span>';
    $("btn-find-sensor").disabled = true;
    hideRegForm();
    $("reg-results").classList.add("hidden");
    $("host-list").innerHTML = "";
    try {
      const data = await control(
        "POST",
        `/api/v1/gateways/${encodeURIComponent(gid)}/devices/discover`
      );
      const hosts = data.hosts || [];
      renderHostList(hosts);
      $("scan-badge").innerHTML = hosts.length
        ? `<span class="badge ok">${hosts.length} found</span>`
        : '<span class="badge warn">0 found</span>';
      $("scan-msg").textContent = hosts.length
        ? "Select a device to continue."
        : "No neighbors found. Enter an IP manually if you know it.";
    } catch (e) {
      $("scan-badge").innerHTML = '<span class="badge bad">Failed</span>';
      $("scan-msg").innerHTML = `<div class="err">${escapeHtml(e.message || e)}</div>`;
      throw e;
    } finally {
      $("btn-find-sensor").disabled = false;
    }
  }

  function enterManualIp() {
    $("reg-results").classList.remove("hidden");
    showRegForm("", { editable: true });
    $("reg-ip").focus();
  }

  async function registerDevice() {
    const gid = requireGateway();
    const user_id = $("reg-user").value.trim();
    const password = $("reg-pass").value;
    const ip = $("reg-ip").value.trim();
    if (!user_id || !password || !ip) {
      throw new Error("Device ID, password, and IP are required.");
    }
    if (password.length < 8) {
      throw new Error("Password must be at least 8 characters.");
    }
    const body = { user_id, password, ip };
    const tr = $("reg-topic-r").value.trim();
    const tw = $("reg-topic-rw").value.trim();
    if (tr) body.topic_read = tr;
    if (tw) body.topic_readwrite = tw;

    $("reg-msg").textContent = "Registering…";
    $("reg-download").classList.add("hidden");
    $("btn-register").disabled = true;
    try {
      const data = await withCaRetry(gid, () =>
        control("POST", `/api/v1/gateways/${encodeURIComponent(gid)}/devices`, {
          body,
        })
      );
      $("reg-msg").innerHTML = `<div class="okmsg">Registered <strong>${escapeHtml(
        user_id
      )}</strong>.</div>`;
      if (data.cert_bundle_token) {
        renderDownloadCards($("reg-download"), gid, [
          {
            device_id: user_id,
            cert_bundle_token: data.cert_bundle_token,
            fingerprint_sha256:
              (data.device && data.device.cert_fingerprint) || null,
          },
        ]);
      }
      $("reg-pass").value = "";
    } finally {
      $("btn-register").disabled = false;
    }
  }

  function parseFakePayload(raw) {
    const text = (raw || "").trim();
    if (!text) return { hello: 1 };
    try {
      return JSON.parse(text);
    } catch {
      throw new Error("Payload must be valid JSON.");
    }
  }

  async function createFakeDevice() {
    const gid = requireGateway();
    const user_id = $("fake-user").value.trim();
    const password = $("fake-pass").value;
    if (!user_id || !password) {
      throw new Error("Device ID and password are required.");
    }
    if (password.length < 8) {
      throw new Error("Password must be at least 8 characters.");
    }
    // Rate / payload are configured later on the Simulate tab (API defaults at create).
    const body = {
      user_id,
      password,
    };
    const tr = $("fake-topic-r").value.trim();
    const tw = $("fake-topic-rw").value.trim();
    if (tr) body.topic_read = tr;
    if (tw) body.topic_readwrite = tw;

    $("fake-msg").textContent = "Creating…";
    $("fake-download").classList.add("hidden");
    $("btn-fake-create").disabled = true;
    try {
      const data = await withCaRetry(gid, () =>
        control(
          "POST",
          `/api/v1/gateways/${encodeURIComponent(gid)}/devices/fake`,
          { body }
        )
      );
      const status = (data.device && data.device.fake && data.device.fake.status) || "";
      const okLine =
        status === "running" || !status
          ? "Fake sensor running. Open Simulate to drive it."
          : `Fake sensor created (${escapeHtml(status)}). Open Simulate to drive it.`;
      $("fake-msg").innerHTML = `<div class="okmsg">${okLine}</div>`;
      if (data.cert_bundle_token) {
        renderDownloadCards($("fake-download"), gid, [
          {
            device_id: user_id,
            cert_bundle_token: data.cert_bundle_token,
            fingerprint_sha256:
              (data.device && data.device.cert_fingerprint) || null,
          },
        ]);
      }
      $("fake-pass").value = "";
    } finally {
      $("btn-fake-create").disabled = false;
    }
  }

  function currentViewSnapshot() {
    return {
      id: ($("view-id").value || "").trim(),
      ip: ($("view-ip").value || "").trim(),
      topic_rw: ($("view-topic-rw").value || "").trim(),
      topic_r: ($("view-topic-r").value || "").trim(),
      monitor: !!$("view-monitor").checked,
      password: ($("view-pass").value || "").trim(),
    };
  }

  function isDirty() {
    if (!baseline) return false;
    const cur = currentViewSnapshot();
    if (cur.password) return true;
    return (
      cur.ip !== baseline.ip ||
      cur.topic_rw !== baseline.topic_rw ||
      cur.topic_r !== baseline.topic_r ||
      cur.monitor !== baseline.monitor
    );
  }

  function syncUpdateButton() {
    const btn = $("btn-view-update");
    if (!btn) return;
    const dirty = isDirty();
    btn.classList.toggle("hidden", !dirty);
    btn.disabled = !dirty;
  }

  function syncDeleteButton() {
    const btn = $("btn-view-delete");
    const confirm = $("view-delete-confirm");
    if (!btn || !confirm) return;
    btn.disabled = !confirm.checked || !($("view-id").value || "").trim();
  }

  function fillViewForm(device) {
    if (!device) {
      baseline = null;
      $("view-form").classList.add("hidden");
      $("view-empty").classList.remove("hidden");
      $("view-msg").innerHTML = "";
      $("view-download").classList.add("hidden");
      if ($("view-fake-meta")) $("view-fake-meta").classList.add("hidden");
      if ($("view-type-badge")) {
        $("view-type-badge").textContent = "";
        $("view-type-badge").className = "badge";
      }
      syncUpdateButton();
      syncDeleteButton();
      return;
    }
    $("view-empty").classList.add("hidden");
    $("view-form").classList.remove("hidden");
    $("view-id").value = device.id || "";
    $("view-ip").value = device.ip || "";
    $("view-topic-rw").value = topicOne(device.topics_rw);
    $("view-topic-r").value = topicOne(device.topics_r);
    $("view-pass").value = "";
    $("view-monitor").checked = !!device.monitor_enabled;
    $("view-fp").textContent = device.cert_fingerprint || "—";
    $("view-expires").textContent = formatEpoch(device.cert_expires_at);
    $("view-delete-confirm").checked = false;
    $("view-remove-ip").checked = false;
    $("view-msg").innerHTML = "";
    $("view-download").classList.add("hidden");

    const badge = $("view-type-badge");
    if (badge) {
      if (device.is_fake) {
        badge.textContent = "Fake";
        badge.className = "badge fake";
      } else {
        badge.textContent = "Real";
        badge.className = "badge real";
      }
    }
    const fakeMeta = $("view-fake-meta");
    if (fakeMeta) {
      if (device.is_fake) {
        fakeMeta.classList.remove("hidden");
        const fake = device.fake || {};
        const attack =
          fake.behaviors &&
          (fake.behaviors.omit_client_cert || fake.behaviors.wrong_client_cert);
        $("view-auto-renew").textContent = attack
          ? "paused (TLS behavior on)"
          : "on";
        $("view-cert-fed").textContent = formatEpoch(fake.cert_fed_at);
      } else {
        fakeMeta.classList.add("hidden");
      }
    }

    baseline = {
      id: device.id || "",
      ip: device.ip || "",
      topic_rw: topicOne(device.topics_rw),
      topic_r: topicOne(device.topics_r),
      monitor: !!device.monitor_enabled,
    };
    syncUpdateButton();
    syncDeleteButton();
  }

  async function refreshDevices() {
    const gid = requireGateway();
    devices = await control(
      "GET",
      `/api/v1/gateways/${encodeURIComponent(gid)}/devices`
    );
    const sel = $("view-device");
    const prev = sel.value;
    sel.innerHTML = "";
    (devices || []).forEach((d) => {
      const opt = document.createElement("option");
      opt.value = d.id;
      opt.textContent = d.id + (d.ip ? ` — ${d.ip}` : "");
      sel.appendChild(opt);
    });
    if (!devices || !devices.length) {
      fillViewForm(null);
      return;
    }
    if (prev && devices.some((d) => d.id === prev)) sel.value = prev;
    const selected =
      devices.find((d) => d.id === sel.value) || devices[0];
    if (selected) sel.value = selected.id;
    fillViewForm(selected);
  }

  async function updateDevice() {
    const gid = requireGateway();
    if (!isDirty()) return;
    const cur = currentViewSnapshot();
    if (!cur.id) throw new Error("Select a device first.");

    const body = {};
    const monitorOnly =
      !cur.password &&
      cur.ip === baseline.ip &&
      cur.topic_rw === baseline.topic_rw &&
      cur.topic_r === baseline.topic_r &&
      cur.monitor !== baseline.monitor;

    if (monitorOnly) {
      body.monitor_enabled = cur.monitor;
    } else {
      if (!cur.password || cur.password.length < 8) {
        throw new Error(
          "Password (min 8 characters) is required to update IP, topics, or credentials."
        );
      }
      body.password = cur.password;
      body.ip = cur.ip;
      if (cur.topic_rw) body.topic_readwrite = cur.topic_rw;
      else body.topic_readwrite = "";
      if (cur.topic_r) body.topic_read = cur.topic_r;
      else body.topic_read = "";
      body.monitor_enabled = cur.monitor;
    }

    $("view-msg").textContent = "Updating…";
    $("btn-view-update").disabled = true;
    try {
      const data = monitorOnly
        ? await control(
            "PATCH",
            `/api/v1/gateways/${encodeURIComponent(gid)}/devices/${encodeURIComponent(cur.id)}`,
            { body }
          )
        : await withCaRetry(gid, () =>
            control(
              "PATCH",
              `/api/v1/gateways/${encodeURIComponent(gid)}/devices/${encodeURIComponent(cur.id)}`,
              { body }
            )
          );
      $("view-msg").innerHTML = `<div class="okmsg">${escapeHtml(
        data.message || "Updated."
      )}</div>`;
      if (data.cert_bundle_token) {
        renderDownloadCards($("view-download"), gid, [
          {
            device_id: cur.id,
            cert_bundle_token: data.cert_bundle_token,
            fingerprint_sha256:
              (data.device && data.device.cert_fingerprint) || null,
          },
        ]);
      }
      await refreshDevices();
      const still = (devices || []).find((d) => d.id === cur.id);
      if (still) {
        $("view-device").value = still.id;
        fillViewForm(still);
      }
    } finally {
      syncUpdateButton();
    }
  }

  async function reissueCert() {
    const gid = requireGateway();
    const device_id = ($("view-id").value || "").trim();
    if (!device_id) throw new Error("Select a device first.");
    $("view-msg").textContent = "Re-issuing certificate…";
    $("view-download").classList.add("hidden");
    $("btn-view-reissue").disabled = true;
    try {
      const data = await withCaRetry(gid, () =>
        control(
          "POST",
          `/api/v1/gateways/${encodeURIComponent(gid)}/devices/${encodeURIComponent(device_id)}/reissue-cert`,
          { body: {} }
        )
      );
      $("view-msg").innerHTML = `<div class="okmsg">${escapeHtml(
        data.message || "Certificate reissued."
      )}</div>`;
      if (data.cert_bundle_token) {
        renderDownloadCards($("view-download"), gid, [
          {
            device_id: device_id,
            cert_bundle_token: data.cert_bundle_token,
            fingerprint_sha256:
              (data.device && data.device.cert_fingerprint) || null,
          },
        ]);
      }
      await refreshDevices();
      const still = (devices || []).find((d) => d.id === device_id);
      if (still) {
        $("view-device").value = still.id;
        fillViewForm(still);
        if (data.cert_bundle_token) {
          renderDownloadCards($("view-download"), gid, [
            {
              device_id: device_id,
              cert_bundle_token: data.cert_bundle_token,
              fingerprint_sha256:
                (data.device && data.device.cert_fingerprint) || null,
            },
          ]);
          $("view-msg").innerHTML = `<div class="okmsg">${escapeHtml(
            data.message || "Certificate reissued."
          )}</div>`;
        }
      }
    } finally {
      $("btn-view-reissue").disabled = false;
    }
  }

  async function deleteDevice() {
    const gid = requireGateway();
    const device_id = ($("view-id").value || "").trim();
    if (!device_id) throw new Error("Select a device first.");
    if (!$("view-delete-confirm").checked) {
      throw new Error("Tick the delete confirmation checkbox first.");
    }
    const remove_ip = $("view-remove-ip").checked;
    $("view-msg").textContent = "Deleting…";
    $("btn-view-delete").disabled = true;
    try {
      const data = await control(
        "DELETE",
        `/api/v1/gateways/${encodeURIComponent(gid)}/devices/${encodeURIComponent(device_id)}`,
        { query: { remove_ip: remove_ip ? "true" : "false" } }
      );
      $("view-msg").innerHTML = `<div class="okmsg">${escapeHtml(
        data.message || "Device deleted."
      )}</div>`;
      await refreshDevices();
    } catch (e) {
      syncDeleteButton();
      throw e;
    }
  }

  function readSimBehaviors() {
    const out = {};
    Object.keys(SIM_BEHAVIOR_IDS).forEach((key) => {
      const el = $(SIM_BEHAVIOR_IDS[key]);
      out[key] = !!(el && el.checked);
    });
    return out;
  }

  function writeSimBehaviors(behaviors) {
    const src = behaviors || {};
    Object.keys(SIM_BEHAVIOR_IDS).forEach((key) => {
      const el = $(SIM_BEHAVIOR_IDS[key]);
      if (el) el.checked = !!src[key];
    });
  }

  function fillSimCertLine(device, fake) {
    const line = $("sim-cert-line");
    if (!line) return;
    const expires = formatEpoch(device && device.cert_expires_at);
    const fp = (device && device.cert_fingerprint) || "";
    const fedFp = (fake && fake.cert_feed_fingerprint) || "";
    const fedAt = formatEpoch(fake && fake.cert_fed_at);
    let match = "—";
    if (fp && fedFp) {
      match = fp === fedFp ? "match" : "lag";
    } else if (fedFp) {
      match = "fed";
    }
    const attack =
      fake &&
      fake.behaviors &&
      (fake.behaviors.omit_client_cert || fake.behaviors.wrong_client_cert);
    const renew = attack ? "paused" : "on";
    line.textContent = `Cert expires ${expires} · feed ${match} · last fed ${fedAt} · auto-renew ${renew}`;
  }

  function fillSimForm(device) {
    if (!device) {
      $("sim-form").classList.add("hidden");
      $("sim-empty").classList.remove("hidden");
      if ($("sim-msg")) $("sim-msg").innerHTML = "";
      return;
    }
    $("sim-empty").classList.add("hidden");
    $("sim-form").classList.remove("hidden");
    const fake = device.fake || {};
    const status = fake.status || "unknown";
    const badge = $("sim-status-badge");
    badge.textContent = status;
    badge.className = `badge ${statusBadgeClass(status)}`;
    $("sim-interval").value =
      fake.send_interval_ms != null ? String(fake.send_interval_ms) : "1000";
    $("sim-topic").value = fake.topic || "";
    if (!$("sim-payload").value.trim()) {
      $("sim-payload").value = '{\n  "hello": 1\n}';
    }
    writeSimBehaviors(fake.behaviors);
    fillSimCertLine(device, fake);
    if ($("sim-msg")) $("sim-msg").innerHTML = "";
    const running = String(status).toLowerCase() === "running";
    $("btn-sim-start").disabled = running;
    $("btn-sim-stop").disabled = !running && String(status).toLowerCase() !== "error";
  }

  async function refreshFakeDevices() {
    const gid = requireGateway();
    fakeDevices = await control(
      "GET",
      `/api/v1/gateways/${encodeURIComponent(gid)}/devices`,
      { query: { is_fake: "true" } }
    );
    const sel = $("sim-device");
    const prev = pendingSimDeviceId || sel.value;
    pendingSimDeviceId = "";
    sel.innerHTML = "";
    (fakeDevices || []).forEach((d) => {
      const opt = document.createElement("option");
      opt.value = d.id;
      const st = (d.fake && d.fake.status) || "";
      opt.textContent =
        d.id + (d.ip ? ` — ${d.ip}` : "") + (st ? ` (${st})` : "");
      sel.appendChild(opt);
    });
    if (!fakeDevices || !fakeDevices.length) {
      fillSimForm(null);
      return;
    }
    if (prev && fakeDevices.some((d) => d.id === prev)) sel.value = prev;
    const selected =
      fakeDevices.find((d) => d.id === sel.value) || fakeDevices[0];
    if (selected) sel.value = selected.id;
    fillSimForm(selected);
  }

  async function simStartStop(action) {
    const gid = requireGateway();
    const device_id = ($("sim-device").value || "").trim();
    if (!device_id) throw new Error("Select a fake sensor first.");
    $("sim-msg").textContent = action === "start" ? "Starting…" : "Stopping…";
    $("btn-sim-start").disabled = true;
    $("btn-sim-stop").disabled = true;
    try {
      const data = await control(
        "POST",
        `/api/v1/gateways/${encodeURIComponent(gid)}/devices/${encodeURIComponent(device_id)}/fake/${action}`,
        { body: {} }
      );
      $("sim-msg").innerHTML = `<div class="okmsg">${escapeHtml(
        data.message || (action === "start" ? "Started." : "Stopped.")
      )}</div>`;
      await refreshFakeDevices();
      if ($("sim-device")) $("sim-device").value = device_id;
      const still = (fakeDevices || []).find((d) => d.id === device_id);
      if (still) fillSimForm(still);
    } finally {
      const still = (fakeDevices || []).find((d) => d.id === device_id);
      if (still) fillSimForm(still);
    }
  }

  async function applySimConfig() {
    const gid = requireGateway();
    const device_id = ($("sim-device").value || "").trim();
    if (!device_id) throw new Error("Select a fake sensor first.");
    const intervalRaw = ($("sim-interval").value || "").trim();
    const send_interval_ms = intervalRaw ? Number(intervalRaw) : 1000;
    if (!Number.isFinite(send_interval_ms) || send_interval_ms < 100) {
      throw new Error("Send interval must be at least 100 ms.");
    }
    const payload = parseFakePayload($("sim-payload").value);
    const body = {
      send_interval_ms: Math.floor(send_interval_ms),
      payload,
      behaviors: readSimBehaviors(),
    };
    const topic = ($("sim-topic").value || "").trim();
    if (topic) body.topic = topic;

    $("sim-msg").textContent = "Applying…";
    $("btn-sim-apply").disabled = true;
    try {
      const data = await control(
        "PATCH",
        `/api/v1/gateways/${encodeURIComponent(gid)}/devices/${encodeURIComponent(device_id)}/fake`,
        { body }
      );
      $("sim-msg").innerHTML = `<div class="okmsg">${escapeHtml(
        data.message || "Applied."
      )}</div>`;
      await refreshFakeDevices();
      if ($("sim-device")) $("sim-device").value = device_id;
      const still = (fakeDevices || []).find((d) => d.id === device_id);
      if (still) fillSimForm(still);
    } finally {
      $("btn-sim-apply").disabled = false;
    }
  }

  function openSimulateForCurrentView() {
    const id = ($("view-id").value || "").trim();
    pendingSimDeviceId = id;
    showTab("simulate");
  }

  function showErr(e) {
    console.error(e);
    const msg = e.message || String(e);
    const panel = document.querySelector(".action-panel:not(.hidden)");
    let target = $("ctrl-msg");
    if (panel) {
      if (panel.dataset.action === "simulate" && $("sim-msg")) {
        target = $("sim-msg");
      } else if ($("fake-form") && !$("fake-form").classList.contains("hidden")) {
        target = $("fake-msg") || target;
      } else if ($("reg-form") && !$("reg-form").classList.contains("hidden")) {
        target = $("reg-msg") || target;
      } else if (panel.querySelector("#view-msg")) {
        target = panel.querySelector("#view-msg");
      }
    }
    if (target) {
      target.innerHTML = `<div class="err">${escapeHtml(msg)}</div>`;
    } else {
      alert(msg);
    }
  }

  function wire() {
    wireTabs();
    showTab("register");

    $("btn-load-gw").addEventListener("click", () =>
      refreshGateways()
        .then(() => {
          const active = document.querySelector("#action-tabs button.active");
          const tab = active && active.dataset.action;
          if (tab === "view") return refreshDevices();
          if (tab === "simulate") return refreshFakeDevices();
        })
        .catch(showErr)
    );
    $("gw-select").addEventListener("change", () => {
      hideRegForm();
      hideFakeForm();
      $("reg-results").classList.add("hidden");
      $("host-list").innerHTML = "";
      $("scan-badge").innerHTML = "";
      $("scan-msg").textContent =
        "Neighbor lists only show devices the gateway has recently talked to.";
      const active = document.querySelector("#action-tabs button.active");
      const tab = active && active.dataset.action;
      if (tab === "view") {
        refreshDevices().catch(showErr);
      } else if (tab === "simulate") {
        refreshFakeDevices().catch(showErr);
      }
    });

    $("btn-find-sensor").addEventListener("click", () =>
      findSensors().catch(showErr)
    );
    $("btn-create-fake").addEventListener("click", () => {
      try {
        requireGateway();
        showFakeForm();
      } catch (e) {
        showErr(e);
      }
    });
    $("btn-fake-cancel").addEventListener("click", () => hideFakeForm());
    $("btn-fake-create").addEventListener("click", () =>
      createFakeDevice().catch(showErr)
    );
    $("fake-user").addEventListener("input", () => {
      const uid = $("fake-user").value.trim();
      if (uid && !$("fake-topic-rw").dataset.touched) {
        $("fake-topic-rw").value = `sensors/${uid}/#`;
      }
    });
    $("fake-topic-rw").addEventListener("input", () => {
      $("fake-topic-rw").dataset.touched = "1";
    });
    $("btn-manual-ip").addEventListener("click", () => {
      try {
        requireGateway();
        enterManualIp();
      } catch (e) {
        showErr(e);
      }
    });
    $("reg-user").addEventListener("input", () => {
      const uid = $("reg-user").value.trim();
      if (uid && !$("reg-topic-rw").dataset.touched) {
        $("reg-topic-rw").value = `sensors/${uid}/#`;
      }
    });
    $("reg-topic-rw").addEventListener("input", () => {
      $("reg-topic-rw").dataset.touched = "1";
    });
    $("btn-register").addEventListener("click", () =>
      registerDevice().catch(showErr)
    );

    $("btn-refresh-view").addEventListener("click", () =>
      refreshDevices().catch(showErr)
    );
    $("view-device").addEventListener("change", () => {
      const d = (devices || []).find((x) => x.id === $("view-device").value);
      fillViewForm(d || null);
    });
    if ($("btn-open-simulate")) {
      $("btn-open-simulate").addEventListener("click", () => {
        try {
          openSimulateForCurrentView();
        } catch (e) {
          showErr(e);
        }
      });
    }

    ["view-ip", "view-topic-rw", "view-topic-r", "view-pass"].forEach((id) => {
      $(id).addEventListener("input", syncUpdateButton);
    });
    $("view-monitor").addEventListener("change", syncUpdateButton);
    $("view-delete-confirm").addEventListener("change", syncDeleteButton);

    $("btn-view-update").addEventListener("click", () =>
      updateDevice().catch(showErr)
    );
    $("btn-view-reissue").addEventListener("click", () =>
      reissueCert().catch(showErr)
    );
    $("btn-view-delete").addEventListener("click", () =>
      deleteDevice().catch(showErr)
    );

    $("btn-refresh-sim").addEventListener("click", () =>
      refreshFakeDevices().catch(showErr)
    );
    $("sim-device").addEventListener("change", () => {
      const d = (fakeDevices || []).find((x) => x.id === $("sim-device").value);
      fillSimForm(d || null);
    });
    $("btn-sim-start").addEventListener("click", () =>
      simStartStop("start").catch(showErr)
    );
    $("btn-sim-stop").addEventListener("click", () =>
      simStartStop("stop").catch(showErr)
    );
    $("btn-sim-apply").addEventListener("click", () =>
      applySimConfig().catch(showErr)
    );

    $("btn-ca-save").addEventListener("click", () => {
      const pass = ($("ca-modal-pass").value || "").trim();
      if (!pass) {
        $("ca-modal-msg").innerHTML =
          '<div class="err">Enter the gateway CA passphrase.</div>';
        return;
      }
      if (pass === "admin") {
        $("ca-modal-msg").innerHTML =
          '<div class="err">Passphrase &quot;admin&quot; is not allowed.</div>';
        return;
      }
      closeCaModal(true, pass);
    });
    $("btn-ca-cancel").addEventListener("click", () => closeCaModal(false));
    $("ca-modal-pass").addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") {
        ev.preventDefault();
        $("btn-ca-save").click();
      }
    });

    refreshGateways().catch(() => {});
  }

  wire();
})();

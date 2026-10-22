/* Control Plane — Registration + View (same-origin /api/v1 wizard proxy). */
(function () {
  const $ = (id) => document.getElementById(id);

  let devices = [];
  let baseline = null;

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
    }
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

  function renderDownloadCards(container, gatewayId, items) {
    container.classList.remove("hidden");
    const ttlNote =
      '<div class="note-box">One-time download (≤5 min). Download now to keep a copy.</div>';
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
    const ca = $("reg-ca").value;
    if (tr) body.topic_read = tr;
    if (tw) body.topic_readwrite = tw;
    if (ca) body.ca_passphrase = ca;
    $("reg-msg").textContent = "Registering…";
    $("reg-download").classList.add("hidden");
    const data = await control(
      "POST",
      `/api/v1/gateways/${encodeURIComponent(gid)}/devices`,
      { body }
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
    $("view-ca").value = "";
    $("view-monitor").checked = !!device.monitor_enabled;
    $("view-fp").textContent = device.cert_fingerprint || "—";
    $("view-expires").textContent =
      device.cert_expires_at != null ? String(device.cert_expires_at) : "—";
    $("view-delete-confirm").checked = false;
    $("view-remove-ip").checked = false;
    $("view-msg").innerHTML = "";
    $("view-download").classList.add("hidden");
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
      const ca = ($("view-ca").value || "").trim();
      if (ca) body.ca_passphrase = ca;
    }

    $("view-msg").textContent = "Updating…";
    $("btn-view-update").disabled = true;
    try {
      const data = await control(
        "PATCH",
        `/api/v1/gateways/${encodeURIComponent(gid)}/devices/${encodeURIComponent(cur.id)}`,
        { body }
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

  function showErr(e) {
    console.error(e);
    const msg = e.message || String(e);
    const active =
      document.querySelector(".action-panel:not(.hidden) #view-msg") ||
      document.querySelector(".action-panel:not(.hidden) #reg-msg") ||
      $("ctrl-msg");
    if (active) {
      active.innerHTML = `<div class="err">${escapeHtml(msg)}</div>`;
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
          if (document.querySelector('#action-tabs button.active[data-action="view"]')) {
            return refreshDevices();
          }
        })
        .catch(showErr)
    );
    $("gw-select").addEventListener("change", () => {
      if (document.querySelector('#action-tabs button.active[data-action="view"]')) {
        refreshDevices().catch(showErr);
      }
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

    ["view-ip", "view-topic-rw", "view-topic-r", "view-pass"].forEach((id) => {
      $(id).addEventListener("input", syncUpdateButton);
    });
    $("view-monitor").addEventListener("change", syncUpdateButton);
    $("view-delete-confirm").addEventListener("change", syncDeleteButton);

    $("btn-view-update").addEventListener("click", () =>
      updateDevice().catch(showErr)
    );
    $("btn-view-delete").addEventListener("click", () =>
      deleteDevice().catch(showErr)
    );

    refreshGateways().catch(() => {});
  }

  wire();
})();

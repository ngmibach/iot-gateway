/* Native Actions chrome — talks to FastAPI control service (:9137). */
(function () {
  const $ = (id) => document.getElementById(id);

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function controlBase() {
    return ($("ctrl-url").value || "http://127.0.0.1:9137").replace(/\/$/, "");
  }

  function authHeaders() {
    const token = ($("ctrl-token").value || "").trim();
    const h = { "Content-Type": "application/json", Accept: "application/json" };
    if (token) h["X-API-Token"] = token;
    return h;
  }

  async function control(method, path, { body, query } = {}) {
    let url = controlBase() + path;
    if (query) {
      const qs = new URLSearchParams(query);
      url += "?" + qs.toString();
    }
    const res = await fetch(url, {
      method,
      headers: authHeaders(),
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
      const detail = data.detail;
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
    return $("gw-select").value || "";
  }

  function requireGateway() {
    const gid = selectedGateway();
    if (!gid) throw new Error("Select a gateway first (Refresh gateways).");
    return gid;
  }

  function showTab(id) {
    document.querySelectorAll(".action-panel").forEach((el) => {
      el.classList.toggle("hidden", el.dataset.action !== id);
    });
    document.querySelectorAll("#action-tabs button").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.action === id);
    });
  }

  function wireTabs() {
    document.querySelectorAll("#action-tabs button").forEach((btn) => {
      btn.addEventListener("click", () => showTab(btn.dataset.action));
    });
  }

  function renderDownloadCards(container, gatewayId, items, { safekeep } = {}) {
    container.classList.remove("hidden");
    const ttlNote =
      '<div class="note-box">One-time download (≤5 min). Token is wiped after first GET — download now to keep a copy.</div>';
    const warnHtml = safekeep
      ? `<div class="note-box danger">Do NOT install on devices yet — TLS frontends may still serve the old CA (reload_failed). Download for safekeeping only.</div>${ttlNote}`
      : ttlNote;
    const cta = safekeep
      ? "Download for safekeeping only (do not install on devices yet)"
      : "Download cert bundle";
    const btnClass = safekeep ? "btn-dl safekeep" : "btn-dl";
    const cards = (items || [])
      .map((it) => {
        const url =
          controlBase() +
          `/api/v1/gateways/${encodeURIComponent(gatewayId)}/devices/${encodeURIComponent(it.device_id)}/cert-bundle?token=${encodeURIComponent(it.cert_bundle_token)}`;
        const fp = it.fingerprint_sha256
          ? `<div class="mono">fp ${escapeHtml(it.fingerprint_sha256)}</div>`
          : "";
        return `<div class="download-card">
          <strong>${escapeHtml(it.device_id)}</strong>
          ${fp}
          <div><a class="${btnClass}" href="${url}" download="${escapeHtml(it.device_id)}-cert-bundle.zip">${escapeHtml(cta)}</a></div>
          <div class="mono" style="margin-top:0.35rem">${escapeHtml(url)}</div>
        </div>`;
      })
      .join("");
    container.innerHTML = warnHtml + (cards || "<p>No bundles.</p>");
  }

  async function loadControlConfig() {
    try {
      const res = await fetch("/api/wizard/control");
      if (!res.ok) return;
      const data = await res.json();
      if (data.url) $("ctrl-url").value = data.url;
      if (data.api_token) $("ctrl-token").value = data.api_token;
    } catch {
      /* wizard may not be hosting — keep defaults */
    }
    if (!$("ctrl-url").value) $("ctrl-url").value = "http://127.0.0.1:9137";
  }

  async function ping() {
    const res = await fetch(controlBase() + "/health");
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || res.statusText);
    $("ctrl-msg").innerHTML = `<div class="okmsg">Healthy: ${escapeHtml(JSON.stringify(data))}</div>`;
    $("hdr-status").innerHTML = '<span class="badge ok">API up</span>';
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
    $("ctrl-msg").innerHTML = `<div class="okmsg">${(rows || []).length} gateway(s)</div>`;
    if (!(rows || []).length) {
      $("ctrl-msg").innerHTML =
        '<div class="err">No gateways in registry. Finish Setup Wizard / provision first.</div>';
    }
  }

  async function registerDevice() {
    const gid = requireGateway();
    const user_id = $("reg-user").value.trim();
    const password = $("reg-pass").value;
    const ip = $("reg-ip").value.trim();
    if (!user_id || !password || !ip) throw new Error("USER_ID, password, and IP are required.");
    if (password.length < 8) throw new Error("Password must be at least 8 characters.");
    const body = { user_id, password, ip };
    const tr = $("reg-topic-r").value.trim();
    const tw = $("reg-topic-rw").value.trim();
    const ca = $("reg-ca").value;
    if (tr) body.topic_read = tr;
    if (tw) body.topic_readwrite = tw;
    if (ca) body.ca_passphrase = ca;
    $("reg-msg").textContent = "Registering…";
    $("reg-download").classList.add("hidden");
    const data = await control("POST", `/api/v1/gateways/${encodeURIComponent(gid)}/devices`, {
      body,
    });
    $("reg-msg").innerHTML = `<div class="okmsg">Registered <strong>${escapeHtml(user_id)}</strong> (status=${escapeHtml(data.status || "ok")}${data.idempotent ? ", idempotent" : ""})</div>`;
    if (data.cert_bundle_token) {
      renderDownloadCards($("reg-download"), gid, [
        {
          device_id: user_id,
          cert_bundle_token: data.cert_bundle_token,
          fingerprint_sha256: (data.device && data.device.cert_fingerprint) || null,
        },
      ]);
    }
    $("reg-pass").value = "";
  }

  async function refreshDevices() {
    const gid = requireGateway();
    const rows = await control("GET", `/api/v1/gateways/${encodeURIComponent(gid)}/devices`);
    const wrap = $("devices-table");
    const dl = $("device-datalist");
    dl.innerHTML = "";
    if (!rows || !rows.length) {
      wrap.innerHTML = "<p>No devices registered.</p>";
      $("devices-msg").textContent = "";
      return;
    }
    const head =
      "<tr><th>ID</th><th>IP</th><th>Monitor</th><th>Fingerprint</th><th>Expires</th></tr>";
    const body = rows
      .map((d) => {
        const opt = document.createElement("option");
        opt.value = d.id;
        dl.appendChild(opt);
        return `<tr>
          <td>${escapeHtml(d.id)}</td>
          <td>${escapeHtml(d.ip || "")}</td>
          <td>${d.monitor_enabled ? "yes" : "no"}</td>
          <td class="mono">${escapeHtml(d.cert_fingerprint || "")}</td>
          <td>${d.cert_expires_at != null ? escapeHtml(String(d.cert_expires_at)) : ""}</td>
        </tr>`;
      })
      .join("");
    wrap.innerHTML = `<table class="devices"><thead>${head}</thead><tbody>${body}</tbody></table>`;
    $("devices-msg").innerHTML = `<div class="okmsg">${rows.length} device(s)</div>`;
  }

  async function unregisterDevice() {
    const gid = requireGateway();
    const device_id = $("unreg-device").value.trim();
    if (!device_id) throw new Error("Device ID is required.");
    const remove_ip = $("unreg-remove-ip").checked;
    if (!window.confirm(`Unregister ${device_id} on ${gid}?`)) return;
    $("unreg-msg").textContent = "Unregistering…";
    const data = await control(
      "DELETE",
      `/api/v1/gateways/${encodeURIComponent(gid)}/devices/${encodeURIComponent(device_id)}`,
      { query: { remove_ip: remove_ip ? "true" : "false" } }
    );
    $("unreg-msg").innerHTML = `<div class="okmsg">${escapeHtml(data.message || "Device unregistered.")} (status=${escapeHtml(data.status || "ok")})</div>`;
  }

  async function rotateServer() {
    const gid = requireGateway();
    const body = {};
    const ip = $("rs-ip").value.trim();
    const ca = $("rs-ca").value;
    if (ip) body.gateway_ip = ip;
    if (ca) body.ca_passphrase = ca;
    $("rs-msg").textContent = "Rotating server cert…";
    const data = await control(
      "POST",
      `/api/v1/gateways/${encodeURIComponent(gid)}/actions/rotate-server-cert`,
      { body }
    );
    const statusClass = data.status === "ok" ? "okmsg" : "warnmsg";
    $("rs-msg").innerHTML = `<div class="${statusClass}">Server cert rotated for ${escapeHtml(data.gateway_ip)} (status=${escapeHtml(data.status)}). fp=${escapeHtml(data.fingerprint_sha256 || "")}</div>`;
    if (data.message) {
      const noteClass = data.status === "ok" ? "note-box" : "note-box danger";
      $("rs-msg").innerHTML += `<div class="${noteClass}">${escapeHtml(data.message)}</div>`;
    }
  }

  async function rotateCa() {
    const gid = requireGateway();
    if (!$("rca-confirm").checked) {
      throw new Error("Confirm break-glass CA rotation first.");
    }
    const body = { confirm_break_glass: true };
    const ip = $("rca-ip").value.trim();
    const ca = $("rca-ca").value;
    if (ip) body.gateway_ip = ip;
    if (ca) body.ca_passphrase = ca;
    if (!window.confirm("Break-glass: rotate CA and reissue ALL device certs?")) return;
    $("rca-msg").textContent = "Rotating CA…";
    $("rca-download").classList.add("hidden");
    const data = await control(
      "POST",
      `/api/v1/gateways/${encodeURIComponent(gid)}/actions/rotate-ca`,
      { body }
    );
    const okClass = data.redistribute ? "okmsg" : "err";
    $("rca-msg").innerHTML = `<div class="${okClass}">status=${escapeHtml(data.status)} redistribute=${data.redistribute} — ${escapeHtml(data.message || "")}</div>`;
    if (data.devices && data.devices.length) {
      renderDownloadCards($("rca-download"), gid, data.devices, {
        safekeep: !data.redistribute,
      });
    }
  }

  function wire() {
    wireTabs();
    showTab("register");
    $("btn-ping").addEventListener("click", () => ping().catch(showErr));
    $("btn-load-gw").addEventListener("click", () => refreshGateways().catch(showErr));
    $("btn-register").addEventListener("click", () => registerDevice().catch(showErr));
    $("btn-refresh-devices").addEventListener("click", () => refreshDevices().catch(showErr));
    $("btn-unregister").addEventListener("click", () => unregisterDevice().catch(showErr));
    $("btn-rotate-server").addEventListener("click", () => rotateServer().catch(showErr));
    $("btn-rotate-ca").addEventListener("click", () => rotateCa().catch(showErr));
    loadControlConfig()
      .then(() => refreshGateways().catch(() => {}))
      .catch(() => {});
  }

  function showErr(e) {
    console.error(e);
    const msg = e.message || String(e);
    alert(msg);
  }

  wire();
})();

/* Admin area — unlock + Code Signing tab (K16). */
(function () {
  let session = sessionStorage.getItem("iotgw_admin_session") || "";
  let lastExport = "";

  const $ = (id) => document.getElementById(id);

  async function api(path, opts) {
    const headers = {
      "Content-Type": "application/json",
      ...(opts && opts.headers),
    };
    if (session) headers["X-Admin-Session"] = session;
    const res = await fetch(path, { ...opts, headers });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.statusText || "request failed");
    return data;
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function showUnlockUI(st) {
    $("row-set-pin").classList.toggle("hidden", !!st.has_pin && !st.unlocked);
    $("btn-lock").disabled = !st.unlocked;
    $("panel-signing").classList.toggle("hidden", !st.unlocked);
    $("hdr-status").innerHTML = st.unlocked
      ? '<span class="badge ok">admin unlocked</span>'
      : st.has_pin
        ? '<span class="badge warn">locked</span>'
        : '<span class="badge bad">no PIN</span>';
  }

  async function refreshStatus() {
    const st = await api("/api/admin/status");
    if (st.unlocked && session) {
      showUnlockUI(st);
    } else if (!st.unlocked) {
      session = "";
      sessionStorage.removeItem("iotgw_admin_session");
      showUnlockUI(st);
    } else {
      // Server thinks unlocked but we lost token — treat as locked client-side
      showUnlockUI({ ...st, unlocked: false });
    }
    return st;
  }

  async function setPin() {
    const pin = $("pin-set").value;
    const data = await api("/api/admin/pin/set", {
      method: "POST",
      body: JSON.stringify({ pin }),
    });
    session = data.session || "";
    sessionStorage.setItem("iotgw_admin_session", session);
    $("pin-set").value = "";
    $("unlock-msg").innerHTML = `<div class="okmsg">PIN saved in keyring; session unlocked.</div>`;
    showUnlockUI(data);
  }

  async function unlock() {
    const pin = $("pin-unlock").value;
    const data = await api("/api/admin/unlock", {
      method: "POST",
      body: JSON.stringify({ pin }),
    });
    session = data.session || "";
    sessionStorage.setItem("iotgw_admin_session", session);
    $("pin-unlock").value = "";
    $("unlock-msg").innerHTML = `<div class="okmsg">Unlocked.</div>`;
    showUnlockUI(data);
    await loadIdentity();
    await detectTools();
  }

  async function lock() {
    await api("/api/admin/lock", { method: "POST", body: "{}" });
    session = "";
    sessionStorage.removeItem("iotgw_admin_session");
    $("unlock-msg").innerHTML = `<div class="okmsg">Locked.</div>`;
    await refreshStatus();
  }

  async function detectTools() {
    const data = await api("/api/admin/signing/tools");
    $("tools-json").textContent = JSON.stringify(data, null, 2);
    const ok = data.windows_ready || data.linux_ready;
    $("tools-badge").innerHTML = ok
      ? `<span class="badge ok">win=${!!data.windows_ready} linux=${!!data.linux_ready}</span>`
      : `<span class="badge bad">no signing tools on PATH</span>`;
  }

  async function loadIdentity() {
    const data = await api("/api/admin/signing/identity");
    if (data.platform) $("plat").value = data.platform;
    if (data.pfx_path) $("pfx-path").value = data.pfx_path;
    if (data.thumbprint) $("thumb").value = data.thumbprint;
    if (data.gpg_key_id) $("gpg-key").value = data.gpg_key_id;
  }

  async function saveIdentity() {
    const body = {
      platform: $("plat").value,
      pfx_path: $("pfx-path").value.trim() || null,
      thumbprint: $("thumb").value.trim() || null,
      gpg_key_id: $("gpg-key").value.trim() || null,
      pfx_passphrase: $("pfx-pass").value || null,
      gpg_passphrase: $("gpg-pass").value || null,
    };
    await api("/api/admin/signing/identity", {
      method: "POST",
      body: JSON.stringify(body),
    });
    $("pfx-pass").value = "";
    $("gpg-pass").value = "";
    $("ident-msg").innerHTML = `<div class="okmsg">Identity saved (passphrases cleared from form).</div>`;
  }

  async function scanFolder() {
    const folder = $("build-folder").value.trim();
    if (!folder) throw new Error("build folder required");
    const data = await api("/api/admin/signing/list-artifacts", {
      method: "POST",
      body: JSON.stringify({ folder }),
    });
    const wrap = $("artifact-list");
    wrap.innerHTML = "";
    const paths = [];
    (data.artifacts || []).forEach((a) => {
      const div = document.createElement("div");
      div.className = "row";
      div.innerHTML = `<span class="badge ok">${escapeHtml(a.platform)}</span> <code class="mono">${escapeHtml(a.path)}</code>`;
      wrap.appendChild(div);
      paths.push(a.path);
    });
    if (paths.length) $("artifact-paths").value = paths.join("\n");
    if (!paths.length) {
      wrap.innerHTML = `<p class="err">No .msi/.exe/.AppImage/.deb found in folder.</p>`;
    }
  }

  async function sign() {
    const lines = $("artifact-paths").value
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    if (!lines.length) throw new Error("no artifact paths");
    const body = {
      artifacts: lines,
      platform: $("plat").value,
      pfx_path: $("pfx-path").value.trim() || undefined,
      thumbprint: $("thumb").value.trim() || undefined,
      gpg_key_id: $("gpg-key").value.trim() || undefined,
      pfx_passphrase: $("pfx-pass").value || undefined,
      gpg_passphrase: $("gpg-pass").value || undefined,
      export_dir: $("export-dir").value.trim() || undefined,
    };
    $("sign-msg").textContent = "Signing…";
    let data;
    try {
      data = await api("/api/admin/signing/sign", {
        method: "POST",
        body: JSON.stringify(body),
      });
    } catch (e) {
      $("sign-msg").innerHTML = `<div class="err">${escapeHtml(e.message)}</div>`;
      throw e;
    }
    $("pfx-pass").value = "";
    $("gpg-pass").value = "";
    $("sign-result").textContent = JSON.stringify(data, null, 2);
    lastExport = data.export_dir || "";
    $("btn-open-export").disabled = !lastExport;
    $("sign-msg").innerHTML = data.ok
      ? `<div class="okmsg">Signed. export=${escapeHtml(lastExport)} audit_id=${data.audit_id}</div>`
      : `<div class="err">${escapeHtml(data.error || "sign failed")}</div>`;
  }

  async function openExport() {
    if (!lastExport) throw new Error("no export folder yet");
    await api("/api/admin/signing/open-export", {
      method: "POST",
      body: JSON.stringify({ folder: lastExport }),
    });
  }

  function wire() {
    $("btn-set-pin").addEventListener("click", () => setPin().catch(showErr));
    $("btn-unlock").addEventListener("click", () => unlock().catch(showErr));
    $("btn-lock").addEventListener("click", () => lock().catch(showErr));
    $("btn-tools").addEventListener("click", () => detectTools().catch(showErr));
    $("btn-save-ident").addEventListener("click", () => saveIdentity().catch(showErr));
    $("btn-scan").addEventListener("click", () => scanFolder().catch(showErr));
    $("btn-sign").addEventListener("click", () => sign().catch(showErr));
    $("btn-open-export").addEventListener("click", () => openExport().catch(showErr));
    refreshStatus()
      .then((st) => {
        if (st.unlocked && session) {
          loadIdentity().catch(() => {});
          detectTools().catch(() => {});
        }
      })
      .catch(showErr);
  }

  function showErr(e) {
    console.error(e);
    $("unlock-msg").innerHTML = `<div class="err">${escapeHtml(e.message || e)}</div>`;
  }

  wire();
})();

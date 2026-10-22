/* Gateways — Registration / Settings / Clean up. */
(function () {
  const TABS = [
    { id: "registration", label: "Registration", title: "Registration" },
    { id: "settings", label: "Settings", title: "Gateway settings" },
    { id: "cleanup", label: "Clean up", title: "Clean up" },
  ];

  const DEFAULT_SSH_PORT = 22;

  const $ = (id) => document.getElementById(id);

  let selectedHost = "";
  let selectedPort = DEFAULT_SSH_PORT;
  let targets = { gateways: [], provisioned: false, default_gateway_id: "gateway" };
  let tab = "registration";

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

  function tabFromHash() {
    const h = (location.hash || "").replace(/^#/, "").toLowerCase();
    if (h === "settings" || h === "setting") return "settings";
    if (h === "cleanup" || h === "clean-up" || h === "clean") return "cleanup";
    if (h === "registration" || h === "register") return "registration";
    return "registration";
  }

  function showTab(id, opts) {
    const next = TABS.some((t) => t.id === id) ? id : "registration";
    tab = next;
    document.querySelectorAll(".gw-panel").forEach((el) => {
      el.classList.toggle("hidden", el.dataset.tab !== tab);
    });
    const meta = TABS.find((t) => t.id === tab) || TABS[0];
    if ($("page-title")) $("page-title").textContent = meta.title;
    if ($("page-sub")) {
      $("page-sub").textContent = "Gateways · " + meta.label;
    }
    const want = "#" + tab;
    if ((opts || {}).syncHash !== false && location.hash !== want) {
      history.replaceState(null, "", want);
    }
    if (typeof window.iotgwRefreshNav === "function") {
      window.iotgwRefreshNav();
    }
    if (tab === "settings" || tab === "cleanup") {
      refreshTargets().catch(() => {});
    }
  }

  async function seedDefaultLan() {
    const data = await api("/api/wizard/nics");
    const pick = data.default || (data.candidates || [])[0];
    if (!pick || !pick.ip) {
      throw new Error("No LAN address available on this PC.");
    }
    await api("/api/wizard/nics/select", {
      method: "POST",
      body: JSON.stringify({
        monitoring_ip: pick.ip,
        nic_name: pick.name,
      }),
    });
    return pick.ip;
  }

  function hideInstallPanel() {
    selectedHost = "";
    selectedPort = DEFAULT_SSH_PORT;
    const panel = $("reg-install");
    if (panel) panel.classList.add("hidden");
    if ($("reg-host")) $("reg-host").value = "";
    if ($("provision-msg")) $("provision-msg").innerHTML = "";
  }

  function showInstallPanel(host, port) {
    selectedHost = host;
    selectedPort = port || DEFAULT_SSH_PORT;
    if ($("reg-host")) $("reg-host").value = host;
    if (!$("ssh-gid").value.trim()) $("ssh-gid").value = "gateway";
    $("reg-install").classList.remove("hidden");
    if ($("provision-msg")) $("provision-msg").innerHTML = "";
  }

  function renderHostList(hosts) {
    const list = $("host-list");
    const results = $("reg-results");
    list.innerHTML = "";
    results.classList.toggle("hidden", false);

    if (!hosts.length) {
      const li = document.createElement("li");
      li.className = "host-list-empty";
      li.textContent = "No devices found. Try Find gateway again.";
      list.appendChild(li);
      hideInstallPanel();
      return;
    }

    hosts.forEach((h) => {
      const ip = h.ip || h;
      const port = h.port || DEFAULT_SSH_PORT;
      const li = document.createElement("li");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "host-list-item";
      btn.dataset.ip = ip;
      btn.dataset.port = String(port);
      btn.textContent = port && port !== DEFAULT_SSH_PORT ? `${ip} :${port}` : ip;
      btn.addEventListener("click", () => {
        list.querySelectorAll(".host-list-item").forEach((el) => {
          el.classList.toggle("selected", el === btn);
        });
        showInstallPanel(ip, port);
      });
      li.appendChild(btn);
      list.appendChild(li);
    });
  }

  async function scanGateways() {
    $("scan-msg").textContent = "Looking for gateways…";
    $("scan-badge").innerHTML = '<span class="badge warn">Scanning…</span>';
    $("btn-scan-gw").disabled = true;
    hideInstallPanel();
    $("reg-results").classList.add("hidden");
    $("host-list").innerHTML = "";
    try {
      let data;
      try {
        data = await api("/api/wizard/discover/gateways", {
          method: "POST",
          body: JSON.stringify({ port: DEFAULT_SSH_PORT }),
        });
      } catch (e) {
        // Seed LAN only when settings have no monitoring_ip yet.
        if (!/monitoring_ip/i.test(String(e.message || e))) throw e;
        await seedDefaultLan();
        data = await api("/api/wizard/discover/gateways", {
          method: "POST",
          body: JSON.stringify({ port: DEFAULT_SSH_PORT }),
        });
      }
      const hosts = data.hosts || [];
      renderHostList(hosts);
      $("scan-badge").innerHTML = hosts.length
        ? `<span class="badge ok">${hosts.length} found</span>`
        : '<span class="badge warn">0 found</span>';
      $("scan-msg").textContent = hosts.length
        ? "Select a device to continue."
        : "No devices found on this LAN.";
    } catch (e) {
      $("scan-badge").innerHTML = '<span class="badge bad">Failed</span>';
      $("scan-msg").innerHTML = `<div class="err">${escapeHtml(e.message || e)}</div>`;
      throw e;
    } finally {
      $("btn-scan-gw").disabled = false;
    }
  }

  async function ensureFirewallQuiet() {
    try {
      const st = await api("/api/wizard/firewall/status");
      if (!st.applicable) return;
      if (st.rule_present || st.confirmed) return;
      await api("/api/wizard/firewall/apply", {
        method: "POST",
        body: "{}",
      });
    } catch (e) {
      // Surface only if install path needs it; caller decides messaging.
      throw e;
    }
  }

  async function installGateway() {
    const msg = $("provision-msg");
    const host = selectedHost || ($("reg-host") && $("reg-host").value.trim()) || "";
    const username = ($("ssh-user").value || "").trim();
    const password = $("ssh-pass").value || "";
    const gatewayId = ($("ssh-gid").value || "").trim() || "gateway";
    const sudoPass = ($("sudo-pass") && $("sudo-pass").value) || "";
    const port = selectedPort || DEFAULT_SSH_PORT;

    if (!host) {
      msg.innerHTML = `<div class="err">Select a device first.</div>`;
      throw new Error("select gateway");
    }
    if (!username) {
      msg.innerHTML = `<div class="err">User required (login name for the gateway).</div>`;
      throw new Error("user required");
    }
    if (!password.trim()) {
      msg.innerHTML = `<div class="err">Password required.</div>`;
      throw new Error("password required");
    }
    if (!sudoPass.trim()) {
      msg.innerHTML = `<div class="err">Sudo password required.</div>`;
      throw new Error("sudo password required");
    }

    const btn = $("btn-provision-agent");
    if (btn) btn.disabled = true;
    try {
      msg.textContent = "Connecting…";
      const hostKey = await api("/api/wizard/ssh/fetch-host-key", {
        method: "POST",
        body: JSON.stringify({ host, port }),
      });
      await api("/api/wizard/ssh/pin-host-key", {
        method: "POST",
        body: JSON.stringify(hostKey),
      });

      msg.textContent = "Installing SSH key…";
      await api("/api/wizard/ssh/install-key", {
        method: "POST",
        body: JSON.stringify({
          host,
          port,
          username,
          password,
          gateway_id: gatewayId,
          host_key_base64: hostKey.base64,
        }),
      });
      $("ssh-pass").value = "";

      msg.textContent = "Preparing…";
      try {
        await ensureFirewallQuiet();
      } catch (fwErr) {
        msg.innerHTML = `<div class="err">${escapeHtml(fwErr.message || fwErr)}</div>`;
        throw fwErr;
      }

      msg.textContent = "Installing…";
      const data = await api("/api/wizard/provision", {
        method: "POST",
        body: JSON.stringify({
          host,
          username,
          port,
          gateway_id: gatewayId,
          gateway_ip: host,
          sudo_password: sudoPass,
        }),
      });
      if ($("sudo-pass")) $("sudo-pass").value = "";
      msg.innerHTML = `<div class="okmsg">Gateway installed.</div>`;
      await refreshTargets();
      return data;
    } catch (e) {
      if ($("sudo-pass")) $("sudo-pass").value = "";
      if (!msg.querySelector(".err")) {
        msg.innerHTML = `<div class="err">${escapeHtml(String(e.message || e))}</div>`;
      }
      throw e;
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function fillSelect(sel, rows, preferred) {
    sel.innerHTML = "";
    if (!rows.length) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "(no gateways registered)";
      sel.appendChild(opt);
      return;
    }
    rows.forEach((g) => {
      const opt = document.createElement("option");
      opt.value = g.id;
      opt.textContent = g.host ? `${g.id} (${g.host})` : g.id;
      if (g.id === preferred) opt.selected = true;
      sel.appendChild(opt);
    });
  }

  async function refreshTargets() {
    targets = await api("/api/wizard/uninstall/targets");
    const rows = targets.gateways || [];
    fillSelect($("cfg-gateway-id"), rows, targets.default_gateway_id);
    fillSelect($("cu-gateway-id"), rows, targets.default_gateway_id);
    loadCfgForm();
    updateCleanupForm();
    $("hdr-status").innerHTML = '<span class="badge ok">Ready</span>';
  }

  function loadCfgForm() {
    const gid = $("cfg-gateway-id").value;
    const row = (targets.gateways || []).find((g) => g.id === gid);
    if ($("cfg-msg")) $("cfg-msg").innerHTML = "";
    if ($("cfg-pass")) $("cfg-pass").value = "";
    if (row) {
      $("cfg-host").value = row.host || "";
      $("cfg-user").value = row.ssh_user || targets.ssh_user || "";
    } else if (targets.provisioned) {
      $("cfg-host").value = targets.ssh_host || "";
      $("cfg-user").value = targets.ssh_user || "";
    } else {
      $("cfg-host").value = "";
      $("cfg-user").value = "";
    }
  }

  async function saveCfg() {
    const msg = $("cfg-msg");
    const gid = $("cfg-gateway-id").value || targets.default_gateway_id || "gateway";
    const host = ($("cfg-host").value || "").trim();
    const username = ($("cfg-user").value || "").trim();
    const password = ($("cfg-pass") && $("cfg-pass").value) || "";
    const port = Number(targets.ssh_port) || DEFAULT_SSH_PORT;

    if (!host) {
      msg.innerHTML = `<div class="err">Select a gateway first.</div>`;
      throw new Error("host required");
    }
    if (!username) {
      msg.innerHTML = `<div class="err">Username required.</div>`;
      throw new Error("user required");
    }

    const btn = $("btn-save-cfg");
    if (btn) btn.disabled = true;
    try {
      msg.textContent = "Saving…";
      await api("/api/wizard/settings/gateway", {
        method: "POST",
        body: JSON.stringify({
          gateway_id: gid,
          gateway_ip: host,
          ssh_host: host,
          ssh_user: username,
          ssh_port: port,
        }),
      });

      if (password.trim()) {
        msg.textContent = "Updating credentials…";
        const hostKey = await api("/api/wizard/ssh/fetch-host-key", {
          method: "POST",
          body: JSON.stringify({ host, port }),
        });
        await api("/api/wizard/ssh/pin-host-key", {
          method: "POST",
          body: JSON.stringify(hostKey),
        });
        await api("/api/wizard/ssh/install-key", {
          method: "POST",
          body: JSON.stringify({
            host,
            port,
            username,
            password,
            gateway_id: gid,
            host_key_base64: hostKey.base64,
          }),
        });
        if ($("cfg-pass")) $("cfg-pass").value = "";
      }

      msg.innerHTML = `<div class="okmsg">Saved.</div>`;
      await refreshTargets();
    } catch (e) {
      if ($("cfg-pass")) $("cfg-pass").value = "";
      msg.innerHTML = `<div class="err">${escapeHtml(e.message || e)}</div>`;
      throw e;
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function updateCleanupForm() {
    const gid = $("cu-gateway-id").value;
    const canRemove = Boolean(gid || targets.provisioned);
    if ($("btn-cu-confirm")) $("btn-cu-confirm").disabled = !canRemove;
    if ($("cu-msg") && !$("cu-msg").querySelector(".err") && !$("cu-msg").querySelector(".okmsg")) {
      $("cu-msg").innerHTML = "";
    }
  }

  async function confirmCleanup() {
    const gid = $("cu-gateway-id").value || undefined;
    const sudoPass = ($("cu-sudo").value || "").trim();
    if (!gid && !targets.provisioned) {
      $("cu-msg").innerHTML = `<div class="err">Select a gateway to remove.</div>`;
      throw new Error("Select a gateway to remove");
    }
    if (!sudoPass) {
      $("cu-msg").innerHTML = `<div class="err">Password required.</div>`;
      throw new Error("password required");
    }
    $("cu-msg").textContent = "Removing…";
    $("btn-cu-confirm").disabled = true;
    try {
      const data = await api("/api/wizard/uninstall", {
        method: "POST",
        body: JSON.stringify({
          gateway: true,
          monitoring: false,
          gateway_id: gid,
          sudo_password: sudoPass,
        }),
      });
      $("cu-msg").innerHTML = `<div class="okmsg">${escapeHtml(
        data.ok === false ? "Finished with some errors." : "Gateway removed."
      )}</div>`;
      $("cu-sudo").value = "";
      await refreshTargets();
    } catch (e) {
      $("cu-msg").innerHTML = `<div class="err">${escapeHtml(e.message || e)}</div>`;
      $("btn-cu-confirm").disabled = false;
    }
  }

  function showErr(e) {
    console.error(e);
    alert(e.message || String(e));
  }

  function wire() {
    showTab(tabFromHash(), { syncHash: true });
    window.addEventListener("hashchange", () => {
      showTab(tabFromHash(), { syncHash: false });
    });

    $("btn-scan-gw").addEventListener("click", () =>
      scanGateways().catch(showErr)
    );
    $("btn-provision-agent").addEventListener("click", () =>
      installGateway().catch(() => {})
    );

    $("cfg-gateway-id").addEventListener("change", loadCfgForm);
    $("btn-save-cfg").addEventListener("click", () => saveCfg().catch(() => {}));

    $("cu-gateway-id").addEventListener("change", () => {
      if ($("cu-msg")) $("cu-msg").innerHTML = "";
      updateCleanupForm();
    });
    $("btn-cu-confirm").addEventListener("click", () =>
      confirmCleanup().catch(() => {})
    );

    refreshTargets().catch(() => {});
  }

  wire();
})();

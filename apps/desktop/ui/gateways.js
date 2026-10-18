/* Gateways — Registration / Settings / Clean up. */
(function () {
  const TABS = [
    { id: "registration", label: "Registration", title: "Registration" },
    { id: "settings", label: "Settings", title: "Gateway settings" },
    { id: "cleanup", label: "Clean up", title: "Clean up" },
  ];

  const $ = (id) => document.getElementById(id);

  let hostKey = null;
  let hostKeyPinned = false;
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

  async function fillNicSelect(selId) {
    const sel = $(selId);
    if (!sel) return;
    const data = await api("/api/wizard/nics");
    sel.innerHTML = "";
    (data.candidates || []).forEach((c) => {
      const opt = document.createElement("option");
      opt.value = JSON.stringify(c);
      opt.textContent = `${c.name} — ${c.ip}${c.prefix != null ? "/" + c.prefix : ""}`;
      sel.appendChild(opt);
    });
    if (data.default) {
      const want = JSON.stringify(data.default);
      [...sel.options].forEach((o) => {
        if (o.value === want) o.selected = true;
      });
    }
    if (!sel.options.length) {
      const opt = document.createElement("option");
      opt.textContent = "(none found)";
      opt.value = "";
      sel.appendChild(opt);
    }
  }

  async function saveNicFrom(selId, msgId, extra) {
    const raw = $(selId).value;
    if (!raw) throw new Error("Select a LAN address");
    const c = JSON.parse(raw);
    const body = {
      monitoring_ip: c.ip,
      nic_name: c.name,
      ...(extra || {}),
    };
    await api("/api/wizard/nics/select", {
      method: "POST",
      body: JSON.stringify(body),
    });
    $(msgId).innerHTML = `<div class="okmsg">Saved ${escapeHtml(c.ip)}</div>`;
  }

  async function fetchHostKey() {
    hostKeyPinned = false;
    $("btn-install-key").disabled = true;
    const host = $("ssh-host").value.trim() || $("gateway-ip").value.trim();
    hostKey = await api("/api/wizard/ssh/fetch-host-key", {
      method: "POST",
      body: JSON.stringify({
        host,
        port: Number($("ssh-port").value) || 22,
      }),
    });
    $("hk-info").textContent = `${hostKey.key_type}  ${hostKey.fingerprint_sha256}`;
    $("btn-pin-hk").disabled = false;
    $("ssh-msg").innerHTML = `<div class="okmsg">Verify fingerprint, then Pin.</div>`;
  }

  async function pinHostKey() {
    if (!hostKey) throw new Error("Fetch the host key first");
    await api("/api/wizard/ssh/pin-host-key", {
      method: "POST",
      body: JSON.stringify(hostKey),
    });
    hostKeyPinned = true;
    $("btn-install-key").disabled = false;
    $("ssh-msg").innerHTML = `<div class="okmsg">Pinned.</div>`;
  }

  async function installKey() {
    if (!hostKeyPinned || !hostKey) throw new Error("Pin the host key first");
    const host = $("ssh-host").value.trim() || $("gateway-ip").value.trim();
    await api("/api/wizard/ssh/install-key", {
      method: "POST",
      body: JSON.stringify({
        host,
        port: Number($("ssh-port").value) || 22,
        username: $("ssh-user").value.trim(),
        password: $("ssh-pass").value,
        gateway_id: $("ssh-gid").value.trim() || "gateway",
        host_key_base64: hostKey.base64,
      }),
    });
    $("ssh-pass").value = "";
    $("ssh-msg").innerHTML = `<div class="okmsg">SSH key installed.</div>`;
  }

  function escapeAttr(s) {
    return escapeHtml(s).replace(/"/g, "&quot;");
  }

  async function refreshChecklist() {
    const data = await api("/api/wizard/checklist");
    const wrap = $("checklist-wrap");
    wrap.innerHTML = "";
    const note = $("localhost-note");
    if (note) {
      note.textContent = "";
      note.classList.add("hidden");
    }
    if (!data.applicable) {
      wrap.innerHTML = `<p>${escapeHtml(data.reason || "Not required on this host.")}</p>`;
      return;
    }
    (data.items || []).forEach((item, idx) => {
      const div = document.createElement("div");
      div.className = "checklist-item";
      div.innerHTML = `<strong>${idx + 1}. ${escapeHtml(item.title)}</strong>
        ${
          item.command
            ? `<div class="row"><code class="mono">${escapeHtml(item.command)}</code>
        <button type="button" class="secondary btn-copy" data-cmd="${escapeAttr(item.command)}">Copy</button></div>`
            : ""
        }`;
      wrap.appendChild(div);
    });
    wrap.querySelectorAll(".btn-copy").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(btn.dataset.cmd || "");
          btn.textContent = "Copied";
        } catch (_) {
          btn.textContent = "Failed";
        }
      });
    });
    if (data.confirmed) {
      $("cl-msg").innerHTML = `<div class="okmsg">Confirmed.</div>`;
    }
  }

  async function confirmChecklist() {
    await api("/api/wizard/checklist/confirm", { method: "POST", body: "{}" });
    $("cl-msg").innerHTML = `<div class="okmsg">Confirmed.</div>`;
  }

  async function provisionAgent() {
    const msg = $("provision-msg");
    const sudoPass = ($("sudo-pass") && $("sudo-pass").value) || "";
    if (!sudoPass.trim()) {
      msg.innerHTML = `<div class="err">Sudo password required.</div>`;
      throw new Error("sudo password required");
    }
    msg.innerHTML = `<div class="okmsg">Installing…</div>`;
    try {
      const host = $("ssh-host").value.trim() || $("gateway-ip").value.trim();
      const data = await api("/api/wizard/provision", {
        method: "POST",
        body: JSON.stringify({
          host: host || undefined,
          username: $("ssh-user").value.trim() || undefined,
          port: Number($("ssh-port").value) || undefined,
          gateway_id: $("ssh-gid").value.trim() || undefined,
          gateway_ip: $("gateway-ip").value.trim() || host || undefined,
          sudo_password: sudoPass,
        }),
      });
      if ($("sudo-pass")) $("sudo-pass").value = "";
      const notes = (data.notes || [])
        .slice(0, 4)
        .map((n) => `<li>${escapeHtml(n)}</li>`)
        .join("");
      msg.innerHTML = `<div class="okmsg">Gateway installed.</div><ul>${notes}</ul>`;
      await refreshTargets();
    } catch (e) {
      if ($("sudo-pass")) $("sudo-pass").value = "";
      msg.innerHTML = `<div class="err">${escapeHtml(String(e.message || e))}</div>`;
      throw e;
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
    const listHtml = rows.length
      ? "<strong>Registered</strong><br/>" +
        rows
          .map(
            (g) =>
              escapeHtml(g.id) + (g.host ? " — " + escapeHtml(g.host) : "")
          )
          .join("<br/>")
      : targets.provisioned
        ? `Provisioned SSH host: ${escapeHtml(targets.ssh_host || "—")}`
        : "No gateways registered yet.";
    if ($("cu-list")) $("cu-list").innerHTML = listHtml;
    loadCfgForm();
    updateCleanupSummary();
    $("hdr-status").innerHTML = '<span class="badge ok">Ready</span>';
  }

  function loadCfgForm() {
    const gid = $("cfg-gateway-id").value;
    const row = (targets.gateways || []).find((g) => g.id === gid);
    if ($("cfg-detail")) {
      $("cfg-detail").textContent = row
        ? `Editing ${row.id}` + (row.host ? ` @ ${row.host}` : "")
        : targets.provisioned
          ? `Provisioned host ${targets.ssh_host || "—"} (not in registry yet).`
          : "Select a gateway or register one first.";
    }
    if (row) {
      $("cfg-host").value = row.host || "";
      $("cfg-user").value = row.ssh_user || targets.ssh_user || "ubuntu";
      $("cfg-port").value = String(targets.ssh_port || 22);
    } else if (targets.provisioned) {
      $("cfg-host").value = targets.ssh_host || "";
      $("cfg-user").value = targets.ssh_user || "ubuntu";
      $("cfg-port").value = String(targets.ssh_port || 22);
    }
  }

  async function saveCfg() {
    const gid = $("cfg-gateway-id").value || targets.default_gateway_id || "gateway";
    const host = $("cfg-host").value.trim();
    if (!host) throw new Error("Host / IP required");
    await api("/api/wizard/settings/gateway", {
      method: "POST",
      body: JSON.stringify({
        gateway_id: gid,
        gateway_ip: host,
        ssh_host: host,
        ssh_user: $("cfg-user").value.trim() || "ubuntu",
        ssh_port: Number($("cfg-port").value) || 22,
      }),
    });
    $("cfg-msg").innerHTML = `<div class="okmsg">Saved settings for ${escapeHtml(gid)}.</div>`;
    await refreshTargets();
  }

  function updateCleanupSummary() {
    const gid = $("cu-gateway-id").value;
    const row = (targets.gateways || []).find((g) => g.id === gid);
    const lines = [];
    if (!gid && !targets.provisioned) {
      lines.push("No gateway is registered or provisioned.");
      $("btn-cu-confirm").disabled = true;
    } else {
      const id = gid || targets.default_gateway_id;
      const host = (row && row.host) || targets.ssh_host || "";
      lines.push(
        `• Remove gateway agent for ${id}` +
          (host ? ` @ ${host}` : "") +
          " and its registry row."
      );
      lines.push("• Monitoring (Loki/Prometheus) on this PC is kept.");
      $("btn-cu-confirm").disabled = false;
    }
    $("cu-summary").textContent = lines.join("\n");
  }

  async function confirmCleanup() {
    const gid = $("cu-gateway-id").value || undefined;
    if (!gid && !targets.provisioned) {
      throw new Error("Select a gateway to remove");
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
          sudo_password: $("cu-sudo").value || undefined,
        }),
      });
      const notes = (data.notes || []).join(" · ");
      $("cu-msg").innerHTML = `<div class="okmsg">${escapeHtml(
        data.ok === false
          ? "Finished with some errors. " + notes
          : "Gateway removed. " + notes
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

    // Sync gateway IP → SSH host when empty.
    $("gateway-ip").addEventListener("change", () => {
      if (!$("ssh-host").value.trim()) {
        $("ssh-host").value = $("gateway-ip").value.trim();
      }
    });

    $("btn-refresh-nics").addEventListener("click", () =>
      fillNicSelect("nic-select").catch(showErr)
    );
    $("btn-save-nic").addEventListener("click", () =>
      saveNicFrom("nic-select", "nic-msg", {
        gateway_ip: $("gateway-ip").value.trim() || undefined,
      }).catch(showErr)
    );
    $("btn-fetch-hk").addEventListener("click", () =>
      fetchHostKey().catch((e) => {
        $("ssh-msg").innerHTML = `<div class="err">${escapeHtml(e.message)}</div>`;
      })
    );
    $("btn-pin-hk").addEventListener("click", () =>
      pinHostKey().catch((e) => {
        $("ssh-msg").innerHTML = `<div class="err">${escapeHtml(e.message)}</div>`;
      })
    );
    $("btn-install-key").addEventListener("click", () =>
      installKey().catch((e) => {
        $("ssh-msg").innerHTML = `<div class="err">${escapeHtml(e.message)}</div>`;
      })
    );
    $("btn-refresh-cl").addEventListener("click", () =>
      refreshChecklist().catch(showErr)
    );
    $("btn-confirm-cl").addEventListener("click", () =>
      confirmChecklist().catch(showErr)
    );
    $("btn-provision-agent").addEventListener("click", () =>
      provisionAgent().catch(showErr)
    );

    $("btn-refresh-cfg").addEventListener("click", () =>
      refreshTargets().catch(showErr)
    );
    $("cfg-gateway-id").addEventListener("change", loadCfgForm);
    $("btn-save-cfg").addEventListener("click", () => saveCfg().catch(showErr));
    $("btn-cfg-refresh-nics").addEventListener("click", () =>
      fillNicSelect("cfg-nic-select").catch(showErr)
    );
    $("btn-cfg-save-nic").addEventListener("click", () =>
      saveNicFrom("cfg-nic-select", "cfg-nic-msg").catch(showErr)
    );

    $("btn-refresh-cu").addEventListener("click", () =>
      refreshTargets().catch(showErr)
    );
    $("cu-gateway-id").addEventListener("change", updateCleanupSummary);
    $("btn-cu-confirm").addEventListener("click", () =>
      confirmCleanup().catch(showErr)
    );

    fillNicSelect("nic-select").catch(() => {});
    fillNicSelect("cfg-nic-select").catch(() => {});
    refreshChecklist().catch(() => {});
    refreshTargets().catch(() => {});
  }

  wire();
})();

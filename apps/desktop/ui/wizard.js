/* Setup Wizard front-end — talks to /api/wizard/* on the shell server. */
(function () {
  const STEPS = ["Engine", "NIC", "SSH", "Firewall", "Launch"];
  let step = 0;
  let hostKey = null;
  let hostKeyPinned = false;

  const $ = (id) => document.getElementById(id);

  async function api(path, opts) {
    const res = await fetch(path, {
      headers: { "Content-Type": "application/json", ...(opts && opts.headers) },
      ...opts,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.statusText || "request failed");
    return data;
  }

  function showStep(n) {
    step = Math.max(0, Math.min(STEPS.length - 1, n));
    document.querySelectorAll(".step").forEach((el) => {
      el.classList.toggle("hidden", Number(el.dataset.step) !== step);
    });
    document.querySelectorAll("#step-tabs button").forEach((btn, i) => {
      btn.classList.toggle("active", i === step);
    });
    $("btn-prev").disabled = step === 0;
    $("btn-next").textContent = step === STEPS.length - 1 ? "Done" : "Next";
  }

  function buildTabs() {
    const nav = $("step-tabs");
    nav.innerHTML = "";
    STEPS.forEach((label, i) => {
      const b = document.createElement("button");
      b.textContent = `${i + 1}. ${label}`;
      b.addEventListener("click", () => showStep(i));
      nav.appendChild(b);
    });
  }

  function badge(el, ok, text) {
    el.innerHTML = `<span class="badge ${ok ? "ok" : "bad"}">${text}</span>`;
  }

  async function refreshEnv() {
    const data = await api("/api/wizard/env");
    $("env-json").textContent = JSON.stringify(data, null, 2);
    const d = data.docker || {};
    badge($("docker-badge"), !!d.healthy, d.healthy ? `Docker OK (${d.version || "?"})` : "Docker not ready");
    $("docker-hint").textContent = d.hint || d.error || "";
    const note = (data.wsl && data.wsl.localhost_forwarding_note) || "";
    $("localhost-note").textContent = note;
    $("localhost-note").classList.toggle("hidden", !note);
    $("hdr-status").innerHTML = d.healthy
      ? '<span class="badge ok">engine ready</span>'
      : '<span class="badge warn">engine blocked</span>';
  }

  async function refreshNics() {
    const mode = $("net-mode").value;
    const q =
      mode === "" || mode == null
        ? ""
        : `?windows_net_mode=${encodeURIComponent(mode)}`;
    const data = await api("/api/wizard/nics" + q);
    const sel = $("nic-select");
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
      opt.textContent = "(no candidates)";
      opt.value = "";
      sel.appendChild(opt);
    }
  }

  async function saveNic() {
    const raw = $("nic-select").value;
    if (!raw) throw new Error("No NIC selected");
    const c = JSON.parse(raw);
    const body = {
      monitoring_ip: c.ip,
      nic_name: c.name,
      gateway_ip: $("gateway-ip").value.trim() || undefined,
      windows_net_mode: $("net-mode").value || undefined,
    };
    await api("/api/wizard/nics/select", { method: "POST", body: JSON.stringify(body) });
    $("nic-msg").innerHTML = `<div class="okmsg">Saved MONITORING_IP=${c.ip}</div>`;
  }

  async function fetchHostKey() {
    hostKeyPinned = false;
    $("btn-install-key").disabled = true;
    hostKey = await api("/api/wizard/ssh/fetch-host-key", {
      method: "POST",
      body: JSON.stringify({
        host: $("ssh-host").value.trim(),
        port: Number($("ssh-port").value) || 22,
      }),
    });
    $("hk-info").textContent =
      `${hostKey.key_type}\n${hostKey.fingerprint_sha256}\n(base64 length ${hostKey.base64.length})`;
    $("btn-pin-hk").disabled = false;
    $("ssh-msg").innerHTML = `<div class="okmsg">Verify fingerprint on the device console, then Pin (required before Install).</div>`;
  }

  async function pinHostKey() {
    if (!hostKey) throw new Error("Fetch host key first");
    await api("/api/wizard/ssh/pin-host-key", {
      method: "POST",
      body: JSON.stringify(hostKey),
    });
    hostKeyPinned = true;
    $("btn-install-key").disabled = false;
    $("ssh-msg").innerHTML = `<div class="okmsg">Pinned ${hostKey.fingerprint_sha256} — Install is now enabled.</div>`;
  }

  async function installKey() {
    if (!hostKeyPinned || !hostKey) {
      throw new Error("Pin the host key before installing");
    }
    const body = {
      host: $("ssh-host").value.trim(),
      port: Number($("ssh-port").value) || 22,
      username: $("ssh-user").value.trim(),
      password: $("ssh-pass").value,
      gateway_id: $("ssh-gid").value.trim() || "gateway",
      host_key_base64: hostKey.base64,
    };
    const res = await api("/api/wizard/ssh/install-key", {
      method: "POST",
      body: JSON.stringify(body),
    });
    $("ssh-pass").value = "";
    $("ssh-msg").innerHTML = `<div class="okmsg">Key installed (password cleared). path=${res.ssh_key_path}</div>`;
  }

  async function refreshChecklist() {
    const data = await api("/api/wizard/checklist");
    const wrap = $("checklist-wrap");
    wrap.innerHTML = "";
    if (data.localhost_forwarding_note) {
      $("localhost-note").textContent = data.localhost_forwarding_note;
      $("localhost-note").classList.remove("hidden");
    }
    if (!data.applicable) {
      wrap.innerHTML = `<p>${data.reason || "Not applicable on this host."}</p>`;
      return;
    }
    (data.items || []).forEach((item, idx) => {
      const div = document.createElement("div");
      div.className = "checklist-item";
      div.innerHTML = `<strong>${idx + 1}. ${item.title}</strong>
        ${item.command ? `<div class="row"><code class="mono">${escapeHtml(item.command)}</code>
        <button class="secondary btn-copy" data-cmd="${escapeAttr(item.command)}">Copy</button></div>` : ""}
        ${item.notes ? `<p>${escapeHtml(item.notes)}</p>` : ""}`;
      wrap.appendChild(div);
    });
    wrap.querySelectorAll(".btn-copy").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(btn.dataset.cmd || "");
          btn.textContent = "Copied";
        } catch (_) {
          btn.textContent = "Copy failed";
        }
      });
    });
    if (data.confirmed) {
      $("cl-msg").innerHTML = `<div class="okmsg">Checklist previously confirmed.</div>`;
    }
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }
  function escapeAttr(s) {
    return escapeHtml(s).replace(/"/g, "&quot;");
  }

  async function confirmChecklist() {
    await api("/api/wizard/checklist/confirm", { method: "POST", body: "{}" });
    $("cl-msg").innerHTML = `<div class="okmsg">Confirmed. Wizard will re-show commands if WSL IP changes.</div>`;
  }

  async function startServices() {
    $("svc-msg").textContent = "Starting…";
    const data = await api("/api/wizard/services/start", {
      method: "POST",
      body: JSON.stringify({ streamlit: true }),
    });
    $("svc-status").textContent = JSON.stringify(data, null, 2);
    const ok = data.control && data.control.healthy;
    $("svc-msg").innerHTML = ok
      ? `<div class="okmsg">Control service healthy. Streamlit healthy=${data.streamlit && data.streamlit.healthy}</div>`
      : `<div class="err">Control service not healthy — check ~/.local/share/iot-gateway-monitor/control-service.log (or %APPDATA%)</div>`;
  }

  async function stopServices() {
    await api("/api/wizard/services/stop", { method: "POST", body: "{}" });
    $("svc-status").textContent = JSON.stringify(await api("/api/wizard/services/status"), null, 2);
    $("svc-msg").innerHTML = `<div class="okmsg">Stopped.</div>`;
  }

  async function openStreamlit() {
    await api("/api/wizard/open-streamlit", {
      method: "POST",
      body: JSON.stringify({ url: "http://127.0.0.1:8501" }),
    });
  }

  function wire() {
    buildTabs();
    $("btn-prev").addEventListener("click", () => showStep(step - 1));
    $("btn-next").addEventListener("click", () => {
      if (step === STEPS.length - 1) return;
      showStep(step + 1);
    });
    $("btn-refresh-env").addEventListener("click", () => refreshEnv().catch(showErr));
    $("btn-refresh-nics").addEventListener("click", () => refreshNics().catch(showErr));
    $("btn-save-nic").addEventListener("click", () => saveNic().catch(showErr));
    $("btn-fetch-hk").addEventListener("click", () => fetchHostKey().catch(e => {
      $("ssh-msg").innerHTML = `<div class="err">${escapeHtml(e.message)}</div>`;
    }));
    $("btn-pin-hk").addEventListener("click", () => pinHostKey().catch(e => {
      $("ssh-msg").innerHTML = `<div class="err">${escapeHtml(e.message)}</div>`;
    }));
    $("btn-install-key").addEventListener("click", () => installKey().catch(e => {
      $("ssh-msg").innerHTML = `<div class="err">${escapeHtml(e.message)}</div>`;
    }));
    $("btn-refresh-cl").addEventListener("click", () => refreshChecklist().catch(showErr));
    $("btn-confirm-cl").addEventListener("click", () => confirmChecklist().catch(showErr));
    $("btn-start-svc").addEventListener("click", () => startServices().catch(showErr));
    $("btn-stop-svc").addEventListener("click", () => stopServices().catch(showErr));
    $("btn-open-st").addEventListener("click", () => openStreamlit().catch(showErr));
    showStep(0);
    refreshEnv().catch(showErr);
    refreshNics().catch(() => {});
    refreshChecklist().catch(() => {});
  }

  function showErr(e) {
    console.error(e);
    alert(e.message || String(e));
  }

  wire();
})();

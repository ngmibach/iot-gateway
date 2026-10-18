/* Settings → Remove — uninstall the monitoring panel (cascades all gateways). */
(function () {
  const $ = (id) => document.getElementById(id);

  let targets = {
    gateways: [],
    provisioned: false,
    default_gateway_id: "gateway",
  };

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

  function updateSummary() {
    const list = targets.gateways || [];
    const lines = [
      "• Stop Loki/Prometheus and wipe local app data (registry, settings, keyring fallback, Chromium profile).",
    ];
    if (list.length) {
      lines.push(
        "• Every registered gateway will also be removed: " +
          list.map((g) => (g.host ? `${g.id} @ ${g.host}` : g.id)).join(", ")
      );
    } else if (targets.provisioned) {
      lines.push(
        "• The provisioned gateway agent will be removed over SSH, then local data is wiped."
      );
    } else {
      lines.push("• No gateways are registered — monitoring wipe only.");
    }
    lines.push("• The downloaded .exe is left for you to delete.");
    $("rm-summary").textContent = lines.join("\n");

    const needSudo = list.length > 0 || targets.provisioned;
    $("sudo-wrap").classList.toggle("hidden", !needSudo);
  }

  async function refreshTargets() {
    targets = await api("/api/wizard/uninstall/targets");
    const reg = $("registered-list");
    if (!(targets.gateways || []).length) {
      reg.textContent = targets.provisioned
        ? `Provisioned SSH host: ${targets.ssh_host || "—"} (will be removed with the panel).`
        : "No gateways registered to this monitoring panel.";
    } else {
      reg.innerHTML =
        "<strong>Gateways that will be removed with this panel</strong><br/>" +
        targets.gateways
          .map(
            (g) =>
              escapeHtml(g.id) +
              (g.host ? " — " + escapeHtml(g.host) : "")
          )
          .join("<br/>");
    }
    updateSummary();
    $("hdr-status").innerHTML = '<span class="badge ok">Ready</span>';
  }

  async function confirmRemove() {
    $("rm-msg").textContent = "Removing…";
    $("btn-rm-confirm").disabled = true;
    try {
      const data = await api("/api/wizard/uninstall", {
        method: "POST",
        body: JSON.stringify({
          gateway: true,
          monitoring: true,
          sudo_password: $("rm-sudo").value || undefined,
        }),
      });
      const notes = (data.notes || []).join(" · ");
      $("rm-msg").innerHTML = `<div class="okmsg">${escapeHtml(
        data.ok === false
          ? "Finished with some errors. " + notes
          : "Monitoring panel removed. " + notes
      )}</div>`;
      $("rm-sudo").value = "";
      if (typeof window.iotgwUnmountShell === "function") {
        window.iotgwUnmountShell();
      }
      setTimeout(() => {
        window.location.href = "wizard.html";
      }, 900);
    } catch (e) {
      $("rm-msg").innerHTML = `<div class="err">${escapeHtml(e.message || e)}</div>`;
      $("btn-rm-confirm").disabled = false;
    }
  }

  function wire() {
    $("btn-rm-confirm").addEventListener("click", () =>
      confirmRemove().catch((e) => {
        $("rm-msg").innerHTML = `<div class="err">${escapeHtml(e.message || e)}</div>`;
        $("btn-rm-confirm").disabled = false;
      })
    );
    refreshTargets().catch((e) => {
      $("hdr-status").innerHTML = `<span class="badge bad">${escapeHtml(e.message || e)}</span>`;
      $("rm-msg").innerHTML = `<div class="err">${escapeHtml(e.message || e)}</div>`;
    });
  }

  wire();
})();

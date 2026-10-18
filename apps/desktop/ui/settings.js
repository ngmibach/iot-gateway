/* Settings → Remove — selective Gateway / Monitoring uninstall. */
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

  function selectedTarget() {
    const el = document.querySelector('input[name="remove-target"]:checked');
    return el ? el.value : "gateway";
  }

  function fillGatewaySelect() {
    const sel = $("rm-gateway-id");
    sel.innerHTML = "";
    const rows = targets.gateways || [];
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
      if (g.id === targets.default_gateway_id) opt.selected = true;
      sel.appendChild(opt);
    });
  }

  function updateSummary() {
    const mode = selectedTarget();
    const monitoring = mode === "monitoring";
    const lines = [];
    const list = targets.gateways || [];
    const gid = $("rm-gateway-id").value;

    $("gateway-pick").classList.toggle("hidden", monitoring);
    $("sudo-wrap").classList.toggle(
      "hidden",
      monitoring ? list.length === 0 && !targets.provisioned : !gid && !targets.provisioned
    );

    if (monitoring) {
      lines.push(
        "• Monitoring: stop Loki/Prometheus, delete telemetry binaries/data, and wipe local app data (registry, settings, keyring fallback, Chromium profile)."
      );
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
        lines.push("• No gateways are registered — Monitoring wipe only.");
      }
      lines.push("• The downloaded .exe is left for you to delete.");
    } else {
      if (!gid && !targets.provisioned) {
        lines.push("No gateway is registered or provisioned.");
      } else {
        const row = list.find((g) => g.id === gid) || {
          id: gid || targets.default_gateway_id,
          host: targets.ssh_host,
        };
        lines.push(
          `• Gateway only: remove agent for ${row.id}` +
            (row.host ? ` @ ${row.host}` : "") +
            " and its registry row. Loki/Prometheus stay installed."
        );
      }
    }

    $("rm-summary").textContent = lines.join("\n");
    const canConfirm = monitoring
      ? true
      : Boolean(gid || targets.provisioned);
    $("btn-rm-confirm").disabled = !canConfirm;
  }

  async function refreshTargets() {
    targets = await api("/api/wizard/uninstall/targets");
    const hint = $("targets-hint");
    if (hint && targets.monitoring_hint) {
      hint.textContent = targets.monitoring_hint;
    }
    const detail = $("gw-option-detail");
    const n = (targets.gateways || []).length;
    if (detail) {
      detail.textContent =
        n > 1
          ? `Remove one gateway agent (${n} registered). Monitoring stays installed.`
          : "Remove the agent on the Raspberry Pi (and its registry row). Monitoring stays installed.";
    }
    const reg = $("registered-list");
    if (!(targets.gateways || []).length) {
      reg.textContent = targets.provisioned
        ? `Provisioned SSH host: ${targets.ssh_host || "—"} (not yet in registry).`
        : "No gateways registered to this monitoring panel.";
    } else {
      reg.innerHTML =
        "<strong>Registered to this panel</strong><br/>" +
        targets.gateways
          .map(
            (g) =>
              escapeHtml(g.id) +
              (g.host ? " — " + escapeHtml(g.host) : "")
          )
          .join("<br/>");
    }
    fillGatewaySelect();
    updateSummary();
    $("hdr-status").innerHTML = '<span class="badge ok">Ready</span>';
  }

  async function confirmRemove() {
    const monitoring = selectedTarget() === "monitoring";
    const body = {
      gateway: true,
      monitoring,
      sudo_password: $("rm-sudo").value || undefined,
    };
    if (!monitoring) {
      body.gateway_id = $("rm-gateway-id").value || undefined;
      if (!body.gateway_id && !targets.provisioned) {
        throw new Error("Select a gateway to remove");
      }
    }

    $("rm-msg").textContent = "Removing…";
    $("btn-rm-confirm").disabled = true;
    try {
      const data = await api("/api/wizard/uninstall", {
        method: "POST",
        body: JSON.stringify(body),
      });
      const notes = (data.notes || []).join(" · ");
      $("rm-msg").innerHTML = `<div class="okmsg">${escapeHtml(
        data.ok === false
          ? "Finished with some errors. " + notes
          : "Remove complete. " + notes
      )}</div>`;
      $("rm-sudo").value = "";
      if (monitoring) {
        if (typeof window.iotgwUnmountShell === "function") {
          window.iotgwUnmountShell();
        }
        setTimeout(() => {
          window.location.href = "wizard.html";
        }, 900);
        return;
      }
      await refreshTargets();
    } catch (e) {
      $("rm-msg").innerHTML = `<div class="err">${escapeHtml(e.message || e)}</div>`;
      $("btn-rm-confirm").disabled = false;
    }
  }

  function wire() {
    document.querySelectorAll('input[name="remove-target"]').forEach((el) => {
      el.addEventListener("change", updateSummary);
    });
    $("rm-gateway-id").addEventListener("change", updateSummary);
    $("btn-refresh-targets").addEventListener("click", () =>
      refreshTargets().catch((e) => {
        $("rm-msg").innerHTML = `<div class="err">${escapeHtml(e.message || e)}</div>`;
      })
    );
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

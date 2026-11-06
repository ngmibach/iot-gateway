/* Shared left-rail navigation for the post-install app shell. */
(function () {
  const SECTIONS = [
    {
      id: "monitoring",
      label: "Monitoring",
      items: [
        {
          id: "metric",
          label: "Gateway Metric",
          href: "monitoring.html#metric",
          page: "monitoring",
          hash: "metric",
        },
        {
          id: "activities",
          label: "Gateway Activities",
          href: "monitoring.html#activities",
          page: "monitoring",
          hash: "activities",
        },
        {
          id: "control",
          label: "Control Plane",
          href: "actions.html",
          page: "actions",
        },
        {
          id: "security",
          label: "Security",
          href: "security.html",
          page: "security",
        },
        {
          id: "grafana",
          label: "Grafana",
          href: "#grafana-external",
          page: null,
          external: true,
          openUrl: "https://127.0.0.1:9140/",
        },
      ],
    },
    {
      id: "gateways",
      label: "Gateways",
      items: [
        {
          id: "registration",
          label: "Registration",
          href: "gateways.html#registration",
          page: "gateways",
          hash: "registration",
        },
        {
          id: "gw-settings",
          label: "Settings",
          href: "gateways.html#settings",
          page: "gateways",
          hash: "settings",
        },
        {
          id: "cleanup",
          label: "Clean up",
          href: "gateways.html#cleanup",
          page: "gateways",
          hash: "cleanup",
        },
      ],
    },
    {
      id: "settings",
      label: "Settings",
      items: [
        { id: "remove", label: "Remove", href: "settings.html", page: "settings" },
        {
          id: "certificates",
          label: "Certificates",
          href: "certificates.html",
          page: "certificates",
        },
        { id: "admin", label: "Admin", href: "admin.html", page: "admin" },
      ],
    },
  ];

  function currentPage() {
    const body = document.body;
    if (body && body.dataset.page) return body.dataset.page;
    const name = (location.pathname.split("/").pop() || "").toLowerCase();
    if (name.indexOf("wizard") === 0) return "wizard";
    if (name.indexOf("monitoring") === 0) return "monitoring";
    if (name.indexOf("actions") === 0) return "actions";
    if (name.indexOf("security") === 0) return "security";
    if (name.indexOf("gateways") === 0) return "gateways";
    if (name.indexOf("certificates") === 0) return "certificates";
    if (name.indexOf("settings") === 0) return "settings";
    if (name.indexOf("admin") === 0) return "admin";
    return "";
  }

  function currentHash() {
    return (location.hash || "").replace(/^#/, "").toLowerCase();
  }

  function isActive(item, page, hash) {
    if (item.external) return false;
    if (item.page !== page) return false;
    if (page === "monitoring" || page === "gateways") {
      const want = item.hash || "";
      const have = hash || (page === "monitoring" ? "metric" : "registration");
      return want === have;
    }
    return true;
  }

  function openExternalUrl(url) {
    fetch("/api/wizard/open-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
    }).catch(() => {
      /* best-effort system-browser open */
    });
  }

  function renderSidebar(mount) {
    const page = currentPage();
    const hash = currentHash();
    const brand = document.createElement("div");
    brand.className = "app-brand";
    brand.innerHTML =
      "<strong>IoT Gateway</strong><span>Monitor</span>";
    mount.appendChild(brand);

    SECTIONS.forEach((section) => {
      const sec = document.createElement("div");
      sec.className = "app-nav-section";
      const title = document.createElement("div");
      title.className = "app-nav-section-label";
      title.textContent = section.label;
      sec.appendChild(title);

      const list = document.createElement("nav");
      list.className = "app-nav-list";
      list.setAttribute("aria-label", section.label);

      section.items.forEach((item) => {
        const a = document.createElement("a");
        a.className = "app-nav-item";
        a.href = item.href;
        a.dataset.navId = item.id;
        a.textContent = item.label;
        if (isActive(item, page, hash)) {
          a.classList.add("active");
          a.setAttribute("aria-current", "page");
        }
        if (item.external && item.openUrl) {
          a.addEventListener("click", (ev) => {
            ev.preventDefault();
            openExternalUrl(item.openUrl);
          });
        }
        list.appendChild(a);
      });
      // Restore Activities alarm badge from session after nav rebuild.
      applyStoredNavAlarm(list);

      sec.appendChild(list);
      mount.appendChild(sec);
    });
  }

  function ensureFrame(sidebar) {
    const body = document.body;
    let frame = document.querySelector(".app-frame");
    if (frame) return frame;
    frame = document.createElement("div");
    frame.className = "app-frame";
    const nodes = [];
    Array.from(body.children).forEach((child) => {
      if (child === sidebar || child.id === "app-sidebar") return;
      if (child.tagName === "SCRIPT") return;
      nodes.push(child);
    });
    nodes.forEach((n) => frame.appendChild(n));
    body.insertBefore(frame, sidebar.nextSibling);
    return frame;
  }

  function mountShell() {
    const body = document.body;
    if (!body || body.classList.contains("first-run")) return;

    body.classList.add("has-app-shell");

    let sidebar = document.getElementById("app-sidebar");
    if (!sidebar) {
      sidebar = document.createElement("aside");
      sidebar.id = "app-sidebar";
      sidebar.className = "app-sidebar";
      sidebar.setAttribute("aria-label", "Application");
      body.insertBefore(sidebar, body.firstChild);
    } else {
      sidebar.innerHTML = "";
    }
    renderSidebar(sidebar);
    ensureFrame(sidebar);
  }

  function unmountShell() {
    const body = document.body;
    if (!body) return;
    body.classList.add("first-run");
    body.classList.remove("has-app-shell");
    const sidebar = document.getElementById("app-sidebar");
    if (sidebar) sidebar.remove();
    const frame = document.querySelector(".app-frame");
    if (frame) {
      while (frame.firstChild) {
        body.insertBefore(frame.firstChild, frame);
      }
      frame.remove();
    }
  }

  function refreshActiveNav() {
    const sidebar = document.getElementById("app-sidebar");
    if (!sidebar || document.body.classList.contains("first-run")) return;
    sidebar.innerHTML = "";
    renderSidebar(sidebar);
  }

  /** Mark setup finished so the next launch skips the installer. */
  window.iotgwMarkSetupComplete = async function iotgwMarkSetupComplete() {
    try {
      await fetch("/api/wizard/setup/complete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
    } catch (_) {
      /* best-effort; telemetry.ready still routes returning users */
    }
  };

  window.iotgwMountShell = mountShell;
  window.iotgwUnmountShell = unmountShell;
  function applyStoredNavAlarm(scope) {
    try {
      const active = sessionStorage.getItem("iotgw.activities.alarmActive") === "1";
      const count = Number(sessionStorage.getItem("iotgw.activities.alarmCount") || 0);
      setNavAlarm(
        "activities",
        { active, count: active ? count || 1 : 0, title: active ? "Invalid messages or auto-prevent quarantine" : "" },
        scope
      );
    } catch (_e) {
      /* ignore */
    }
  }

  function setNavAlarm(navId, state, scope) {
    const root = scope || document;
    const el =
      root.querySelector &&
      root.querySelector(`.app-nav-item[data-nav-id="${navId}"]`);
    if (!el) return;
    const active = !!(state && state.active);
    const count = active ? Number((state && state.count) || 0) || 1 : 0;
    el.classList.toggle("alarm", active);
    if (active) {
      el.setAttribute("title", (state && state.title) || "Alarm");
    } else {
      el.removeAttribute("title");
    }
    let badge = el.querySelector(".app-nav-badge");
    if (!active) {
      if (badge) badge.remove();
      return;
    }
    if (!badge) {
      badge = document.createElement("span");
      badge.className = "app-nav-badge";
      el.appendChild(badge);
    }
    badge.textContent = count > 99 ? "99+" : String(count);
  }

  window.iotgwRefreshNav = refreshActiveNav;
  window.iotgwSetNavAlarm = function (navId, state) {
    try {
      if (navId === "activities") {
        sessionStorage.setItem(
          "iotgw.activities.alarmActive",
          state && state.active ? "1" : "0"
        );
        sessionStorage.setItem(
          "iotgw.activities.alarmCount",
          String(state && state.active ? Number(state.count) || 1 : 0)
        );
      }
    } catch (_e) {
      /* ignore */
    }
    setNavAlarm(navId, state);
  };
  window.iotgwNavSections = SECTIONS;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mountShell);
  } else {
    mountShell();
  }

  window.addEventListener("hashchange", refreshActiveNav);
})();

const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { setImmediate: immediate } = require("node:timers");
const { runInNewContext } = require("node:vm");
const test = require("node:test");

const script = readFileSync(join(__dirname, "../ui/security.js"), "utf8");

class Element {
  constructor(tagName = "div") {
    this.tagName = tagName.toLowerCase();
    this.children = [];
    this.listeners = {};
    this.style = {};
    this.className = "";
    this.value = "";
    this.checked = false;
    this.disabled = false;
    this.classes = new Set();
    this.classList = {
      add: (name) => this.classes.add(name),
      remove: (name) => this.classes.delete(name),
      toggle: (name, force) => {
        const enabled = force === undefined ? !this.classes.has(name) : force;
        if (enabled) this.classes.add(name);
        else this.classes.delete(name);
        return enabled;
      },
    };
  }

  set textContent(value) {
    this.text = String(value ?? "");
    this.children = [];
  }

  get textContent() {
    return this.text ?? this.children.map((child) => child.textContent).join("");
  }

  addEventListener(name, callback) {
    this.listeners[name] = callback;
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  replaceChildren(...children) {
    this.children = children;
    this.text = undefined;
  }
}

function makeHarness({ initialStatusFailure = false, initialAlertsFailure = false } = {}) {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const controls = [
    "ids-enabled", "rules-enabled", "ml-enabled", "ml-threshold",
    "rate-threshold", "clock-threshold", "connect-ratio", "cooldown",
    "btn-apply-ids",
  ];
  const state = {
    enabled: false,
    alerts: [],
    statusFailure: initialStatusFailure,
    alertsFailure: initialAlertsFailure,
    posted: null,
  };
  const config = () => ({
    enabled: state.enabled,
    rules_enabled: true,
    ml_enabled: true,
    threshold: 0.05,
    max_message_rate_per_sec: 1.5,
    max_clock_skew_seconds: 2.5,
    max_connect_publish_ratio: 1.15,
    alert_cooldown_seconds: 60,
  });
  const response = (body, ok = true) => ({
    ok,
    statusText: ok ? "OK" : "Unavailable",
    json: async () => body,
  });
  const fetch = async (path, options = {}) => {
    if (path === "/api/v1/gateways") {
      return response([{ id: "gw1", host: "192.0.2.8" }]);
    }
    if (path.endsWith("/ids/status")) {
      if (state.statusFailure) return response({ detail: "SSH unavailable" }, false);
      return response({
        installed: true,
        configured_enabled: state.enabled,
        service_state: state.enabled ? "running" : "stopped",
        result: "success",
        model_ready: true,
        runtime_ready: state.enabled,
        config: config(),
      });
    }
    if (path.includes("/ids/alerts")) {
      if (state.alertsFailure) return response({ detail: "Loki unavailable" }, false);
      return response({ count: state.alerts.length, alerts: state.alerts });
    }
    if (path.endsWith("/ids/config") && options.method === "POST") {
      state.posted = JSON.parse(options.body);
      state.enabled = state.posted.enabled;
      state.alerts = [{
        occurred_at: "2026-11-01T10:00:00Z",
        severity: "critical",
        device_id: "<img src=x onerror=alert(1)>",
        detection: "message_pattern_anomaly",
        message: "suspicious",
        score: 0.91,
      }];
      return response({
        ok: true,
        config: config(),
        status: {
          installed: true,
          configured_enabled: true,
          service_state: "running",
          result: "success",
          model_ready: true,
          runtime_ready: true,
          config: config(),
        },
      });
    }
    return response({ detail: `Unexpected request ${path}` }, false);
  };
  const document = {
    getElementById: element,
    createElement: (tag) => new Element(tag),
    querySelectorAll: (selector) =>
      [...selector.matchAll(/#([\w-]+)/g)].map((match) => element(match[1])),
  };
  runInNewContext(script, {
    document,
    window: { setInterval: () => 1 },
    fetch,
    URLSearchParams,
    Date,
    Number,
    String,
    Boolean,
    Error,
    encodeURIComponent,
  });
  return { elements, element, state, controls };
}

async function flush() {
  await new Promise((resolve) => immediate(resolve));
  await new Promise((resolve) => immediate(resolve));
}

test("disabled/no-alert state, settings apply, periodic records, and safe alert text", async () => {
  const { element, state } = makeHarness();
  await flush();

  assert.match(element("ids-configured").textContent, /Disabled/);
  assert.match(element("alerts-message").textContent, /IDS is disabled/);
  assert.equal(element("alert-empty").textContent, "No IDS alerts in this time range.");

  element("ids-enabled").checked = true;
  element("ids-enabled").listeners.input();
  const apply = element("btn-apply-ids").listeners.click;
  const pending = apply();
  assert.equal(element("btn-apply-ids").disabled, true);
  await pending;
  await flush();

  assert.equal(state.posted.enabled, true);
  assert.equal(Object.hasOwn(state.posted, "sudo_password"), false);
  assert.equal(element("ids-service").textContent, "running");
  assert.match(element("alerts-message").textContent, /1 alert/);
  assert.equal(element("security-alert-rows").children[0].children[2].textContent,
    "<img src=x onerror=alert(1)>");
  assert.equal(element("security-alert-rows").children[0].children.some(
    (child) => child.tagName === "img"
  ), false);
});

test("gateway and Loki failures are surfaced separately", async () => {
  const { element, state } = makeHarness({
    initialStatusFailure: true,
    initialAlertsFailure: true,
  });
  await flush();

  assert.match(element("ids-status-badge").textContent, /Gateway unreachable/);
  assert.match(element("security-message").textContent, /SSH unavailable/);
  assert.match(element("alerts-message").textContent, /Alerts unavailable: Loki unavailable/);

  state.statusFailure = false;
  state.alertsFailure = false;
  await element("btn-refresh").listeners.click();
  assert.match(element("ids-status-badge").textContent, /Disabled/);
  assert.match(element("alerts-message").textContent, /IDS is disabled/);
});

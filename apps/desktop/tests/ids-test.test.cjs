const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { runInNewContext } = require("node:vm");
const test = require("node:test");

const script = readFileSync(join(__dirname, "../ui/ids-test.js"), "utf8");

function harness({ alertsAfterBaseline = [], rulesEnabled = false, behaviors = { wrong_topic: false, ids_test_alternate_order: false } } = {}) {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        value: "", disabled: false, textContent: "", children: [], listeners: {},
        classList: { toggle() {} },
        addEventListener(name, callback) { this.listeners[name] = callback; },
        replaceChildren() { this.children = []; this.value = ""; },
        appendChild(child) {
          this.children.push(child);
          if (!this.value) this.value = child.value;
        },
      });
    }
    return elements.get(id);
  };
  element("gateway-select").value = "gw1";
  let now = Date.parse("2026-01-01T00:00:00Z");
  let queryCount = 0;
  const oldAlert = {
    timestamp: "2026-01-01T00:00:00Z", device_id: "fake1",
    alert_type: "ml_anomaly", score_type: "ml_probability", score: 0.9,
  };
  const fetch = async (url) => {
    let data;
    if (url.includes("/devices?")) data = [{ id: "fake1", is_fake: true }];
    else if (url.endsWith("/ids/status")) data = {
      installed: true, configured_enabled: true, service_state: "running",
      model_ready: true, runtime_ready: true,
      config: { ml_enabled: true, behavioral_rules: { enabled: rulesEnabled } },
    };
    else if (url.endsWith("/fake")) data = {
      status: "running", send_interval_ms: 100,
      behaviors,
    };
    else if (url.includes("/ids/alerts?")) {
      queryCount += 1;
      data = { alerts: [oldAlert, ...(queryCount > 1 ? alertsAfterBaseline : [])] };
    } else throw new Error("Unexpected request: " + url);
    return { ok: true, json: async () => data };
  };
  runInNewContext(script, {
    document: {
      getElementById: element,
      createElement: () => ({ value: "", textContent: "" }),
    },
    window: {
      setTimeout(callback, ms) {
        if (ms === 3000) { now += ms; callback(); }
        return 1;
      },
      clearTimeout() {},
    },
    Date: { now: () => now, parse: Date.parse },
    URLSearchParams, AbortController, fetch, encodeURIComponent, Error, Number, Object, Set, JSON,
  });
  return { element, getQueryCount: () => queryCount };
}

test("passes only on a new ML alert for the selected sensor", async () => {
  const { element } = harness({ alertsAfterBaseline: [{
    timestamp: "2026-01-01T00:00:01Z", device_id: "fake1",
    alert_type: "ml_anomaly", score_type: "ml_probability", score: 0.95,
  }] });
  await element("ids-test-refresh").listeners.click();
  await element("ids-test-start").listeners.click();
  assert.match(element("ids-test-message").textContent, /^OBSERVED:/);
  assert.equal(element("gateway-select").disabled, false);
});

test("old, delayed and rule alerts do not pass the model test", async () => {
  const { element } = harness({ alertsAfterBaseline: [
    {
      timestamp: "2025-12-31T23:59:59Z", device_id: "fake1",
      alert_type: "ml_anomaly", score_type: "ml_probability", score: 0.9,
    },
    {
      timestamp: "2026-01-01T00:00:02Z", device_id: "fake1",
      alert_type: "behavioral_rule", score_type: "rule_confidence", score: 1,
    },
  ] });
  await element("ids-test-refresh").listeners.click();
  await element("ids-test-start").listeners.click();
  assert.match(element("ids-test-message").textContent, /^INCONCLUSIVE:/);
});

test("requires behavioral rules to be disabled", async () => {
  const { element, getQueryCount } = harness({ rulesEnabled: true });
  await element("ids-test-refresh").listeners.click();
  await element("ids-test-start").listeners.click();
  assert.match(element("ids-test-message").textContent, /disable behavioral rules/);
  assert.equal(getQueryCount(), 0);
});

test("rejects alternate order instead of artificially triggering the model", async () => {
  const { element, getQueryCount } = harness({ behaviors: { ids_test_alternate_order: true } });
  await element("ids-test-refresh").listeners.click();
  await element("ids-test-start").listeners.click();
  assert.match(element("ids-test-message").textContent, /Disable all simulated behaviors/);
  assert.equal(getQueryCount(), 0);
});

test("rejects missing fake-sensor behavior settings", async () => {
  const { element, getQueryCount } = harness({ behaviors: null });
  await element("ids-test-refresh").listeners.click();
  await element("ids-test-start").listeners.click();
  assert.match(element("ids-test-message").textContent, /behavior settings are unavailable/);
  assert.equal(getQueryCount(), 0);
});

/* Native Monitoring tabs — talks to control-service via wizard /api/v1 proxy. */
(function () {
  const TABS = [
    { id: "metric", label: "Gateway Metric" },
    { id: "activities", label: "Gateway Activities" },
  ];
  const WIZARD_MONITORING = "http://127.0.0.1:9138/monitoring.html";
  let tab = "metric";
  let timer = null;
  let lastWarnings = [];
  let activitiesSensors = [];
  let selectedSensorId = null;
  /** Active query window from the last summary response: { from, to, range }. */
  let lastTimeWindow = null;
  /** Per-chart zoom state: { values:[{t,v}], opts, window, sliced }. */
  const chartZoom = Object.create(null);

  function tabFromHash() {
    const h = (location.hash || "").replace(/^#/, "").toLowerCase();
    if (h === "activities" || h === "gateway") return "activities";
    if (h === "metric" || h === "raspi" || h === "host") return "metric";
    return "metric";
  }

  const $ = (id) => document.getElementById(id);

  /** Wizard shell proxies /api/v1 and injects IOTGW_API_TOKEN — not Tauri asset origin. */
  function onWizardOrigin() {
    if (location.protocol !== "http:" && location.protocol !== "https:") {
      return false;
    }
    const host = location.hostname;
    return host === "127.0.0.1" || host === "localhost";
  }

  async function control(path, opts) {
    if (!onWizardOrigin()) {
      throw new Error(
        "Open Monitoring from the Setup Wizard at " +
          WIZARD_MONITORING +
          " (same-origin /api/v1 proxy)."
      );
    }
    const headers = { "Content-Type": "application/json", ...(opts && opts.headers) };
    const res = await fetch(path, { ...opts, headers });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = data.detail || data.error || res.statusText;
      throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    }
    return data;
  }

  function showWarnings(warnings) {
    lastWarnings = Array.isArray(warnings) ? warnings : [];
    const banner = $("warn-banner");
    if (!banner) return;
    if (!lastWarnings.length) {
      banner.classList.add("hidden");
      banner.textContent = "";
      return;
    }
    banner.classList.remove("hidden");
    banner.textContent =
      "Backend warnings (" +
      lastWarnings.length +
      "): " +
      String(lastWarnings[0]).slice(0, 240);
  }

  function setStatusBadge(kind, text) {
    $("hdr-status").innerHTML =
      `<span class="badge ${kind}">${escapeHtml(text)}</span>`;
  }

  const METRIC_LINE_CHARTS = [
    "cpu_pct",
    "mem_used_pct",
    "load1",
    "fs_used_pct",
    "net_rx_mbps",
    "net_tx_mbps",
    "temp_c",
  ];

  function sparkSvg(values, opts) {
    const w = (opts && opts.w) || 96;
    const h = (opts && opts.h) || 28;
    if (!values || !values.length) {
      return `<svg viewBox="0 0 ${w} ${h}" class="spark"><text x="4" y="${h / 2 + 3}" fill="#8b9bb4" font-size="10">—</text></svg>`;
    }
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = max - min || 1;
    const pts = values
      .map((v, i) => {
        const x = (i / Math.max(values.length - 1, 1)) * (w - 2) + 1;
        const y = h - 2 - ((v - min) / span) * (h - 4);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
    return `<svg viewBox="0 0 ${w} ${h}" class="spark" preserveAspectRatio="none"><polyline fill="none" stroke="#4da3ff" stroke-width="1.5" points="${pts}" /></svg>`;
  }

  function chartEmptySvg(w, h, message) {
    const msg = message || "No data in range";
    return (
      `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet" aria-label="${escapeHtml(msg)}">` +
      `<rect x="44" y="10" width="${w - 54}" height="${h - 36}" fill="none" stroke="#243044" stroke-dasharray="4 4"/>` +
      `<line x1="44" y1="${h - 26}" x2="${w - 10}" y2="${h - 26}" stroke="#243044"/>` +
      `<line x1="44" y1="10" x2="44" y2="${h - 26}" stroke="#243044"/>` +
      `<text x="${w / 2}" y="${h / 2}" text-anchor="middle" fill="#8b9bb4" font-size="12">${escapeHtml(msg)}</text>` +
      `</svg>`
    );
  }

  function fmtChartNum(v) {
    const n = Number(v);
    if (!Number.isFinite(n)) return "—";
    const a = Math.abs(n);
    if (a >= 1e9) return (n / 1e9).toFixed(2) + "G";
    if (a >= 1e6) return (n / 1e6).toFixed(2) + "M";
    if (a >= 1e4) return (n / 1e3).toFixed(1) + "k";
    if (a >= 100) return n.toFixed(0);
    if (a >= 10) return n.toFixed(1);
    if (a >= 1) return n.toFixed(2);
    return n.toFixed(3);
  }

  /** Human delay for Activities cards (values are milliseconds). */
  function formatDelay(ms, { cumulative = false } = {}) {
    if (ms == null || ms === "" || !Number.isFinite(Number(ms))) return "—";
    const n = Number(ms);
    // Per-sample gauges reject epoch-sized nonsense; totals may exceed 24h.
    const max = cumulative
      ? 365 * 24 * 60 * 60 * 1000
      : 24 * 60 * 60 * 1000;
    if (n < 0 || n > max) return "—";
    if (n < 1000) return n < 10 ? n.toFixed(1) + " ms" : Math.round(n) + " ms";
    if (n < 60_000) return (n / 1000).toFixed(n < 10_000 ? 2 : 1) + " s";
    if (n < 3_600_000) return (n / 60_000).toFixed(1) + " min";
    return (n / 3_600_000).toFixed(1) + " h";
  }

  function pad2(n) {
    return String(n).padStart(2, "0");
  }

  function parseRangeToSeconds(range) {
    const raw = String(range || "1h").trim().toLowerCase();
    const m = raw.match(/^(\d+)([smhd])$/);
    if (!m) return 3600;
    const n = Number(m[1]);
    const u = m[2];
    if (u === "s") return Math.max(n, 1);
    if (u === "m") return Math.max(n * 60, 1);
    if (u === "h") return Math.max(n * 3600, 1);
    if (u === "d") return Math.max(n * 86400, 1);
    return 3600;
  }

  function formatAxisTime(unixSec, spanSec) {
    const d = new Date(Number(unixSec) * 1000);
    if (Number.isNaN(d.getTime())) return "—";
    const hm = pad2(d.getHours()) + ":" + pad2(d.getMinutes());
    if (spanSec > 86400) {
      return pad2(d.getMonth() + 1) + "/" + pad2(d.getDate()) + " " + hm;
    }
    if (spanSec <= 900) {
      return hm + ":" + pad2(d.getSeconds());
    }
    return hm;
  }

  function formatHoverTime(unixSec, spanSec) {
    const d = new Date(Number(unixSec) * 1000);
    if (Number.isNaN(d.getTime())) return "—";
    const hms =
      pad2(d.getHours()) +
      ":" +
      pad2(d.getMinutes()) +
      ":" +
      pad2(d.getSeconds());
    if (spanSec > 86400) {
      return (
        d.getFullYear() +
        "-" +
        pad2(d.getMonth() + 1) +
        "-" +
        pad2(d.getDate()) +
        " " +
        hms
      );
    }
    return hms;
  }

  function formatTimeWindow(from, to) {
    const span = Math.max(Number(to) - Number(from), 1);
    return formatAxisTime(from, span) + " → " + formatAxisTime(to, span);
  }

  function setTimeWindow(meta, fallbackRange) {
    const el = $("time-window");
    const range =
      (meta && meta.range) ||
      fallbackRange ||
      ($("range") && $("range").value) ||
      "1h";
    let from = meta && Number(meta.from);
    let to = meta && Number(meta.to);
    if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) {
      to = Math.floor(Date.now() / 1000);
      from = to - parseRangeToSeconds(range);
    }
    lastTimeWindow = { from: from, to: to, range: range };
    if (el) el.textContent = formatTimeWindow(from, to);
  }

  /** Normalize API chart series to ``[{t,v}, ...]`` (accepts legacy float[]). */
  function normalizeSeries(raw, timeMeta) {
    if (!raw || !raw.length) return [];
    const first = raw[0];
    if (first && typeof first === "object" && "v" in first) {
      return raw
        .map((p) => ({ t: Number(p.t) || 0, v: Number(p.v) }))
        .filter((p) => Number.isFinite(p.v));
    }
    const nums = raw.map((v) => Number(v)).filter((v) => Number.isFinite(v));
    if (!nums.length) return [];
    let to = timeMeta && Number(timeMeta.to);
    let from = timeMeta && Number(timeMeta.from);
    if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) {
      to =
        (lastTimeWindow && lastTimeWindow.to) ||
        Math.floor(Date.now() / 1000);
      from =
        (lastTimeWindow && lastTimeWindow.from) ||
        to -
          parseRangeToSeconds(($("range") && $("range").value) || "1h");
    }
    const n = nums.length;
    if (n === 1) return [{ t: to, v: nums[0] }];
    return nums.map((v, i) => ({
      t: Math.round(from + ((to - from) * i) / (n - 1)),
      v: v,
    }));
  }

  function sanitizeDelaySeries(values) {
    const pts = normalizeSeries(values, lastTimeWindow);
    const max = 24 * 60 * 60 * 1000;
    return pts.map((p) => {
      const n = Number(p.v);
      if (!Number.isFinite(n) || n < 0 || n > max) return { t: p.t, v: 0 };
      return { t: p.t, v: n };
    });
  }

  function seriesSpanSec(points) {
    if (!points || points.length < 2) {
      if (lastTimeWindow) {
        return Math.max(lastTimeWindow.to - lastTimeWindow.from, 1);
      }
      return 3600;
    }
    const a = Number(points[0].t);
    const b = Number(points[points.length - 1].t);
    if (Number.isFinite(a) && Number.isFinite(b) && b > a) return b - a;
    if (lastTimeWindow) {
      return Math.max(lastTimeWindow.to - lastTimeWindow.from, 1);
    }
    return 3600;
  }

  function lineChartSvg(points, opts) {
    const w = (opts && opts.w) || 360;
    const h = (opts && opts.h) || 140;
    const padL = 48;
    const padR = 14;
    const padT = 16;
    const padB = 34;
    const unit = (opts && opts.unit) || "";
    const formatValue =
      (opts && opts.formatValue) || ((v) => fmtChartNum(v) + (unit ? " " + unit : ""));
    if (!points || !points.length) {
      return chartEmptySvg(w, h, (opts && opts.empty) || "No data in range");
    }
    const values = points.map((p) => Number(p.v));
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = max - min || 1;
    const plotW = w - padL - padR;
    const plotH = h - padT - padB;
    const n = values.length;
    const timeSpan = seriesSpanSec(points);
    const xAt = (i) => padL + (i / Math.max(n - 1, 1)) * plotW;
    const yAt = (v) => padT + plotH - ((v - min) / span) * plotH;
    const pts = values
      .map((v, i) => `${xAt(i).toFixed(1)},${yAt(v).toFixed(1)}`)
      .join(" ");
    const area =
      `${padL},${padT + plotH} ` + pts + ` ${padL + plotW},${padT + plotH}`;

    // Mesh grid: 4 horizontal + several vertical guides for easier reading.
    const yDivs = 4;
    const xDivs = Math.min(8, Math.max(4, Math.ceil(n / 8)));
    let mesh = "";
    let yTicks = "";
    for (let g = 0; g <= yDivs; g++) {
      const frac = g / yDivs;
      const y = padT + plotH * (1 - frac);
      const val = min + span * frac;
      const major = g === 0 || g === yDivs || g === Math.floor(yDivs / 2);
      mesh +=
        `<line class="chart-mesh" x1="${padL}" y1="${y.toFixed(1)}" ` +
        `x2="${padL + plotW}" y2="${y.toFixed(1)}" ` +
        `stroke="${major ? "#2a3548" : "#1a2330"}" ` +
        `stroke-width="${major ? "1" : "0.75"}"/>`;
      yTicks +=
        `<text x="4" y="${(y + 3).toFixed(1)}" fill="#8b9bb4" font-size="9">` +
        `${escapeHtml(formatValue(val))}</text>`;
    }
    for (let g = 0; g <= xDivs; g++) {
      const frac = g / xDivs;
      const x = padL + plotW * frac;
      const major = g === 0 || g === xDivs || g === Math.floor(xDivs / 2);
      mesh +=
        `<line class="chart-mesh" x1="${x.toFixed(1)}" y1="${padT}" ` +
        `x2="${x.toFixed(1)}" y2="${padT + plotH}" ` +
        `stroke="${major ? "#2a3548" : "#1a2330"}" ` +
        `stroke-width="${major ? "1" : "0.75"}"/>`;
    }

    // Point markers (dense enough to hit with the mouse; title as fallback).
    const step = Math.max(1, Math.ceil(n / 60));
    const dots = values
      .map((v, i) => {
        if (i % step !== 0 && i !== n - 1) return "";
        const tip = escapeHtml(
          formatHoverTime(points[i].t, timeSpan) + " · " + formatValue(v)
        );
        return (
          `<circle class="chart-dot" data-i="${i}" cx="${xAt(i).toFixed(1)}" cy="${yAt(v).toFixed(1)}" ` +
          `r="3" fill="#4da3ff" stroke="#0b1118" stroke-width="1">` +
          `<title>${tip}</title></circle>`
        );
      })
      .join("");

    const xLabelIdx = [];
    const tickCount = Math.min(5, Math.max(2, xDivs));
    for (let g = 0; g <= tickCount; g++) {
      const i = Math.round((g / tickCount) * (n - 1));
      if (!xLabelIdx.includes(i)) xLabelIdx.push(i);
    }
    const seenLabels = Object.create(null);
    const xLabels = xLabelIdx
      .map((i, idx) => {
        let label = formatAxisTime(points[i].t, timeSpan);
        if (seenLabels[label] && idx !== 0 && idx !== xLabelIdx.length - 1) {
          return "";
        }
        seenLabels[label] = 1;
        const anchor =
          idx === 0 ? "start" : idx === xLabelIdx.length - 1 ? "end" : "middle";
        return (
          `<text x="${xAt(i).toFixed(1)}" y="${h - 8}" text-anchor="${anchor}" ` +
          `fill="#8b9bb4" font-size="9">${escapeHtml(label)}</text>`
        );
      })
      .join("");

    // Invisible hit layer + crosshair group (JS hover drives these).
    return (
      `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet" class="line-chart" ` +
      `data-pad-l="${padL}" data-pad-r="${padR}" data-pad-t="${padT}" data-pad-b="${padB}" ` +
      `data-min="${min}" data-max="${max}" data-n="${n}" data-span="${timeSpan}">` +
      `<rect class="chart-plot-bg" x="${padL}" y="${padT}" width="${plotW}" height="${plotH}" fill="#0b1118"/>` +
      mesh +
      `<line x1="${padL}" y1="${padT + plotH}" x2="${padL + plotW}" y2="${padT + plotH}" stroke="#3a465c"/>` +
      `<line x1="${padL}" y1="${padT}" x2="${padL}" y2="${padT + plotH}" stroke="#3a465c"/>` +
      yTicks +
      xLabels +
      `<polygon fill="rgba(77,163,255,0.12)" points="${area}"/>` +
      `<polyline fill="none" stroke="#4da3ff" stroke-width="1.8" points="${pts}"/>` +
      dots +
      `<g class="chart-crosshair" style="display:none">` +
      `<line class="chart-cross-v" x1="0" y1="${padT}" x2="0" y2="${padT + plotH}" stroke="#9fd0ff" stroke-width="1" stroke-dasharray="3 3" opacity="0.85"/>` +
      `<line class="chart-cross-h" x1="${padL}" y1="0" x2="${padL + plotW}" y2="0" stroke="#9fd0ff" stroke-width="1" stroke-dasharray="3 3" opacity="0.85"/>` +
      `<circle class="chart-cross-dot" cx="0" cy="0" r="5" fill="#9fd0ff" stroke="#0b1118" stroke-width="1.5"/>` +
      `</g>` +
      `<rect class="chart-hit" x="${padL}" y="${padT}" width="${plotW}" height="${plotH}" ` +
      `fill="transparent" style="cursor:crosshair"/>` +
      `</svg>` +
      `<div class="chart-readout" hidden></div>`
    );
  }

  function barChartSvg(rows, opts) {
    const w = (opts && opts.w) || 360;
    const h = (opts && opts.h) || 160;
    const padL = 78;
    const padR = 12;
    const padT = 8;
    const padB = 18;
    if (!rows || !rows.length) {
      return chartEmptySvg(w, h, (opts && opts.empty) || "No data in range");
    }
    const max = Math.max(...rows.map((r) => Number(r.value) || 0), 0.001);
    const plotW = w - padL - padR;
    const plotH = h - padT - padB;
    const rowH = plotH / rows.length;
    const xDivs = 4;
    let mesh = "";
    let xTicks = "";
    for (let g = 0; g <= xDivs; g++) {
      const frac = g / xDivs;
      const x = padL + plotW * frac;
      const major = g === 0 || g === xDivs || g === Math.floor(xDivs / 2);
      mesh +=
        `<line class="chart-mesh" x1="${x.toFixed(1)}" y1="${padT}" ` +
        `x2="${x.toFixed(1)}" y2="${padT + plotH}" ` +
        `stroke="${major ? "#2a3548" : "#1a2330"}" ` +
        `stroke-width="${major ? "1" : "0.75"}"/>`;
      const tickVal = max * frac;
      xTicks +=
        `<text x="${x.toFixed(1)}" y="${h - 4}" text-anchor="middle" fill="#8b9bb4" font-size="9">` +
        `${escapeHtml(fmtChartNum(tickVal))}</text>`;
    }
    const bars = rows
      .map((r, i) => {
        const val = Number(r.value) || 0;
        const bw = (val / max) * plotW;
        const y = padT + i * rowH + rowH * 0.18;
        const bh = rowH * 0.64;
        const label = String(r.name || "?").slice(0, 14);
        const tip = val >= 10 ? val.toFixed(0) : val.toFixed(2);
        return (
          `<text x="4" y="${(y + bh / 2 + 3).toFixed(1)}" fill="#8b9bb4" font-size="9">${escapeHtml(label)}</text>` +
          `<rect x="${padL}" y="${y.toFixed(1)}" width="${Math.max(bw, 1).toFixed(1)}" height="${bh.toFixed(1)}" fill="#4da3ff" rx="2">` +
          `<title>${escapeHtml(label)}: ${escapeHtml(tip)}</title></rect>` +
          `<text x="${(padL + Math.max(bw, 1) + 4).toFixed(1)}" y="${(y + bh / 2 + 3).toFixed(1)}" fill="#c9d4e5" font-size="9">${tip}</text>`
        );
      })
      .join("");
    return (
      `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet" class="bar-chart">` +
      `<rect x="${padL}" y="${padT}" width="${plotW}" height="${plotH}" fill="#0b1118"/>` +
      mesh +
      bars +
      xTicks +
      `</svg>`
    );
  }

  function bindChartHover(el, id) {
    const state = chartZoom[id];
    if (!el || !state) return;
    const svg = el.querySelector("svg.line-chart");
    const readout = el.querySelector(".chart-readout");
    const hit = svg && svg.querySelector(".chart-hit");
    const cross = svg && svg.querySelector(".chart-crosshair");
    if (!svg || !hit || !cross || !readout) return;

    const unit = (state.opts && state.opts.unit) || "";
    const formatValue =
      (state.opts && state.opts.formatValue) ||
      ((v) => fmtChartNum(v) + (unit ? " " + unit : ""));
    const sliced = state.sliced || state.values || [];

    const hide = () => {
      cross.style.display = "none";
      readout.hidden = true;
      readout.textContent = "";
    };

    const showAt = (clientX) => {
      if (!sliced.length) return hide();
      const rect = svg.getBoundingClientRect();
      const vb = svg.viewBox.baseVal;
      const sx = vb.width / Math.max(rect.width, 1);
      const sy = vb.height / Math.max(rect.height, 1);
      const padL = Number(svg.getAttribute("data-pad-l") || 48);
      const padR = Number(svg.getAttribute("data-pad-r") || 14);
      const padT = Number(svg.getAttribute("data-pad-t") || 16);
      const padB = Number(svg.getAttribute("data-pad-b") || 34);
      const min = Number(svg.getAttribute("data-min"));
      const max = Number(svg.getAttribute("data-max"));
      const timeSpan = Number(svg.getAttribute("data-span")) || seriesSpanSec(sliced);
      const span = max - min || 1;
      const plotW = vb.width - padL - padR;
      const plotH = vb.height - padT - padB;
      const localX = (clientX - rect.left) * sx;
      const n = sliced.length;
      let i = Math.round(((localX - padL) / Math.max(plotW, 1)) * (n - 1));
      i = Math.max(0, Math.min(n - 1, i));
      const pt = sliced[i];
      const v = pt && typeof pt === "object" ? Number(pt.v) : Number(pt);
      const x = padL + (i / Math.max(n - 1, 1)) * plotW;
      const y = padT + plotH - ((v - min) / span) * plotH;
      const vLine = cross.querySelector(".chart-cross-v");
      const hLine = cross.querySelector(".chart-cross-h");
      const dot = cross.querySelector(".chart-cross-dot");
      if (vLine) {
        vLine.setAttribute("x1", x.toFixed(1));
        vLine.setAttribute("x2", x.toFixed(1));
      }
      if (hLine) {
        hLine.setAttribute("y1", y.toFixed(1));
        hLine.setAttribute("y2", y.toFixed(1));
      }
      if (dot) {
        dot.setAttribute("cx", x.toFixed(1));
        dot.setAttribute("cy", y.toFixed(1));
      }
      cross.style.display = "";
      readout.hidden = false;
      const tLabel =
        pt && typeof pt === "object" && Number.isFinite(Number(pt.t))
          ? formatHoverTime(pt.t, timeSpan)
          : "#" + (i + 1);
      readout.textContent = tLabel + "  ·  " + formatValue(v);
      // Keep readout inside the chart body.
      const px = (x / sx);
      const py = (y / sy);
      const rw = readout.offsetWidth || 90;
      const rh = readout.offsetHeight || 22;
      let left = px + 12;
      let top = py - rh - 8;
      if (left + rw > rect.width - 4) left = px - rw - 12;
      if (top < 4) top = py + 12;
      readout.style.left = `${Math.max(4, left)}px`;
      readout.style.top = `${Math.max(4, top)}px`;
    };

    hit.onmousemove = (ev) => showAt(ev.clientX);
    hit.onmouseleave = hide;
    svg.onmouseleave = hide;
  }

  function paintLineChart(id, values, opts) {
    const el = $(id);
    if (!el) return;
    const series = normalizeSeries(values || [], lastTimeWindow);
    const baseOpts = { w: 560, h: 200, ...(opts || {}) };
    const prev = chartZoom[id];
    const keepWindow =
      prev &&
      prev.values &&
      prev.values.length === series.length &&
      prev.window &&
      prev.window > 0 &&
      prev.window < series.length;
    const window = keepWindow ? prev.window : series.length;
    const sliced =
      series.length && window < series.length
        ? series.slice(series.length - window)
        : series;
    chartZoom[id] = { values: series, opts: baseOpts, window, sliced };
    el.innerHTML = lineChartSvg(sliced, baseOpts);
    bindChartHover(el, id);
  }

  function applyChartZoom(id, action) {
    const state = chartZoom[id];
    if (!state || !state.values || !state.values.length) return;
    const n = state.values.length;
    let window = state.window || n;
    if (action === "in") window = Math.max(4, Math.floor(window / 2));
    else if (action === "out") window = Math.min(n, Math.max(window * 2, window + 4));
    else window = n;
    state.window = window;
    const sliced = window < n ? state.values.slice(n - window) : state.values;
    state.sliced = sliced;
    const el = $(id);
    if (el) {
      el.innerHTML = lineChartSvg(sliced, state.opts || { w: 560, h: 200 });
      bindChartHover(el, id);
    }
  }

  const BAR_CHART_IDS = {
    "chart-app_activity": 1,
    "chart-app_status": 1,
    "chart-app_cpu": 1,
    "chart-app_mem": 1,
    "chart-container_cpu": 1,
    "chart-container_mem": 1,
  };

  /** Attach +/-/reset zoom to every line-chart panel that is missing controls. */
  function ensureLineChartZoomControls() {
    document.querySelectorAll(".chart-panel .chart-body[id]").forEach((body) => {
      const id = body.id;
      if (!id || BAR_CHART_IDS[id]) return;
      const panel = body.closest(".chart-panel");
      const head = panel && panel.querySelector(".chart-head");
      if (!head || head.querySelector(".chart-zoom")) return;
      const zoom = document.createElement("span");
      zoom.className = "chart-zoom";
      zoom.setAttribute("data-zoom-for", id);
      zoom.innerHTML =
        '<button type="button" class="chart-zoom-btn" data-zoom="in" title="Zoom in">+</button>' +
        '<button type="button" class="chart-zoom-btn" data-zoom="out" title="Zoom out">−</button>' +
        '<button type="button" class="chart-zoom-btn" data-zoom="reset" title="Reset zoom">⟲</button>';
      head.appendChild(zoom);
    });
  }

  function paintBarChart(id, rows) {
    const el = $(id);
    if (!el) return;
    el.innerHTML = barChartSvg(rows || [], { w: 420, h: 170 });
  }

  function paintEmptyMetricCharts() {
    METRIC_LINE_CHARTS.forEach((key) => paintLineChart("chart-" + key, []));
    paintBarChart("chart-app_activity", []);
    paintBarChart("chart-app_status", []);
    paintBarChart("chart-app_cpu", []);
    paintBarChart("chart-app_mem", []);
    paintLineChart("chart-gw_msgs", []);
    paintLineChart("chart-gw_delay", []);
    paintLineChart("chart-sensor_kafka", []);
    paintLineChart("chart-sensor_delay", []);
  }

  function fmtRetention(bytes) {
    if (bytes == null || !isFinite(Number(bytes))) return "—";
    return fmtBytes(Number(bytes));
  }

  function numOrDash(v, digits) {
    if (v == null || v === "" || !isFinite(Number(v))) return "—";
    const n = Number(v);
    if (digits == null) return String(n);
    return n.toFixed(digits);
  }

  function fmtBytes(n) {
    if (n == null || !isFinite(n)) return "—";
    const u = ["B", "KB", "MB", "GB", "TB"];
    let v = Number(n);
    let i = 0;
    while (v >= 1024 && i < u.length - 1) {
      v /= 1024;
      i++;
    }
    return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${u[i]}`;
  }

  function fmtUptime(seconds) {
    const s = Number(seconds) || 0;
    if (!s) return "—";
    const days = s / 86400;
    if (days >= 1) return `${days.toFixed(1)} d`;
    const hours = s / 3600;
    if (hours >= 1) return `${hours.toFixed(1)} h`;
    return `${Math.round(s / 60)} m`;
  }

  function gaugeTone(pct) {
    if (pct == null || !isFinite(pct)) return "";
    if (pct >= 90) return "bad";
    if (pct >= 70) return "warn";
    return "";
  }

  function renderGauges(el, items) {
    if (!el) return;
    el.innerHTML = items
      .map(([label, display, pct]) => {
        const width = pct == null || !isFinite(pct) ? 0 : Math.max(0, Math.min(100, pct));
        const tone = gaugeTone(pct);
        return (
          `<div class="gauge-card">` +
          `<div class="label">${escapeHtml(label)}</div>` +
          `<div class="value">${escapeHtml(display)}</div>` +
          `<div class="gauge-track"><div class="gauge-fill ${tone}" style="width:${width}%"></div></div>` +
          `</div>`
        );
      })
      .join("");
  }

  function renderFsBar(el, usedPct, usedLabel, totalLabel) {
    if (!el) return;
    const pct = usedPct == null || !isFinite(usedPct) ? null : usedPct;
    const width = pct == null ? 0 : Math.max(0, Math.min(100, pct));
    const tone = gaugeTone(pct);
    el.innerHTML =
      `<div class="fs-meta"><strong>Root filesystem</strong>` +
      `<span class="muted">${escapeHtml(usedLabel)} / ${escapeHtml(totalLabel)}` +
      `${pct == null ? "" : ` · ${pct.toFixed(0)}% used`}</span></div>` +
      `<div class="gauge-track"><div class="gauge-fill ${tone}" style="width:${width}%"></div></div>`;
  }

  function metricCards(el, items) {
    el.innerHTML = items
      .map(
        ([label, value]) =>
          `<div class="metric-card"><div class="label">${escapeHtml(label)}</div><div class="value">${escapeHtml(value)}</div></div>`
      )
      .join("");
  }

  function fillTable(table, headers, rows) {
    const thead = table.querySelector("thead");
    const tbody = table.querySelector("tbody");
    thead.innerHTML = `<tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr>`;
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="${headers.length}" class="muted">No data</td></tr>`;
      return;
    }
    tbody.innerHTML = rows
      .map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`)
      .join("");
  }

  function formatArrivalMs(ms) {
    const n = Number(ms);
    if (!n || !isFinite(n)) return "—";
    try {
      return new Date(n).toLocaleString();
    } catch (_e) {
      return String(n);
    }
  }

  function reasonLabel(reason) {
    const r = String(reason || "denied");
    const map = {
      missing_client_cert: "Missing client certificate",
      bad_client_cert: "Bad client certificate",
      tls_eof: "TLS connection dropped",
      tls_protocol: "TLS protocol error",
      tls_handshake: "TLS handshake failed",
      bad_password: "Bad MQTT password",
      acl_deny: "ACL deny",
      fernet: "Bad encryption / Fernet",
      schema: "Schema validation",
      key_only: "Key half only",
      data_only: "Data half only",
      stamp: "Stamp mismatch",
      day: "Wrong / missing day material",
      unwrap: "Envelope unwrap failed",
      gcm: "GCM auth failed",
      legacy: "Legacy wrapper rejected",
      version: "Envelope version",
    };
    return map[r] || r.replace(/_/g, " ");
  }

  function fillDeniedTable(table, events) {
    if (!table) return;
    const rows = (events || []).map((ev) => [
      escapeHtml(formatArrivalMs(ev.arrival_ms)),
      escapeHtml(reasonLabel(ev.reason)),
      escapeHtml(ev.source_ip || "—"),
      escapeHtml(ev.device_id || "—"),
      escapeHtml(ev.gateway_id || "—"),
    ]);
    fillTable(
      table,
      ["Arrival", "Reason", "IP", "Sensor", "Gateway"],
      rows
    );
  }

  function buildTabs() {
    const nav = $("mon-tabs");
    nav.innerHTML = "";
    TABS.forEach((t) => {
      const b = document.createElement("button");
      b.textContent = t.label;
      b.dataset.tab = t.id;
      b.classList.toggle("active", t.id === tab);
      b.addEventListener("click", () => showTab(t.id, { syncHash: true }));
      nav.appendChild(b);
    });
  }

  function showTab(id, opts) {
    const next = id === "activities" ? "activities" : "metric";
    tab = next;
    document.querySelectorAll(".mon-panel").forEach((el) => {
      el.classList.toggle("hidden", el.dataset.tab !== tab);
    });
    document.querySelectorAll("#mon-tabs button").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.tab === tab);
    });
    const wantHash = "#" + tab;
    if ((opts || {}).syncHash !== false && location.hash !== wantHash) {
      history.replaceState(null, "", wantHash);
    }
    if (typeof window.iotgwRefreshNav === "function") {
      window.iotgwRefreshNav();
    }
  }

  async function loadGateways() {
    const sel = $("gateway-id");
    try {
      const rows = await control("/api/v1/gateways");
      const prev = sel.value;
      sel.innerHTML = "";
      (rows || []).forEach((g) => {
        const opt = document.createElement("option");
        opt.value = g.id;
        // Name only — host/IP lives under Gateways → Settings.
        opt.textContent = g.id;
        sel.appendChild(opt);
      });
      if (!rows || !rows.length) {
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "(no gateways in registry)";
        sel.appendChild(opt);
      } else if (prev && [...sel.options].some((o) => o.value === prev)) {
        sel.value = prev;
      }
    } catch (e) {
      sel.innerHTML = `<option value="">control API offline</option>`;
      $("hdr-status").innerHTML = `<span class="badge bad">${escapeHtml(e.message)}</span>`;
      throw e;
    }
  }

  function typeBadgeHtml(isFake) {
    return isFake
      ? '<span class="badge fake">Fake</span>'
      : '<span class="badge real">Real</span>';
  }

  function renderSensorDetail(sensor) {
    const detail = $("gw-sensor-detail");
    const empty = $("gw-sensors-empty");
    const tabs = $("gw-sensor-tabs");
    if (!detail) return;

    if (!sensor) {
      detail.classList.add("hidden");
      if (tabs) {
        tabs.classList.add("hidden");
        tabs.innerHTML = "";
      }
      return;
    }

    detail.classList.remove("hidden");
    if (empty) empty.classList.add("hidden");

    const title = $("gw-sensor-title");
    if (title) {
      title.innerHTML = `${escapeHtml(sensor.device_id || "Sensor")} ${typeBadgeHtml(
        !!sensor.is_fake
      )}`;
    }

    const sm = sensor.metrics || {};
    metricCards($("gw-sensor-metrics"), [
      ["Total msgs", String(sm.total_messages ?? "—")],
      ["Msgs / sec", numOrDash(sm.messages_per_sec, 4)],
      ["Denied", String(sm.denied_publishes ?? "—")],
      ["IDS", String(sm.ids_detections ?? "—")],
    ]);
    metricCards($("gw-sensor-kafka-meta"), [
      ["Topic", sensor.kafka_topic || "—"],
      ["Retention cap", fmtRetention(sensor.kafka_retention_bytes)],
    ]);
    metricCards($("gw-sensor-delay-metrics"), [
      ["Latest delay", formatDelay(sm.delay_latest)],
      ["Total delay", formatDelay(sm.delay_total, { cumulative: true })],
    ]);

    const charts = sensor.charts || {};
    paintLineChart("chart-sensor_kafka", charts.kafka_messages || [], {
      unit: "msgs/s",
      formatValue: (v) => fmtChartNum(v) + " msgs/s",
    });
    paintLineChart(
      "chart-sensor_delay",
      sanitizeDelaySeries(charts.delay || []),
      {
        formatValue: (v) => formatDelay(v),
      }
    );
    fillDeniedTable($("gw-sensor-denied"), sensor.denied_messages || []);
  }

  function renderSensorTabs(sensors) {
    const tabs = $("gw-sensor-tabs");
    const detail = $("gw-sensor-detail");
    const empty = $("gw-sensors-empty");
    if (!tabs || !detail) return;

    if (!sensors.length) {
      tabs.classList.add("hidden");
      tabs.innerHTML = "";
      detail.classList.add("hidden");
      if (empty) empty.classList.remove("hidden");
      selectedSensorId = null;
      return;
    }

    if (empty) empty.classList.add("hidden");

    if (sensors.length === 1) {
      tabs.classList.add("hidden");
      tabs.innerHTML = "";
      selectedSensorId = sensors[0].device_id;
      renderSensorDetail(sensors[0]);
      return;
    }

    if (
      !selectedSensorId ||
      !sensors.some((s) => s.device_id === selectedSensorId)
    ) {
      selectedSensorId = sensors[0].device_id;
    }

    tabs.classList.remove("hidden");
    tabs.innerHTML = "";
    sensors.forEach((s) => {
      const b = document.createElement("button");
      b.type = "button";
      b.innerHTML = `${escapeHtml(s.device_id)} ${typeBadgeHtml(!!s.is_fake)}`;
      b.dataset.deviceId = s.device_id;
      b.classList.toggle("active", s.device_id === selectedSensorId);
      b.addEventListener("click", () => {
        selectedSensorId = s.device_id;
        tabs.querySelectorAll("button").forEach((btn) => {
          btn.classList.toggle("active", btn.dataset.deviceId === selectedSensorId);
        });
        const row = activitiesSensors.find((x) => x.device_id === selectedSensorId);
        renderSensorDetail(row || null);
      });
      tabs.appendChild(b);
    });

    const active = sensors.find((s) => s.device_id === selectedSensorId) || sensors[0];
    renderSensorDetail(active);
  }

  async function refreshGateway() {
    const range = $("range").value;
    const gid = ($("gateway-id") && $("gateway-id").value) || "";
    let path = `/api/v1/query/summaries/gateway?range=${encodeURIComponent(range)}`;
    if (gid) path += `&gateway_id=${encodeURIComponent(gid)}`;
    const data = await control(path);
    setTimeWindow(data.time, data.range || range);
    const m = data.metrics || {};
    const charts = data.charts || {};

    metricCards($("gw-metrics"), [
      ["Total msgs", String(m.total_sensor_messages ?? "—")],
      ["Msgs / sec", numOrDash(m.messages_per_sec, 4)],
      ["Denied", String(m.denied_publishes ?? "—")],
      ["IDS", String(m.ids_detections ?? "—")],
    ]);
    paintLineChart("chart-gw_msgs", charts.messages || [], {
      unit: "msgs/s",
      formatValue: (v) => fmtChartNum(v) + " msgs/s",
    });
    metricCards($("gw-delay-metrics"), [
      ["Latest delay", formatDelay(m.delay_latest)],
      ["Total delay", formatDelay(m.delay_total, { cumulative: true })],
    ]);
    paintLineChart(
      "chart-gw_delay",
      sanitizeDelaySeries(charts.delay || m.delay_sparkline || []),
      { formatValue: (v) => formatDelay(v) }
    );

    activitiesSensors = data.connected_sensors || [];
    fillTable(
      $("gw-connected"),
      ["Device", "Type", "IP", "Kafka topic", "Retention", "Monitor"],
      activitiesSensors.map((r) => [
        escapeHtml(r.device_id),
        typeBadgeHtml(!!r.is_fake),
        escapeHtml(r.ip || r.source_ip || ""),
        escapeHtml(r.kafka_topic || ""),
        escapeHtml(fmtRetention(r.kafka_retention_bytes)),
        r.monitor_enabled ? "on" : "off",
      ])
    );
    fillDeniedTable($("gw-denied"), data.denied_messages || []);
    renderSensorTabs(activitiesSensors);

    $("gw-msg").textContent =
      `gateway=${data.gateway_id || gid || "—"} range=${data.range || range}`;
    showWarnings(data.warnings);
  }

  async function refreshRaspi() {
    const range = $("range").value;
    const data = await control(
      `/api/v1/query/summaries/raspi?range=${encodeURIComponent(range)}` +
        `&node=gateway&job=iot-gateway-agent`
    );
    setTimeWindow(data.time, data.range || range);
    const m = data.metrics || {};
    const charts = data.charts || {};
    const applications = data.applications || {};
    const containers = data.containers || {};
    const appsUp =
      m.apps_up != null
        ? m.apps_up
        : m.active_containers != null
          ? m.active_containers
          : "—";
    const appsTotal = m.apps_total != null ? m.apps_total : null;
    const appsLabel =
      appsTotal != null && appsUp !== "—"
        ? `${appsUp}/${appsTotal}`
        : String(appsUp);

    metricCards($("raspi-metrics"), [
      ["Status", data.up ? "up" : "down"],
      ["Temp", m.temp_c == null ? "—" : `${m.temp_c} °C`],
      ["Uptime", fmtUptime(m.uptime_s)],
      ["CPU busy (cores)", String(m.cpu_cores_busy ?? "—")],
      ["Cores", String(m.cpu_cores ?? "—")],
      ["Load1", String(m.load1 ?? "—")],
      ["Apps", appsLabel],
    ]);
    metricCards($("raspi-metrics-extra"), [
      ["Mem used", `${m.mem_used_pct ?? "—"}%`],
      ["Mem", `${fmtBytes(m.mem_used_bytes)} / ${fmtBytes(m.mem_total_bytes)}`],
      ["Swap", `${m.swap_pct ?? "—"}%`],
      ["IOWait", String(m.iowait_cores ?? "—")],
      [
        "Procs",
        `R:${m.procs_running ?? 0} B:${m.procs_blocked ?? 0}`,
      ],
      ["Disk used", `${m.fs_used_pct ?? "—"}%`],
    ]);

    const cpuPct =
      m.cpu_cores && m.cpu_cores_busy != null
        ? Math.min(100, (Number(m.cpu_cores_busy) / Number(m.cpu_cores)) * 100)
        : null;
    renderGauges($("raspi-gauges"), [
      [
        "CPU load",
        cpuPct == null ? "—" : `${cpuPct.toFixed(0)}%`,
        cpuPct,
      ],
      [
        "RAM used",
        m.mem_used_pct == null ? "—" : `${m.mem_used_pct}%`,
        m.mem_used_pct,
      ],
      [
        "Swap used",
        m.swap_pct == null ? "—" : `${m.swap_pct}%`,
        m.swap_pct,
      ],
    ]);
    renderFsBar(
      $("raspi-fs-bar"),
      m.fs_used_pct,
      fmtBytes(m.fs_size_bytes != null && m.fs_avail_bytes != null
        ? m.fs_size_bytes - m.fs_avail_bytes
        : null),
      fmtBytes(m.fs_size_bytes)
    );

    METRIC_LINE_CHARTS.forEach((key) => {
      const series =
        charts[key] ||
        (key === "cpu_pct" ? data.cpu_sparkline_pct : null) ||
        [];
      paintLineChart("chart-" + key, series);
    });

    const statusRows = applications.status || [];
    const statusCards =
      statusRows.length > 0
        ? statusRows.map((s) => [
            String(s.name || s.id || "app"),
            s.up ? "up" : "down",
          ])
        : [["Applications", appsLabel]];
    const appMetricsEl = $("raspi-app-metrics") || $("raspi-container-metrics");
    if (appMetricsEl) metricCards(appMetricsEl, statusCards);

    const activity =
      applications.activity ||
      [];
    const appCpu = applications.cpu || containers.cpu || [];
    const appMem = applications.mem_mib || containers.mem_mib || [];
    const statusBars = statusRows.map((s) => ({
      name: s.name || s.id || "?",
      value: s.up ? 1 : 0,
    }));

    paintBarChart("chart-app_activity", activity);
    paintBarChart("chart-app_status", statusBars);
    paintBarChart("chart-app_cpu", appCpu);
    paintBarChart("chart-app_mem", appMem);
    // Older bundled HTML still uses container chart ids.
    paintBarChart("chart-container_cpu", appCpu);
    paintBarChart("chart-container_mem", appMem);

    $("raspi-msg").textContent = `node=${data.node} job=${data.job} range=${data.range || range}`;
    showWarnings(data.warnings);
    return data;
  }

  async function refresh() {
    setStatusBadge("warn", "loading…");
    try {
      let hostUp = true;
      if (tab === "metric") {
        const data = await refreshRaspi();
        hostUp = data ? !!data.up : false;
      } else {
        await refreshGateway();
      }
      if (lastWarnings.length) {
        setStatusBadge("warn", "degraded");
      } else if (tab === "metric" && !hostUp) {
        setStatusBadge("warn", "no scrape");
      } else {
        setStatusBadge("ok", "live");
      }
    } catch (e) {
      showWarnings([]);
      setStatusBadge("bad", e.message);
    }
  }

  function scheduleAuto() {
    if (timer) clearInterval(timer);
    timer = null;
    if ($("auto-refresh").checked) {
      timer = setInterval(() => refresh().catch(() => {}), 15000);
    }
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function wire() {
    buildTabs();
    showTab(tabFromHash(), { syncHash: true });
    paintEmptyMetricCharts();
    window.addEventListener("hashchange", () => {
      showTab(tabFromHash(), { syncHash: false });
      refresh().catch(console.error);
    });
    const originBanner = $("origin-banner");
    if (!onWizardOrigin() && originBanner) {
      originBanner.classList.remove("hidden");
      originBanner.innerHTML =
        `Monitoring must be opened from the app shell so <code>/api/v1</code> is proxied ` +
        `(with optional <code>IOTGW_API_TOKEN</code>). Use ` +
        `<a class="link" href="${WIZARD_MONITORING}">${WIZARD_MONITORING}</a>.`;
      setStatusBadge("bad", "wrong origin");
    }
    $("btn-refresh").addEventListener("click", () => refresh().catch(console.error));
    $("auto-refresh").addEventListener("change", scheduleAuto);
    $("range").addEventListener("change", () => refresh().catch(console.error));
    $("gateway-id").addEventListener("change", () => {
      selectedSensorId = null;
      activitiesSensors = [];
      if (tab === "activities") refresh().catch(console.error);
    });
    ensureLineChartZoomControls();
    document.addEventListener("click", (ev) => {
      const btn = ev.target && ev.target.closest && ev.target.closest(".chart-zoom-btn");
      if (!btn) return;
      const wrap = btn.closest(".chart-zoom");
      const chartId = wrap && wrap.getAttribute("data-zoom-for");
      const action = btn.getAttribute("data-zoom");
      if (chartId && action) applyChartZoom(chartId, action);
    });
    // Ctrl/Cmd + wheel over a line chart zooms that series.
    document.addEventListener(
      "wheel",
      (ev) => {
        if (!ev.ctrlKey && !ev.metaKey) return;
        const body = ev.target && ev.target.closest && ev.target.closest(".chart-body[id]");
        if (!body || BAR_CHART_IDS[body.id]) return;
        if (!chartZoom[body.id]) return;
        ev.preventDefault();
        applyChartZoom(body.id, ev.deltaY < 0 ? "in" : "out");
      },
      { passive: false }
    );
    $("mon-tabs").addEventListener("click", () => refresh().catch(console.error));
    if (!onWizardOrigin()) return;
    loadGateways()
      .catch(() => {})
      .finally(() => {
        refresh().catch(console.error);
        scheduleAuto();
      });
  }

  wire();
})();

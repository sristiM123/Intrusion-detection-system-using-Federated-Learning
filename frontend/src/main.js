// src/main.js
import "./style.css";
import Chart from "chart.js/auto";

// ---- CONFIG ----
const RENDER_HOST = "intrusion-detection-system-using-1h6f.onrender.com";
const WS_URL = window.location.hostname === "localhost"
  ? "ws://localhost:9002/ws"
  : `wss://${RENDER_HOST}/ws`;
const API_BASE = window.location.hostname === "localhost"
  ? "/api"
  : `https://${RENDER_HOST}/api`;

// ---- STATE ----
const state = {
  ws: null,
  connected: false,
  devices: [],
  environment: {
    simulatorRunning: false,
    attackType: "none",
    attackLevel: 0,
    driftLevel: 0
  },
  stats: {
    totalEvents: 0,
    TP: 0, FP: 0, TN: 0, FN: 0,
    precision: 0, recall: 0, f1: 0, fpRate: 0
  },
  globalModel: {
    round: 1,
    accuracy: 0.92
  },
  alerts: [],
  telemetry: [],
  timeseries: null,
  chart: null
};

// ---- SMALL HELPERS ----
function fmt(n, d = 3) {
  if (n === null || n === undefined || Number.isNaN(n)) return "-";
  return Number(n).toFixed(d);
}

async function apiGet(path) {
  const url = `${API_BASE}${path}`;
  try {
    console.log("GET", url);
    const r = await fetch(url);
    console.log("GET", url, r.status);
    if (!r.ok) return { ok: false };
    return await r.json();
  } catch (e) {
    console.error("GET error", url, e);
    return { ok: false };
  }
}

async function apiPost(path, body = {}) {
  const url = `${API_BASE}${path}`;
  try {
    console.log("POST", url, body);
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    console.log("POST", url, r.status);
    if (!r.ok) return { ok: false };
    return await r.json();
  } catch (e) {
    console.error("POST error", url, e);
    return { ok: false };
  }
}

function pill(text, dotClass) {
  const s = document.createElement("span");
  s.className = "pill";
  const d = document.createElement("span");
  d.className = `dot ${dotClass}`;
  const t = document.createElement("span");
  t.textContent = text;
  s.appendChild(d);
  s.appendChild(t);
  return s;
}

// ---- BADGES + KPI ----
function renderBadges() {
  const root = document.getElementById("badges");
  root.textContent = "";

  const env = state.environment;
  const s = state.stats;
  const gm = state.globalModel;

  const items = [
    ["WS", state.connected ? "connected" : "disconnected"],
    ["Simulator", env.simulatorRunning ? "running" : "stopped"],
    ["Attack", `${env.attackType} (${fmt(env.attackLevel, 2)})`],
    ["Drift", fmt(env.driftLevel, 2)],
    ["F1", fmt(s.f1, 3)],
    ["FP rate", fmt(s.fpRate, 3)],
    ["Global acc", fmt(gm.accuracy, 3)],
    ["Round", gm.round ?? "-"]
  ];

  for (const [k, v] of items) {
    const b = document.createElement("div");
    b.className = "badge";
    const st = document.createElement("strong");
    st.textContent = `${k}: `;
    const span = document.createElement("span");
    span.textContent = String(v);
    b.appendChild(st);
    b.appendChild(span);
    root.appendChild(b);
  }
}

function renderKpiAndEnv() {
  document.getElementById("kpi-devices").textContent = String(state.devices.length);
  document.getElementById("kpi-events").textContent = String(state.stats.totalEvents ?? 0);
  document.getElementById("kpi-f1").textContent = fmt(state.stats.f1, 3);
  document.getElementById("kpi-acc").textContent = fmt(state.globalModel.accuracy, 3);

  const env = state.environment;
  document.getElementById("env-text").textContent =
    `Simulator: ${env.simulatorRunning ? "running" : "stopped"}\n` +
    `Attack: ${env.attackType} (level ${fmt(env.attackLevel, 2)})\n` +
    `Drift level: ${fmt(env.driftLevel, 2)}`;
}

// ---- DEVICES TABLES ----
function renderDevicesTables() {
  const bodies = [
    document.getElementById("devices-tbody"),
    document.getElementById("devices-tbody-ctrl")
  ];

  bodies.forEach((tbody) => {
    tbody.textContent = "";
    for (const d of state.devices) {
      const tr = document.createElement("tr");

      const td1 = document.createElement("td");
      td1.textContent = `${d.name} (${d.model})`;

      const drift = d.driftScore ?? 0;
      const driftClass = drift > 0.6 ? "bad" : drift > 0.35 ? "warn" : "good";
      const td2 = document.createElement("td");
      td2.appendChild(pill(fmt(drift, 3), driftClass));

      const td3 = document.createElement("td");
      td3.textContent = fmt(d.localAccuracy, 3);

      const td4 = document.createElement("td");
      td4.appendChild(
        pill(d.quarantined ? "quarantined" : "active", d.quarantined ? "bad" : "good")
      );

      const td5 = document.createElement("td");
      const row = document.createElement("div");
      row.className = "row";

      const qBtn = document.createElement("button");
      qBtn.className = `btn ${d.quarantined ? "" : "bad"}`;
      qBtn.textContent = "Quarantine";
      qBtn.onclick = async () => {
        await apiPost(`/devices/${d.id}/quarantine`, {});
        await refreshDevices();
      };

      const uBtn = document.createElement("button");
      uBtn.className = `btn ${d.quarantined ? "good" : ""}`;
      uBtn.textContent = "Unquarantine";
      uBtn.onclick = async () => {
        await apiPost(`/devices/${d.id}/unquarantine`, {});
        await refreshDevices();
      };

      row.appendChild(qBtn);
      row.appendChild(uBtn);
      td5.appendChild(row);

      [td1, td2, td3, td4, td5].forEach((td) => tr.appendChild(td));
      tbody.appendChild(tr);
    }
  });
}

// ---- STREAMS (telemetry + alerts) ----
function renderStreams() {
  const teleRoot = document.getElementById("telemetry-stream");
  const alertsRoot = document.getElementById("alerts-stream");
  teleRoot.textContent = "";
  alertsRoot.textContent = "";

  document.getElementById("telemetry-count").textContent = `${state.telemetry.length} events`;
  document.getElementById("alerts-count").textContent = `${state.alerts.length} alerts`;

  for (const ev of state.telemetry) {
    const item = document.createElement("div");
    item.className = "item";

    const top = document.createElement("div");
    top.className = "top";

    const sev = ev.predicted === "Attack" ? "bad" : "good";
    top.appendChild(
      pill(`${ev.predicted} • ${fmt(ev.score, 3)} (thr ${fmt(ev.threshold, 3)})`, sev)
    );

    const ts = document.createElement("span");
    ts.className = "small mono";
    ts.textContent = ev.ts;
    top.appendChild(ts);

    const msg = document.createElement("div");
    msg.className = "small mono";
    msg.textContent =
      `${ev.deviceName} | packets=${ev.features.packetsPerSec}, ` +
      `failedAuth=${ev.features.failedAuth}, bytesOut=${ev.features.bytesOut} | ` +
      `true=${ev.trueLabel}`;

    item.appendChild(top);
    item.appendChild(msg);
    teleRoot.appendChild(item);
  }

  for (const a of state.alerts) {
    const item = document.createElement("div");
    item.className = "item";

    const top = document.createElement("div");
    top.className = "top";

    const sevDot = a.severity === "high" ? "bad" : a.severity === "medium" ? "warn" : "good";
    top.appendChild(pill(`${a.severity} • ${a.type}`, sevDot));

    const ts = document.createElement("span");
    ts.className = "small mono";
    ts.textContent = a.ts;
    top.appendChild(ts);

    const msg = document.createElement("div");
    msg.className = "small";
    msg.textContent =
      `${a.deviceName}: ${a.message} (score=${fmt(a.score, 3)}, drift=${fmt(a.driftScore, 3)})`;

    item.appendChild(top);
    item.appendChild(msg);
    alertsRoot.appendChild(item);
  }
}

// ---- STATS TEXT + CHART ----
function renderStatsText() {
  const s = state.stats;
  const gm = state.globalModel;
  const env = state.environment;

  const txt =
    `Total events: ${s.totalEvents}\n` +
    `TP: ${s.TP}  FP: ${s.FP}  TN: ${s.TN}  FN: ${s.FN}\n\n` +
    `Precision: ${fmt(s.precision, 3)}\n` +
    `Recall   : ${fmt(s.recall, 3)}\n` +
    `F1       : ${fmt(s.f1, 3)}\n` +
    `FP rate  : ${fmt(s.fpRate, 3)}\n\n` +
    `Global accuracy: ${fmt(gm.accuracy, 3)} (round ${gm.round})\n` +
    `Attack type: ${env.attackType} (${fmt(env.attackLevel, 2)})\n` +
    `Drift level: ${fmt(env.driftLevel, 2)}`;

  document.getElementById("stats-text").textContent = txt;
}

function ensureChart() {
  if (state.chart) return;
  const ctx = document.getElementById("stats-chart");
  state.chart = new Chart(ctx, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        { label: "F1", data: [], tension: 0.25 },
        { label: "Global acc", data: [], tension: 0.25 }
      ]
    },
    options: {
      responsive: true,
      animation: false,
      scales: { y: { suggestedMin: 0, suggestedMax: 1 } }
    }
  });
}

function updateChart(ts) {
  if (!ts || !ts.t || !state.chart) return;

  const labels = ts.t.map((t) => {
    const d = new Date(t);
    return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(
      2,
      "0"
    )}:${String(d.getSeconds()).padStart(2, "0")}`;
  });

  state.chart.data.labels = labels;
  state.chart.data.datasets[0].data = ts.f1 || [];
  state.chart.data.datasets[1].data = ts.globalAccuracy || [];
  state.chart.update();
}

// ---- TABS ----
function setupTabs() {
  const buttons = document.querySelectorAll(".tab-btn");
  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      buttons.forEach((b) => b.classList.toggle("active", b === btn));

      const id = btn.dataset.tab;
      document.querySelectorAll(".tab-panel").forEach((p) => {
        p.classList.toggle("active", p.id === `tab-${id}`);
      });

      if (id === "stats") ensureChart();
    });
  });
}

// ---- WEBSOCKET ----
function connectWS() {
  if (state.ws && (state.ws.readyState === WebSocket.OPEN || state.ws.readyState === WebSocket.CONNECTING)) {
    return;
  }

  const ws = new WebSocket(WS_URL);
  state.ws = ws;

  ws.onopen = () => {
    state.connected = true;
    renderBadges();
  };

  ws.onclose = () => {
    state.connected = false;
    renderBadges();
    setTimeout(connectWS, 1500);
  };

  ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      handleWS(msg);
    } catch (err) {
      console.error("WS parse error", err);
    }
  };
}

function clamp(arr, max) {
  if (arr.length > max) arr.length = max;
}

function handleWS({ type, payload }) {
  if (type === "snapshot") {
    state.devices = payload.devices || [];
    state.environment = payload.environment || state.environment;
    state.stats = payload.stats || state.stats;
    state.globalModel = payload.globalModel || state.globalModel;
    state.alerts = payload.alerts || [];
    state.telemetry = payload.telemetry || [];
    clamp(state.alerts, 120);
    clamp(state.telemetry, 120);
  } else if (type === "device_updated" || type === "device_registered") {
    const d = payload.device;
    const i = state.devices.findIndex((x) => x.id === d.id);
    if (i >= 0) state.devices[i] = d;
    else state.devices.unshift(d);
  } else if (type === "telemetry_event") {
    if (payload.event) {
      state.telemetry.unshift(payload.event);
      clamp(state.telemetry, 120);
    }
  } else if (type === "alert_event") {
    if (payload.alert) {
      state.alerts.unshift(payload.alert);
      clamp(state.alerts, 120);
    }
  } else if (type === "model_update") {
    if (payload.globalModel) state.globalModel = payload.globalModel;
  }

  // Whenever WS data arrives, refresh UI
  renderBadges();
  renderKpiAndEnv();
  renderDevicesTables();
  renderStreams();
  renderStatsText();
}

// ---- POLLING STATS FROM HTTP ----
async function pollStats() {
  try {
    const over = await apiGet("/stats/overview");
    if (over.ok) {
      state.environment = over.environment;
      state.stats = over.stats;
      state.globalModel = over.globalModel;
      renderBadges();
      renderKpiAndEnv();
      renderStatsText();
      renderDevicesTables();
    }

    const ts = await apiGet("/stats/timeseries");
    if (ts.ok) {
      state.timeseries = ts.timeseries;
      ensureChart();
      updateChart(state.timeseries);
    }
  } catch (e) {
    console.error("pollStats error", e);
  }
}

async function refreshDevices() {
  const d = await apiGet("/devices");
  if (d.ok) {
    state.devices = d.devices || [];
    renderDevicesTables();
    renderKpiAndEnv();
    renderBadges();
  }
}

// ---- CONTROLS ----
function setupControls() {
  // simulator
  document.getElementById("btn-sim-start").onclick = async () => {
    await apiPost("/sim/start", { intervalMs: 700 });
    await pollStats();
  };
  document.getElementById("btn-sim-stop").onclick = async () => {
    await apiPost("/sim/stop", {});
    await pollStats();
  };
  document.getElementById("btn-sim-reset").onclick = async () => {
    await apiPost("/sim/reset", {});
    await pollStats();
  };

  // attack
  const attackType = document.getElementById("attack-type");
  const attackLevel = document.getElementById("attack-level");
  const attackLevelVal = document.getElementById("attack-level-val");
  attackLevel.addEventListener("input", () => {
    attackLevelVal.textContent = fmt(attackLevel.value, 2);
  });

  document.getElementById("btn-apply-attack").onclick = async () => {
    await apiPost("/sim/attack", {
      type: attackType.value,
      intensity: Number(attackLevel.value)
    });
    await pollStats();
  };

  // drift
  const driftLevel = document.getElementById("drift-level");
  const driftLevelVal = document.getElementById("drift-level-val");
  driftLevel.addEventListener("input", () => {
    driftLevelVal.textContent = fmt(driftLevel.value, 2);
  });

  document.getElementById("btn-apply-drift").onclick = async () => {
    await apiPost("/sim/drift", { level: Number(driftLevel.value) });
    await pollStats();
  };

  // FL round
  document.getElementById("btn-fl-round").onclick = async () => {
    await apiPost("/fl/round", {});
    await pollStats();
  };

  // refresh devices list
  document.getElementById("btn-refresh-devices").onclick = async () => {
    await refreshDevices();
  };
}

// ---- BOOT ----
async function boot() {
  setupTabs();
  setupControls();
  connectWS();

  await refreshDevices();
  await pollStats();

  renderBadges();
  renderKpiAndEnv();
  renderDevicesTables();
  renderStreams();
  renderStatsText();
  ensureChart();
  if (state.timeseries) updateChart(state.timeseries);

  // keep stats updated
  setInterval(pollStats, 2000);
}

boot();

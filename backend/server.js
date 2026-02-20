// backend/server.js
// Simple backend with simulator + WebSocket + stats
const express = require("express");
const http = require("http");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const WebSocket = require("ws");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: "/ws" });

app.use(cors());
app.use(express.json());

// ---------------- In-memory state ----------------
let devices = [];
let alerts = [];
let telemetry = [];

let environment = {
  simulatorRunning: false,
  attackType: "none",
  attackLevel: 0,
  driftLevel: 0
};

let stats = {
  totalEvents: 0,
  TP: 0,
  FP: 0,
  TN: 0,
  FN: 0,
  precision: 0,
  recall: 0,
  f1: 0,
  fpRate: 0
};

let globalModel = {
  round: 1,
  accuracy: 0.92
};

let timeseries = {
  t: [],
  f1: [],
  globalAccuracy: []
};

let simTimer = null;

// -------------- Helper functions -----------------
function clampList(list, maxLen) {
  if (list.length > maxLen) {
    list.splice(maxLen);
  }
}

function recalcMetrics() {
  const { TP, FP, TN, FN } = stats;
  const total = TP + FP + TN + FN;
  stats.totalEvents = total;

  stats.precision = TP + FP === 0 ? 0 : TP / (TP + FP);
  stats.recall = TP + FN === 0 ? 0 : TP / (TP + FN);
  stats.f1 =
    stats.precision + stats.recall === 0
      ? 0
      : (2 * stats.precision * stats.recall) /
        (stats.precision + stats.recall);
  const negatives = TN + FP;
  stats.fpRate = negatives === 0 ? 0 : FP / negatives;
}

function pushTimeseriesPoint() {
  const now = Date.now();
  timeseries.t.push(now);
  timeseries.f1.push(stats.f1);
  timeseries.globalAccuracy.push(globalModel.accuracy);

  clampList(timeseries.t, 200);
  clampList(timeseries.f1, 200);
  clampList(timeseries.globalAccuracy, 200);
}

function broadcast(type, payload) {
  const msg = JSON.stringify({ type, payload });
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(msg);
    }
  });
}

function broadcastSnapshot() {
  const snapshot = {
    devices,
    environment,
    stats,
    globalModel,
    alerts: alerts.slice(0, 80),
    telemetry: telemetry.slice(0, 80)
  };
  broadcast("snapshot", snapshot);
}

function broadcastSimStatus() {
  broadcast("sim_status", { environment });
}

function broadcastModelUpdate() {
  broadcast("model_update", { globalModel });
}

// -------------- Device + simulator logic ---------------
function seedDevices() {
  if (devices.length > 0) return;
  devices = [
    {
      id: uuidv4(),
      name: "IoT Cam 1",
      model: "1D CNN",
      driftScore: 0,
      localAccuracy: 0.93,
      quarantined: false
    },
    {
      id: uuidv4(),
      name: "Router GW 1",
      model: "GRU",
      driftScore: 0,
      localAccuracy: 0.91,
      quarantined: false
    },
    {
      id: uuidv4(),
      name: "Sensor Node 7",
      model: "Autoencoder",
      driftScore: 0,
      localAccuracy: 0.90,
      quarantined: false
    }
  ];
}

// *** NEW: much more realistic scoring + labels ***
function generateTelemetryTick() {
  if (!environment.simulatorRunning) return;
  if (devices.length === 0) seedDevices();

  // “normal” base traffic
  const basePackets = 200;
  const baseFailed = 1;
  const baseBytes = 10000;

  devices.forEach((dev) => {
    if (dev.quarantined) return;

    const drift = environment.driftLevel || 0;

    // ---- 1. Start from drifted-but-normal behaviour ----
    let packets =
      basePackets +
      (Math.random() - 0.5) * 80 +      // random noise
      drift * 80;                       // slow drift in packet rate

    let failedAuth =
      baseFailed +
      Math.random() * 3 +               // random login failures
      drift * 1.5;                      // drift can slightly increase failures

    let bytesOut =
      baseBytes +
      (Math.random() - 0.5) * 4000 +    // noise
      drift * 4000;                     // drift in traffic volume

    dev.driftScore = drift;

    // ---- 2. Decide the TRUE label (Normal vs Attack) probabilistically ----
    let trueLabel;
    if (environment.attackType === "none") {
      // no attack configured -> very few real attacks (background noise)
      trueLabel = Math.random() < 0.05 ? "Attack" : "Normal";
    } else {
      // attack mode on -> majority are attacks, but not all
      const baseProb = 0.15; // even under attack, some traffic is still normal
      const extra = 0.55 * (environment.attackLevel || 0); // 0..0.495
      const pAttack = Math.min(0.9, baseProb + extra);     // cap at 0.9
      trueLabel = Math.random() < pAttack ? "Attack" : "Normal";
    }

    // ---- 3. Only distort the features if this sample is truly an attack ----
    const atkType = environment.attackType;
    const level = environment.attackLevel || 0;

    if (trueLabel === "Attack" && atkType !== "none") {
      if (atkType === "port_scan") {
        packets += level * 1000 + Math.random() * 200;
      } else if (atkType === "bruteforce") {
        failedAuth += level * 20 + Math.random() * 5;
      } else if (atkType === "ddos") {
        packets += level * 1500 + Math.random() * 300;
        bytesOut += level * 8000 + Math.random() * 3000;
      } else if (atkType === "exfiltration") {
        bytesOut += level * 20000 + Math.random() * 5000;
      } else {
        // generic
        packets += level * 600;
        failedAuth += level * 8;
        bytesOut += level * 8000;
      }
    }

    // ---- 4. Compute anomaly score vs “expected” drifted baseline ----
    const expectedPackets = basePackets + drift * 80;
    const expectedFailed = baseFailed + drift * 1.5;
    const expectedBytes = baseBytes + drift * 4000;

    let score = 0;
    score += Math.abs(packets - expectedPackets) / 400;   // packets sensitivity
    score += Math.abs(failedAuth - expectedFailed) / 10;  // auth failures
    score += Math.abs(bytesOut - expectedBytes) / 12000;  // bytes out

    // add some random noise so we never get “perfect” behaviour
    score += (Math.random() - 0.5) * 0.15;
    if (score < 0) score = 0;
    if (score > 1) score = 1;

    // ---- 5. Dynamic threshold: slightly easier when drift is high ----
    const thresholdBase = 0.55;
    const threshold = thresholdBase - 0.1 * drift; // at drift=0.9 -> ~0.46

    const isAttack = score > threshold;
    const predicted = isAttack ? "Attack" : "Normal";

    // ---- 6. Update confusion matrix ----
    if (trueLabel === "Attack" && predicted === "Attack") stats.TP++;
    else if (trueLabel === "Attack" && predicted === "Normal") stats.FN++;
    else if (trueLabel === "Normal" && predicted === "Attack") stats.FP++;
    else if (trueLabel === "Normal" && predicted === "Normal") stats.TN++;

    recalcMetrics();

    // ---- 7. Slightly nudge local model accuracy over time ----
    dev.localAccuracy = Math.max(
      0.7,
      Math.min(0.99, dev.localAccuracy + (Math.random() - 0.5) * 0.01)
    );

    // ---- 8. Record telemetry & alerts ----
    const features = {
      packetsPerSec: Math.max(0, Math.round(packets)),
      failedAuth: Math.max(0, Math.round(failedAuth)),
      bytesOut: Math.max(0, Math.round(bytesOut))
    };

    const event = {
      id: uuidv4(),
      deviceId: dev.id,
      deviceName: dev.name,
      ts: new Date().toISOString(),
      features,
      score,
      threshold,
      predicted,
      trueLabel
    };
    telemetry.unshift(event);
    clampList(telemetry, 200);
    broadcast("telemetry_event", { event });

    if (isAttack) {
      const alert = {
        id: uuidv4(),
        deviceId: dev.id,
        deviceName: dev.name,
        ts: event.ts,
        severity: score > threshold + 0.25 ? "high" : "medium",
        type: "anomaly",
        score,
        driftScore: dev.driftScore,
        message: `Anomalous behaviour: packets=${features.packetsPerSec}, failedAuth=${features.failedAuth}, bytesOut=${features.bytesOut}`
      };
      alerts.unshift(alert);
      clampList(alerts, 200);
      broadcast("alert_event", { alert });
    }
  });

  // ---- 9. Update global model accuracy a bit ----
  const targetAcc = 0.90 + (environment.attackType === "none" ? 0.05 : -0.05);
  globalModel.accuracy += (targetAcc - globalModel.accuracy) * 0.02;
  globalModel.accuracy = Math.min(0.99, Math.max(0.7, globalModel.accuracy));

  pushTimeseriesPoint();
  broadcastModelUpdate();
}

function startSimulator(intervalMs) {
  if (simTimer) return;
  seedDevices();
  environment.simulatorRunning = true;
  simTimer = setInterval(generateTelemetryTick, intervalMs || 700);
  broadcastSimStatus();
  broadcastSnapshot();
}

function stopSimulator() {
  if (simTimer) {
    clearInterval(simTimer);
    simTimer = null;
  }
  environment.simulatorRunning = false;
  broadcastSimStatus();
}

function resetSimulator() {
  stopSimulator();
  devices = [];
  alerts = [];
  telemetry = [];
  environment = {
    simulatorRunning: false,
    attackType: "none",
    attackLevel: 0,
    driftLevel: 0
  };
  stats = {
    totalEvents: 0,
    TP: 0,
    FP: 0,
    TN: 0,
    FN: 0,
    precision: 0,
    recall: 0,
    f1: 0,
    fpRate: 0
  };
  globalModel = { round: 1, accuracy: 0.92 };
  timeseries = { t: [], f1: [], globalAccuracy: [] };
  broadcastSnapshot();
}

// -------------- HTTP API -----------------
app.get("/api/health", (req, res) => {
  res.json({ ok: true, status: "backend-alive" });
});

app.get("/api/devices", (req, res) => {
  res.json({ ok: true, devices });
});

app.post("/api/devices/:id/quarantine", (req, res) => {
  const { id } = req.params;
  devices = devices.map((d) =>
    d.id === id ? { ...d, quarantined: true } : d
  );
  const dev = devices.find((d) => d.id === id);
  if (dev) broadcast("device_updated", { device: dev });
  res.json({ ok: true });
});

app.post("/api/devices/:id/unquarantine", (req, res) => {
  const { id } = req.params;
  devices = devices.map((d) =>
    d.id === id ? { ...d, quarantined: false } : d
  );
  const dev = devices.find((d) => d.id === id);
  if (dev) broadcast("device_updated", { device: dev });
  res.json({ ok: true });
});

app.get("/api/stats/overview", (req, res) => {
  res.json({ ok: true, environment, stats, globalModel });
});

app.get("/api/stats/timeseries", (req, res) => {
  res.json({ ok: true, timeseries });
});

app.post("/api/sim/start", (req, res) => {
  const { intervalMs } = req.body || {};
  startSimulator(intervalMs || 700);
  res.json({ ok: true, environment });
});

app.post("/api/sim/stop", (req, res) => {
  stopSimulator();
  res.json({ ok: true, environment });
});

app.post("/api/sim/reset", (req, res) => {
  resetSimulator();
  res.json({ ok: true, environment });
});

app.post("/api/sim/attack", (req, res) => {
  const { type, intensity } = req.body || {};
  environment.attackType = type || "none";
  environment.attackLevel = Number(intensity) || 0;
  broadcastSimStatus();
  res.json({ ok: true, environment });
});

app.post("/api/sim/drift", (req, res) => {
  const { level } = req.body || {};
  environment.driftLevel = Number(level) || 0;
  broadcastSimStatus();
  res.json({ ok: true, environment });
});

app.post("/api/fl/round", (req, res) => {
  // simple: increase round and nudge accuracy
  globalModel.round += 1;
  globalModel.accuracy += (Math.random() - 0.5) * 0.01;
  globalModel.accuracy = Math.min(0.99, Math.max(0.7, globalModel.accuracy));
  pushTimeseriesPoint();
  broadcastModelUpdate();
  res.json({ ok: true, globalModel });
});

// -------------- WebSocket -----------------
wss.on("connection", (ws) => {
  console.log("Client connected to WS");
  const snapshot = {
    devices,
    environment,
    stats,
    globalModel,
    alerts: alerts.slice(0, 80),
    telemetry: telemetry.slice(0, 80)
  };
  ws.send(JSON.stringify({ type: "snapshot", payload: snapshot }));

  ws.on("close", () => {
    console.log("Client disconnected from WS");
  });
});

// -------------- Start server -----------------
const PORT = process.env.PORT || 9002;
server.listen(PORT, () => {
  console.log(`Backend listening on http://localhost:${PORT}`);
});

// simulator.js
const { store, now, addTelemetry, addAlert, snapshotDevice, pushTimeseriesSnapshot } = require("./store");
const { anomalyScore, computeDriftScore, updateMetrics, clamp, maybeCreateAlert } = require("./detector");

function randn() {
  const u = 1 - Math.random();
  const v = 1 - Math.random();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}

function pickOne(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// benign telemetry (drift shifts means)
function benignTelemetry(driftLevel) {
  const driftBoost = 1 + driftLevel * 0.8;

  const packets = 200 * driftBoost + randn() * (40 + driftLevel * 25);
  const failed = Math.max(0, 0.5 + randn() * (0.7 + driftLevel * 0.4));
  const bytesOut = Math.max(0, 25000 * driftBoost + randn() * (8000 + driftLevel * 6000));

  return {
    packetsPerSec: Math.round(clamp(packets, 20, 1400)),
    failedAuth: Number(clamp(failed, 0, 80).toFixed(1)),
    bytesOut: Math.round(clamp(bytesOut, 1000, 400000))
  };
}

function attackTelemetry(type, intensity, driftLevel) {
  const base = benignTelemetry(driftLevel);
  const k = 1 + intensity * 2.2;

  if (type === "port_scan") {
    return {
      ...base,
      packetsPerSec: Math.round(clamp(base.packetsPerSec * (1.5 * k), 80, 3500)),
      failedAuth: Number(clamp(base.failedAuth + randn() * 0.6, 0, 10).toFixed(1))
    };
  }

  if (type === "bruteforce") {
    return {
      ...base,
      failedAuth: Number(clamp(base.failedAuth + 6 * k + Math.abs(randn()) * 3, 0, 120).toFixed(1)),
      packetsPerSec: Math.round(clamp(base.packetsPerSec * (1.15 * k), 40, 2500))
    };
  }

  if (type === "ddos") {
    return {
      ...base,
      packetsPerSec: Math.round(clamp(base.packetsPerSec + 900 * k + Math.abs(randn()) * 600, 250, 8000)),
      bytesOut: Math.round(clamp(base.bytesOut + 70000 * k + Math.abs(randn()) * 50000, 8000, 1200000))
    };
  }

  if (type === "exfiltration") {
    return {
      ...base,
      bytesOut: Math.round(clamp(base.bytesOut + 150000 * k + Math.abs(randn()) * 80000, 15000, 1500000)),
      packetsPerSec: Math.round(clamp(base.packetsPerSec * (1.2 * k), 50, 2600))
    };
  }

  // generic
  return {
    ...base,
    packetsPerSec: Math.round(clamp(base.packetsPerSec * (1.35 * k), 60, 3500)),
    failedAuth: Number(clamp(base.failedAuth + 2 * k + Math.abs(randn()), 0, 100).toFixed(1))
  };
}

function processTelemetry({ device, features, trueLabel }) {
  if (!device || device.quarantined) return { evt: null, alert: null };

  const env = store.environment;
  const ts = now();

  const score = anomalyScore(features);

  // threshold increases slightly under drift (uncertainty)
  const threshold = clamp(0.55 + env.driftLevel * 0.15, 0.45, 0.85);
  const predictedAttack = score > threshold;

  const evt = {
    id: Math.random().toString(16).slice(2),
    ts,
    deviceId: device.id,
    deviceName: device.name,
    features,
    trueLabel: trueLabel || "Unknown",
    predicted: predictedAttack ? "Attack" : "Normal",
    score: Number(score.toFixed(3)),
    threshold: Number(threshold.toFixed(3))
  };

  // update device window
  device.window.push(evt);
  if (device.window.length > device.maxWindow) device.window.shift();

  // drift score
  const driftScore = computeDriftScore(device);
  device.driftScore = driftScore;

  // local accuracy estimate
  device.localAccuracy = clamp(
    device.baseAccuracy * (1 - env.attackLevel * 0.15 - driftScore * 0.22),
    0.4,
    0.99
  );

  device.lastSeen = ts;

  // update global stats
  store.stats.totalEvents += 1;
  updateMetrics({ trueAttack: (trueLabel === "Attack"), predictedAttack });

  addTelemetry(evt);

  // alerts
  const alertObj = maybeCreateAlert({ device, score, driftScore, predictedAttack, ts });
  if (alertObj) addAlert(alertObj);

  // snapshot timeseries every 10 events
  if (store.stats.totalEvents % 10 === 0) pushTimeseriesSnapshot();

  return { evt, alert: alertObj, device: snapshotDevice(device) };
}

// ---- simulator loop ----
let timer = null;

function startSimulator({ intervalMs = 800 } = {}, onOut) {
  if (timer) return;

  store.environment.simulatorRunning = true;

  timer = setInterval(() => {
    const deviceIds = Array.from(store.devices.keys());
    if (deviceIds.length === 0) return;

    const env = store.environment;

    // choose 1 device, or multiple for ddos
    const count = env.attackType === "ddos" ? Math.min(3, deviceIds.length) : 1;
    const selected = [];
    while (selected.length < count) {
      const id = pickOne(deviceIds);
      if (!selected.includes(id)) selected.push(id);
    }

    for (const id of selected) {
      const device = store.devices.get(id);
      if (!device || device.quarantined) continue;

      // probability attack
      const pAttack = clamp(0.03 + env.attackLevel * 0.55 + env.driftLevel * 0.15, 0, 0.95);
      const isAttack = env.attackType !== "none" && Math.random() < pAttack;

      const features = isAttack
        ? attackTelemetry(env.attackType, env.attackLevel, env.driftLevel)
        : benignTelemetry(env.driftLevel);

      const out = processTelemetry({
        device,
        features,
        trueLabel: isAttack ? "Attack" : "Normal"
      });

      if (onOut && out && out.evt) onOut(out);
    }
  }, intervalMs);
}

function stopSimulator() {
  if (!timer) return;
  clearInterval(timer);
  timer = null;
  store.environment.simulatorRunning = false;
}

module.exports = {
  startSimulator,
  stopSimulator,
  processTelemetry
};

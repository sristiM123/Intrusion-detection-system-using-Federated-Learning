// store.js
const { randomUUID } = require("crypto");

function now() {
  return new Date().toISOString();
}

const store = {
  devices: new Map(), // id -> device
  telemetry: [],      // newest first
  alerts: [],         // newest first

  environment: {
    simulatorRunning: false,
    attackLevel: 0,         // 0..1
    driftLevel: 0,          // 0..1
    attackType: "none"      // none|port_scan|bruteforce|ddos|exfiltration|generic
  },

  globalModel: {
    round: 1,
    accuracy: 0.92,
    w: Array.from({ length: 20 }, () => (Math.random() - 0.5) * 0.1)
  },

  stats: {
    totalEvents: 0,
    TP: 0, FP: 0, TN: 0, FN: 0,
    precision: 0,
    recall: 0,
    f1: 0,
    fpRate: 0,

    timeseries: {
      t: [],
      f1: [],
      fpRate: [],
      globalAccuracy: [],
      attackLevel: [],
      driftLevel: []
    }
  }
};

function createDevice({ name, model, dataSize }) {
  const id = randomUUID();
  const device = {
    id,
    name: name || `IoT Device ${store.devices.size + 1}`,
    model: model || "Lightweight Model",
    dataSize: Number.isFinite(dataSize) ? dataSize : 2000,

    quarantined: false,
    lastSeen: now(),

    // local model vector (demo FL)
    localW: Array.from({ length: 20 }, () => (Math.random() - 0.5) * 0.1),

    // drift tracking
    window: [],
    maxWindow: 200,
    baseline: null,
    driftScore: 0.05,

    // quality estimate for FL demo
    baseAccuracy: 0.92,
    localAccuracy: 0.92
  };

  store.devices.set(id, device);
  return device;
}

function listDevices() {
  return Array.from(store.devices.values()).map(snapshotDevice);
}

function snapshotDevice(d) {
  return {
    id: d.id,
    name: d.name,
    model: d.model,
    dataSize: d.dataSize,
    quarantined: d.quarantined,
    lastSeen: d.lastSeen,
    driftScore: Number((d.driftScore ?? 0).toFixed(3)),
    localAccuracy: Number((d.localAccuracy ?? d.baseAccuracy).toFixed(3))
  };
}

function addTelemetry(evt) {
  store.telemetry.unshift(evt);
  if (store.telemetry.length > 600) store.telemetry.pop();
}

function addAlert(alert) {
  store.alerts.unshift(alert);
  if (store.alerts.length > 400) store.alerts.pop();
}

function pushTimeseriesSnapshot() {
  const s = store.stats;
  const env = store.environment;
  const gm = store.globalModel;

  s.timeseries.t.push(Date.now());
  s.timeseries.f1.push(s.f1);
  s.timeseries.fpRate.push(s.fpRate);
  s.timeseries.globalAccuracy.push(gm.accuracy);
  s.timeseries.attackLevel.push(env.attackLevel);
  s.timeseries.driftLevel.push(env.driftLevel);

  const max = 250;
  Object.values(s.timeseries).forEach((arr) => {
    if (arr.length > max) arr.shift();
  });
}

module.exports = {
  store,
  now,
  createDevice,
  listDevices,
  snapshotDevice,
  addTelemetry,
  addAlert,
  pushTimeseriesSnapshot
};

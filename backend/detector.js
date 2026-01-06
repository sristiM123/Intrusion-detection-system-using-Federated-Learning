// detector.js
const crypto = require("crypto");
const { store } = require("./store");

// Benign baseline (tunable)
const BENIGN = {
  packetsMean: 200,
  packetsStd: 40,
  failedMean: 0.5,
  failedStd: 0.7,
  bytesOutMean: 25000,
  bytesOutStd: 8000
};

function clamp(x, lo, hi) {
  return Math.max(lo, Math.min(hi, x));
}

function z(x, mean, std) {
  return (x - mean) / (std || 1e-6);
}

// 0..1 anomaly score
function anomalyScore(features) {
  const zp = z(features.packetsPerSec, BENIGN.packetsMean, BENIGN.packetsStd);
  const zf = z(features.failedAuth, BENIGN.failedMean, BENIGN.failedStd);
  const zb = z(features.bytesOut, BENIGN.bytesOutMean, BENIGN.bytesOutStd);
  const dist = Math.sqrt(zp * zp + zf * zf + zb * zb);
  return clamp(dist / 4.0, 0, 1);
}

function mean(arr) {
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function std(arr) {
  const m = mean(arr);
  const v = arr.reduce((a, b) => a + (b - m) ** 2, 0) / arr.length;
  return Math.sqrt(v);
}

// drift score 0..1 by comparing recent window mean vs baseline mean
function computeDriftScore(device) {
  if (!device.window || device.window.length < 30) return device.driftScore ?? 0.05;

  const pk = device.window.map((e) => e.features.packetsPerSec);
  const fa = device.window.map((e) => e.features.failedAuth);
  const bo = device.window.map((e) => e.features.bytesOut);

  const recent = {
    pkMean: mean(pk), pkStd: std(pk) || 1,
    faMean: mean(fa), faStd: std(fa) || 1,
    boMean: mean(bo), boStd: std(bo) || 1
  };

  // baseline set once after some stable data
  if (!device.baseline && device.window.length >= 60) {
    device.baseline = recent;
  }
  if (!device.baseline) return device.driftScore ?? 0.05;

  const dp = Math.abs(recent.pkMean - device.baseline.pkMean) / device.baseline.pkStd;
  const df = Math.abs(recent.faMean - device.baseline.faMean) / device.baseline.faStd;
  const db = Math.abs(recent.boMean - device.baseline.boMean) / device.baseline.boStd;

  const d = (dp + df + db) / 3;
  return clamp(d / 3.0, 0, 1);
}

// metrics update
function updateMetrics({ trueAttack, predictedAttack }) {
  const s = store.stats;

  if (trueAttack && predictedAttack) s.TP++;
  else if (!trueAttack && predictedAttack) s.FP++;
  else if (!trueAttack && !predictedAttack) s.TN++;
  else if (trueAttack && !predictedAttack) s.FN++;

  const TP = s.TP, FP = s.FP, TN = s.TN, FN = s.FN;

  const precision = TP + FP === 0 ? 0 : TP / (TP + FP);
  const recall = TP + FN === 0 ? 0 : TP / (TP + FN);
  const f1 = (precision + recall) === 0 ? 0 : (2 * precision * recall) / (precision + recall);

  const totalNormal = FP + TN;
  const fpRate = totalNormal === 0 ? 0 : FP / totalNormal;

  s.precision = precision;
  s.recall = recall;
  s.f1 = f1;
  s.fpRate = fpRate;
}

function id8() {
  return crypto.randomBytes(8).toString("hex");
}

function severityFrom(score, drift, predictedAttack) {
  if (predictedAttack && score >= 0.80) return "high";
  if (predictedAttack && score >= 0.60) return "medium";
  if (drift >= 0.55) return "medium";
  return "low";
}

function maybeCreateAlert({ device, score, driftScore, predictedAttack, ts }) {
  // create alerts for anomalies OR high drift
  const isDriftAlert = driftScore >= 0.55;
  const isAnomAlert = predictedAttack;

  if (!isDriftAlert && !isAnomAlert) return null;

  const alert = {
    id: id8(),
    ts,
    deviceId: device.id,
    deviceName: device.name,
    type: isAnomAlert ? "anomaly" : "drift",
    severity: severityFrom(score, driftScore, predictedAttack),
    message: isAnomAlert
      ? `Anomaly detected (score=${score.toFixed(2)} > threshold).`
      : `Concept drift detected (driftScore=${driftScore.toFixed(2)}).`,
    score: Number(score.toFixed(3)),
    driftScore: Number(driftScore.toFixed(3)),
    quarantined: device.quarantined
  };

  return alert;
}

module.exports = {
  anomalyScore,
  computeDriftScore,
  updateMetrics,
  maybeCreateAlert,
  clamp
};

export interface TrafficWindow {
  index: number;
  timeLabel: string;
  lstmRisk: number; // 0.0 - 1.0
  lrRisk: number;   // 0.0 - 1.0
  label: string;    // 'BENIGN' | 'SSH-Patator' | 'FTP-Patator'
  features: {
    name: string;
    value: number;
    shap: number;   // positive = increases risk, negative = decreases risk
    unit?: string;
  }[];
  synFlags: number;
  flowPacketsSec: number;
  flowBytesSec: number;
  flowDurationMs: number;
  packetLengthMean: number;
}

// 60 consecutive windows representing Tuesday Working Hours (Benign -> Patator buildup -> Attack -> Cool down -> FTP Patator)
export const SAMPLE_WINDOWS: TrafficWindow[] = Array.from({ length: 60 }, (_, i) => {
  let label = "BENIGN";
  let baseRisk = 0.08 + Math.sin(i / 4) * 0.05;
  let lrBaseRisk = 0.12 + Math.sin(i / 4) * 0.04;
  let syn = 0 + Math.floor(Math.random() * 2);
  let pps = 45 + Math.random() * 30;
  let bps = 3200 + Math.random() * 1500;
  let duration = 2100 + Math.random() * 800;
  let pktLen = 54 + Math.random() * 15;

  if (i >= 15 && i <= 21) {
    // Pre-attack reconnaissance / early buildup
    label = "Pre-Attack Buildup";
    baseRisk = 0.35 + (i - 15) * 0.06;
    lrBaseRisk = 0.28 + (i - 15) * 0.04;
    syn = 4 + (i - 15) * 2;
    pps = 180 + (i - 15) * 60;
    bps = 14500 + (i - 15) * 4000;
    duration = 4500 + (i - 15) * 1200;
    pktLen = 68 + Math.random() * 10;
  } else if (i >= 22 && i <= 34) {
    // Active SSH-Patator Brute-Force attack burst
    label = "SSH-Patator (Brute Force)";
    baseRisk = 0.82 + Math.random() * 0.12;
    lrBaseRisk = 0.68 + Math.random() * 0.14;
    syn = 18 + Math.floor(Math.random() * 8);
    pps = 740 + Math.random() * 180;
    bps = 68000 + Math.random() * 15000;
    duration = 18500 + Math.random() * 4000;
    pktLen = 82 + Math.random() * 8;
  } else if (i >= 35 && i <= 40) {
    // Post-attack mitigation
    label = "Transient Anomaly";
    baseRisk = 0.42 - (i - 35) * 0.06;
    lrBaseRisk = 0.35 - (i - 35) * 0.05;
    syn = 3 + Math.floor(Math.random() * 2);
    pps = 110 + Math.random() * 40;
    bps = 8500 + Math.random() * 2000;
    duration = 3200 + Math.random() * 1000;
    pktLen = 60 + Math.random() * 10;
  } else if (i >= 45 && i <= 54) {
    // Second wave: FTP-Patator authentication sweep
    label = "FTP-Patator (Credential Access)";
    baseRisk = 0.88 + Math.random() * 0.08;
    lrBaseRisk = 0.72 + Math.random() * 0.11;
    syn = 14 + Math.floor(Math.random() * 6);
    pps = 590 + Math.random() * 140;
    bps = 92000 + Math.random() * 22000;
    duration = 24000 + Math.random() * 6000;
    pktLen = 142 + Math.random() * 25;
  }

  const cappedRisk = Math.min(0.99, Math.max(0.02, baseRisk));
  const cappedLrRisk = Math.min(0.95, Math.max(0.04, lrBaseRisk));

  // Generate realistic SHAP attributions based on the features
  const shapSyn = (syn - 1) * 0.042;
  const shapPps = ((pps - 50) / 100) * 0.065;
  const shapBps = ((bps - 4000) / 10000) * 0.048;
  const shapDur = ((duration - 2500) / 5000) * 0.035;
  const shapLen = ((pktLen - 55) / 30) * 0.028;
  const shapIAT = (cappedRisk > 0.5 ? 0.045 : -0.032);

  const features = [
    { name: "SYN Flag Count", value: syn, shap: shapSyn, unit: "flags" },
    { name: "Flow Packets/s", value: Math.round(pps), shap: shapPps, unit: "pkts/s" },
    { name: "Flow Bytes/s", value: Math.round(bps), shap: shapBps, unit: "bytes/s" },
    { name: "Flow Duration", value: Math.round(duration), shap: shapDur, unit: "ms" },
    { name: "Packet Length Mean", value: Math.round(pktLen * 10) / 10, shap: shapLen, unit: "bytes" },
    { name: "Flow IAT Mean", value: Math.round(250 / (pps || 1)), shap: shapIAT, unit: "ms" },
  ];

  return {
    index: i,
    timeLabel: `10:${String(Math.floor(i / 2) + 15).padStart(2, "0")}:${(i % 2) * 30 === 0 ? "00" : "30"}`,
    lstmRisk: cappedRisk,
    lrRisk: cappedLrRisk,
    label,
    features,
    synFlags: syn,
    flowPacketsSec: Math.round(pps),
    flowBytesSec: Math.round(bps),
    flowDurationMs: Math.round(duration),
    packetLengthMean: Math.round(pktLen * 10) / 10,
  };
});

export const MODEL_METRICS = {
  lr: {
    accuracy: 0.8842,
    precision: 0.8215,
    recall: 0.7934,
    f1: 0.8072,
    roc_auc: 0.8912,
    cm: [
      [1420, 112],
      [104, 398],
    ],
  },
  lstm: {
    accuracy: 0.9528,
    precision: 0.9412,
    recall: 0.9285,
    f1: 0.9348,
    roc_auc: 0.9784,
    cm: [
      [1498, 34],
      [36, 466],
    ],
  },
};

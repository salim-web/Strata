# 🛡️ STRATA: Passive Network Threat Intelligence Enclave

**STRATA v2.0** is an autonomous, read-only **Passive Network Threat Intelligence Enclave** engineered under strict **unidirectional data diode / passive optical mirroring** constraints. 

STRATA operates exclusively as a one-directional streaming consumer of passive network metadata (NetFlow/IPFIX, PCAP/pcap-ng metadata, or streaming flow records). In accordance with hardware air-gap and optical tap security standards, **all inline blocking, reverse-proxy interception, return-path actions, TCP resets, and firewall pushbacks are strictly prohibited and architecturally eliminated**. Furthermore, payload decryption is strictly forbidden: TLS/QUIC traffic is analyzed non-intrusively via metadata (JA3/JA4 fingerprints, cipher suites, and packet length/timing sequence arrays).

---

## 🏗️ Unidirectional Data Diode Architecture

```
                                  UNIDIRECTIONAL OPTICAL TAP
                                   (ZERO RETURN PATH / RX-ONLY)
                                             │
      ┌──────────────────────────────────────┼──────────────────────────────────────┐
      │ Core Network Optical Tap             │ Physical Data Diode (Transmit Fiber Severed)
      │ NetFlow / IPFIX / Mirror Telemetry   ▼
┌─────┴─────────────────────────────────────────────────────────────────────────────┴─────┐
│                          STRATA PASSIVE INTELLIGENCE ENCLAVE                             │
│                                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ 1. PASSIVE INGEST & DUAL-QUEUE INGESTION (500 – 5,000+ flows/sec)                   │  │
│  │    • Standard FIFO Streaming Queue for continuous ambient baseline traffic          │  │
│  │    • Priority Deque for immediate, real-time Threat Burst Injection scoring         │  │
│  │    • Rolling 10s Sliding-Window Feature Pipeline (Incremental, bounded memory)      │  │
│  └──────────────────────────────────────┬──────────────────────────────────────────────┘  │
│                                         ▼                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ 2. SPECIALIZED ML INFERENCE ENSEMBLE (<0.05ms SLA Latency)                          │  │
│  │    • HistGradientBoosting multi-class classifier with calibrated probabilities      │  │
│  │    • IsolationForest unsupervised baseline for zero-day anomaly scoring             │  │
│  │    • Physical Protocol Domain Guards (Zero cross-protocol false positives)          │  │
│  │    • Standardized Alert Schema Output adhering strictly to diode constraints        │  │
│  └──────────────────────────────────────┬──────────────────────────────────────────────┘  │
│                                         ▼                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ 3. COGNITIVE THREAT INTELLIGENCE (Google Gemini 2.5 Flash)                          │  │
│  │    • Automated MITRE ATT&CK Mapping & Threat Actor Hypotheses                       │  │
│  │    • Passive Evidence Breakdown & Non-Intrusive SOC Monitoring Actions              │  │
│  │    • Deterministic air-gapped local intelligence fallback when offline              │  │
│  └──────────────────────────────────────┬──────────────────────────────────────────────┘  │
│                                         ▼                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ 4. AIR-GAPPED DATA DIODE INTELLIGENCE CONSOLE (Next.js 14 & Tailwind)               │  │
│  │    • Diode Read-Only Status & Zero Return Path Badge                                │  │
│  │    • Telemetry KPIs: Sustained Throughput (Flows/s & Mbps), Ingested Packets, SLA   │  │
│  │    • Live Multi-Threat Radar (6-Vector Confidence, Active Count & Evidence Gauges)  │  │
│  │    • Real-Time Streaming Incident Feed & Gemini AI Analyst Card                     │  │
│  │    • On-Demand Threat Burst Injection Control (Instantaneous 6-vector scoring)      │  │
│  └─────────────────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 6 Threat Detection Vectors

STRATA inspects passive network telemetry across 6 dedicated threat categories without decrypting payloads:

| Threat Vector | Passive Metadata Analyzed | Baseline Normal | Anomaly Threshold & Invariants |
| :--- | :--- | :--- | :--- |
| **1. Volumetric / Protocol DDoS** | Rolling flow velocity, SYN-to-ACK ratio, Source IP Shannon entropy | Flow rate < 500/s, SYN/ACK ~1.0, Entropy ~2-4 | Flow rate > 1,500/s, SYN/ACK > 4.0x, Entropy > 6.0. Strictly requires `ack_count == 0` (SYN flood). |
| **2. Botnet C2 Beaconing** | Inter-arrival time (IAT) variance, autocorrelation peak / FFT periodicity | IAT variance > 1.0s, Random jitter | IAT variance < 0.05s, Mean IAT $\ge 0.05\text{s}$, Periodicity > 65% with $\ge 3$ flow samples. |
| **3. DNS Tunnelling & DGA** | Query character Shannon entropy, bigram distribution, label length, TXT/NULL record types | Entropy < 3.2, Vowels 35-45%, Label < 20 chars | Entropy > 3.8, Vowels < 20%, or TXT/NULL queries with label length > 20 chars. |
| **4. Encrypted Traffic (Zero Decryption)** | JA3/JA4 client/server hash matching, SNI heuristics, first-N packet size sequences | Known browser/OS fingerprints, Valid SNI | Matches threat intelligence DB (AsyncRAT, Cobalt Strike, etc.), Direct-IP TLS or fixed-size beacon. |
| **5. Reconnaissance / Scanning** | 10-second rolling fan-out cardinality (unique destination IPs and ports per source IP) | Fan-out < 5 targets/10s | Fan-out > 8 targets/10s with `syn_only_ratio >= 0.65` and `ack_count == 0` (SYN probes). |
| **6. Data Exfiltration** | Directional byte asymmetry ($B_{out} / (B_{in} + 1)$), packet asymmetry | Outbound/Inbound ratio < 1.0 (Downloads > Uploads) | Outbound/Inbound ratio > 4.0x with > 100 KB transferred. |

---

## ⚡ Real-Time Threat Burst Injection

Operators can inject synthetic traffic bursts for any of the 6 threat vectors directly from the console header to observe real-time ML scoring:

1. **Dedicated Ingestion Priority Queue**: Injected burst packets bypass ambient queuing via `IngestReceiver.priority_queue` to guarantee immediate next-tick processing.
2. **Sliding-Window State Priming**: The sliding window aggregator primes historical state (e.g. periodic beacon intervals or port scan targets) so that burst flows immediately trigger high-confidence detections.
3. **Feed Dominance**: Within 150ms of injection, the injected threat vector achieves $\ge 98\%$ feed dominance in the Streaming Incident Feed and increments the Multi-Threat Radar counter.

---

## 📋 Standardized Alert Schema Contract

Every detection emitted by the ML ensemble adheres to the following strict contract:

```json
{
  "timestamp": "2026-09-10T12:00:00Z",
  "flow_id": "10.0.2.14:5312->8.8.8.8:53:UDP",
  "threat_class": "DGA_DNS_TUNNEL",
  "confidence_score": 0.96,
  "severity": "CRITICAL",
  "evidence": {
    "dns_query": "x92v7m4b1q8z3k5w.exfil-intel.cc",
    "query_char_entropy": "4.82",
    "vowel_ratio": "12.5%",
    "max_label_length": "32",
    "record_type": "TXT",
    "baseline_threshold": "Entropy > 3.80 OR (TXT/NULL AND Length > 20)"
  }
}
```

---

## 🚀 Quick Start Guide

### 1. Environment Setup
```bash
# Clone the repository
git clone https://github.com/salim-web/Strata.git
cd Strata

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
```

### 2. Configure Environment Variables
```bash
cp .env.example .env
# Add your GEMINI_API_KEY in .env for cognitive analyst features
```

### 3. Start the STRATA Backend Enclave
```bash
# In project root (with venv active):
python run_backend.py
# Or with uvicorn directly:
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
*The FastAPI Diode Enclave will start on `http://127.0.0.1:8000` with OpenAPI documentation at `http://127.0.0.1:8000/docs`.*

### 4. Start the Air-Gapped Intelligence Console (Frontend)
```bash
cd frontend
npm install
npm run dev
```
*Access the Next.js Cyber-Analyst Console on `http://localhost:3000`.*

### 5. Retrain or Verify the ML Models
```bash
# Retrain calibrated HistGradientBoosting model & IsolationForest baseline:
python backend/ml_engine/train_threat_models.py
```
*Full ML documentation, confusion matrices, and benchmark numbers are available in [`ML_MODEL_DOCUMENTATION.md`](ML_MODEL_DOCUMENTATION.md).*

### 6. Replay High-Throughput Passive Telemetry Stream
```bash
# Replay 3,000 flows/sec across all 6 threat vectors:
python scripts/stream_emitter.py --target-rate 3000

# Custom rate and duration:
python scripts/stream_emitter.py --target-rate 5000 --duration 60
```

### 7. Run Automated Test Suite
```bash
python -m pytest backend/tests/ -v
```

---

## 🔒 Diode Security & Privacy Guarantees

1. **Zero Return Path**: The system never transmits packets onto the monitored segment. Physical air-gap emulated with transmit fiber severed.
2. **Zero Active Mitigation**: No IP bans, no firewall rule pushing, no TCP resets, no HTTP 403/429 rejection payloads.
3. **Payload Privacy**: Encrypted traffic (TLS/QUIC) is never decrypted. All intelligence is derived exclusively from metadata.
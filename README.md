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
│  │ 4. ENTERPRISE MULTI-PAGE AIR-GAPPED SAAS CONSOLE (Next.js 14 App Router)            │  │
│  │    • Floating "Island Dock" Vertical Navigation with Active Route Detection         │  │
│  │    • Soft-Neomorphic SaaS Design with 100% Light & Dark Mode Parity                 │  │
│  │    • 5 Dedicated App Router Workspaces: Overview, Radar, Incidents, AI, Controls    │  │
│  │    • Real-Time Telemetry & Alerts Synced via Global React Context Provider          │  │
│  └─────────────────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🖥️ Modular Multi-Page Architecture & Floating Island Dock

The STRATA frontend is architected as an enterprise-grade, multi-page Next.js 14 application following a **soft-neomorphic SaaS theme** with full **Light Mode** and **Dark Mode** parity:

### 🏝️ The Floating "Island Dock" (`IslandDock.tsx`)
A persistent, detached vertical navigation island positioned on the left viewport margin:
- **Active Route Highlighting**: Dynamic detection via Next.js `usePathname()` with saturated indigo capsules and micro-indicators.
- **Sun/Moon Theme Switch Pill**: Smooth, animated toggle with instant transitions and `localStorage` state persistence.
- **Live SLA Pipeline Gauge**: Real-time bounded latency monitor (`SLA: X.Xms < 50ms`) with pulsing health indicator.
- **Quick Burst Trigger**: One-click threat burst injection directly from the global navigation dock.

### 🗂️ 5 Dedicated App Router Routes

| Route | Workspace | Purpose & Core Capabilities |
| :--- | :--- | :--- |
| **`/`** | **Executive Overview** | High-level SOC situational awareness: Enclave KPIs (Ingest rate, Bandwidth, Packets, SLA Latency), multi-threat posture overview, recent anomaly snapshot table, and quick workbench jump cards. |
| **`/radar`** | **6-Vector Threat Radar** | Deep-dive vector analysis across DDoS, C2 Beaconing, DNS Tunnelling, Encrypted Malware (JA3/JA4), Recon Scanning, and Data Exfiltration with baseline vs. anomaly mathematical matrices. |
| **`/incidents`** | **Incident Feed & Forensics** | Full-width real-time incident table: Multi-parameter search, severity pill filters (`ALL`, `CRITICAL`, `HIGH`, `MEDIUM`), raw evidence JSON inspector, and one-click JSON/CSV export actions. |
| **`/analyst`** | **Cognitive Threat Analyst** | AI Investigation Workbench powered by Google Gemini: Incident selector drawer, MITRE ATT&CK TTP matrix, threat hypotheses, zero-decryption passive evidence breakdown, and non-intrusive action playbooks. |
| **`/enclave`** | **Diode Health & Controls** | Hardware RX-only optical tap verification, zero return-path audit, volume-controlled threat burst generator (20 to 250 flows), and ML ensemble weights status (`threat_model.joblib`). |

---

## 🎨 Design Tokens & Theming

STRATA features a soft-neomorphic SaaS aesthetic with geometric typography (`Plus Jakarta Sans`), large rounded cards (`rounded-2xl` / `16px–20px`), floating pill badges, and circular icon containers:

- **Light Mode**:
  - **Canvas Background**: Soft ambient lilac-gray (`#ECEBF5`)
  - **Card Surfaces**: Pure white (`#FFFFFF`) with diffuse drop shadows (`0 8px 24px -4px rgba(100, 100, 130, 0.08)`) and hairline borders (`#E5E5F0`)
  - **Typography**: Deep charcoal slate (`#1E1E2D`) with muted metadata in cool gray (`#8A8FA3`)
  - **Primary Accent**: Vibrant electric indigo/violet (`#6366F1`)
- **Dark Mode**:
  - **Canvas Background**: Deep charcoal slate (`#1C1D21`)
  - **Card Surfaces**: Elevated charcoal-gray panels (`#26282E`) with ambient shadows (`0 8px 24px -4px rgba(0, 0, 0, 0.4)`) and minimal borders (`border-white/5`)
  - **Typography**: Crisp off-white (`#F3F4F6`) with secondary metrics in soft slate (`#9CA3AF`)
  - **Primary Accent**: Luminous lavender/violet (`#818CF8`)

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

Operators can inject synthetic traffic bursts for any of the 6 threat vectors directly from the Island Dock or Enclave Controls page:

1. **Dedicated Priority Queue**: Injected burst packets bypass ambient queuing via `IngestReceiver.priority_queue` for instantaneous scoring.
2. **Sliding-Window State Priming**: The sliding window primes historical state so that burst flows immediately trigger high-confidence detections.
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
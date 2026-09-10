# 🛡️ STRATA — Complete Project Context & Architecture Reference

**System Designation:** Autonomous Passive Network Threat Intelligence Enclave  
**Operating Constraint:** Unidirectional Data Diode / Passive Optical Mirroring (Hardware RX-Only)  
**Classification:** Open Telemetry / Air-Gapped Surveillance / Zero Return Path  
**Version:** 2.0.0-PROD  

---

## 📖 Executive Summary & Architectural Pivot

**STRATA** an **autonomous, read-only "Passive Network Threat Intelligence Enclave"** operating under physical **unidirectional data diode / passive optical tap** constraints:

1. **Zero Return Path Enforcement**:
   - Monitored networks are tapped via physical or virtual optical mirrors (RX-only fibers with the transmit fiber physically severed).
   - The enclave **never transmits packets onto the monitored segment**.
   - Strictly zero inline blocking, zero reverse-proxy interception, zero TCP resets, zero dynamic firewall rule pushing, and zero HTTP 403/429 rejection payloads.

2. **Strict Prohibition on Payload Decryption**:
   - Decryption of TLS/QUIC payloads is strictly forbidden to preserve absolute confidentiality and legal compliance.
   - Encrypted traffic is analyzed **exclusively via handshake metadata**: JA3/JA4 client/server hashes, SNI negotiation, cipher suite lists, and packet length / inter-arrival delta sequence arrays.

3. **High-Throughput Streaming Ingestion**:
   - The pipeline is engineered to sustain **2,000 – 5,000+ flows/second** (~1,000+ Mbps) with bounded sub-50ms ML inference latency.

4. **Cognitive Threat Intelligence**:
   - Powered by **Google Gemini** (`gemini-2.5-flash` via `google-genai`), synthesizing passive metadata evidence into structured MITRE ATT&CK mappings, threat hypotheses, and out-of-band monitoring actions.

---

## 🏗️ System Architecture & Data Flow

```
                                      MONITORED BACKBONE
                                               │
                                 ┌─────────────▼─────────────┐
                                 │   Passive Optical Tap     │
                                 │   (Physical RX-Only Fiber)│
                                 └─────────────┬─────────────┘
                                               │ (One-Way Telemetry)
┌──────────────────────────────────────────────┴──────────────────────────────────────────────┐
│                                 STRATA DATA DIODE ENCLAVE                                  │
│                                                                                            │
│   ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│   │ 1. Passive Stream Ingest Subsystem (backend/ingest/)                                │  │
│   │    • Async Queue Receiver (IngestReceiver)                                          │  │
│   │    • Ambient In-Process Telemetry Generator (AmbientTelemetryEmitter ~2,500 fps)    │  │
│   │    • External High-Throughput Stream Replay (scripts/stream_emitter.py)             │  │
│   │    • Sliding-Window Feature Extractor (SlidingWindowAggregator: 10s horizon)        │  │
│   └──────────────────────────────────────────┬──────────────────────────────────────────┘  │
│                                              ▼                                             │
│   ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│   │ 2. Feature Extraction Pipeline across 6 Threat Vectors (backend/pipeline.py)        │  │
│   │    ├── Volumetric / Protocol DDoS: Rolling Flow Rate, SYN/ACK Ratio, Shannon Entropy│  │
│   │    ├── Botnet C2 Beaconing: IAT Variance & Autocorrelation / FFT Periodicity Score │  │
│   │    ├── DNS Tunnelling & DGA: Character Entropy, N-Gram Transition, TXT/NULL Ratio   │  │
│   │    ├── Encrypted Malware (Zero Decryption): JA3/JA4 Hashes, SNI, First-N Lengths    │  │
│   │    ├── Reconnaissance / Scanning: 10s Fan-out Cardinality (Dst IPs & Dst Ports)     │  │
│   │    └── Data Exfiltration: Directional Byte Asymmetry Ratios (Outbound >> Inbound)   │  │
│   └──────────────────────────────────────────┬──────────────────────────────────────────┘  │
│                                              ▼                                             │
│   ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│   │ 3. Specialized ML Inference Ensemble (backend/ml_engine/ensemble.py)                │  │
│   │    • Multi-Detector Ensemble with 6 Calibrated Threat Heads                         │  │
│   │    • Bounded Inference Latency (<50ms per batch; benchmarked <5ms per 500 flows)    │  │
│   │    • Standardized Alert Schema Generation                                           │  │
│   └──────────────────────────────────────────┬──────────────────────────────────────────┘  │
│                                              ▼                                             │
│   ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│   │ 4. Cognitive Threat Intelligence (backend/services/gemini_analyst.py)              │  │
│   │    • Powered by Google Gemini (gemini-2.5-flash via google-genai)                   │  │
│   │    • Deterministic Air-Gapped Local Intelligence Engine (Offline Fallback)          │  │
│   │    • Automatic MITRE ATT&CK Mapping & Threat Hypotheses                             │  │
│   └──────────────────────────────────────────┬──────────────────────────────────────────┘  │
│                                              ▼                                             │
│   ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│   │ 5. Air-Gapped Data Diode Intelligence Console (frontend/app/page.tsx)               │  │
│   │    • Glowing "DIODE READ-ONLY: ZERO RETURN PATH" Indicator Badge                    │  │
│   │    • 4 Core KPIs: Sustained Flows/s, Bandwidth Mbps, Packets Ingested, SLA Latency  │  │
│   │    • 6-Vector Multi-Threat Radar with Real-Time Confidence & Evidence Gauges        │  │
│   │    • Live Streaming Incident Feed (Standardized Alert Records)                      │  │
│   │    • Interactive Google Gemini Threat Analyst Card                                  │  │
│   │    • On-Demand Threat Burst Injection Control                                       │  │
│   └─────────────────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 The 6 Passive Threat Classes & Feature Mathematics

### 1. Volumetric / Protocol DDoS
- **Core Vector:** Floods intended to saturate state tables or ingress pipes.
- **Mathematical Formulations:**
  - **Rolling Flow Velocity:** $R_{flow} = \frac{N_{window}}{\Delta t_{window}} \text{ flows/sec}$.
  - **SYN-to-ACK Ratio:** $\text{Ratio}_{syn/ack} = \frac{\sum \text{SYN flags}}{\sum \text{ACK flags} + 1.0}$.
    - Baseline is typically $\approx 1.0$; SYN floods exhibit $> 4.5\times - 20\times$.
  - **Source IP Shannon Entropy:** 
    $$H(S) = -\sum_{i=1}^{K} p_i \log_2(p_i), \quad p_i = \frac{\text{count}(\text{IP}_i)}{N}$$
    - Under distributed IP spoofing floods, entropy surges toward $\log_2(N)$ ($>6.0-10.0$).
- **Evidence Output:** `"flow_rate_rps": "4820.0/s"`, `"syn_to_ack_ratio": "18.5x"`, `"src_ip_entropy": "7.92"`.

### 2. Botnet C2 Beaconing
- **Core Vector:** Automated persistence beaconing from internal compromised nodes to external C2 controllers.
- **Mathematical Formulations:**
  - **Inter-Arrival Time (IAT) Variance:** Consecutive flow arrival deltas $\Delta t_i = t_i - t_{i-1}$.
    $$\sigma^2(IAT) = \frac{1}{n-1}\sum_{i=1}^{n-1} (\Delta t_i - \bar{\Delta t})^2$$
    - Automated beacons feature near-zero variance ($\sigma^2 < 0.05\text{s}$) or deterministic jitter.
  - **Periodicity Score (Autocorrelation & FFT):**
    $$R(1) = \frac{\sum (\Delta t_i - \bar{\Delta t})(\Delta t_{i+1} - \bar{\Delta t})}{\sum (\Delta t_i - \bar{\Delta t})^2}$$
    - Evaluates coefficient of variation ($CV = \sigma / \mu$) and normalized lag correlation ($>65\%-98\%$).
- **Evidence Output:** `"periodicity_score": "98.4%"`, `"iat_variance": "0.0028s"`, `"mean_interval": "5.00s"`.

### 3. DNS Tunnelling & DGA (Domain Generation Algorithms)
- **Core Vector:** Covert data transmission or algorithmic C2 rendezvous over port 53.
- **Mathematical Formulations:**
  - **Character Shannon Entropy:** Domain string entropy $H(Q) = -\sum \frac{c_i}{L} \log_2 \frac{c_i}{L}$.
    - Natural language domains score $2.2 - 3.2$; DGA and base32/hex tunnels score $> 3.80 - 4.85$.
  - **N-Gram & Vowel Distribution:** Ratio of vowels to total letters $\frac{V}{L}$. Natural domains average $35\%-45\%$; DGAs skew to $<18\%$ or $>70\%$.
  - **Record Type Anomaly:** High ratio of TXT, NULL, or ANY queries compared to standard A/AAAA lookups.
- **Evidence Output:** `"dns_query": "x92v7m4b1q8z3k5w.exfil-intel.cc"`, `"query_char_entropy": "4.82"`, `"record_type": "TXT"`.

### 4. Encrypted Traffic Metadata (No Decryption)
- **Core Vector:** Encrypted malware channels (Cobalt Strike, AsyncRAT, TrickBot, Metasploit) evaluated without breaking encryption.
- **Inspection Attributes:**
  - **JA3 Client Fingerprint:** MD5 hash of `SSLVersion,Ciphers,Extensions,EllipticCurves,PointFormats`.
  - **JA4 Client Fingerprint:** Modern format combining protocol, cipher count, SNI indicator, and SHA256 hashes (e.g. `t13d1516h2_c2_botnet_pulse`).
  - **SNI Analysis:** Mismatched SNI, dynamic DNS domains, or direct IP handshakes with missing SNI.
  - **First-N Packet Size Arrays:** Sequence of initial client/server packet lengths (e.g. `[240, -180, 64, -64]`), matching malleable C2 profiles.
- **Evidence Output:** `"matched_threat": "AsyncRAT C2 Client"`, `"ja3_hash": "e7d705a39f6c0a54e601275bfbb0a221"`.

### 5. Reconnaissance / Scanning
- **Core Vector:** Network enumeration (horizontal IP subnet sweeps and vertical service port scans).
- **Mathematical Formulations:**
  - **Rolling 10-Second Fan-Out Cardinality:**
    $$\text{FanOut} = \max\left(|\text{Unique Dst IPs}_{10s}|, |\text{Unique Dst Ports}_{10s}|\right)$$
    - Baseline: $< 5$ targets per host.
    - Flagged Scan: $> 15$ destination IPs or $> 20$ destination ports within 10 seconds.
  - **SYN-Only Ratio:** Ratio of connection attempts with no corresponding ACK or data completion ($>90\%$).
- **Evidence Output:** `"scan_type": "Vertical Port Scan"`, `"fanout_cardinality": "142 targets/10s"`, `"syn_only_ratio": "98.0%"`.

### 6. Data Exfiltration
- **Core Vector:** Unauthorized bulk data transfer over outbound channels.
- **Mathematical Formulations:**
  - **Directional Byte Asymmetry Ratio:**
    $$R_{bytes} = \frac{\text{Bytes Sent (Outbound)}}{\text{Bytes Received (Inbound)} + 1.0}$$
    - Normal browsing/API usage has $R_{bytes} \ll 1.0$ (inbound downloads dwarf outbound requests).
    - Exfiltration presents $R_{bytes} > 8.0\times - 500\times$ coupled with high volume ($> 250\text{ KB} - \text{MBs}$).
- **Evidence Output:** `"byte_asymmetry_ratio": "14.2x"`, `"outbound_bytes": "2840.5 KB"`, `"packet_asymmetry_ratio": "18.0x"`.

---

## 📋 Standardized Alert Schema Contract

Every detection emitted by the ML ensemble adheres to the strict contract:

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

## 🧠 Google Gemini Cognitive Threat Analyst Subsystem

**Location:** [`backend/services/gemini_analyst.py`](file:///Users/atreyeepaul/Strata%20/backend/services/gemini_analyst.py)

### Functional Mechanics:
- Integrates Google's official Python SDK (`from google import genai`) with model **`gemini-2.5-flash`**.
- Evaluates the standardized alert schema and evidence attributes non-intrusively.
- Synthesizes four core analytical components:
  1. **MITRE ATT&CK Mapping:** Identifies the precise Tactic, Technique ID (e.g. `T1498.001`, `T1071.001`, `T1071.004`, `T1573.002`, `T1595.001`, `T1048.003`), and Technique Name.
  2. **Analyst Threat Hypothesis:** 2-3 sentences explaining what the adversary is attempting based strictly on passive metadata deviation.
  3. **Passive Evidence Breakdown:** Detailed justification of how the metric values exceed normal baselines without decrypting payloads.
  4. **Recommended Passive Actions:** Strictly out-of-band actions (SIEM correlation, passive DNS sinkholing, host-level EDR isolation). **Zero firewall rules or inline drops are ever recommended.**

### Air-Gapped Fallback Guarantee:
If `GEMINI_API_KEY` is not present in `.env` or if the enclave is running in a fully network-isolated environment without cloud egress, the service automatically engages its **deterministic local cyber intelligence engine**, generating structured assessments with 100% offline reliability.

---

## 🗂️ Codebase Directory Map

```
Strata/
├── .env                              # Active environment variables (GEMINI_API_KEY) - GIT IGNORED
├── .env.example                      # Configuration template for deployment
├── .gitignore                        # Strict rules excluding secrets & node_modules
├── README.md                         # Operational overview and quickstart
├── PROJECT_CONTEXT.md                # Comprehensive technical context & architecture (This File)
├── run_backend.py                    # Root entrypoint to start the FastAPI enclave
│
├── backend/                          # FastAPI Backend Diode Enclave
│   ├── config.py                     # Pydantic Settings & dynamic .env synchronization
│   ├── main.py                       # FastAPI application, lifespan context & router registration
│   ├── pipeline.py                   # PassiveTelemetryPipeline: ingestion, sliding window & ML coordination
│   ├── ingest/                       # Passive Ingest Subsystem
│   │   ├── __init__.py
│   │   ├── models.py                 # Pydantic schemas (FlowRecord, StandardizedAlert, EnclaveKPIs)
│   │   ├── receiver.py               # IngestReceiver: async queue & throughput accounting (fps/Mbps)
│   │   ├── sliding_window.py         # SlidingWindowAggregator: 10s sliding window feature mathematics
│   │   └── generator.py              # AmbientTelemetryEmitter: continuous ~2,500 fps realistic traffic generator
│   ├── ml_engine/                    # Specialized ML Inference Ensemble
│   │   ├── __init__.py
│   │   └── ensemble.py               # MultiDetectorEnsemble (6 calibrated threat heads, <50ms SLA)
│   ├── routes/                       # Enclave API Endpoints
│   │   ├── diode.py                  # Telemetry stats, alert stream, burst trigger & Gemini assess
│   │   └── threats.py                # Backward-compatibility read-only threat observability
│   ├── services/
│   │   ├── __init__.py
│   │   └── gemini_analyst.py         # Google Gemini (gemini-2.5-flash) intelligence analyst service
│   └── tests/                        # Automated Pytest Suite
│       ├── test_sliding_window.py    # Unit tests for sliding-window feature calculations
│       └── test_ml_ensemble.py       # Unit tests for 6 threat heads & <50ms latency SLA
│
├── frontend/                         # Next.js 14 & Tailwind Air-Gapped Intelligence Console
│   ├── app/
│   │   ├── globals.css               # Dark cyber-analyst theme tokens, glassmorphism & diode pulse
│   │   ├── layout.tsx                # Application HTML root & metadata
│   │   └── page.tsx                  # Main Air-Gapped Data Diode Intelligence Console page
│   ├── components/
│   │   ├── DiodeHeader.tsx           # Glowing "DIODE READ-ONLY: ZERO RETURN PATH" badge & burst control
│   │   ├── TelemetryKPIs.tsx         # 4 KPI cards: Ingest Rate, Mbps, Packets, SLA Latency
│   │   ├── MultiThreatRadar.tsx      # 6 Threat Vector Breakdown Cards with confidence bars
│   │   ├── StreamingIncidentFeed.tsx # Real-time standardized alert stream with evidence drawer
│   │   └── GeminiAnalystCard.tsx     # Google Gemini Cognitive Threat Intelligence Card
│   ├── lib/
│   │   ├── api.ts                    # Frontend API client for diode endpoints
│   │   └── mockData.ts               # TypeScript interfaces and baseline state fixtures
│   └── package.json                  # Frontend dependencies
│
├── ml_engine/                        # Root ML module forwarders
│   └── ensemble.py                   # Forwarder to backend.ml_engine.ensemble
│
└── scripts/
    └── stream_emitter.py             # High-throughput replay emitter (2,000 - 5,000 flows/sec)
```

---

## 🔌 API Endpoints Reference

| Method | Endpoint | Description | Return Schema |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/diode/stats` | Enclave KPIs & 6-vector Threat Radar summaries | `{"kpis": EnclaveKPIs, "threat_radar": {...}}` |
| `GET` | `/api/v1/diode/alerts` | Live standardized alerts (last $N$ items) | `{"alerts_count": int, "alerts": [StandardizedAlert]}` |
| `POST` | `/api/v1/diode/ingest` | Unidirectional streaming flow ingestion | `{"status": "ingested", "count": int}` |
| `POST` | `/api/v1/diode/emitter/burst`| Injects an immediate threat burst on demand | `{"status": "burst_injected", "count": int}` |
| `POST` | `/api/v1/analyst/assess` | Google Gemini Threat Intelligence Assessment | Structured MITRE ATT&CK & Hypothesis JSON |
| `GET` | `/health` | Enclave health, diode status & pipeline latency | `{"status": "healthy", "diode_mode": "READ_ONLY"}` |

---

## 🛠️ Developer & Operator Commands

### 1. Start Backend Enclave
```bash
python3 run_backend.py
```

### 2. Start Frontend Console
```bash
cd frontend
npm run dev
# Or production build:
npm run start -- -p 3000
```

### 3. Run High-Throughput Stream Emitter
```bash
# Replay 3,000 flows/sec across all 6 threat vectors:
python3 scripts/stream_emitter.py --target-rate 3000

# Continuous run with custom batch size:
python3 scripts/stream_emitter.py --target-rate 5000 --batch-size 200
```

### 4. Execute Automated Test Suite
```bash
python3 -m pytest backend/tests/ -v
```

---

## 🔒 Security & Data Diode Guarantees

1. **Hardware RX Air-Gap Adherence:** The enclave operates under the assumption that the physical transmit fiber on the optical tap has been severed. No data can leave the enclave onto the monitored backbone.
2. **No Inline Drops:** All TCP SYN, ACK, and data packets pass unimpeded on the primary network. The enclave only processes passive mirrors.
3. **No Dynamic Firewall Changes:** The system does not possess credentials, APIs, or interfaces to configure upstream routers or firewalls.
4. **Privacy-Preserving:** Payloads are neither inspected nor decrypted. All detection relies strictly on statistical, temporal, and metadata invariants.

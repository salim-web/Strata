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
      │ Core Network Optical Tap             │ Physical Data Diode (Transmit Fiber Cut)
      │ NetFlow / IPFIX / Mirror Telemetry   ▼
┌─────┴─────────────────────────────────────────────────────────────────────────────┴─────┐
│                          STRATA PASSIVE INTELLIGENCE ENCLAVE                             │
│                                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ 1. PASSIVE INGEST & SLIDING-WINDOW FEATURE PIPELINE (2,000 - 5,000+ flows/sec)     │  │
│  │    • Volumetric / Protocol DDoS: Rolling Flow-rate, SYN/ACK Ratio, Shannon Entropy  │  │
│  │    • Botnet C2 Beaconing: IAT Variance & Periodicity (FFT/Autocorrelation)           │  │
│  │    • DNS Tunnelling & DGA: Character Entropy, N-gram distribution, TXT/NULL ratios  │  │
│  │    • Encrypted Traffic (No Decryption): JA3/JA4 Hashes, SNI, First-N Packet Sizes   │  │
│  │    • Recon / Scan: 10s Window Fan-out Cardinality (Unique Dst IPs & Dst Ports)      │  │
│  │    • Data Exfiltration: Directional Byte Asymmetry Ratios (Outbound >> Inbound)     │  │
│  └──────────────────────────────────────┬──────────────────────────────────────────────┘  │
│                                         ▼                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ 2. SPECIALIZED ML INFERENCE ENSEMBLE (<50ms Latency SLA)                            │  │
│  │    • Multi-Detector Ensemble (DDoS, C2, DGA, Encrypted Malware, Recon, Exfil)       │  │
│  │    • Standardized Alert Schema Output                                               │  │
│  └──────────────────────────────────────┬──────────────────────────────────────────────┘  │
│                                         ▼                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ 3. COGNITIVE THREAT INTELLIGENCE (Google Gemini)                                    │  │
│  │    • Automated MITRE ATT&CK Mapping & Threat Hypotheses                             │  │
│  │    • Passive Evidence Breakdown & Non-Intrusive SOC Monitoring Actions              │  │
│  └──────────────────────────────────────┬──────────────────────────────────────────────┘  │
│                                         ▼                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ 4. AIR-GAPPED DATA DIODE INTELLIGENCE CONSOLE (Next.js & Tailwind)                  │  │
│  │    • Diode Read-Only Status & Zero Return Path Badge                                │  │
│  │    • Telemetry KPIs: Sustained Throughput (Flows/s & Mbps), Ingested Packets, SLA   │  │
│  │    • Live Multi-Threat Radar (6-Vector Confidence & Evidence Gauges)                │  │
│  │    • Streaming Incident Feed & Gemini AI Analyst Card                               │  │
│  └─────────────────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 6 Threat Detection Vectors

| Threat Vector | Passive Metadata Analyzed | Baseline Normal | Anomaly Threshold |
| :--- | :--- | :--- | :--- |
| **1. Volumetric / Protocol DDoS** | Rolling flow velocity, SYN-to-ACK ratio, Source IP Shannon entropy | Flow rate < 500/s, SYN/ACK ~1.0, Entropy ~2-4 | Flow rate > 1,500/s, SYN/ACK > 4.5x, Entropy > 6.0 |
| **2. Botnet C2 Beaconing** | Inter-arrival time (IAT) variance, autocorrelation peak / FFT periodicity | IAT variance > 1.0s, Random jitter | IAT variance < 0.05s, Periodicity > 65% |
| **3. DNS Tunnelling & DGA** | Query character Shannon entropy, bigram distribution, label length, TXT/NULL record types | Entropy < 3.2, Vowels 35-45%, Label < 20 chars | Entropy > 3.8, Vowels < 18%, TXT query with length > 24 |
| **4. Encrypted Traffic (Zero Decryption)** | JA3/JA4 client/server hash matching, SNI heuristics, first-N packet size sequences | Known browser/OS fingerprints, Valid SNI | Matches threat intelligence DB (AsyncRAT, Cobalt Strike, etc.), Direct-IP TLS |
| **5. Reconnaissance / Scanning** | 10-second rolling fan-out cardinality (unique destination IPs and ports per source IP) | Fan-out < 5 targets/10s | Fan-out > 15 destination IPs or > 20 ports in 10s |
| **6. Data Exfiltration** | Directional byte asymmetry ($B_{out} / (B_{in} + 1)$), packet asymmetry | Outbound/Inbound ratio < 1.0 (Downloads > Uploads) | Outbound/Inbound ratio > 8.0x with > 250 KB transferred |

---

## 📋 Standardized Alert Schema

Every detection emitted by the ML ensemble adheres to the following contract:

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

### 1. Start the STRATA Backend Enclave
```bash
# In project root:
python run_backend.py
```
*The FastAPI Diode Enclave will start on `http://127.0.0.1:8000` with Swagger docs at `http://127.0.0.1:8000/docs`.*

### 2. Start the Air-Gapped Intelligence Console (Frontend)
```bash
cd frontend
npm run dev
```
*Access the Next.js Cyber-Analyst Console on `http://localhost:3000`.*

### 3. Replay High-Throughput Passive Telemetry Stream
```bash
# Replay 3,000 flows/sec across all 6 threat vectors:
python scripts/stream_emitter.py --target-rate 3000

# Custom rate and duration:
python scripts/stream_emitter.py --target-rate 5000 --duration 60
```

### 4. Run Automated Test Suite
```bash
python -m pytest backend/tests/ -v
```

---

## 🔒 Diode Security & Privacy Guarantees

1. **Zero Return Path**: The system never responds to monitored traffic. No packets are transmitted back onto the mirrored segment.
2. **Zero Active Mitigation**: No IP bans, no firewall rule pushing, no TCP resets, no HTTP 403/429 status codes.
3. **Payload Privacy**: Encrypted traffic (TLS/QUIC) is never decrypted. All intelligence is derived exclusively from metadata.
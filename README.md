# 🛡️ STRATA

**STRATA** is an AI-powered, real-time threat detection and rate-limiting system built for high-concurrency API protection. STRATA combines FastAPI backend security middleware, Redis sliding-window rate limiting, a local dual-engine ML threat detector (**Hugging Face MobileBERT + Scikit-Learn IsolationForest**), and a Next.js command dashboard for real-time security operations.

---

## 🏗️ Monorepo Architecture

```
STRATA/
├── backend/               # FastAPI Security Gateway & Middleware
│   ├── config.py          # Pydantic Settings configuration & env parser
│   ├── main.py            # Gateway entry point, lifespan & route registration
│   ├── middleware/        # Redis rate-limiting, IP blacklisting, PyJWT & Telemetry
│   │   ├── __init__.py
│   │   ├── rate_limiter.py # Sliding-window rate limiter & dynamic IP blocker
│   │   ├── redis_rate_limit.py # ThreatTracker singleton & telemetry metrics
│   │   ├── telemetry.py    # Live request streaming & dynamic sampling dispatcher
│   │   └── auth.py        # PyJWT verification & access tokens
│   ├── routes/            # Target API endpoints, honeypot & simulation routes
│   └── requirements.txt   # Backend Python dependencies
├── frontend/              # Next.js & Tailwind Security Operations Dashboard
│   ├── app/               # Next.js App Router (page.tsx, layout.tsx)
│   ├── components/        # Dashboard shell, TrafficChart, ThreatFeed, BlockedIPsTable & AttackerConsole
│   ├── lib/               # API fetching & telemetry interface types
│   └── package.json
├── ml_engine/             # 100% Local Dual ML Threat Detection Engine
│   ├── train_model.py     # IsolationForest baseline anomaly detector trainer
│   ├── inference.py       # MobileBERT + IsolationForest thread-safe local inference
│   ├── ai_reporter.py     # CISO Security Incident Report Generator
│   ├── iso_forest.joblib  # Serialized IsolationForest anomaly detector
│   └── requirements.txt   # ML dependencies (torch, transformers, scikit-learn, numpy, joblib, pydantic)
├── scripts/               # Attacker Simulation Suite
│   └── attacker.py        # Automated attack script (DDoS, SQLi, Auth Brute-force)
├── .env.example           # Shared environment variables
├── .gitignore
└── README.md
```

---

## 🧠 Dual-Engine ML Architecture

STRATA utilizes a **100% local, sub-15ms dual-model threat detection pipeline** that runs completely offline on CPU without external API dependencies:

1. **Hugging Face MobileBERT (`cssupport/mobilebert-sql-injection-detect`)**:
   - Pre-trained transformer sequence classification model fine-tuned for deep SQL Injection vector and syntax analysis.
   - Evaluates incoming request parameters and body payloads with PyTorch evaluation mode (`torch.no_grad()`).
2. **Scikit-Learn IsolationForest (`iso_forest.joblib`)**:
   - Unsupervised anomaly detector trained on baseline request vectors `[request_velocity, payload_size, header_entropy]`.
   - Identifies high-rate DDoS floods, abnormal payload spikes, and header manipulation.

---

## 📦 Backend Dependencies & Requirements

The STRATA backend gateway relies on the following core Python libraries:

| Dependency | Minimum Version | Purpose |
| :--- | :--- | :--- |
| **`fastapi`** | `0.110.0` | High-performance ASGI web framework |
| **`uvicorn[standard]`** | `0.28.0` | Production ASGI web server with `httptools` & `uvloop` |
| **`redis`** | `5.0.0` | Async Redis client (`redis.asyncio`) for ZSET sliding-window rate limiting & IP blacklisting |
| **`torch`** | `2.0+` | PyTorch CPU runtime for MobileBERT local inference |
| **`transformers`** | `4.38+` | Hugging Face Transformers library for `mobilebert-sql-injection-detect` |
| **`scikit-learn`** | `1.4.0` | Anomaly detection model (`IsolationForest`) |
| **`pydantic`** | `2.6.0` | Strict data validation & type enforcement |
| **`pydantic-settings`** | `2.2.0` | Environment settings management parsing `.env` file |
| **`pyjwt`** | `2.8.0` | JSON Web Token encoding and verification |

---

## 🚀 Quick Start Guide

### 1. Backend Setup (FastAPI & Redis)

#### **Step 1: Navigate to the `backend/` directory**
```bash
cd backend
```

#### **Step 2: Create & activate virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate
```

#### **Step 3: Install backend & ML dependencies**
```bash
pip install -r requirements.txt
pip install -r ../ml_engine/requirements.txt
```

#### **Step 4: Configure environment variables (optional)**
```bash
cp ../.env.example .env
```

#### **Step 5: Start the FastAPI Gateway server**
```bash
uvicorn main:app --reload --port 8000
```
*The API gateway will start on `http://127.0.0.1:8000` with interactive Swagger docs at `http://127.0.0.1:8000/docs`.*

---

### 2. Frontend Setup (Next.js & Tailwind Dashboard)
```bash
cd frontend
npm install
npm run dev
```

### 3. ML Engine Setup (MobileBERT + IsolationForest)
```bash
cd ml_engine
python train_model.py  # Trains IsolationForest baseline detector (iso_forest.joblib)
python inference.py    # Downloads/loads MobileBERT and verifies sub-15ms inference pipeline
```

### 4. Run Attacker Simulation Suite
```bash
cd scripts
python attacker.py
```

---

## 🔒 Key Features

- **MobileBERT Transformer SQLi Inspection:** Local Hugging Face `cssupport/mobilebert-sql-injection-detect` transformer model for deep SQL Injection vector detection.
- **IsolationForest Anomaly Detection:** Unsupervised behavioral anomaly detector trained on request velocity, payload size, and header entropy.
- **Redis IP Rate Limiting & Autonomous Blocking:** Dynamic IP throttling via ZSET sliding window and automatic 24-hour blacklisting upon high anomaly scores.
- **Dynamic API Traffic Sampling:** Adjustable ML sampling rates (25%, 50%, 75%, 100%) to balance inspection depth against CPU compute overhead.
- **Real-Time Block Velocity Observability:** High-precision graph velocity synchronization reflecting exact 403/429 blocked request bursts in real time.
- **Live Blocked Sources Table:** Real-time table displaying quarantined IP addresses with dynamic relative timestamps (`Just now`, `5s ago`) and threat vector classifications.
- **Custom Attack Payload Lab:** Red-Team simulation bench for testing SQLi, XSS, and custom payloads against target gateway endpoints.
- **Split-Screen War Room Dashboard:** Next.js operator control panel featuring live ML Latency indicator (~9.3ms), ML Anomaly Index Gauge, and Enterprise Defense Ticker.

Backend Startup
cd /home/mad-hunter/Documents/Programs/Tigmaminds/backend
source venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000

Frontend Startup

cd /home/mad-hunter/Documents/Programs/Tigmaminds/frontend
npm run dev

salim
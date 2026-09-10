#!/usr/bin/env python3
"""
STRATA ML Engine Model Training Entrypoint.
Delegates to backend/ml_engine/train_threat_models.py to train the multi-detector
HistGradientBoosting and IsolationForest models for passive network threat intelligence.
"""

import os
import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from backend.ml_engine.train_threat_models import train_and_evaluate_models

if __name__ == "__main__":
    output_dir = str(root_dir / "backend" / "ml_engine")
    print(f"🚀 Training STRATA ML threat models to: {output_dir}")
    train_and_evaluate_models(output_dir=output_dir)

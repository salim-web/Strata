import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

def train_iso_forest(output_path: str):
    """
    Trains an IsolationForest model on normal request baseline features: [request_velocity, payload_size, header_entropy].
    """
    np.random.seed(42)
    normal_traffic = np.random.normal(loc=[5, 120, 3.2], scale=[2, 40, 0.4], size=(1000, 3))
    iso_forest = IsolationForest(contamination=0.05, random_state=42).fit(normal_traffic)
    joblib.dump(iso_forest, output_path)
    print(f"✅ IsolationForest Anomaly Detector successfully trained and saved to: {output_path}")

train_and_save_model = train_iso_forest

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    iso_path = os.path.join(base_dir, "iso_forest.joblib")
    print("🚀 Initializing IsolationForest offline training pipeline...")
    train_iso_forest(iso_path)


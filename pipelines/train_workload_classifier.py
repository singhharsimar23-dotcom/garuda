"""
Offline Training Pipeline: Workload Classifier Pipeline
Trains and validates a machine learning workload classification model (IDLE, WEB_SERVER, DATABASE, BATCH) using physical hardware features.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import os
import pickle
from typing import Any, Dict, Tuple
import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

logger = logging.getLogger("pipeline.workload_classifier")

WORKLOAD_CLASSES = ["IDLE", "WEB_SERVER", "DATABASE", "BATCH"]


def generate_synthetic_workload_dataset(samples_per_class: int = 10000) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generates realistic hardware telemetry features with Gaussian noise across 4 workload classes:
    Features: [rapl_pkg_w, rapl_dram_w, perf_instructions_norm, perf_cache_miss_norm]
    """
    np.random.seed(42)
    X_list = []
    y_list = []

    # 1. IDLE: low power, low instructions, low cache
    idle_pkg = np.random.normal(loc=7.5, scale=1.5, size=samples_per_class)
    idle_dram = np.random.normal(loc=3.0, scale=0.8, size=samples_per_class)
    idle_inst = np.random.normal(loc=0.05, scale=0.02, size=samples_per_class)
    idle_cache = np.random.normal(loc=0.02, scale=0.01, size=samples_per_class)
    idle_X = np.column_stack([idle_pkg, idle_dram, idle_inst, idle_cache])
    X_list.append(idle_X)
    y_list.append(np.zeros(samples_per_class, dtype=int))

    # 2. WEB_SERVER: medium power, high instructions, medium cache
    web_pkg = np.random.normal(loc=25.0, scale=5.0, size=samples_per_class)
    web_dram = np.random.normal(loc=11.5, scale=2.5, size=samples_per_class)
    web_inst = np.random.normal(loc=0.70, scale=0.10, size=samples_per_class)
    web_cache = np.random.normal(loc=0.35, scale=0.08, size=samples_per_class)
    web_X = np.column_stack([web_pkg, web_dram, web_inst, web_cache])
    X_list.append(web_X)
    y_list.append(np.ones(samples_per_class, dtype=int))

    # 3. DATABASE: medium CPU power, high DRAM power, medium instructions, high cache
    db_pkg = np.random.normal(loc=17.5, scale=4.0, size=samples_per_class)
    db_dram = np.random.normal(loc=22.5, scale=4.0, size=samples_per_class)
    db_inst = np.random.normal(loc=0.45, scale=0.08, size=samples_per_class)
    db_cache = np.random.normal(loc=0.75, scale=0.10, size=samples_per_class)
    db_X = np.column_stack([db_pkg, db_dram, db_inst, db_cache])
    X_list.append(db_X)
    y_list.append(np.full(samples_per_class, 2, dtype=int))

    # 4. BATCH: very high CPU power, medium-high DRAM, very high instructions
    batch_pkg = np.random.normal(loc=60.0, scale=10.0, size=samples_per_class)
    batch_dram = np.random.normal(loc=15.0, scale=3.0, size=samples_per_class)
    batch_inst = np.random.normal(loc=0.90, scale=0.05, size=samples_per_class)
    batch_cache = np.random.normal(loc=0.50, scale=0.12, size=samples_per_class)
    batch_X = np.column_stack([batch_pkg, batch_dram, batch_inst, batch_cache])
    X_list.append(batch_X)
    y_list.append(np.full(samples_per_class, 3, dtype=int))

    X = np.vstack(X_list)
    y = np.concatenate(y_list)
    return X, y


def train_and_export_classifier(output_model_path: str, output_meta_path: str) -> Dict[str, Any]:
    """Train sklearn Pipeline with StandardScaler and RandomForest, assert accuracy > 0.85."""
    X, y = generate_synthetic_workload_dataset(samples_per_class=10000)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(n_estimators=50, max_depth=8, random_state=42)),
    ])

    pipeline.fit(X_train, y_train)

    # Validate
    y_pred = pipeline.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    assert acc > 0.85, f"Validation accuracy {acc:.4f} is below required threshold 0.85"

    data_hash = hashlib.sha256(X.tobytes()).hexdigest()

    metadata = {
        "version": "1.0.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "classes": WORKLOAD_CLASSES,
        "sample_count": len(X),
        "test_accuracy": round(acc, 4),
        "data_hash": data_hash,
        "features": ["rapl_pkg_w", "rapl_dram_w", "perf_instructions", "perf_cache_miss"],
    }

    os.makedirs(os.path.dirname(output_model_path), exist_ok=True)
    with open(output_model_path, "wb") as f:
        pickle.dump(pipeline, f)

    with open(output_meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Exported workload classifier model to {output_model_path} (Accuracy: {acc:.4f})")
    return metadata


if __name__ == "__main__":
    base_data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data"))
    model_path = os.path.join(base_data_dir, "workload_classifier.pkl")
    meta_path = os.path.join(base_data_dir, "workload_classifier_metadata.json")
    meta = train_and_export_classifier(model_path, meta_path)
    print(f"Workload classifier trained successfully. Validation accuracy: {meta['test_accuracy']:.4f}")

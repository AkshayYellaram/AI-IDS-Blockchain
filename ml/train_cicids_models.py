import os
import json
import time

import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier,
    GradientBoostingClassifier
)
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score
)
from sklearn.utils.class_weight import compute_sample_weight


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATASET = os.path.join(
    PROJECT_ROOT,
    "dataset",
    "cicids2017_common.parquet"
)

MODEL_DIR = os.path.join(
    PROJECT_ROOT,
    "ml"
)


# ============================================================
# FEATURES
# ============================================================

FEATURES = [
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "fwd_rate",
    "bwd_rate",
    "sinpkt",
    "dinpkt",
    "smean",
    "dmean",
    "swin",
    "dwin"
]

TARGET = "target"


# ============================================================
# LOAD DATA
# ============================================================

print("\n========================================")
print("CICIDS2017 MULTI-MODEL TRAINING")
print("========================================")

print("\n[1/6] Loading dataset...")

if not os.path.exists(DATASET):
    raise FileNotFoundError(
        f"Dataset not found:\n{DATASET}"
    )

df = pd.read_parquet(DATASET)

print(f"Dataset shape: {df.shape}")


# ============================================================
# CLEAN DATA
# ============================================================

print("\n[2/6] Preparing features...")

X = df[FEATURES].copy()
y = df[TARGET].astype(int)


# Safety cleanup
X = X.replace(
    [np.inf, -np.inf],
    np.nan
)

valid_rows = X.notna().all(axis=1) & y.notna()

X = X.loc[valid_rows]
y = y.loc[valid_rows]


print(f"Usable rows: {len(X):,}")

print("\nClass distribution:")

print(
    y.value_counts()
    .sort_index()
    .rename(
        index={
            0: "NORMAL",
            1: "ATTACK"
        }
    )
)


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

print("\n[3/6] Creating train/test split...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(f"Training rows: {len(X_train):,}")
print(f"Testing rows : {len(X_test):,}")


# ============================================================
# MODELS
# ============================================================

models = {

    "random_forest": RandomForestClassifier(
        n_estimators=250,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
        max_features="sqrt"
    ),

    "extra_trees": ExtraTreesClassifier(
        n_estimators=250,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
        max_features="sqrt"
    ),

    "gradient_boosting": GradientBoostingClassifier(
        n_estimators=150,
        learning_rate=0.08,
        max_depth=5,
        random_state=42
    )
}


# ============================================================
# METRICS STORAGE
# ============================================================

results = {}


# ============================================================
# TRAIN
# ============================================================

print("\n[4/6] Training models...")

for name, model in models.items():

    print("\n----------------------------------------")
    print(f"Training: {name}")
    print("----------------------------------------")

    start = time.time()

    # Gradient Boosting does not have class_weight.
    # Give it balanced sample weights.
    if name == "gradient_boosting":

        sample_weights = compute_sample_weight(
            class_weight="balanced",
            y=y_train
        )

        model.fit(
            X_train,
            y_train,
            sample_weight=sample_weights
        )

    else:

        model.fit(
            X_train,
            y_train
        )

    elapsed = time.time() - start

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    y_pred = model.predict(X_test)

    y_prob = model.predict_proba(X_test)[:, 1]

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    auc = roc_auc_score(
        y_test,
        y_prob
    )

    cm = confusion_matrix(
        y_test,
        y_pred
    )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    model_file = os.path.join(
        MODEL_DIR,
        f"cicids_{name}.pkl"
    )

    joblib.dump(
        model,
        model_file
    )

    # --------------------------------------------------------
    # Save metrics
    # --------------------------------------------------------

    results[name] = {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "roc_auc": float(auc),
        "training_seconds": float(elapsed),
        "confusion_matrix": cm.tolist(),
        "model_file": model_file
    }

    # --------------------------------------------------------
    # Console output
    # --------------------------------------------------------

    print(
        f"Training time : {elapsed:.2f} sec"
    )

    print(
        f"Accuracy      : {accuracy:.4f}"
    )

    print(
        f"Precision     : {precision:.4f}"
    )

    print(
        f"Recall        : {recall:.4f}"
    )

    print(
        f"F1 Score      : {f1:.4f}"
    )

    print(
        f"ROC-AUC       : {auc:.4f}"
    )

    print("\nConfusion Matrix:")

    print(cm)

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            y_pred,
            target_names=[
                "NORMAL",
                "ATTACK"
            ],
            digits=4,
            zero_division=0
        )
    )

    print(
        f"Saved: {model_file}"
    )


# ============================================================
# SAVE METRICS
# ============================================================

print("\n[5/6] Saving evaluation results...")

metrics_file = os.path.join(
    MODEL_DIR,
    "cicids_metrics.json"
)

with open(
    metrics_file,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        results,
        f,
        indent=4
    )


# ============================================================
# SUMMARY
# ============================================================

print("\n[6/6] FINAL MODEL SUMMARY")

print(
    "\n"
    f"{'MODEL':<25}"
    f"{'ACC':<10}"
    f"{'PREC':<10}"
    f"{'RECALL':<10}"
    f"{'F1':<10}"
    f"{'AUC':<10}"
)

print("-" * 75)

for name, metrics in results.items():

    print(
        f"{name:<25}"
        f"{metrics['accuracy']:<10.4f}"
        f"{metrics['precision']:<10.4f}"
        f"{metrics['recall']:<10.4f}"
        f"{metrics['f1']:<10.4f}"
        f"{metrics['roc_auc']:<10.4f}"
    )


print("\n========================================")
print("TRAINING COMPLETE")
print("========================================")

print("\nModels saved:")

for name in models:
    print(
        f"  ml/cicids_{name}.pkl"
    )

print(
    "\nMetrics saved:"
    f"\n  ml/cicids_metrics.json"
)
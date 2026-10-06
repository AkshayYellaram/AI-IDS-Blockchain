import os
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)


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


# ============================================================
# SETTINGS
# ============================================================

THRESHOLD = 0.80


# ============================================================
# LOAD DATA
# ============================================================

print("\n========================================")
print("DECISION ENGINE EVALUATION")
print("========================================")

print("\n[1/6] Loading dataset...")

df = pd.read_parquet(
    DATASET
)

X = df[FEATURES].copy()
y = df["target"].astype(int)


# ============================================================
# SAME SPLIT AS TRAINING
# ============================================================

print("\n[2/6] Creating identical test split...")

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.20,

    random_state=42,

    stratify=y
)

print(
    f"Test samples: {len(X_test):,}"
)


# ============================================================
# LOAD MODELS
# ============================================================

print("\n[3/6] Loading models...")

rf = joblib.load(
    os.path.join(
        MODEL_DIR,
        "cicids_random_forest.pkl"
    )
)

et = joblib.load(
    os.path.join(
        MODEL_DIR,
        "cicids_extra_trees.pkl"
    )
)

gb = joblib.load(
    os.path.join(
        MODEL_DIR,
        "cicids_gradient_boosting.pkl"
    )
)

isolation_forest = joblib.load(
    os.path.join(
        MODEL_DIR,
        "isolation_forest.pkl"
    )
)


# ============================================================
# SUPERVISED PREDICTIONS
# ============================================================

print("\n[4/6] Running ensemble predictions...")

rf_prob = rf.predict_proba(
    X_test
)[:, 1]

et_prob = et.predict_proba(
    X_test
)[:, 1]

gb_prob = gb.predict_proba(
    X_test
)[:, 1]


# Average probabilities

ensemble_prob = (
    rf_prob
    + et_prob
    + gb_prob
) / 3.0


# Threshold

ensemble_pred = (
    ensemble_prob >= THRESHOLD
).astype(int)


# ============================================================
# ISOLATION FOREST
# ============================================================

print(
    "\n[5/6] Running Isolation Forest..."
)

isolation_pred_raw = (
    isolation_forest.predict(
        X_test
    )
)

isolation_pred = (
    isolation_pred_raw == -1
).astype(int)


# ============================================================
# METRICS FUNCTION
# ============================================================

def calculate_metrics(
    name,
    y_true,
    y_pred,
    probabilities=None
):

    cm = confusion_matrix(
        y_true,
        y_pred
    )

    tn, fp, fn, tp = cm.ravel()

    accuracy = accuracy_score(
        y_true,
        y_pred
    )

    precision = precision_score(
        y_true,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_true,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_true,
        y_pred,
        zero_division=0
    )

    false_positive_rate = (
        fp / (fp + tn)
        if (fp + tn) > 0
        else 0
    )

    false_negative_rate = (
        fn / (fn + tp)
        if (fn + tp) > 0
        else 0
    )

    print("\n----------------------------------------")
    print(name)
    print("----------------------------------------")

    print(
        f"Accuracy           : {accuracy:.4%}"
    )

    print(
        f"Precision          : {precision:.4%}"
    )

    print(
        f"Recall             : {recall:.4%}"
    )

    print(
        f"F1 Score           : {f1:.4%}"
    )

    print(
        f"False Positive Rate: {false_positive_rate:.4%}"
    )

    print(
        f"False Negative Rate: {false_negative_rate:.4%}"
    )

    if probabilities is not None:

        auc = roc_auc_score(
            y_true,
            probabilities
        )

        print(
            f"ROC-AUC            : {auc:.4%}"
        )

    print("\nConfusion Matrix:")

    print(
        f"                 Predicted"
    )

    print(
        f"                 Normal  Attack"
    )

    print(
        f"Actual Normal    {tn:6d}  {fp:6d}"
    )

    print(
        f"Actual Attack    {fn:6d}  {tp:6d}"
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp)
    }


# ============================================================
# RESULTS
# ============================================================

ensemble_metrics = calculate_metrics(

    "SUPERVISED ENSEMBLE",

    y_test,

    ensemble_pred,

    ensemble_prob
)


isolation_metrics = calculate_metrics(

    "ISOLATION FOREST",

    y_test,

    isolation_pred
)


# ============================================================
# FINAL REPORT
# ============================================================

print("\n========================================")
print("ENSEMBLE CLASSIFICATION REPORT")
print("========================================")

print(
    classification_report(
        y_test,
        ensemble_pred,
        target_names=[
            "NORMAL",
            "ATTACK"
        ],
        digits=4,
        zero_division=0
    )
)


print("\n========================================")
print("EVALUATION COMPLETE")
print("========================================")

print(
    "\nThreshold:",
    f"{THRESHOLD:.0%}"
)

print(
    "\nThe ensemble uses:"
)

print(
    "  • Random Forest"
)

print(
    "  • Extra Trees"
)

print(
    "  • Gradient Boosting"
)

print(
    "\nIsolation Forest is reported separately"
    " because it is an anomaly detector,"
    " not a supervised attack classifier."
)
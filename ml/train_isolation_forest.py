import os
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest


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

MODEL_FILE = os.path.join(
    PROJECT_ROOT,
    "ml",
    "isolation_forest.pkl"
)


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


print("\n========================================")
print("ISOLATION FOREST TRAINING")
print("========================================")


# ============================================================
# LOAD
# ============================================================

print("\n[1/4] Loading CICIDS2017...")

df = pd.read_parquet(DATASET)

print(
    f"Total dataset rows: {len(df):,}"
)


# ============================================================
# BENIGN ONLY
# ============================================================

print("\n[2/4] Selecting BENIGN traffic...")

benign = df[
    df["target"] == 0
].copy()

print(
    f"Benign flows: {len(benign):,}"
)


# ============================================================
# FEATURES
# ============================================================

X = benign[FEATURES].copy()

X = X.replace(
    [np.inf, -np.inf],
    np.nan
)

X = X.dropna()

print(
    f"Usable benign flows: {len(X):,}"
)


# ============================================================
# TRAIN
# ============================================================

print("\n[3/4] Training Isolation Forest...")

model = IsolationForest(

    n_estimators=250,

    contamination=0.01,

    max_samples="auto",

    random_state=42,

    n_jobs=-1

)


model.fit(X)


# ============================================================
# SAVE
# ============================================================

joblib.dump(
    model,
    MODEL_FILE
)

print(
    f"\nSaved model:\n{MODEL_FILE}"
)


# ============================================================
# QUICK CHECK
# ============================================================

predictions = model.predict(X)

normal_count = np.sum(
    predictions == 1
)

anomaly_count = np.sum(
    predictions == -1
)

print("\n[4/4] Training sanity check")

print(
    f"Normal-like flows : {normal_count:,}"
)

print(
    f"Anomalous flows   : {anomaly_count:,}"
)

print(
    f"Anomaly rate      : "
    f"{anomaly_count / len(X) * 100:.2f}%"
)

print("\n========================================")
print("ISOLATION FOREST COMPLETE")
print("========================================")
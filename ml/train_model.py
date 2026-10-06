import pandas as pd
import numpy as np

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

import joblib


# ============================================================
# 1. LOAD DATASET
# ============================================================

TRAIN_FILE = "dataset/UNSW_NB15_training-set.parquet"
TEST_FILE = "dataset/UNSW_NB15_testing-set.parquet"

print("=" * 70)
print("AI-IDS - UNSW-NB15 MODEL TRAINING")
print("=" * 70)

print("\nLoading training dataset...")
train_df = pd.read_parquet(TRAIN_FILE)

print("Loading testing dataset...")
test_df = pd.read_parquet(TEST_FILE)

print(f"\nTraining samples: {len(train_df)}")
print(f"Testing samples : {len(test_df)}")


# ============================================================
# 2. SELECT FEATURES
# ============================================================

FEATURES = [
    "dur",
    "proto",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sload",
    "dload",
    "sinpkt",
    "dinpkt",
    "smean",
    "dmean",
    "swin",
    "dwin"
]

TARGET = "label"

X_train = train_df[FEATURES].copy()
y_train = train_df[TARGET].copy()

X_test = test_df[FEATURES].copy()
y_test = test_df[TARGET].copy()


# ============================================================
# 3. CATEGORICAL / NUMERICAL FEATURES
# ============================================================

categorical_features = [
    "proto"
]

numeric_features = [
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sload",
    "dload",
    "sinpkt",
    "dinpkt",
    "smean",
    "dmean",
    "swin",
    "dwin"
]


# ============================================================
# 4. PREPROCESSING
# ============================================================

preprocessor = ColumnTransformer(
    transformers=[
        (
            "categorical",
            OneHotEncoder(
                handle_unknown="ignore"
            ),
            categorical_features
        ),
        (
            "numeric",
            "passthrough",
            numeric_features
        )
    ]
)


# ============================================================
# 5. RANDOM FOREST
# ============================================================

model = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)


# ============================================================
# 6. PIPELINE
# ============================================================

pipeline = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        ("model", model)
    ]
)


# ============================================================
# 7. TRAIN
# ============================================================

print("\nTraining Random Forest...")
pipeline.fit(X_train, y_train)

print("Training complete.")


# ============================================================
# 8. TEST
# ============================================================

print("\nRunning predictions...")

predictions = pipeline.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)

print("\n" + "=" * 70)
print("MODEL RESULTS")
print("=" * 70)

print(f"\nAccuracy: {accuracy:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "NORMAL",
            "ATTACK"
        ]
    )
)

print("\nConfusion Matrix:")
print(
    confusion_matrix(
        y_test,
        predictions
    )
)


# ============================================================
# 9. SAVE MODEL
# ============================================================

MODEL_FILE = "ml/ids_model.pkl"

joblib.dump(
    pipeline,
    MODEL_FILE
)

print("\n" + "=" * 70)
print(f"Model saved to: {MODEL_FILE}")
print("=" * 70)
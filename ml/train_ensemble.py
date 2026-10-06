import os
import time
import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.pipeline import Pipeline

from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


# ============================================================
# CONFIGURATION
# ============================================================

TRAIN_FILE = "dataset/UNSW_NB15_training-set.parquet"
TEST_FILE = "dataset/UNSW_NB15_testing-set.parquet"

MODEL_DIR = "ml/models"

os.makedirs(MODEL_DIR, exist_ok=True)


# ============================================================
# FEATURES
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


# ============================================================
# LOAD DATA
# ============================================================

print()
print("=" * 60)
print("LOADING UNSW-NB15 DATASET")
print("=" * 60)

print("\nLoading training dataset...")

train_df = pd.read_parquet(TRAIN_FILE)

print("Training shape:", train_df.shape)


print("\nLoading testing dataset...")

test_df = pd.read_parquet(TEST_FILE)

print("Testing shape:", test_df.shape)


# ============================================================
# CHECK FEATURES
# ============================================================

missing_train = [
    column
    for column in FEATURES
    if column not in train_df.columns
]

missing_test = [
    column
    for column in FEATURES
    if column not in test_df.columns
]


if missing_train:

    raise ValueError(
        "Missing training features: "
        + str(missing_train)
    )


if missing_test:

    raise ValueError(
        "Missing testing features: "
        + str(missing_test)
    )


# ============================================================
# PREPARE X / Y
# ============================================================

X_train = train_df[FEATURES].copy()
y_train = train_df[TARGET].astype(int)

X_test = test_df[FEATURES].copy()
y_test = test_df[TARGET].astype(int)


print("\nFeatures being used:")

for feature in FEATURES:
    print("  -", feature)


print("\nTraining labels:")
print(y_train.value_counts())

print("\nTesting labels:")
print(y_test.value_counts())


# ============================================================
# FEATURE TYPES
# ============================================================

CATEGORICAL_FEATURES = [
    "proto"
]

NUMERIC_FEATURES = [
    feature
    for feature in FEATURES
    if feature not in CATEGORICAL_FEATURES
]


# ============================================================
# PREPROCESSOR FOR TREE MODELS
# ============================================================

tree_preprocessor = ColumnTransformer(

    transformers=[

        (
            "categorical",
            OneHotEncoder(
                handle_unknown="ignore"
            ),
            CATEGORICAL_FEATURES
        ),

        (
            "numeric",
            "passthrough",
            NUMERIC_FEATURES
        )
    ]
)


# ============================================================
# PREPROCESSOR FOR LOGISTIC REGRESSION
# ============================================================

logistic_preprocessor = ColumnTransformer(

    transformers=[

        (
            "categorical",
            OneHotEncoder(
                handle_unknown="ignore"
            ),
            CATEGORICAL_FEATURES
        ),

        (
            "numeric",
            StandardScaler(),
            NUMERIC_FEATURES
        )
    ]
)


# ============================================================
# MODEL 1 — RANDOM FOREST
# ============================================================

print()
print("=" * 60)
print("MODEL 1 — RANDOM FOREST")
print("=" * 60)

rf_pipeline = Pipeline(

    steps=[

        (
            "preprocessor",
            tree_preprocessor
        ),

        (
            "classifier",
            RandomForestClassifier(

                n_estimators=200,

                random_state=42,

                n_jobs=-1,

                class_weight="balanced"
            )
        )
    ]
)


start = time.time()

rf_pipeline.fit(
    X_train,
    y_train
)

rf_time = time.time() - start

print(
    f"Training completed in {rf_time:.2f} seconds."
)


# ============================================================
# MODEL 2 — EXTRA TREES
# ============================================================

print()
print("=" * 60)
print("MODEL 2 — EXTRA TREES")
print("=" * 60)

et_pipeline = Pipeline(

    steps=[

        (
            "preprocessor",
            tree_preprocessor
        ),

        (
            "classifier",
            ExtraTreesClassifier(

                n_estimators=200,

                random_state=42,

                n_jobs=-1,

                class_weight="balanced"
            )
        )
    ]
)


start = time.time()

et_pipeline.fit(
    X_train,
    y_train
)

et_time = time.time() - start

print(
    f"Training completed in {et_time:.2f} seconds."
)


# ============================================================
# MODEL 3 — LOGISTIC REGRESSION
# ============================================================

print()
print("=" * 60)
print("MODEL 3 — LOGISTIC REGRESSION")
print("=" * 60)

lr_pipeline = Pipeline(

    steps=[

        (
            "preprocessor",
            logistic_preprocessor
        ),

        (
            "classifier",
            LogisticRegression(

                max_iter=1000,

                class_weight="balanced",

                random_state=42
            )
        )
    ]
)


start = time.time()

lr_pipeline.fit(
    X_train,
    y_train
)

lr_time = time.time() - start

print(
    f"Training completed in {lr_time:.2f} seconds."
)


# ============================================================
# PREDICTIONS
# ============================================================

print()
print("=" * 60)
print("GENERATING TEST PREDICTIONS")
print("=" * 60)


rf_predictions = rf_pipeline.predict(X_test)
rf_probabilities = rf_pipeline.predict_proba(X_test)[:, 1]


et_predictions = et_pipeline.predict(X_test)
et_probabilities = et_pipeline.predict_proba(X_test)[:, 1]


lr_predictions = lr_pipeline.predict(X_test)
lr_probabilities = lr_pipeline.predict_proba(X_test)[:, 1]


# ============================================================
# ENSEMBLE
# ============================================================

print()
print("=" * 60)
print("CREATING ENSEMBLE")
print("=" * 60)


# Average the three model probabilities

ensemble_probability = (
    rf_probabilities
    + et_probabilities
    + lr_probabilities
) / 3.0


# 50% classification threshold for model evaluation

ensemble_predictions = (
    ensemble_probability >= 0.50
).astype(int)


# ============================================================
# METRIC FUNCTION
# ============================================================

def evaluate_model(
    name,
    y_true,
    predictions
):

    accuracy = accuracy_score(
        y_true,
        predictions
    )

    precision = precision_score(
        y_true,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_true,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_true,
        predictions,
        zero_division=0
    )

    cm = confusion_matrix(
        y_true,
        predictions
    )


    print()
    print("-" * 60)
    print(name)
    print("-" * 60)

    print(
        f"Accuracy  : {accuracy:.4f}"
    )

    print(
        f"Precision : {precision:.4f}"
    )

    print(
        f"Recall    : {recall:.4f}"
    )

    print(
        f"F1-score  : {f1:.4f}"
    )

    print("\nConfusion Matrix:")

    print(cm)

    print("\nClassification Report:")

    print(
        classification_report(
            y_true,
            predictions,
            target_names=[
                "NORMAL",
                "ATTACK"
            ],
            zero_division=0
        )
    )


    return {

        "model": name,

        "accuracy": accuracy,

        "precision": precision,

        "recall": recall,

        "f1": f1
    }


# ============================================================
# EVALUATE ALL MODELS
# ============================================================

results = []


results.append(

    evaluate_model(
        "RANDOM FOREST",
        y_test,
        rf_predictions
    )
)


results.append(

    evaluate_model(
        "EXTRA TREES",
        y_test,
        et_predictions
    )
)


results.append(

    evaluate_model(
        "LOGISTIC REGRESSION",
        y_test,
        lr_predictions
    )
)


results.append(

    evaluate_model(
        "3-MODEL ENSEMBLE",
        y_test,
        ensemble_predictions
    )
)


# ============================================================
# COMPARISON TABLE
# ============================================================

print()
print("=" * 60)
print("MODEL COMPARISON")
print("=" * 60)


results_df = pd.DataFrame(results)

print()

print(
    results_df.to_string(
        index=False,
        float_format=lambda value:
        f"{value:.4f}"
    )
)


# ============================================================
# SAVE MODELS
# ============================================================

print()
print("=" * 60)
print("SAVING MODELS")
print("=" * 60)


joblib.dump(
    rf_pipeline,
    f"{MODEL_DIR}/random_forest.pkl"
)

print(
    "Saved:",
    f"{MODEL_DIR}/random_forest.pkl"
)


joblib.dump(
    et_pipeline,
    f"{MODEL_DIR}/extra_trees.pkl"
)

print(
    "Saved:",
    f"{MODEL_DIR}/extra_trees.pkl"
)


joblib.dump(
    lr_pipeline,
    f"{MODEL_DIR}/logistic_regression.pkl"
)

print(
    "Saved:",
    f"{MODEL_DIR}/logistic_regression.pkl"
)


# ============================================================
# SAVE ENSEMBLE INFORMATION
# ============================================================

ensemble_config = {

    "models": [
        "random_forest",
        "extra_trees",
        "logistic_regression"
    ],

    "weights": [
        1 / 3,
        1 / 3,
        1 / 3
    ],

    "classification_threshold": 0.50,

    "features": FEATURES
}


joblib.dump(
    ensemble_config,
    f"{MODEL_DIR}/ensemble_config.pkl"
)


print(
    "Saved:",
    f"{MODEL_DIR}/ensemble_config.pkl"
)


# ============================================================
# FINISHED
# ============================================================

print()
print("=" * 60)
print("ENSEMBLE TRAINING COMPLETE")
print("=" * 60)

print()
print("Models created:")
print("  1. Random Forest")
print("  2. Extra Trees")
print("  3. Logistic Regression")
print("  4. 3-model probability ensemble")

print()
print("IMPORTANT:")
print("These models have NOT been connected to the live IDS yet.")
print("The existing working IDS remains unchanged.")

print()
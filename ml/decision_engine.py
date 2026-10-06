import os
import joblib
import numpy as np
import pandas as pd


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
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
# MODEL FILES
# ============================================================

RF_FILE = os.path.join(
    MODEL_DIR,
    "cicids_random_forest.pkl"
)

ET_FILE = os.path.join(
    MODEL_DIR,
    "cicids_extra_trees.pkl"
)

GB_FILE = os.path.join(
    MODEL_DIR,
    "cicids_gradient_boosting.pkl"
)

IF_FILE = os.path.join(
    MODEL_DIR,
    "isolation_forest.pkl"
)


# ============================================================
# DECISION ENGINE
# ============================================================

class DecisionEngine:

    def __init__(
        self,
        attack_threshold=0.80
    ):

        self.attack_threshold = attack_threshold

        print("\n[DECISION] Loading models...")

        self.random_forest = joblib.load(
            RF_FILE
        )

        print(
            "[DECISION] Random Forest loaded"
        )

        self.extra_trees = joblib.load(
            ET_FILE
        )

        print(
            "[DECISION] Extra Trees loaded"
        )

        self.gradient_boosting = joblib.load(
            GB_FILE
        )

        print(
            "[DECISION] Gradient Boosting loaded"
        )

        self.isolation_forest = joblib.load(
            IF_FILE
        )

        print(
            "[DECISION] Isolation Forest loaded"
        )

        print(
            "[DECISION] Attack threshold:",
            f"{attack_threshold:.0%}"
        )


    # ========================================================
    # PREPARE INPUT
    # ========================================================

    def _prepare_input(
        self,
        flow
    ):

        if isinstance(
            flow,
            dict
        ):

            X = pd.DataFrame(
                [flow]
            )

        elif isinstance(
            flow,
            pd.DataFrame
        ):

            X = flow.copy()

        else:

            X = pd.DataFrame(
                flow,
                columns=FEATURES
            )

        X = X[FEATURES]

        return X


    # ========================================================
    # PREDICT
    # ========================================================

    def predict(
        self,
        flow
    ):

        X = self._prepare_input(
            flow
        )


        # ----------------------------------------------------
        # SUPERVISED MODELS
        # ----------------------------------------------------

        rf_probability = (
            self.random_forest
            .predict_proba(X)[0][1]
        )

        et_probability = (
            self.extra_trees
            .predict_proba(X)[0][1]
        )

        gb_probability = (
            self.gradient_boosting
            .predict_proba(X)[0][1]
        )


        # ----------------------------------------------------
        # SUPERVISED ENSEMBLE
        # ----------------------------------------------------

        supervised_probability = float(
            np.mean([
                rf_probability,
                et_probability,
                gb_probability
            ])
        )


        # ----------------------------------------------------
        # ISOLATION FOREST
        # ----------------------------------------------------

        anomaly_prediction = int(
            self.isolation_forest.predict(X)[0]
        )

        anomaly_score = float(
            self.isolation_forest
            .decision_function(X)[0]
        )

        is_anomaly = (
            anomaly_prediction == -1
        )


        # ----------------------------------------------------
        # DECISION
        # ----------------------------------------------------

        if supervised_probability >= self.attack_threshold:

            prediction = "ATTACK"

            reason = (
                "SUPERVISED_MODELS_HIGH_CONFIDENCE"
            )

        else:

            prediction = "NORMAL"

            if is_anomaly:

                reason = (
                    "ANOMALOUS_BUT_BELOW_ATTACK_THRESHOLD"
                )

            else:

                reason = (
                    "SUPERVISED_MODELS_LOW_CONFIDENCE"
                )


        # ----------------------------------------------------
        # RETURN
        # ----------------------------------------------------

        return {

            "prediction": prediction,

            "supervised_probability":
                supervised_probability,

            "random_forest_probability":
                float(rf_probability),

            "extra_trees_probability":
                float(et_probability),

            "gradient_boosting_probability":
                float(gb_probability),

            "isolation_forest_anomaly":
                is_anomaly,

            "isolation_forest_prediction":
                anomaly_prediction,

            "isolation_forest_score":
                anomaly_score,

            "threshold":
                self.attack_threshold,

            "reason":
                reason
        }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    engine = DecisionEngine(
        attack_threshold=0.80
    )


    # Same representative flow
    # used during ensemble testing.

    example = {

        "dur": 1.2,

        "spkts": 20,

        "dpkts": 15,

        "sbytes": 1500,

        "dbytes": 1200,

        "rate": 29.16,

        "fwd_rate": 16.67,

        "bwd_rate": 12.50,

        "sinpkt": 0.06,

        "dinpkt": 0.08,

        "smean": 75,

        "dmean": 80,

        "swin": 64240,

        "dwin": 65535

    }


    result = engine.predict(
        example
    )


    print("\n========================================")
    print("DECISION ENGINE TEST")
    print("========================================")

    print(
        "\nFinal prediction:",
        result["prediction"]
    )

    print(
        "Supervised probability:",
        f"{result['supervised_probability']:.2%}"
    )

    print(
        "Random Forest:",
        f"{result['random_forest_probability']:.2%}"
    )

    print(
        "Extra Trees:",
        f"{result['extra_trees_probability']:.2%}"
    )

    print(
        "Gradient Boosting:",
        f"{result['gradient_boosting_probability']:.2%}"
    )

    print(
        "Isolation Forest anomaly:",
        result["isolation_forest_anomaly"]
    )

    print(
        "Isolation Forest score:",
        f"{result['isolation_forest_score']:.6f}"
    )

    print(
        "Reason:",
        result["reason"]
    )
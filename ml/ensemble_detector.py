import os
import joblib
import numpy as np
import pandas as pd


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_DIR = os.path.join(
    PROJECT_ROOT,
    "ml"
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


MODEL_FILES = {
    "random_forest":
        os.path.join(
            MODEL_DIR,
            "cicids_random_forest.pkl"
        ),

    "extra_trees":
        os.path.join(
            MODEL_DIR,
            "cicids_extra_trees.pkl"
        ),

    "gradient_boosting":
        os.path.join(
            MODEL_DIR,
            "cicids_gradient_boosting.pkl"
        )
}


class EnsembleDetector:

    def __init__(
        self,
        threshold=0.80
    ):

        self.threshold = threshold

        self.models = {}

        print("\n[ENSEMBLE] Loading models...")

        for name, path in MODEL_FILES.items():

            if not os.path.exists(path):

                raise FileNotFoundError(
                    f"Model not found: {path}"
                )

            self.models[name] = joblib.load(path)

            print(
                f"[ENSEMBLE] Loaded {name}"
            )

        print(
            f"[ENSEMBLE] Threshold: "
            f"{self.threshold:.0%}"
        )


    def predict(
        self,
        flow_features
    ):

        # ----------------------------------------------------
        # Convert input to DataFrame
        # ----------------------------------------------------

        if isinstance(
            flow_features,
            dict
        ):

            X = pd.DataFrame(
                [flow_features]
            )

        elif isinstance(
            flow_features,
            pd.DataFrame
        ):

            X = flow_features.copy()

        else:

            X = pd.DataFrame(
                flow_features,
                columns=FEATURES
            )


        # ----------------------------------------------------
        # Ensure correct feature order
        # ----------------------------------------------------

        X = X[FEATURES]


        # ----------------------------------------------------
        # Individual model probabilities
        # ----------------------------------------------------

        probabilities = {}

        for name, model in self.models.items():

            probability = model.predict_proba(
                X
            )[0][1]

            probabilities[name] = float(
                probability
            )


        # ----------------------------------------------------
        # Ensemble probability
        # ----------------------------------------------------

        ensemble_probability = float(
            np.mean(
                list(
                    probabilities.values()
                )
            )
        )


        # ----------------------------------------------------
        # Final decision
        # ----------------------------------------------------

        prediction = (
            "ATTACK"
            if ensemble_probability >= self.threshold
            else "NORMAL"
        )


        return {

            "prediction": prediction,

            "attack_probability":
                ensemble_probability,

            "models":
                probabilities,

            "threshold":
                self.threshold,

        }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    detector = EnsembleDetector(
        threshold=0.80
    )

    # Example flow
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


    result = detector.predict(
        example
    )


    print("\n========================================")
    print("ENSEMBLE TEST")
    print("========================================")

    print(
        "\nFinal prediction:",
        result["prediction"]
    )

    print(
        "Ensemble attack probability:",
        f"{result['attack_probability']:.2%}"
    )

    print("\nIndividual models:")

    for name, probability in result["models"].items():

        print(
            f"  {name:<20}"
            f"{probability:.2%}"
        )
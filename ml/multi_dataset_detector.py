import joblib
import pandas as pd
from pathlib import Path


# ============================================================
# MODEL PATHS
# ============================================================

UNSW_MODEL_PATH = Path("ml/ids_model.pkl")

CICIDS_RF_PATH = Path("ml/cicids_random_forest.pkl")
CICIDS_ET_PATH = Path("ml/cicids_extra_trees.pkl")
CICIDS_GB_PATH = Path("ml/cicids_gradient_boosting.pkl")

ISOLATION_FOREST_PATH = Path("ml/isolation_forest.pkl")


# ============================================================
# FEATURE DEFINITIONS
# ============================================================

# ------------------------------------------------------------
# UNSW-NB15
# ------------------------------------------------------------

UNSW_FEATURES = [
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
    "dwin",
]


# ------------------------------------------------------------
# CICIDS2017
# ------------------------------------------------------------

CICIDS_FEATURES = [
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
    "dwin",
]


# ============================================================
# MULTI-DATASET WEIGHTS
# ============================================================

# UNSW provides an independent supervised view.
#
# CICIDS uses three supervised models:
#   - Random Forest
#   - Extra Trees
#   - Gradient Boosting
#
# Their probabilities are averaged first.
#
# The resulting supervised multi-dataset score is:
#
#       40% UNSW
#       60% CICIDS ensemble
#
# Isolation Forest is NOT included in this probability.
# It remains an independent anomaly signal.

UNSW_WEIGHT = 0.40
CICIDS_WEIGHT = 0.60


# ============================================================
# THRESHOLD
# ============================================================

DEFAULT_THRESHOLD = 0.80


# ============================================================
# MULTI-DATASET DETECTOR
# ============================================================

class MultiDatasetDetector:

    """
    Multi-dataset IDS detector.

    Models used:

        1. UNSW-NB15 Random Forest

        2. CICIDS2017 Random Forest

        3. CICIDS2017 Extra Trees

        4. CICIDS2017 Gradient Boosting

        5. Isolation Forest

    Decision architecture:

        Live Flow
             |
             +-------------------+
             |                   |
          UNSW              CICIDS2017
             |                   |
        UNSW RF          RF + ET + GB
             |                   |
             |            CICIDS Ensemble
             |                   |
             +---------+---------+
                       |
              Multi-dataset score
                       |
                Decision Engine
                       |
              +--------+--------+
              |                 |
        Strong CICIDS      Weighted score
          evidence          >= threshold
              |                 |
            ATTACK            ATTACK
              |
              +----------------+
                       |
                    otherwise
                       |
                    NORMAL

    Isolation Forest is kept as an additional anomaly
    signal and is not treated as an attack classifier.
    """

    def __init__(self, threshold=DEFAULT_THRESHOLD):

        self.threshold = threshold

        print("\n" + "=" * 70)
        print("LOADING MULTI-DATASET IDS MODELS")
        print("=" * 70)

        # ====================================================
        # UNSW-NB15 MODEL
        # ====================================================

        print("\nLoading UNSW-NB15 model...")

        self.unsw_model = joblib.load(
            UNSW_MODEL_PATH
        )

        print(
            "  OK:",
            UNSW_MODEL_PATH
        )

        # ====================================================
        # CICIDS2017 MODELS
        # ====================================================

        print("\nLoading CICIDS2017 models...")

        self.cicids_rf = joblib.load(
            CICIDS_RF_PATH
        )

        print(
            "  OK:",
            CICIDS_RF_PATH
        )

        self.cicids_et = joblib.load(
            CICIDS_ET_PATH
        )

        print(
            "  OK:",
            CICIDS_ET_PATH
        )

        self.cicids_gb = joblib.load(
            CICIDS_GB_PATH
        )

        print(
            "  OK:",
            CICIDS_GB_PATH
        )

        # ====================================================
        # ISOLATION FOREST
        # ====================================================

        print("\nLoading Isolation Forest...")

        self.isolation_forest = joblib.load(
            ISOLATION_FOREST_PATH
        )

        print(
            "  OK:",
            ISOLATION_FOREST_PATH
        )

        print("\n" + "=" * 70)
        print("ALL MODELS LOADED")
        print("=" * 70)


    # ========================================================
    # HELPER
    # ========================================================

    @staticmethod
    def _probability_of_attack(model, dataframe):

        """
        Return probability of class 1 = ATTACK.
        """

        probabilities = model.predict_proba(
            dataframe
        )

        classes = list(
            model.classes_
        )

        if 1 in classes:

            attack_index = classes.index(1)

            return float(
                probabilities[0][attack_index]
            )

        return 0.0


    # ========================================================
    # UNSW REPRESENTATION
    # ========================================================

    def build_unsw_dataframe(self, flow):

        """
        Convert a live flow into the
        UNSW-NB15 feature schema.
        """

        row = {

            "dur": float(
                flow.get("dur", 0.0)
            ),

            "proto": str(
                flow.get("proto", "tcp")
            ).lower(),

            "spkts": float(
                flow.get("spkts", 0)
            ),

            "dpkts": float(
                flow.get("dpkts", 0)
            ),

            "sbytes": float(
                flow.get("sbytes", 0)
            ),

            "dbytes": float(
                flow.get("dbytes", 0)
            ),

            "rate": float(
                flow.get("rate", 0.0)
            ),

            "sload": float(
                flow.get("sload", 0.0)
            ),

            "dload": float(
                flow.get("dload", 0.0)
            ),

            "sinpkt": float(
                flow.get("sinpkt", 0.0)
            ),

            "dinpkt": float(
                flow.get("dinpkt", 0.0)
            ),

            "smean": float(
                flow.get("smean", 0.0)
            ),

            "dmean": float(
                flow.get("dmean", 0.0)
            ),

            "swin": float(
                flow.get("swin", 0.0)
            ),

            "dwin": float(
                flow.get("dwin", 0.0)
            ),
        }

        return pd.DataFrame(
            [row],
            columns=UNSW_FEATURES
        )


    # ========================================================
    # CICIDS REPRESENTATION
    # ========================================================

    def build_cicids_dataframe(self, flow):

        """
        Convert a live flow into the
        CICIDS2017 feature schema.
        """

        row = {

            "dur": float(
                flow.get("dur", 0.0)
            ),

            "spkts": float(
                flow.get("spkts", 0)
            ),

            "dpkts": float(
                flow.get("dpkts", 0)
            ),

            "sbytes": float(
                flow.get("sbytes", 0)
            ),

            "dbytes": float(
                flow.get("dbytes", 0)
            ),

            "rate": float(
                flow.get("rate", 0.0)
            ),

            "fwd_rate": float(
                flow.get("fwd_rate", 0.0)
            ),

            "bwd_rate": float(
                flow.get("bwd_rate", 0.0)
            ),

            "sinpkt": float(
                flow.get("sinpkt", 0.0)
            ),

            "dinpkt": float(
                flow.get("dinpkt", 0.0)
            ),

            "smean": float(
                flow.get("smean", 0.0)
            ),

            "dmean": float(
                flow.get("dmean", 0.0)
            ),

            "swin": float(
                flow.get("swin", 0.0)
            ),

            "dwin": float(
                flow.get("dwin", 0.0)
            ),
        }

        return pd.DataFrame(
            [row],
            columns=CICIDS_FEATURES
        )


    # ========================================================
    # DETECT
    # ========================================================

    def detect(self, flow):

        """
        Analyze one network flow.

        Returns:

            UNSW probability
            CICIDS RF probability
            CICIDS Extra Trees probability
            CICIDS Gradient Boosting probability
            CICIDS ensemble probability
            supervised multi-dataset probability
            Isolation Forest anomaly
            Isolation Forest score
            final prediction
            decision reason
        """

        # ====================================================
        # BUILD FEATURE REPRESENTATIONS
        # ====================================================

        unsw_df = self.build_unsw_dataframe(
            flow
        )

        cicids_df = self.build_cicids_dataframe(
            flow
        )


        # ====================================================
        # UNSW-NB15
        # ====================================================

        unsw_probability = self._probability_of_attack(
            self.unsw_model,
            unsw_df
        )


        # ====================================================
        # CICIDS2017
        # ====================================================

        cicids_rf_probability = self._probability_of_attack(
            self.cicids_rf,
            cicids_df
        )

        cicids_et_probability = self._probability_of_attack(
            self.cicids_et,
            cicids_df
        )

        cicids_gb_probability = self._probability_of_attack(
            self.cicids_gb,
            cicids_df
        )


        # ====================================================
        # CICIDS ENSEMBLE
        # ====================================================

        cicids_probability = (

            cicids_rf_probability

            + cicids_et_probability

            + cicids_gb_probability

        ) / 3.0


        # ====================================================
        # MULTI-DATASET SUPERVISED SCORE
        # ====================================================

        supervised_probability = (

            UNSW_WEIGHT
            * unsw_probability

            +

            CICIDS_WEIGHT
            * cicids_probability

        )


        # ====================================================
        # ISOLATION FOREST
        # ====================================================

        isolation_prediction = int(

            self.isolation_forest.predict(
                cicids_df
            )[0]

        )

        isolation_anomaly = (

            isolation_prediction == -1

        )

        isolation_score = float(

            self.isolation_forest.decision_function(
                cicids_df
            )[0]

        )


        # ====================================================
        # FINAL DECISION ENGINE
        # ====================================================

        # ----------------------------------------------------
        # RULE 1:
        #
        # Strong CICIDS supervised evidence.
        #
        # CICIDS already contains three independent
        # supervised classifiers:
        #
        #   Random Forest
        #   Extra Trees
        #   Gradient Boosting
        #
        # If their combined probability reaches the
        # threshold, classify as ATTACK.
        # ----------------------------------------------------

        if cicids_probability >= self.threshold:

            prediction = "ATTACK"

            reason = "CICIDS_HIGH_CONFIDENCE"


        # ----------------------------------------------------
        # RULE 2:
        #
        # Cross-dataset agreement.
        #
        # Both UNSW and CICIDS contribute to this score.
        # ----------------------------------------------------

        elif supervised_probability >= self.threshold:

            prediction = "ATTACK"

            reason = "MULTI_DATASET_HIGH_CONFIDENCE"


        # ----------------------------------------------------
        # RULE 3:
        #
        # Isolation Forest anomaly.
        #
        # IMPORTANT:
        #
        # Isolation Forest does NOT independently declare
        # an attack.
        #
        # It is only recorded as an anomaly signal.
        # ----------------------------------------------------

        elif isolation_anomaly:

            prediction = "NORMAL"

            reason = (
                "ANOMALY_SIGNAL_BELOW_ATTACK_THRESHOLD"
            )


        # ----------------------------------------------------
        # RULE 4:
        #
        # No strong supervised evidence.
        # ----------------------------------------------------

        else:

            prediction = "NORMAL"

            reason = (
                "MULTI_DATASET_LOW_CONFIDENCE"
            )


        # ====================================================
        # RESULT
        # ====================================================

        return {

            # ------------------------------------------------
            # FINAL DECISION
            # ------------------------------------------------

            "prediction": prediction,


            # ------------------------------------------------
            # FINAL SUPERVISED SCORE
            # ------------------------------------------------

            "attack_probability": round(
                supervised_probability * 100,
                2
            ),

            "supervised_probability": round(
                supervised_probability * 100,
                2
            ),


            # ------------------------------------------------
            # UNSW-NB15
            # ------------------------------------------------

            "unsw_attack_probability": round(
                unsw_probability * 100,
                2
            ),


            # ------------------------------------------------
            # CICIDS2017 INDIVIDUAL MODELS
            # ------------------------------------------------

            "cicids_random_forest": round(
                cicids_rf_probability * 100,
                2
            ),

            "cicids_extra_trees": round(
                cicids_et_probability * 100,
                2
            ),

            "cicids_gradient_boosting": round(
                cicids_gb_probability * 100,
                2
            ),


            # ------------------------------------------------
            # CICIDS ENSEMBLE
            # ------------------------------------------------

            "cicids_ensemble_probability": round(
                cicids_probability * 100,
                2
            ),


            # ------------------------------------------------
            # COMPATIBILITY FIELDS
            #
            # These are useful for the existing dashboard
            # and API.
            # ------------------------------------------------

            "random_forest_probability": round(
                cicids_rf_probability * 100,
                2
            ),

            "extra_trees_probability": round(
                cicids_et_probability * 100,
                2
            ),

            "gradient_boosting_probability": round(
                cicids_gb_probability * 100,
                2
            ),


            # ------------------------------------------------
            # ISOLATION FOREST
            # ------------------------------------------------

            "isolation_anomaly": isolation_anomaly,

            "isolation_score": round(
                isolation_score,
                6
            ),


            # ------------------------------------------------
            # DECISION REASON
            # ------------------------------------------------

            "reason": reason,


            # ------------------------------------------------
            # THRESHOLD
            # ------------------------------------------------

            "threshold": self.threshold,


            # ------------------------------------------------
            # MODELS USED
            # ------------------------------------------------

            "models_used": [

                "UNSW-NB15 Random Forest",

                "CICIDS2017 Random Forest",

                "CICIDS2017 Extra Trees",

                "CICIDS2017 Gradient Boosting",

                "Isolation Forest",

            ],
        }


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    detector = MultiDatasetDetector()

    print(
        "\nTesting detector with a sample flow..."
    )


    sample_flow = {

        "dur": 1.0,

        "proto": "tcp",

        "spkts": 10,

        "dpkts": 8,

        "sbytes": 1000,

        "dbytes": 1200,

        "rate": 18.0,

        "fwd_rate": 10.0,

        "bwd_rate": 8.0,

        "sload": 8000.0,

        "dload": 9600.0,

        "sinpkt": 0.1,

        "dinpkt": 0.12,

        "smean": 100.0,

        "dmean": 150.0,

        "swin": 65535,

        "dwin": 65535,

    }


    result = detector.detect(
        sample_flow
    )


    print(
        "\n"
        + "=" * 70
    )

    print(
        "MULTI-DATASET DETECTION RESULT"
    )

    print(
        "=" * 70
    )


    for key, value in result.items():

        print(
            f"{key}: {value}"
        )


    print(
        "=" * 70
    )
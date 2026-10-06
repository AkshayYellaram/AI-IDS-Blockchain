import joblib
import pandas as pd

MODEL_FILE = "ml/ids_model.pkl"

print("=" * 70)
print("AI-IDS LIVE MODEL PREDICTION TEST")
print("=" * 70)

# Load trained model
model = joblib.load(MODEL_FILE)

print("Model loaded successfully.")


# ------------------------------------------------------------
# Simulated flow
# ------------------------------------------------------------
# These values represent ONE network flow.
# We will replace these with real Scapy values later.

flow = {
    "dur": 1.0,
    "proto": "tcp",
    "spkts": 10,
    "dpkts": 8,
    "sbytes": 1000,
    "dbytes": 800,
    "rate": 18.0,
    "sload": 8000.0,
    "dload": 6400.0,
    "sinpkt": 0.1,
    "dinpkt": 0.125,
    "smean": 100.0,
    "dmean": 100.0,
    "swin": 8192,
    "dwin": 8192
}


# Convert to DataFrame
X = pd.DataFrame([flow])


print("\nFlow features:")
print(X.to_string(index=False))


# ------------------------------------------------------------
# Prediction
# ------------------------------------------------------------

prediction = model.predict(X)[0]

probabilities = model.predict_proba(X)[0]

normal_probability = probabilities[0]
attack_probability = probabilities[1]


print("\n" + "=" * 70)
print("PREDICTION")
print("=" * 70)

if prediction == 1:
    print("RESULT: ATTACK")
else:
    print("RESULT: NORMAL")

print(f"Normal probability: {normal_probability:.4f}")
print(f"Attack probability: {attack_probability:.4f}")

print("=" * 70)
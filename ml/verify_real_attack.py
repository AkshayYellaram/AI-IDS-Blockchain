from multi_dataset_detector import MultiDatasetDetector

print("=" * 70)
print("FULL MULTI-DATASET PORTSCAN VERIFICATION")
print("=" * 70)

# Real PortScan feature row from CICIDS2017
flow = {
    "dur": 0.000037,
    "proto": "tcp",
    "spkts": 1,
    "dpkts": 1,
    "sbytes": 0,
    "dbytes": 6,
    "rate": 54054.05405,
    "fwd_rate": 27027.02703,
    "bwd_rate": 27027.02703,
    "sload": 0.0,
    "dload": 162162.16216,
    "sinpkt": 0.0,
    "dinpkt": 0.0,
    "smean": 0.0,
    "dmean": 6.0,
    "swin": 29200,
    "dwin": 0
}

print("\nKnown dataset attack: PortScan")
print("Known target: ATTACK")

print("\nLoading complete detector...")

detector = MultiDatasetDetector()

result = detector.detect(flow)

print("\n" + "=" * 70)
print("FULL DETECTOR RESULT")
print("=" * 70)

for key, value in result.items():
    print(f"{key}: {value}")

print("=" * 70)
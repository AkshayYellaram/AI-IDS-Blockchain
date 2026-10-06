import os
import zipfile
import glob
import pandas as pd
import numpy as np

# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ZIP_FILE = os.path.join(PROJECT_ROOT, "CICIDS2017.zip")
EXTRACT_DIR = os.path.join(PROJECT_ROOT, "dataset", "CICIDS2017_raw")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "dataset")

OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "cicids2017_common.parquet"
)

# Number of rows kept from each class/file.
# We will increase this later if needed.
MAX_ROWS_PER_FILE = 50000


# ============================================================
# COMMON FEATURE SCHEMA
# ============================================================

# CICIDS2017 -> our common schema
COLUMN_MAP = {
    " Flow Duration": "dur",
    " Total Fwd Packets": "spkts",
    " Total Backward Packets": "dpkts",
    "Total Length of Fwd Packets": "sbytes",
    " Total Length of Bwd Packets": "dbytes",
    " Flow Packets/s": "rate",
    " Fwd Packets/s": "fwd_rate",
    " Bwd Packets/s": "bwd_rate",
    " Fwd IAT Mean": "sinpkt",
    " Bwd IAT Mean": "dinpkt",
    " Fwd Packet Length Mean": "smean",
    " Bwd Packet Length Mean": "dmean",
    "Init_Win_bytes_forward": "swin",
    " Init_Win_bytes_backward": "dwin",
}


# ============================================================
# CHECK ZIP
# ============================================================

if not os.path.exists(ZIP_FILE):
    raise FileNotFoundError(
        f"\nCICIDS2017.zip not found.\n"
        f"Put it here:\n{ZIP_FILE}\n"
    )


# ============================================================
# CREATE DIRECTORIES
# ============================================================

os.makedirs(EXTRACT_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================
# EXTRACT DATASET
# ============================================================

print("\n========================================")
print("CICIDS2017 DATA PREPARATION")
print("========================================")

print("\n[1/5] Extracting CICIDS2017...")

with zipfile.ZipFile(ZIP_FILE, "r") as z:
    z.extractall(EXTRACT_DIR)

print("[OK] Extraction complete.")


# ============================================================
# FIND CSV FILES
# ============================================================

csv_files = glob.glob(
    os.path.join(EXTRACT_DIR, "**", "*.csv"),
    recursive=True
)

if not csv_files:
    raise RuntimeError("No CSV files found after extraction.")

print(f"\nFound {len(csv_files)} CSV files:")

for f in csv_files:
    print("  -", os.path.basename(f))


# ============================================================
# PROCESS FILES
# ============================================================

all_data = []

print("\n[2/5] Reading and cleaning files...")

for csv_file in csv_files:

    print("\nProcessing:")
    print(os.path.basename(csv_file))

    try:
        # Read CSV
        df = pd.read_csv(
            csv_file,
            low_memory=False
        )

    except Exception as e:
        print("[ERROR]", e)
        continue

    # Remove whitespace from column names
    df.columns = df.columns.str.strip()

    # Find label column
    if "Label" not in df.columns:
        print("[WARNING] Label column missing. Skipping.")
        continue

    # Rename columns
    rename_map = {}

    for original, new in COLUMN_MAP.items():

        original_clean = original.strip()

        if original_clean in df.columns:
            rename_map[original_clean] = new

    df = df.rename(columns=rename_map)

    required = [
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
        "Label",
    ]

    missing = [
        col for col in required
        if col not in df.columns
    ]

    if missing:
        print("[WARNING] Missing:", missing)
        print("[WARNING] Skipping file.")
        continue

    # Keep only required columns
    df = df[required].copy()

    # --------------------------------------------------------
    # Convert numeric fields
    # --------------------------------------------------------

    numeric_columns = [
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

    for col in numeric_columns:

        df[col] = pd.to_numeric(
            df[col],
            errors="coerce"
        )

    # --------------------------------------------------------
    # CICIDS duration is microseconds.
    #
    # UNSW-NB15 duration is seconds.
    #
    # Convert CICIDS -> seconds.
    # --------------------------------------------------------

    df["dur"] = df["dur"] / 1_000_000.0

    # --------------------------------------------------------
    # Remove invalid/infinite values
    # --------------------------------------------------------

    df = df.replace(
        [np.inf, -np.inf],
        np.nan
    )

    df = df.dropna()

    # --------------------------------------------------------
    # Normalize labels
    #
    # BENIGN -> 0
    # Everything else -> 1
    # --------------------------------------------------------

    df["Label"] = (
        df["Label"]
        .astype(str)
        .str.strip()
    )

    df["target"] = (
        df["Label"]
        .str.upper()
        .ne("BENIGN")
        .astype(int)
    )

    # --------------------------------------------------------
    # Keep original attack name for analysis
    # --------------------------------------------------------

    df["attack_type"] = df["Label"]

    # --------------------------------------------------------
    # Remove original label
    # --------------------------------------------------------

    df = df.drop(columns=["Label"])

    # --------------------------------------------------------
    # Limit rows per file for initial experiment
    # --------------------------------------------------------

    if len(df) > MAX_ROWS_PER_FILE:

        # Preserve both classes where possible
        normal = df[df["target"] == 0]
        attack = df[df["target"] == 1]

        normal_n = min(
            len(normal),
            MAX_ROWS_PER_FILE // 2
        )

        attack_n = min(
            len(attack),
            MAX_ROWS_PER_FILE - normal_n
        )

        normal = normal.sample(
            n=normal_n,
            random_state=42
        )

        attack = attack.sample(
            n=attack_n,
            random_state=42
        )

        df = pd.concat(
            [normal, attack],
            ignore_index=True
        )

    print(
        f"  rows kept: {len(df):,} | "
        f"normal: {(df['target'] == 0).sum():,} | "
        f"attack: {(df['target'] == 1).sum():,}"
    )

    all_data.append(df)


# ============================================================
# COMBINE
# ============================================================

print("\n[3/5] Combining datasets...")

if not all_data:
    raise RuntimeError(
        "No valid CICIDS2017 data was processed."
    )

combined = pd.concat(
    all_data,
    ignore_index=True
)


# ============================================================
# FINAL CLEANUP
# ============================================================

print("\n[4/5] Final cleanup...")

feature_columns = [
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

# Replace remaining invalid values
combined = combined.replace(
    [np.inf, -np.inf],
    np.nan
)

combined = combined.dropna(
    subset=feature_columns + ["target"]
)

# Remove impossible negative values
for col in feature_columns:

    combined = combined[
        combined[col] >= 0
    ]

# Shuffle
combined = combined.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)


# ============================================================
# SAVE
# ============================================================

print("\n[5/5] Saving cleaned dataset...")

combined.to_parquet(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# SUMMARY
# ============================================================

print("\n========================================")
print("CICIDS2017 PREPARATION COMPLETE")
print("========================================")

print(
    f"Total rows : {len(combined):,}"
)

print(
    f"Normal     : {(combined['target'] == 0).sum():,}"
)

print(
    f"Attack     : {(combined['target'] == 1).sum():,}"
)

print(
    f"Attack %   : "
    f"{combined['target'].mean() * 100:.2f}%"
)

print(
    f"\nSaved to:\n{OUTPUT_FILE}"
)

print("\nFeatures:")
for feature in feature_columns:
    print("  -", feature)

print("\nAttack types:")
print(
    combined["attack_type"]
    .value_counts()
    .to_string()
)
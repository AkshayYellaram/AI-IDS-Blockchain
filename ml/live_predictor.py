from scapy.all import sniff, IP, TCP, UDP, conf
from datetime import datetime
import pandas as pd
import joblib

# Blockchain integration
import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from blockchain.blockchain_logger import BlockchainLogger


# ============================================================
# CONFIGURATION
# ============================================================

INTERFACE = conf.ifaces.dev_from_index(5)

MODEL_FILE = "ml/ids_model.pkl"

CAPTURE_TIME = 30

# ML confidence required before creating a security alert
ALERT_THRESHOLD = 0.80

# Known LAN discovery destinations
BENIGN_MULTICAST_DESTINATIONS = {
    "224.0.0.251",       # mDNS
    "239.255.255.250"    # SSDP
}


# ============================================================
# LOAD MODEL
# ============================================================

print("=" * 80)
print("AI-POWERED IDS - LIVE ML PREDICTOR")
print("=" * 80)

print("\nLoading ML model...")

model = joblib.load(MODEL_FILE)

print("Model loaded successfully.")
print(f"Interface: {INTERFACE}")
print(f"Capture time: {CAPTURE_TIME} seconds")
print(f"Alert threshold: {ALERT_THRESHOLD * 100:.0f}%")


# ============================================================
# CONNECT TO BLOCKCHAIN
# ============================================================

print("\nConnecting to blockchain...")

try:

    blockchain_logger = BlockchainLogger()

    print("Blockchain logger ready.")

except Exception as e:

    print("WARNING: Blockchain connection failed.")
    print("Reason:", e)

    blockchain_logger = None


# ============================================================
# FLOW STORAGE
# ============================================================

flows = {}


# ============================================================
# FLOW KEY
# ============================================================

def get_flow_key(packet):

    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if TCP in packet:

        protocol = "tcp"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:

        protocol = "udp"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    else:

        protocol = str(packet[IP].proto)
        src_port = 0
        dst_port = 0

    endpoint1 = (src_ip, src_port)
    endpoint2 = (dst_ip, dst_port)

    if endpoint1 <= endpoint2:

        return (
            endpoint1,
            endpoint2,
            protocol
        )

    return (
        endpoint2,
        endpoint1,
        protocol
    )


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(packet):

    if IP not in packet:
        return

    key = get_flow_key(packet)

    if key is None:
        return

    now = datetime.now()

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if TCP in packet:

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        src_window = packet[TCP].window

    elif UDP in packet:

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        src_window = 0

    else:

        src_port = 0
        dst_port = 0
        src_window = 0


    # --------------------------------------------------------
    # Create flow
    # --------------------------------------------------------

    if key not in flows:

        flows[key] = {

            "src_ip": src_ip,
            "dst_ip": dst_ip,

            "src_port": src_port,
            "dst_port": dst_port,

            "protocol": key[2],

            "first_seen": now,
            "last_seen": now,

            "src_packets": 0,
            "dst_packets": 0,

            "src_bytes": 0,
            "dst_bytes": 0,

            "src_times": [],
            "dst_times": [],

            "src_window": 0,
            "dst_window": 0
        }


    flow = flows[key]

    flow["last_seen"] = now


    # --------------------------------------------------------
    # Direction
    # --------------------------------------------------------

    if (
        src_ip == flow["src_ip"]
        and
        src_port == flow["src_port"]
    ):

        flow["src_packets"] += 1
        flow["src_bytes"] += len(packet)

        flow["src_times"].append(now)

        flow["src_window"] = src_window

    else:

        flow["dst_packets"] += 1
        flow["dst_bytes"] += len(packet)

        flow["dst_times"].append(now)

        flow["dst_window"] = src_window


# ============================================================
# INTER-PACKET TIME
# ============================================================

def average_interpacket_time(times):

    if len(times) < 2:
        return 0.0

    intervals = []

    for i in range(1, len(times)):

        delta = (
            times[i] -
            times[i - 1]
        ).total_seconds()

        intervals.append(delta)

    return sum(intervals) / len(intervals)


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def flow_to_features(flow):

    duration = (
        flow["last_seen"] -
        flow["first_seen"]
    ).total_seconds()

    if duration <= 0:
        duration = 0.000001


    src_packets = flow["src_packets"]
    dst_packets = flow["dst_packets"]

    src_bytes = flow["src_bytes"]
    dst_bytes = flow["dst_bytes"]


    total_packets = (
        src_packets +
        dst_packets
    )


    rate = total_packets / duration


    sload = (
        src_bytes * 8
    ) / duration


    dload = (
        dst_bytes * 8
    ) / duration


    sinpkt = average_interpacket_time(
        flow["src_times"]
    )


    dinpkt = average_interpacket_time(
        flow["dst_times"]
    )


    if src_packets > 0:
        smean = src_bytes / src_packets
    else:
        smean = 0.0


    if dst_packets > 0:
        dmean = dst_bytes / dst_packets
    else:
        dmean = 0.0


    return {

        "dur": duration,

        "proto": flow["protocol"],

        "spkts": src_packets,

        "dpkts": dst_packets,

        "sbytes": src_bytes,

        "dbytes": dst_bytes,

        "rate": rate,

        "sload": sload,

        "dload": dload,

        "sinpkt": sinpkt,

        "dinpkt": dinpkt,

        "smean": smean,

        "dmean": dmean,

        "swin": flow["src_window"],

        "dwin": flow["dst_window"]
    }


# ============================================================
# PREDICTION
# ============================================================

def predict_flow(flow):

    features = flow_to_features(flow)

    dataframe = pd.DataFrame([features])

    prediction = model.predict(
        dataframe
    )[0]

    probabilities = model.predict_proba(
        dataframe
    )[0]

    normal_probability = probabilities[0]

    attack_probability = probabilities[1]

    if prediction == 1:
        result = "ATTACK"
    else:
        result = "NORMAL"


    return (
        result,
        normal_probability,
        attack_probability,
        features
    )


# ============================================================
# SECURITY ALERT DECISION
# ============================================================

def determine_alert(
    flow,
    result,
    attack_probability
):

    destination_ip = flow["dst_ip"]


    # --------------------------------------------------------
    # Known multicast discovery traffic
    # --------------------------------------------------------

    if destination_ip in BENIGN_MULTICAST_DESTINATIONS:

        return (
            False,
            "BENIGN_MULTICAST_DISCOVERY"
        )


    # --------------------------------------------------------
    # ML did not classify it as attack
    # --------------------------------------------------------

    if result != "ATTACK":

        return (
            False,
            "ML_CLASSIFIED_NORMAL"
        )


    # --------------------------------------------------------
    # Confidence below alert threshold
    # --------------------------------------------------------

    if attack_probability < ALERT_THRESHOLD:

        return (
            False,
            "BELOW_ALERT_THRESHOLD"
        )


    # --------------------------------------------------------
    # Security alert
    # --------------------------------------------------------

    return (
        True,
        "ML_ATTACK_HIGH_CONFIDENCE"
    )


# ============================================================
# START CAPTURE
# ============================================================

print("\n" + "=" * 80)
print("STARTING LIVE PACKET CAPTURE")
print("=" * 80)

print("Generate normal network traffic.")
print(
    f"The system will capture for "
    f"{CAPTURE_TIME} seconds."
)

print()


sniff(
    iface=INTERFACE,
    prn=packet_callback,
    store=False,
    timeout=CAPTURE_TIME
)


# ============================================================
# ANALYSIS
# ============================================================

print("\n" + "=" * 80)
print("LIVE ML ANALYSIS")
print("=" * 80)

print(
    f"{'SOURCE':<25}"
    f"{'DESTINATION':<25}"
    f"{'PROTO':<8}"
    f"{'PACKETS':<8}"
    f"{'ML':<9}"
    f"{'ATTACK %':<10}"
    f"{'ALERT':<7}"
)

print("-" * 105)


live_features = []

security_alerts = []


# ============================================================
# PROCESS FLOWS
# ============================================================

for key, flow in flows.items():

    try:

        (
            result,
            normal_probability,
            attack_probability,
            features
        ) = predict_flow(flow)


        # ----------------------------------------------------
        # Security alert decision
        # ----------------------------------------------------

        is_alert, alert_reason = determine_alert(
            flow,
            result,
            attack_probability
        )


        # ----------------------------------------------------
        # Metadata
        # ----------------------------------------------------

        features["prediction"] = result

        features["normal_probability"] = (
            normal_probability
        )

        features["attack_probability"] = (
            attack_probability
        )

        features["src_ip"] = flow["src_ip"]

        features["dst_ip"] = flow["dst_ip"]

        features["src_port"] = flow["src_port"]

        features["dst_port"] = flow["dst_port"]

        features["security_alert"] = is_alert

        features["alert_reason"] = alert_reason


        live_features.append(
            features
        )


        # ----------------------------------------------------
        # Save security alert
        # ----------------------------------------------------

        if is_alert:

            alert_timestamp = datetime.now().isoformat()

            alert_probability_percent = round(
                attack_probability * 100
            )


            security_alerts.append({

                "timestamp": alert_timestamp,

                "src_ip": flow["src_ip"],

                "src_port": flow["src_port"],

                "dst_ip": flow["dst_ip"],

                "dst_port": flow["dst_port"],

                "protocol": flow["protocol"],

                "attack_probability": attack_probability,

                "reason": alert_reason
            })


            # ------------------------------------------------
            # SEND ALERT TO BLOCKCHAIN
            # ------------------------------------------------

            if blockchain_logger is not None:

                try:

                    blockchain_result = (
                        blockchain_logger.store_alert(

                            timestamp=alert_timestamp,

                            src_ip=flow["src_ip"],

                            dst_ip=flow["dst_ip"],

                            src_port=flow["src_port"],

                            dst_port=flow["dst_port"],

                            protocol=flow["protocol"],

                            attack_probability=(
                                alert_probability_percent
                            )
                        )
                    )

                    print()
                    print(
                        "[BLOCKCHAIN] Alert successfully stored."
                    )

                    print(
                        "[BLOCKCHAIN] Block:",
                        blockchain_result["block"]
                    )

                    print(
                        "[BLOCKCHAIN] Transaction:",
                        blockchain_result["transaction"]
                    )

                except Exception as blockchain_error:

                    print()
                    print(
                        "[BLOCKCHAIN] ERROR:",
                        blockchain_error
                    )

            else:

                print()
                print(
                    "[BLOCKCHAIN] Logger unavailable."
                )


        # ----------------------------------------------------
        # Display
        # ----------------------------------------------------

        source = (
            f"{flow['src_ip']}:{flow['src_port']}"
        )

        destination = (
            f"{flow['dst_ip']}:{flow['dst_port']}"
        )

        total_packets = (
            flow["src_packets"] +
            flow["dst_packets"]
        )


        alert_text = "YES" if is_alert else "NO"


        print(
            f"{source:<25}"
            f"{destination:<25}"
            f"{flow['protocol']:<8}"
            f"{total_packets:<8}"
            f"{result:<9}"
            f"{attack_probability * 100:>7.2f}%"
            f"{alert_text:<7}"
        )


    except Exception as e:

        print(
            f"Prediction error: {e}"
        )


# ============================================================
# SAVE LIVE FEATURES
# ============================================================

if live_features:

    live_df = pd.DataFrame(
        live_features
    )

    live_df.to_csv(
        "ml/live_features.csv",
        index=False
    )

    print("\nLive feature data saved to:")
    print("ml/live_features.csv")


# ============================================================
# SAVE SECURITY ALERTS
# ============================================================

if security_alerts:

    alerts_df = pd.DataFrame(
        security_alerts
    )

    alerts_df.to_csv(
        "ml/security_alerts.csv",
        index=False
    )

else:

    # Create an empty file with expected columns
    alerts_df = pd.DataFrame(
        columns=[
            "timestamp",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
            "attack_probability",
            "reason"
        ]
    )

    alerts_df.to_csv(
        "ml/security_alerts.csv",
        index=False
    )


# ============================================================
# SUMMARY
# ============================================================

ml_attack_count = sum(
    1
    for row in live_features
    if row["prediction"] == "ATTACK"
)


alert_count = len(
    security_alerts
)


print("\n" + "=" * 80)
print("IDS SUMMARY")
print("=" * 80)

print(
    f"Total flows analyzed : {len(flows)}"
)

print(
    f"ML ATTACK predictions: {ml_attack_count}"
)

print(
    f"Security alerts      : {alert_count}"
)

print(
    "\nSecurity alerts saved to:"
)

print(
    "ml/security_alerts.csv"
)

print("=" * 80)
print("LIVE IDS ANALYSIS COMPLETE")
print("=" * 80)
import threading
import time
from datetime import datetime

import pandas as pd
import joblib

from scapy.all import sniff, IP, TCP, UDP, ICMP, conf

from blockchain.blockchain_logger import BlockchainLogger


# ============================================================
# CONFIGURATION
# ============================================================

INTERFACE = conf.ifaces.dev_from_index(5)

MODEL_FILE = "ml/ids_model.pkl"

ALERT_THRESHOLD = 0.80

# A flow is analyzed after no new packets have been seen
# for this amount of time.
FLOW_IDLE_TIMEOUT = 3.0

# Ignore extremely small flows.
MIN_PACKETS = 2

BENIGN_MULTICAST_DESTINATIONS = {
    "224.0.0.251",
    "239.255.255.250"
}


# ============================================================
# IDS ENGINE
# ============================================================

class IDSEngine:

    def __init__(self):

        print("[IDS] Loading ML model...")

        self.model = joblib.load(MODEL_FILE)

        print("[IDS] ML model loaded.")

        self.running = False

        self.capture_thread = None
        self.analysis_thread = None

        self.flows = {}

        self.results = []
        self.alerts = []

        self.lock = threading.Lock()

        # ----------------------------------------------------
        # Blockchain
        # ----------------------------------------------------

        try:

            self.blockchain = BlockchainLogger()

            print("[IDS] Blockchain logger connected.")

        except Exception as e:

            print("[IDS] Blockchain unavailable:", e)

            self.blockchain = None


    # ========================================================
    # FLOW KEY
    # ========================================================

    def get_flow_key(self, packet):

        if IP not in packet:
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # TCP
        if TCP in packet:

            protocol = "tcp"

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        # UDP
        elif UDP in packet:

            protocol = "udp"

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # ICMP
        elif ICMP in packet:

            protocol = "icmp"

            src_port = 0
            dst_port = 0

        # Other IP protocols
        else:

            protocol = str(packet[IP].proto)

            src_port = 0
            dst_port = 0


        endpoint1 = (
            src_ip,
            src_port
        )

        endpoint2 = (
            dst_ip,
            dst_port
        )


        # Canonical bidirectional flow key
        if endpoint1 <= endpoint2:

            return (
                endpoint1,
                endpoint2,
                protocol
            )

        else:

            return (
                endpoint2,
                endpoint1,
                protocol
            )


    # ========================================================
    # PACKET CALLBACK
    # ========================================================

    def packet_callback(self, packet):

        if IP not in packet:
            return


        key = self.get_flow_key(packet)

        if key is None:
            return


        now = datetime.now()

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst


        # ----------------------------------------------------
        # Determine protocol and ports
        # ----------------------------------------------------

        if TCP in packet:

            protocol = "tcp"

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            src_window = packet[TCP].window

        elif UDP in packet:

            protocol = "udp"

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            src_window = 0

        elif ICMP in packet:

            protocol = "icmp"

            src_port = 0
            dst_port = 0

            src_window = 0

        else:

            protocol = str(packet[IP].proto)

            src_port = 0
            dst_port = 0

            src_window = 0


        # ====================================================
        # CREATE NEW FLOW
        # ====================================================

        if key not in self.flows:

            self.flows[key] = {

                "src_ip": src_ip,
                "dst_ip": dst_ip,

                "src_port": src_port,
                "dst_port": dst_port,

                "protocol": protocol,

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


        flow = self.flows[key]

        flow["last_seen"] = now


        # ====================================================
        # DETERMINE FLOW DIRECTION
        # ====================================================

        if (
            src_ip == flow["src_ip"]
            and src_port == flow["src_port"]
        ):

            # Source → Destination

            flow["src_packets"] += 1

            flow["src_bytes"] += len(packet)

            flow["src_times"].append(now)

            flow["src_window"] = src_window

        else:

            # Destination → Source

            flow["dst_packets"] += 1

            flow["dst_bytes"] += len(packet)

            flow["dst_times"].append(now)

            flow["dst_window"] = src_window


    # ========================================================
    # AVERAGE INTER-PACKET TIME
    # ========================================================

    def average_interpacket_time(self, times):

        if len(times) < 2:

            return 0.0


        intervals = []

        for i in range(1, len(times)):

            delta = (
                times[i] - times[i - 1]
            ).total_seconds()

            intervals.append(delta)


        return sum(intervals) / len(intervals)


    # ========================================================
    # FLOW → ML FEATURES
    # ========================================================

    def flow_to_features(self, flow):

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


        # Packet rate
        rate = total_packets / duration


        # Source load
        sload = (
            src_bytes * 8
        ) / duration


        # Destination load
        dload = (
            dst_bytes * 8
        ) / duration


        # Inter-packet times
        sinpkt = self.average_interpacket_time(
            flow["src_times"]
        )

        dinpkt = self.average_interpacket_time(
            flow["dst_times"]
        )


        # Mean packet sizes
        smean = (
            src_bytes / src_packets
            if src_packets > 0
            else 0.0
        )

        dmean = (
            dst_bytes / dst_packets
            if dst_packets > 0
            else 0.0
        )


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


    # ========================================================
    # ANALYZE FLOW
    # ========================================================

    def analyze_flow(self, flow):

        features = self.flow_to_features(flow)


        dataframe = pd.DataFrame(
            [features]
        )


        # ----------------------------------------------------
        # ML prediction
        # ----------------------------------------------------

        prediction = self.model.predict(
            dataframe
        )[0]


        probabilities = self.model.predict_proba(
            dataframe
        )[0]


        normal_probability = float(
            probabilities[0]
        )

        attack_probability = float(
            probabilities[1]
        )


        result = (
            "ATTACK"
            if prediction == 1
            else "NORMAL"
        )


        # ----------------------------------------------------
        # Alert decision
        # ----------------------------------------------------

        destination_ip = flow["dst_ip"]

        is_alert = False

        reason = "ML_CLASSIFIED_NORMAL"


        # Multicast discovery traffic
        if destination_ip in BENIGN_MULTICAST_DESTINATIONS:

            result = "NORMAL"
            attack_probability = 0.0
            is_alert = False
            reason = "BENIGN_MULTICAST_DISCOVERY"


        elif result == "ATTACK":

            if attack_probability >= ALERT_THRESHOLD:

                is_alert = True

                reason = (
                    "ML_ATTACK_HIGH_CONFIDENCE"
                )

            else:

                reason = (
                    "BELOW_ALERT_THRESHOLD"
                )


        # ====================================================
        # RESULT OBJECT
        # ====================================================

        result_data = {

            "timestamp":
                datetime.now().isoformat(),

            "src_ip":
                flow["src_ip"],

            "src_port":
                flow["src_port"],

            "dst_ip":
                flow["dst_ip"],

            "dst_port":
                flow["dst_port"],

            "protocol":
                flow["protocol"],

            "packets":
                flow["src_packets"] +
                flow["dst_packets"],

            "prediction":
                result,

            "normal_probability":
                round(
                    normal_probability,
                    4
                ),

            "attack_probability":
                round(
                    attack_probability,
                    4
                ),

            "security_alert":
                is_alert,

            "alert_reason":
                reason
        }


        # ====================================================
        # SAVE RESULT
        # ====================================================

        with self.lock:

            self.results.append(
                result_data
            )

            self.results = (
                self.results[-100:]
            )


        # ====================================================
        # BLOCKCHAIN
        # ====================================================

        if is_alert:

            self.store_blockchain_alert(
                result_data
            )


        return result_data


    # ========================================================
    # BLOCKCHAIN ALERT
    # ========================================================

    def store_blockchain_alert(self, alert):

        if self.blockchain is None:

            return


        try:

            probability = round(
                alert["attack_probability"] * 100
            )


            blockchain_result = (
                self.blockchain.store_alert(

                    timestamp=
                        alert["timestamp"],

                    src_ip=
                        alert["src_ip"],

                    dst_ip=
                        alert["dst_ip"],

                    src_port=
                        alert["src_port"],

                    dst_port=
                        alert["dst_port"],

                    protocol=
                        alert["protocol"],

                    attack_probability=
                        probability
                )
            )


            # Add blockchain information
            # to dashboard alert

            alert["blockchain_block"] = (
                blockchain_result["block"]
            )

            alert["blockchain_transaction"] = (
                blockchain_result["transaction"]
            )

            alert["blockchain_hash"] = (
                blockchain_result["hash"]
            )


            with self.lock:

                self.alerts.append(
                    alert.copy()
                )

                self.alerts = (
                    self.alerts[-100:]
                )


            print()
            print(
                "[IDS] SECURITY ALERT STORED ON BLOCKCHAIN"
            )

            print(
                "[IDS] Block:",
                blockchain_result["block"]
            )

            print(
                "[IDS] Transaction:",
                blockchain_result["transaction"]
            )

            print(
                "[IDS] SHA-256:",
                blockchain_result["hash"]
            )

            print()


        except Exception as e:

            print(
                "[IDS] Blockchain error:",
                e
            )


    # ========================================================
    # PACKET CAPTURE LOOP
    # ========================================================

    def capture_loop(self):

        print(
            "[IDS] Live packet capture started."
        )

        print(
            "[IDS] Interface:",
            INTERFACE
        )


        sniff(

            iface=INTERFACE,

            prn=self.packet_callback,

            store=False,

            stop_filter=
                lambda packet:
                not self.running
        )


        print(
            "[IDS] Packet capture stopped."
        )


    # ========================================================
    # FLOW ANALYSIS LOOP
    # ========================================================

    def analysis_loop(self):

        analyzed_keys = set()


        while self.running:

            now = datetime.now()


            # Copy flow list safely
            with self.lock:

                current_flows = list(
                    self.flows.items()
                )


            for key, flow in current_flows:

                # Already analyzed
                if key in analyzed_keys:

                    continue


                total_packets = (
                    flow["src_packets"] +
                    flow["dst_packets"]
                )


                # Need minimum packet count
                if total_packets < MIN_PACKETS:

                    continue


                # ------------------------------------------------
                # Wait until flow becomes idle
                # ------------------------------------------------

                idle_time = (
                    now - flow["last_seen"]
                ).total_seconds()


                if idle_time < FLOW_IDLE_TIMEOUT:

                    continue


                # ------------------------------------------------
                # Analyze completed flow
                # ------------------------------------------------

                try:

                    result = self.analyze_flow(
                        flow
                    )


                    analyzed_keys.add(key)


                    print(
                        "[IDS] Flow analyzed:",
                        result["src_ip"],
                        "→",
                        result["dst_ip"],
                        result["protocol"],
                        "packets=",
                        result["packets"],
                        "prediction=",
                        result["prediction"],
                        "attack_probability=",
                        round(
                            result[
                                "attack_probability"
                            ] * 100,
                            2
                        ),
                        "%"
                    )


                except Exception as e:

                    print(
                        "[IDS] Analysis error:",
                        e
                    )


            time.sleep(1)


    # ========================================================
    # START IDS
    # ========================================================

    def start(self):

        if self.running:

            return False


        print()
        print(
            "======================================"
        )
        print(
            "        STARTING LIVE IDS"
        )
        print(
            "======================================"
        )


        self.running = True


        # Reset current session
        with self.lock:

            self.flows = {}

            self.results = {}

            self.results = []

            self.alerts = []


        # ----------------------------------------------------
        # Capture thread
        # ----------------------------------------------------

        self.capture_thread = threading.Thread(

            target=self.capture_loop,

            daemon=True
        )


        # ----------------------------------------------------
        # Analysis thread
        # ----------------------------------------------------

        self.analysis_thread = threading.Thread(

            target=self.analysis_loop,

            daemon=True
        )


        self.capture_thread.start()

        self.analysis_thread.start()


        return True


    # ========================================================
    # STOP IDS
    # ========================================================

    def stop(self):

        if not self.running:

            return True


        print(
            "[IDS] Stopping live IDS..."
        )


        self.running = False


        return True


    # ========================================================
    # STATUS
    # ========================================================

    def get_status(self):

        with self.lock:

            attack_count = sum(

                1

                for item in self.results

                if item["prediction"] == "ATTACK"

            )


            alert_count = sum(

                1

                for item in self.results

                if item["security_alert"]

            )


            return {

                "running":
                    self.running,

                "flows":
                    len(self.results),

                "attacks":
                    attack_count,

                "alerts":
                    alert_count
            }


    # ========================================================
    # RESULTS
    # ========================================================

    def get_results(self):

        with self.lock:

            return list(
                reversed(
                    self.results[-50:]
                )
            )


    # ========================================================
    # ALERTS
    # ========================================================

    def get_alerts(self):

        with self.lock:

            return list(
                reversed(
                    self.alerts[-50:]
                )
            )


# ============================================================
# GLOBAL IDS ENGINE
# ============================================================

ids_engine = IDSEngine()
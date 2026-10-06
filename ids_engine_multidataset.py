import threading
import time
from datetime import datetime

import numpy as np
import joblib

from ml.multi_dataset_detector import MultiDatasetDetector

from scapy.all import (
    AsyncSniffer,
    IP,
    TCP,
    UDP,
    ICMP,
)

from blockchain.blockchain_logger import BlockchainLogger


# ============================================================
# CONFIGURATION
# ============================================================

INTERFACE = r"\Device\NPF_{D5C9670E-4686-4AF5-B253-205E238EE144}"

ISOLATION_MODEL_FILE = "ml/isolation_forest.pkl"

ALERT_THRESHOLD = 0.80

FLOW_IDLE_TIMEOUT = 3.0

# Ignore extremely small flows.
MIN_PACKETS = 2

MAX_RESULTS = 300

MAX_ALERTS = 100

BENIGN_MULTICAST_DESTINATIONS = {
    "224.0.0.251",
    "239.255.255.250"
}


# ============================================================
# COMMON FEATURE SCHEMA
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
# IDS ENGINE
# ============================================================

class IDSEngine:

    def __init__(self):

        # ----------------------------------------------------
        # Runtime state
        # ----------------------------------------------------

        self.running = False

        self.lock = threading.RLock()

        self.capture_thread = None
        self.analysis_thread = None

        self.sniffer = None

        # ----------------------------------------------------
        # Flow state
        # ----------------------------------------------------

        self.flows = {}

        # ----------------------------------------------------
        # Results
        # ----------------------------------------------------

        self.results = []

        self.alerts = []

        # ----------------------------------------------------
        # Counters
        # ----------------------------------------------------

        self.packet_count = 0

        self.flow_analyzed_count = 0

        self.attack_prediction_count = 0

        self.session_alert_count = 0

        # ----------------------------------------------------
        # Session
        # ----------------------------------------------------

        self.start_time = None

        # ----------------------------------------------------
        # Load multi-dataset detector
        # ----------------------------------------------------

        print("\n========================================")
        print("INITIALIZING AI IDS ENGINE")
        print("========================================")

        print("\n[IDS] Loading full multi-dataset detector...")

        self.multi_dataset_detector = MultiDatasetDetector()

        print("[IDS] Full detector ready:")
        print("      UNSW-NB15")
        print("      CICIDS2017 Random Forest")
        print("      CICIDS2017 Extra Trees")
        print("      CICIDS2017 Gradient Boosting")
        print("      Isolation Forest")

        # ----------------------------------------------------
        # Isolation Forest
        # ----------------------------------------------------

        print(
            "\n[IDS] Loading anomaly detector..."
        )

        self.isolation_forest = joblib.load(
            ISOLATION_MODEL_FILE
        )

        print(
            f"[IDS] Loaded isolation forest: "
            f"{ISOLATION_MODEL_FILE}"
        )

        # ----------------------------------------------------
        # Blockchain
        # ----------------------------------------------------

        try:

            self.blockchain = BlockchainLogger()

            print(
                "[IDS] Blockchain logger connected."
            )

        except Exception as e:

            self.blockchain = None

            print(
                "[IDS] Blockchain unavailable:",
                e
            )

        # ----------------------------------------------------
        # Configuration
        # ----------------------------------------------------

        print(
            f"\n[IDS] Alert threshold: "
            f"{ALERT_THRESHOLD:.0%}"
        )

        print(
            f"[IDS] Flow idle timeout: "
            f"{FLOW_IDLE_TIMEOUT:.1f}s"
        )

        print(
            f"[IDS] Minimum packets: "
            f"{MIN_PACKETS}"
        )

        print(
            f"[IDS] Interface: "
            f"{INTERFACE}"
        )

        print(
            "\n[IDS] Engine ready."
        )


    # ========================================================
    # FLOW KEY
    # ========================================================

    def get_flow_key(
        self,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol
    ):

        endpoint_a = (
            src_ip,
            int(src_port),
            protocol
        )

        endpoint_b = (
            dst_ip,
            int(dst_port),
            protocol
        )

        if endpoint_a <= endpoint_b:

            return (
                endpoint_a,
                endpoint_b
            )

        return (
            endpoint_b,
            endpoint_a
        )


    # ========================================================
    # PACKET INFORMATION
    # ========================================================

    def get_packet_info(self, packet):

        if not packet.haslayer(IP):

            return None

        ip = packet[IP]

        src_ip = ip.src

        dst_ip = ip.dst

        # ----------------------------------------------------
        # TCP
        # ----------------------------------------------------

        if packet.haslayer(TCP):

            transport = packet[TCP]

            protocol = "tcp"

            src_port = int(
                transport.sport
            )

            dst_port = int(
                transport.dport
            )

            window = int(
                getattr(
                    transport,
                    "window",
                    0
                )
            )

        # ----------------------------------------------------
        # UDP
        # ----------------------------------------------------

        elif packet.haslayer(UDP):

            transport = packet[UDP]

            protocol = "udp"

            src_port = int(
                transport.sport
            )

            dst_port = int(
                transport.dport
            )

            window = 0

        # ----------------------------------------------------
        # ICMP
        # ----------------------------------------------------

        elif packet.haslayer(ICMP):

            protocol = "icmp"

            src_port = 0

            dst_port = 0

            window = 0

        else:

            return None

        return {

            "src_ip":
                src_ip,

            "dst_ip":
                dst_ip,

            "src_port":
                src_port,

            "dst_port":
                dst_port,

            "protocol":
                protocol,

            "window":
                window,

            "packet_length":
                len(packet),

            "timestamp":
                float(packet.time)

        }


    # ========================================================
    # PROCESS PACKET
    # ========================================================

    def process_packet(
        self,
        packet
    ):

        try:

            info = self.get_packet_info(
                packet
            )

            if info is None:

                return

            self.packet_count += 1

            key = self.get_flow_key(
                info["src_ip"],
                info["src_port"],
                info["dst_ip"],
                info["dst_port"],
                info["protocol"]
            )

            now = info["timestamp"]

            with self.lock:

                # ------------------------------------------------
                # New flow
                # ------------------------------------------------

                if key not in self.flows:

                    self.flows[key] = {

                        "key":
                            key,

                        "first_seen":
                            now,

                        "last_seen":
                            now,

                        "packet_count":
                            0,

                        "forward_packets":
                            0,

                        "backward_packets":
                            0,

                        "forward_bytes":
                            0,

                        "backward_bytes":
                            0,

                        "timestamps":
                            [],

                        "forward_timestamps":
                            [],

                        "backward_timestamps":
                            [],

                        "forward_lengths":
                            [],

                        "backward_lengths":
                            [],

                        "forward_window":
                            0,

                        "backward_window":
                            0,

                        "src_ip":
                            info["src_ip"],

                        "dst_ip":
                            info["dst_ip"],

                        "src_port":
                            info["src_port"],

                        "dst_port":
                            info["dst_port"],

                        "protocol":
                            info["protocol"],

                    }

                flow = self.flows[key]

                # ------------------------------------------------
                # Direction
                # ------------------------------------------------

                # Direction is based on the FIRST packet of the flow,
                # not on lexical sorting of the bidirectional flow key.
                #
                # forward  = original sender -> receiver
                # backward = receiver -> original sender

                packet_endpoint = (
                    info["src_ip"],
                    info["src_port"],
                    info["protocol"]
                )

                is_forward = (
                    packet_endpoint
                    ==
                    (
                        flow["src_ip"],
                        flow["src_port"],
                        flow["protocol"]
                    )
                )

                # ------------------------------------------------
                # Common values
                # ------------------------------------------------

                flow["packet_count"] += 1

                flow["last_seen"] = now

                flow["timestamps"].append(
                    now
                )

                packet_length = (
                    info["packet_length"]
                )

                # ------------------------------------------------
                # Forward
                # ------------------------------------------------

                if is_forward:

                    flow[
                        "forward_packets"
                    ] += 1

                    flow[
                        "forward_bytes"
                    ] += packet_length

                    flow[
                        "forward_timestamps"
                    ].append(now)

                    flow[
                        "forward_lengths"
                    ].append(
                        packet_length
                    )

                    if (
                        flow[
                            "forward_window"
                        ] == 0
                    ):

                        flow[
                            "forward_window"
                        ] = info["window"]

                # ------------------------------------------------
                # Backward
                # ------------------------------------------------

                else:

                    flow[
                        "backward_packets"
                    ] += 1

                    flow[
                        "backward_bytes"
                    ] += packet_length

                    flow[
                        "backward_timestamps"
                    ].append(now)

                    flow[
                        "backward_lengths"
                    ].append(
                        packet_length
                    )

                    if (
                        flow[
                            "backward_window"
                        ] == 0
                    ):

                        flow[
                            "backward_window"
                        ] = info["window"]

        except Exception as e:

            print(
                "[IDS] Packet processing error:",
                repr(e)
            )


    # ========================================================
    # MEAN INTER-PACKET TIME
    # ========================================================

    def mean_iat(
        self,
        timestamps
    ):

        if len(timestamps) < 2:

            return 0.0

        intervals = np.diff(
            np.asarray(
                timestamps,
                dtype=float
            )
        )

        if len(intervals) == 0:

            return 0.0

        return float(
            np.mean(intervals)
        )


    # ========================================================
    # BUILD FEATURES
    # ========================================================

    def build_features(self, flow):

        duration = max(
            flow["last_seen"] - flow["first_seen"],
            1e-6
        )

        total_packets = (
            flow["forward_packets"]
            +
            flow["backward_packets"]
        )

        rate = total_packets / duration

        fwd_rate = (
            flow["forward_packets"]
            /
            duration
        )

        bwd_rate = (
            flow["backward_packets"]
            /
            duration
        )

        # UNSW-NB15 live-compatible load features

        sload = (
            flow["forward_bytes"]
            *
            8.0
        ) / duration

        dload = (
            flow["backward_bytes"]
            *
            8.0
        ) / duration

        if flow["forward_lengths"]:

            smean = float(
                np.mean(
                    flow["forward_lengths"]
                )
            )

        else:

            smean = 0.0

        if flow["backward_lengths"]:

            dmean = float(
                np.mean(
                    flow["backward_lengths"]
                )
            )

        else:

            dmean = 0.0

        sinpkt = self.mean_iat(
            flow["forward_timestamps"]
        )

        dinpkt = self.mean_iat(
            flow["backward_timestamps"]
        )

        return {

            "dur":
                duration,

            "proto":
                flow["protocol"],

            "spkts":
                flow["forward_packets"],

            "dpkts":
                flow["backward_packets"],

            "sbytes":
                flow["forward_bytes"],

            "dbytes":
                flow["backward_bytes"],

            "rate":
                rate,

            "fwd_rate":
                fwd_rate,

            "bwd_rate":
                bwd_rate,

            "sload":
                sload,

            "dload":
                dload,

            "sinpkt":
                sinpkt,

            "dinpkt":
                dinpkt,

            "smean":
                smean,

            "dmean":
                dmean,

            "swin":
                flow["forward_window"],

            "dwin":
                flow["backward_window"]

        }


    # ========================================================
    # MODEL PREDICTION
    # ========================================================

    def predict(self, features):

        return self.multi_dataset_detector.detect(
            features
        )


    # ========================================================
    # ANALYZE FLOW
    # ========================================================

    def analyze_flow(
        self,
        flow
    ):

        features = self.build_features(
            flow
        )

        print(
            "[DEBUG FEATURES]",
            features
        )

        prediction = self.predict(
            features
        )

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # IMPORTANT:
        # MultiDatasetDetector already returns
        # attack_probability as a percentage.
        #
        # Example:
        # 67.68 means 67.68%.
        #
        # DO NOT multiply by 100 again.

        probability_percent = float(
            prediction[
                "attack_probability"
            ]
        )

        result = {

            "timestamp":
                timestamp,

            "src_ip":
                flow["src_ip"],

            "dst_ip":
                flow["dst_ip"],

            "src_port":
                flow["src_port"],

            "dst_port":
                flow["dst_port"],

            "protocol":
                flow["protocol"],

            "packets":
                flow["packet_count"],

            "prediction":
                prediction["prediction"],

            "attack_probability":
                round(
                    probability_percent,
                    2
                ),

            # These values are already percentages
            # from MultiDatasetDetector.

            "random_forest_probability":
                round(
                    float(
                        prediction[
                            "random_forest_probability"
                        ]
                    ),
                    2
                ),

            "extra_trees_probability":
                round(
                    float(
                        prediction[
                            "extra_trees_probability"
                        ]
                    ),
                    2
                ),

            "gradient_boosting_probability":
                round(
                    float(
                        prediction[
                            "gradient_boosting_probability"
                        ]
                    ),
                    2
                ),

            "isolation_anomaly":
                bool(
                    prediction[
                        "isolation_anomaly"
                    ]
                ),

            "isolation_score":
                round(
                    prediction[
                        "isolation_score"
                    ],
                    6
                ),

            "reason":
                prediction["reason"],

            "blockchain_block":
                None,

            "blockchain_transaction":
                None,

            "alert_hash":
                None

        }

        # ----------------------------------------------------
        # Benign multicast
        # ----------------------------------------------------

        if (
            flow["dst_ip"]
            in BENIGN_MULTICAST_DESTINATIONS
        ):

            result["prediction"] = (
                "NORMAL"
            )

            result["reason"] = (
                "BENIGN_MULTICAST_DISCOVERY"
            )

            result[
                "attack_probability"
            ] = 0.0

            return result

        # ----------------------------------------------------
        # Security alert
        # ----------------------------------------------------

        if (
            prediction["prediction"]
            ==
            "ATTACK"
        ):

            self.session_alert_count += 1

            # -----------------------------------------------
            # Blockchain
            # -----------------------------------------------

            if self.blockchain is not None:

                try:

                    blockchain_result = (
                        self.blockchain.store_alert(

                            timestamp,

                            flow["src_ip"],

                            flow["dst_ip"],

                            flow["src_port"],

                            flow["dst_port"],

                            flow["protocol"],

                            probability_percent

                        )
                    )

                    result[
                        "blockchain_block"
                    ] = (
                        blockchain_result[
                            "block"
                        ]
                    )

                    result[
                        "blockchain_transaction"
                    ] = (
                        blockchain_result[
                            "transaction"
                        ]
                    )

                    result[
                        "alert_hash"
                    ] = (
                        blockchain_result[
                            "hash"
                        ]
                    )

                except Exception as e:

                    result["reason"] += (
                        " | BLOCKCHAIN_ERROR: "
                        +
                        str(e)
                    )

            # -----------------------------------------------
            # Security alert list
            # -----------------------------------------------

            with self.lock:

                self.alerts.insert(
                    0,
                    result
                )

                self.alerts = (
                    self.alerts[
                        :MAX_ALERTS
                    ]
                )

        return result


    # ========================================================
    # ANALYSIS LOOP
    # ========================================================

    def analysis_loop(self):

        print(
            "[IDS] Analysis thread started."
        )

        while self.running:

            ready_flows = []

            now = time.time()

            # ------------------------------------------------
            # Find completed flows
            # ------------------------------------------------

            with self.lock:

                for key, flow in list(
                    self.flows.items()
                ):

                    idle_time = (
                        now
                        -
                        flow["last_seen"]
                    )

                    if (
                        flow["packet_count"]
                        >=
                        MIN_PACKETS
                        and
                        idle_time
                        >=
                        FLOW_IDLE_TIMEOUT
                    ):

                        # Copy the complete flow

                        ready_flows.append(
                            (
                                key,
                                flow.copy()
                            )
                        )

                        # Remove from active flows.

                        del self.flows[key]

            # ------------------------------------------------
            # Analyze completed flows
            # ------------------------------------------------

            for key, flow in ready_flows:

                try:

                    result = self.analyze_flow(
                        flow
                    )

                    with self.lock:

                        self.results.insert(
                            0,
                            result
                        )

                        self.results = (
                            self.results[
                                :MAX_RESULTS
                            ]
                        )

                        self.flow_analyzed_count += 1

                        if (
                            result["prediction"]
                            ==
                            "ATTACK"
                        ):

                            self.attack_prediction_count += 1

                    print(
                        "[IDS] FLOW:",
                        flow["src_ip"],
                        ":",
                        flow["src_port"],
                        "->",
                        flow["dst_ip"],
                        ":",
                        flow["dst_port"],
                        "|",
                        flow["protocol"],
                        "|",
                        result[
                            "prediction"
                        ],
                        "|",
                        result[
                            "attack_probability"
                        ],
                        "%"
                    )

                except Exception as e:

                    print(
                        "[IDS] Flow analysis error:",
                        repr(e)
                    )

            time.sleep(
                0.25
            )

        print(
            "[IDS] Analysis thread stopped."
        )


    # ========================================================
    # CAPTURE LOOP
    # ========================================================

    def capture_loop(self):

        print(
            "[IDS] Capture thread started."
        )

        print(
            "[IDS] Capturing on:",
            INTERFACE
        )

        try:

            self.sniffer = AsyncSniffer(

                iface=INTERFACE,

                prn=self.process_packet,

                store=False

            )

            self.sniffer.start()

            while self.running:

                time.sleep(
                    0.2
                )

        except Exception as e:

            print(
                "[IDS] Capture error:",
                repr(e)
            )

        finally:

            print(
                "[IDS] Capture thread stopped."
            )


    # ========================================================
    # START
    # ========================================================

    def start(self):

        with self.lock:

            if self.running:

                return {
                    "status":
                        "already_running"
                }

            # -----------------------------------------------
            # New session
            # -----------------------------------------------

            self.running = True

            self.start_time = (
                time.time()
            )

            self.packet_count = 0

            self.flow_analyzed_count = 0

            self.attack_prediction_count = 0

            self.session_alert_count = 0

            self.flows.clear()

            self.results.clear()

            self.alerts.clear()

        print(
            "\n========================================"
        )

        print(
            "[IDS] LIVE IDS STARTING"
        )

        print(
            "========================================"
        )

        self.capture_thread = (
            threading.Thread(
                target=self.capture_loop,
                daemon=True
            )
        )

        self.analysis_thread = (
            threading.Thread(
                target=self.analysis_loop,
                daemon=True
            )
        )

        self.capture_thread.start()

        self.analysis_thread.start()

        return {
            "status":
                "started"
        }


    # ========================================================
    # STOP
    # ========================================================

    def stop(self):

        with self.lock:

            if not self.running:

                return {
                    "status":
                        "already_stopped"
                }

            self.running = False

        print(
            "\n[IDS] STOP requested."
        )

        # ----------------------------------------------------
        # Stop AsyncSniffer
        # ----------------------------------------------------

        try:

            if self.sniffer is not None:

                self.sniffer.stop()

        except Exception as e:

            print(
                "[IDS] Sniffer stop error:",
                repr(e)
            )

        self.sniffer = None

        return {
            "status":
                "stopped"
        }


    # ========================================================
    # STATUS
    # ========================================================

    def get_status(self):

        with self.lock:

            active_flows = len(
                self.flows
            )

            result_count = len(
                self.results
            )

            alert_count = len(
                self.alerts
            )

            running = self.running

            packet_count = (
                self.packet_count
            )

            analyzed_count = (
                self.flow_analyzed_count
            )

            attack_count = (
                self.attack_prediction_count
            )

            session_alerts = (
                self.session_alert_count
            )

        uptime = 0.0

        if (
            running
            and
            self.start_time is not None
        ):

            uptime = (
                time.time()
                -
                self.start_time
            )

        return {

            "running":
                running,

            "interface":
                str(INTERFACE),

            "packet_count":
                packet_count,

            "flow_count":
                active_flows,

            "result_count":
                result_count,

            "alert_count":
                alert_count,

            "analyzed_flow_count":
                analyzed_count,

            "attack_prediction_count":
                attack_count,

            "session_alert_count":
                session_alerts,

            "uptime":
                round(
                    uptime,
                    1
                ),

            "threshold":
                ALERT_THRESHOLD,

            "flow_idle_timeout":
                FLOW_IDLE_TIMEOUT

        }


    # ========================================================
    # RESULTS
    # ========================================================

    def get_results(self):

        with self.lock:

            return list(
                self.results
            )


    # ========================================================
    # ALERTS
    # ========================================================

    def get_alerts(self):

        with self.lock:

            return list(
                self.alerts
            )


# ============================================================
# GLOBAL ENGINE INSTANCE
# ============================================================

ids_engine = IDSEngine()
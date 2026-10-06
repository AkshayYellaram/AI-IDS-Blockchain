from scapy.all import sniff, IP, TCP, UDP, conf
from collections import defaultdict
from datetime import datetime

# Use Wi-Fi interface
INTERFACE = conf.ifaces.dev_from_index(5)

# Flow storage
flows = defaultdict(lambda: {
    "packets": 0,
    "bytes": 0,
    "first_seen": None,
    "last_seen": None,
    "protocol": None
})


def get_flow_key(packet):
    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    else:
        protocol = str(packet[IP].proto)
        src_port = 0
        dst_port = 0

    return (
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol
    )


def packet_callback(packet):

    if IP not in packet:
        return

    flow_key = get_flow_key(packet)

    if flow_key is None:
        return

    now = datetime.now()

    flow = flows[flow_key]

    flow["packets"] += 1
    flow["bytes"] += len(packet)

    if flow["first_seen"] is None:
        flow["first_seen"] = now

    flow["last_seen"] = now
    flow["protocol"] = flow_key[4]


print("=" * 100)
print("AI-POWERED IDS - LIVE FLOW MONITOR")
print("=" * 100)
print(f"Interface: {INTERFACE}")
print("Capturing traffic for 30 seconds...")
print("Generate some traffic now.")
print("=" * 100)

# Capture for exactly 30 seconds
sniff(
    iface=INTERFACE,
    prn=packet_callback,
    store=False,
    timeout=30
)

print("\n" + "=" * 100)
print("CAPTURE COMPLETE")
print("=" * 100)

print(
    f"{'SOURCE':<25}"
    f"{'DESTINATION':<25}"
    f"{'PROTO':<8}"
    f"{'PACKETS':<10}"
    f"{'BYTES':<10}"
)

print("-" * 100)

for key, flow in list(flows.items())[-20:]:

    src_ip, src_port, dst_ip, dst_port, protocol = key

    source = f"{src_ip}:{src_port}"
    destination = f"{dst_ip}:{dst_port}"

    print(
        f"{source:<25}"
        f"{destination:<25}"
        f"{protocol:<8}"
        f"{flow['packets']:<10}"
        f"{flow['bytes']:<10}"
    )

print("-" * 100)
print(f"Total flows captured: {len(flows)}")
print("=" * 100)
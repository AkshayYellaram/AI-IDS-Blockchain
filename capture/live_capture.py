from scapy.all import sniff, conf


# Windows Wi-Fi interface
INTERFACE = conf.ifaces.dev_from_index(5)


def packet_callback(packet):
    print(packet.summary())


print("=" * 60)
print("AI-IDS - LIVE PACKET CAPTURE TEST")
print("=" * 60)
print(f"Interface: {INTERFACE}")
print("Listening for packets...")
print("Press Ctrl+C to stop.")
print("=" * 60)

sniff(
    iface=INTERFACE,
    prn=packet_callback,
    store=False
)
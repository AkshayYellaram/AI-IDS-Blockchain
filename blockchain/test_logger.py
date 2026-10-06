from blockchain_logger import BlockchainLogger


logger = BlockchainLogger()


result = logger.store_alert(
    timestamp="2026-09-20T18:00:00",
    src_ip="192.168.1.35",
    dst_ip="10.0.2.15",
    src_port=4444,
    dst_port=80,
    protocol="tcp",
    attack_probability=92
)


print()
print("=" * 60)
print("LOGGER TEST SUCCESSFUL")
print("=" * 60)
print("Alert hash:", result["hash"])
print("Transaction:", result["transaction"])
print("Block:", result["block"])
print("=" * 60)
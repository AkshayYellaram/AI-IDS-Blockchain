import json
import csv
import hashlib
from web3 import Web3

from blockchain_config import GANACHE_RPC, CONTRACT_ADDRESS


# ============================================================
# CONFIGURATION
# ============================================================

ABI_FILE = "blockchain/AlertStorage_abi.json"
ALERT_FILE = "ml/security_alerts.csv"

# Your local Ganache account private key
PRIVATE_KEY = "0x82258edfd854df14dc06b0658120b11046c4dad98fd691e434170232a2d99cab"


# ============================================================
# CONNECT TO GANACHE
# ============================================================

print("=" * 70)
print("IDS ALERT → BLOCKCHAIN")
print("=" * 70)

w3 = Web3(Web3.HTTPProvider(GANACHE_RPC))

if not w3.is_connected():
    print("ERROR: Could not connect to Ganache")
    exit()

print("[+] Ganache connected")


# ============================================================
# LOAD SMART CONTRACT ABI
# ============================================================

with open(ABI_FILE, "r") as f:
    abi = json.load(f)

contract = w3.eth.contract(
    address=Web3.to_checksum_address(CONTRACT_ADDRESS),
    abi=abi
)

print("[+] Smart contract connected")
print("[+] Contract:", CONTRACT_ADDRESS)


# ============================================================
# GANACHE ACCOUNT
# ============================================================

account = w3.eth.account.from_key(PRIVATE_KEY)

print("[+] Blockchain account:", account.address)


# ============================================================
# READ SECURITY ALERT CSV
# ============================================================

try:
    with open(ALERT_FILE, "r", newline="") as f:
        reader = csv.DictReader(f)
        alerts = list(reader)

except FileNotFoundError:
    print()
    print("ERROR: security_alerts.csv was not found.")
    print("Expected location:")
    print(ALERT_FILE)
    exit()


if not alerts:
    print()
    print("No security alerts found.")
    exit()


print()
print("[+] Alerts found:", len(alerts))


# ============================================================
# PROCESS ALERTS
# ============================================================

for index, alert in enumerate(alerts, start=1):

    print()
    print("-" * 70)
    print(f"Processing alert {index}/{len(alerts)}")
    print("-" * 70)

    timestamp = alert["timestamp"]
    src_ip = alert["src_ip"]
    dst_ip = alert["dst_ip"]
    src_port = int(alert["src_port"])
    dst_port = int(alert["dst_port"])
    protocol = alert["protocol"]

    # CSV stores probability as decimal.
    # Example: 0.846666 → 84
    attack_probability = round(
        float(alert["attack_probability"]) * 100
    )

    reason = alert.get("reason", "")

    print("Timestamp:", timestamp)
    print("Source:", f"{src_ip}:{src_port}")
    print("Destination:", f"{dst_ip}:{dst_port}")
    print("Protocol:", protocol)
    print("Attack probability:", f"{attack_probability}%")
    print("Reason:", reason)


    # ========================================================
    # CREATE DATA TO HASH
    # ========================================================

    alert_data = (
        f"{timestamp}|"
        f"{src_ip}|"
        f"{dst_ip}|"
        f"{src_port}|"
        f"{dst_port}|"
        f"{protocol}|"
        f"{attack_probability}"
    )


    # ========================================================
    # SHA-256
    # ========================================================

    alert_hash = hashlib.sha256(
        alert_data.encode("utf-8")
    ).hexdigest()

    print("SHA-256:", alert_hash)


    # ========================================================
    # GET NONCE
    # ========================================================

    nonce = w3.eth.get_transaction_count(
        account.address,
        "pending"
    )


    # ========================================================
    # BUILD BLOCKCHAIN TRANSACTION
    # ========================================================

    transaction = contract.functions.storeAlert(
        alert_hash,
        timestamp,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        attack_probability
    ).build_transaction({
        "from": account.address,
        "nonce": nonce,
        "gas": 500000,
        "gasPrice": w3.to_wei(20, "gwei")
    })


    # ========================================================
    # SIGN TRANSACTION
    # ========================================================

    signed_transaction = w3.eth.account.sign_transaction(
        transaction,
        private_key=PRIVATE_KEY
    )


    # ========================================================
    # SEND TRANSACTION
    # ========================================================

    print("Sending transaction...")

    tx_hash = w3.eth.send_raw_transaction(
        signed_transaction.raw_transaction
    )

    print("Transaction:", tx_hash.hex())


    # ========================================================
    # WAIT FOR CONFIRMATION
    # ========================================================

    receipt = w3.eth.wait_for_transaction_receipt(
        tx_hash
    )

    print("[+] Confirmed")
    print("Block:", receipt.blockNumber)
    print("Gas:", receipt.gasUsed)


# ============================================================
# FINAL BLOCKCHAIN COUNT
# ============================================================

count = contract.functions.alertCount().call()

print()
print("=" * 70)
print("BLOCKCHAIN STORAGE COMPLETE")
print("=" * 70)
print("Total alerts stored on blockchain:", count)
print("=" * 70)
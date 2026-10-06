import json
import hashlib
from web3 import Web3

from blockchain_config import GANACHE_RPC, CONTRACT_ADDRESS


# ============================================================
# CONFIGURATION
# ============================================================

ABI_FILE = "blockchain/AlertStorage_abi.json"

# Paste your Ganache PRIVATE KEY here
PRIVATE_KEY = "0x82258edfd854df14dc06b0658120b11046c4dad98fd691e434170232a2d99cab"


# ============================================================
# CONNECT TO GANACHE
# ============================================================

print("=" * 60)
print("BLOCKCHAIN ALERT STORAGE TEST")
print("=" * 60)

w3 = Web3(Web3.HTTPProvider(GANACHE_RPC))

if not w3.is_connected():
    print("ERROR: Could not connect to Ganache")
    exit()

print("Ganache connected successfully")


# ============================================================
# LOAD ABI
# ============================================================

with open(ABI_FILE, "r") as f:
    abi = json.load(f)


# ============================================================
# CONNECT TO SMART CONTRACT
# ============================================================

contract = w3.eth.contract(
    address=Web3.to_checksum_address(CONTRACT_ADDRESS),
    abi=abi
)

print("Contract connected successfully")
print("Contract:", CONTRACT_ADDRESS)


# ============================================================
# GANACHE ACCOUNT
# ============================================================

account = w3.eth.account.from_key(PRIVATE_KEY)

print("Sender account:", account.address)


# ============================================================
# SAMPLE IDS ALERT
# ============================================================

timestamp = "2026-09-20T17:10:32.298511"
src_ip = "192.168.1.35"
dst_ip = "203.192.217.2"
src_port = 62242
dst_port = 53
protocol = "udp"
attack_probability = 84


# ============================================================
# CREATE ALERT DATA
# ============================================================

alert_data = (
    f"{timestamp}|"
    f"{src_ip}|"
    f"{dst_ip}|"
    f"{src_port}|"
    f"{dst_port}|"
    f"{protocol}|"
    f"{attack_probability}"
)

print()
print("Alert data:")
print(alert_data)


# ============================================================
# CREATE SHA-256 HASH
# ============================================================

alert_hash = hashlib.sha256(
    alert_data.encode("utf-8")
).hexdigest()

print()
print("SHA-256:")
print(alert_hash)


# ============================================================
# GET NONCE
# ============================================================

nonce = w3.eth.get_transaction_count(account.address)


# ============================================================
# BUILD TRANSACTION
# ============================================================

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


# ============================================================
# SIGN TRANSACTION
# ============================================================

signed_transaction = w3.eth.account.sign_transaction(
    transaction,
    private_key=PRIVATE_KEY
)


# ============================================================
# SEND TRANSACTION
# ============================================================

print()
print("Sending transaction...")

tx_hash = w3.eth.send_raw_transaction(
    signed_transaction.raw_transaction
)

print("Transaction sent!")
print("TX hash:", tx_hash.hex())


# ============================================================
# WAIT FOR CONFIRMATION
# ============================================================

print("Waiting for blockchain confirmation...")

receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

print()
print("Transaction confirmed!")
print("Block number:", receipt.blockNumber)
print("Gas used:", receipt.gasUsed)


# ============================================================
# READ ALERT COUNT
# ============================================================

count = contract.functions.alertCount().call()

print()
print("Total alerts stored:", count)


# ============================================================
# READ STORED ALERT
# ============================================================

stored_alert = contract.functions.getAlert(count).call()

print()
print("Stored blockchain alert:")
print("----------------------------------------")

print("ID:", stored_alert[0])
print("Hash:", stored_alert[1])
print("Timestamp:", stored_alert[2])
print("Source IP:", stored_alert[3])
print("Destination IP:", stored_alert[4])
print("Source Port:", stored_alert[5])
print("Destination Port:", stored_alert[6])
print("Protocol:", stored_alert[7])
print("Attack Probability:", stored_alert[8])

print("----------------------------------------")

print()
print("BLOCKCHAIN ALERT STORAGE SUCCESSFUL")
print("=" * 60)
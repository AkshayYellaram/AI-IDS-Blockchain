import json
import hashlib
from web3 import Web3

from .blockchain_config import GANACHE_RPC, CONTRACT_ADDRESS


# ============================================================
# CONFIGURATION
# ============================================================

ABI_FILE = "blockchain/AlertStorage_abi.json"

# Use the same Ganache private key you used earlier
PRIVATE_KEY = "0x82258edfd854df14dc06b0658120b11046c4dad98fd691e434170232a2d99cab"


# ============================================================
# BLOCKCHAIN LOGGER
# ============================================================

class BlockchainLogger:

    def __init__(self):

        # Connect to Ganache
        self.w3 = Web3(
            Web3.HTTPProvider(GANACHE_RPC)
        )

        if not self.w3.is_connected():
            raise Exception(
                "Could not connect to Ganache"
            )

        # Load contract ABI
        with open(ABI_FILE, "r") as f:
            abi = json.load(f)

        # Connect to smart contract
        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(
                CONTRACT_ADDRESS
            ),
            abi=abi
        )

        # Load Ganache account
        self.account = self.w3.eth.account.from_key(
            PRIVATE_KEY
        )

        print("[BLOCKCHAIN] Connected")
        print(
            "[BLOCKCHAIN] Account:",
            self.account.address
        )

    # ========================================================
    # STORE ALERT
    # ========================================================

    def store_alert(
        self,
        timestamp,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        attack_probability
    ):

        # ----------------------------------------------------
        # Create deterministic alert string
        # ----------------------------------------------------

        alert_data = (
            f"{timestamp}|"
            f"{src_ip}|"
            f"{dst_ip}|"
            f"{src_port}|"
            f"{dst_port}|"
            f"{protocol}|"
            f"{attack_probability}"
        )

        # ----------------------------------------------------
        # SHA-256
        # ----------------------------------------------------

        alert_hash = hashlib.sha256(
            alert_data.encode("utf-8")
        ).hexdigest()

        print()
        print("[BLOCKCHAIN] New security alert")
        print(
            "[BLOCKCHAIN] Source:",
            f"{src_ip}:{src_port}"
        )
        print(
            "[BLOCKCHAIN] Destination:",
            f"{dst_ip}:{dst_port}"
        )
        print(
            "[BLOCKCHAIN] Probability:",
            f"{attack_probability}%"
        )
        print(
            "[BLOCKCHAIN] SHA-256:",
            alert_hash
        )

        # ----------------------------------------------------
        # Get pending transaction nonce
        # ----------------------------------------------------

        nonce = self.w3.eth.get_transaction_count(
            self.account.address,
            "pending"
        )

        # ----------------------------------------------------
        # Build transaction
        # ----------------------------------------------------

        transaction = self.contract.functions.storeAlert(
            alert_hash,
            timestamp,
            src_ip,
            dst_ip,
            int(src_port),
            int(dst_port),
            protocol,
            int(attack_probability)
        ).build_transaction({

            "from": self.account.address,
            "nonce": nonce,
            "gas": 500000,
            "gasPrice": self.w3.to_wei(
                20,
                "gwei"
            )
        })

        # ----------------------------------------------------
        # Sign transaction
        # ----------------------------------------------------

        signed_transaction = (
            self.w3.eth.account.sign_transaction(
                transaction,
                private_key=PRIVATE_KEY
            )
        )

        # ----------------------------------------------------
        # Send transaction
        # ----------------------------------------------------

        tx_hash = self.w3.eth.send_raw_transaction(
            signed_transaction.raw_transaction
        )

        print(
            "[BLOCKCHAIN] Transaction:",
            tx_hash.hex()
        )

        # ----------------------------------------------------
        # Wait for confirmation
        # ----------------------------------------------------

        receipt = (
            self.w3.eth.wait_for_transaction_receipt(
                tx_hash
            )
        )

        print(
            "[BLOCKCHAIN] Confirmed in block:",
            receipt.blockNumber
        )

        print(
            "[BLOCKCHAIN] Gas used:",
            receipt.gasUsed
        )

        return {
            "hash": alert_hash,
            "transaction": tx_hash.hex(),
            "block": receipt.blockNumber,
            "gas": receipt.gasUsed
        }
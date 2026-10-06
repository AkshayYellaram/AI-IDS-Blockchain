import json
from web3 import Web3
from blockchain_config import GANACHE_RPC, CONTRACT_ADDRESS


print("=" * 60)
print("BLOCKCHAIN CONNECTION TEST")
print("=" * 60)

# Connect to Ganache
w3 = Web3(Web3.HTTPProvider(GANACHE_RPC))

if not w3.is_connected():
    print("ERROR: Could not connect to Ganache")
    exit()

print("Ganache connected successfully")
print("RPC:", GANACHE_RPC)

# Load ABI
with open("blockchain/AlertStorage_abi.json", "r") as f:
    abi = json.load(f)

# Connect to deployed contract
contract = w3.eth.contract(
    address=Web3.to_checksum_address(CONTRACT_ADDRESS),
    abi=abi
)

print("Contract connected successfully")
print("Contract address:", CONTRACT_ADDRESS)

# Read alert count
count = contract.functions.alertCount().call()

print("Current alert count:", count)

print("=" * 60)
print("BLOCKCHAIN TEST SUCCESSFUL")
print("=" * 60)
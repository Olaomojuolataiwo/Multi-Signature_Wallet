from web3 import Web3, HTTPProvider
import json

ALCHEMY_URL = "https://eth-sepolia.g.alchemy.com/v2/F8X3H2cE64aIbdybBl01B"
w3 = Web3(HTTPProvider(ALCHEMY_URL))
assert w3.is_connected()

# Replace with your values
PROPOSE_TX_HASH = "0x9c46ea21b4cf7f90f0095bae8c8cc3faeb3adecea2a5cc25b38ef5535830af78"
MULTISIG_ADDRESS = "0x01aA12e58defD72CA2b8F5708d314b74EBB5F197"

# Minimal ABI that includes proposeTransaction signature
MULTISIG_ABI = [
  {"inputs":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"bytes","name":"data","type":"bytes"}],
   "name":"proposeTransaction","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"nonpayable","type":"function"}
]

multisig = w3.eth.contract(address=w3.to_checksum_address(MULTISIG_ADDRESS), abi=MULTISIG_ABI)
tx = w3.eth.get_transaction(PROPOSE_TX_HASH)

# decode input
fn_name, fn_args = multisig.decode_function_input(tx.input)
print("Decoded function:", fn_name.fn_name)
print("Arguments passed to propose:")
print("  to:", fn_args['to'])
print("  value (wei):", fn_args['value'], " =>", w3.from_wei(fn_args['value'], 'ether'), "ETH")
print("  data bytes length:", len(fn_args['data']))

# Replace pid from your logs (e.g., 21)
pid = 21

# ABI entry for reading proposals (adjust field names/types to match your contract)
# Example generic Proposal struct ABI approximation:
PROPOSAL_ABI = [
  {"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"proposals","outputs":[
      {"internalType":"address","name":"to","type":"address"},
      {"internalType":"uint256","name":"value","type":"uint256"},
      {"internalType":"bytes","name":"data","type":"bytes"},
      {"internalType":"bool","name":"executed","type":"bool"},
      {"internalType":"uint256","name":"confirmationCount","type":"uint256"}
  ],"stateMutability":"view","type":"function"}
]

# Append or re-use an ABI that includes the proposals getter
multisig_with_prop = w3.eth.contract(address=w3.to_checksum_address(MULTISIG_ADDRESS), abi=PROPOSAL_ABI)
try:
    p = multisig_with_prop.functions.proposals(pid).call()
    print("Proposal stored on-chain (raw):", p)
    print("  to:", p[0])
    print("  value (wei):", p[1], "=>", w3.from_wei(p[1], 'ether'), "ETH")
    print("  executed:", p[3])
except Exception as e:
    print("Could not read proposals(pid) - contract may not expose that getter exactly:", e)

# the attacker address you thought you deployed
EXPECTED_ATTACKER = "0x37b9528E46CB14Ee2BAbd161835E735802DB1693"  # update if different
# the address your runner used (inspect env var or variable in your script):
print("Expected attacker:", EXPECTED_ATTACKER)
# If you have variable REENTRANCY_ATTACKER_ADDRESS in your env/script, print it here:
import os
print("Runner's REENTRANCY_ATTACKER_ADDRESS from env:", os.getenv("REENTRANCY_ATTACKER_ADDRESS"))

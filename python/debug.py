from web3 import Web3
import json

ALCHEMY_URL = "https://eth-sepolia.g.alchemy.com/v2/F8X3H2cE64aIbdybBl01B"
w3 = Web3(Web3.HTTPProvider(ALCHEMY_URL))
assert w3.is_connected(), "RPC connect failed"

TX = "0xee3844b9831b70301036719e0b851f590462d5cc09237a281ca35e90304013f9"
ATTACKER = "0xe5fCF1F6c237789011a3C1Ac9Cb3879EAc3e2b59"

# Minimal ABI for the attacker: the Received event and setProposalId (for convenience)
REENTRANCY_ABI = [
    {
      "anonymous": False,
      "inputs": [
        {"indexed": False, "internalType": "address", "name": "sender", "type": "address"},
        {"indexed": False, "internalType": "uint256", "name": "amount", "type": "uint256"},
        {"indexed": False, "internalType": "bool", "name": "reenteredAttempted", "type": "bool"}
      ],
      "name": "Received",
      "type": "event"
    },
    {"inputs":[{"internalType":"uint256","name":"proposalId","type":"uint256"}],"name":"setProposalId","outputs":[],"stateMutability":"nonpayable","type":"function"},
]

att = w3.eth.contract(address=w3.to_checksum_address(ATTACKER), abi=REENTRANCY_ABI)

# 1) Get receipt + block number
rec = w3.eth.get_transaction_receipt(TX)
print("Receipt status:", rec.status, "blockNumber:", rec.blockNumber, "gasUsed:", rec.gasUsed)

# 2) Get logs for the attacker around that block (2 blocks window)
from_block = rec.blockNumber - 2
to_block = rec.blockNumber + 2
print("Looking for Received events around blocks", from_block, "->", to_block)

try:
    events = att.events.Received().get_logs(from_block=from_block, to_block=to_block)
    print("Found", len(events), "Received() events:")
    for ev in events:
        print("  block", ev.blockNumber, "sender", ev.args.sender, "amount", w3.from_wei(ev.args.amount, "ether"), "ETH reenteredAttempted:", ev.args.reenteredAttempted)
except Exception as e:
    print("Error fetching events:", e)

# 3) Print simple balances
vuln_addr = "0x01aA12e58defD72CA2b8F5708d314b74EBB5F197"
print("Balances (ETH):")
print("  Vulnerable:", w3.from_wei(w3.eth.get_balance(vuln_addr), "ether"))
print("  Attacker:  ", w3.from_wei(w3.eth.get_balance(ATTACKER), "ether"))

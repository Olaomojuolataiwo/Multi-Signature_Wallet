from web3 import Web3
from eth_account import Account

ALCHEMY_URL = "https://eth-sepolia.g.alchemy.com/v2/F8X3H2cE64aIbdybBl01B"
w3 = Web3(Web3.HTTPProvider(ALCHEMY_URL))

PRIVATE_KEY = 0xec534f9f428ae01495037aa3eec0765bc20ae36c905231ad0d87ef53c0f98a6e   # <--- replace
acct = Account.from_key(PRIVATE_KEY)

nonce = 1000  # same as stuck tx
to = "0x01aA12e58defD72CA2b8F5708d314b74EBB5F197"
data = "0x5e90852d000000000000000000000000cc7a3706df7fccfbf99f577382bc62c0e565fcf00000000000000000000000000000000000000000000000000000e35fa931a0000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000"

# use a *reasonable* gas fee for Sepolia
base = w3.eth.get_block("pending").baseFeePerGas
tx = {
    "chainId": 11155111,
    "to": to,
    "value": 0,
    "data": data,
    "nonce": nonce,
    "gas": 400000,
    "maxPriorityFeePerGas": w3.to_wei("2", "gwei"),
    "maxFeePerGas": base + w3.to_wei("2", "gwei"),
}

signed = acct.sign_transaction(tx)
txh2 = w3.eth.send_raw_transaction(signed.raw_transaction)
print("Replacement sent:", txh2.hex())
print("Now wait for the receipt using wait_for_transaction_receipt(txh2)")

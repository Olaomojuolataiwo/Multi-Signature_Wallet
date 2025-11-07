from web3 import Web3
ALCHEMY_URL = "https://eth-sepolia.g.alchemy.com/v2/F8X3H2cE64aIbdybBl01B"
w3 = Web3(Web3.HTTPProvider(ALCHEMY_URL))
txh = "0xfcca5f7dcb0285028f2ad9531f9da053eea5146181bed278a9b2451eac7cdde4"

# 1) Does the network know about the tx at all?
try:
    tx = w3.eth.get_transaction(txh)
    print("TX found in mempool / chain:", tx)
except Exception as e:
    print("get_transaction: tx not found (still pending or dropped).", e)

# 2) Any receipt? (should raise if not mined)
try:
    rec = w3.eth.get_transaction_receipt(txh)
    print("Receipt found:", rec)
except Exception as e:
    print("get_transaction_receipt: not mined yet.", e)

# 3) Check the sender nonce situation
sender = "0xcc7a3706Df7FCcFbF99f577382BC62C0e565FcF0"  # replace with the exact account used to sign the tx
latest_nonce = w3.eth.get_transaction_count(sender, "latest")
pending_nonce = w3.eth.get_transaction_count(sender, "pending")
print("latest nonce:", latest_nonce, "pending nonce:", pending_nonce)

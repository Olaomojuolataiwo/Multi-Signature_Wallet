from web3 import Web3
ALCHEMY_URL = "https://eth-sepolia.g.alchemy.com/v2/F8X3H2cE64aIbdybBl01B"
w3 = Web3(Web3.HTTPProvider(ALCHEMY_URL))
txh = "0x815edc41c7f9aa78d0a243eac21d705f11de24b60a5241349caf9de26be3f220"

rec = w3.eth.wait_for_transaction_receipt(txh, timeout=600)  # blocks until mined or timeout
print("receipt.status:", rec.status)     # 1 = success, 0 = reverted
print("blockNumber:", rec.blockNumber)
print("gasUsed:", rec.gasUsed)
print("transactionIndex:", rec.transactionIndex)
print("See on Etherscan:", f"https://sepolia.etherscan.io/tx/{txh}")

from web3 import Web3
from eth_account import Account
import os

ALCHEMY_URL = "https://eth-sepolia.g.alchemy.com/v2/F8X3H2cE64aIbdybBl01B"
w3 = Web3(Web3.HTTPProvider(ALCHEMY_URL))

ATTACKER_CONTRACT = w3.to_checksum_address("0xe5fCF1F6c237789011a3C1Ac9Cb3879EAc3e2b59")
OWNER_PRIVATE_KEY = os.getenv("ATTACKER_OWNER_PK")  # set this in env securely
DEPLOYER_ADDR = w3.to_checksum_address("0x1f9162aDf495696C72Be2473e62C51B7B6fd2E50")

# minimal ABI for withdraw(address)
ABI = [{
  "inputs": [{"internalType":"address","name":"to","type":"address"}],
  "name": "withdraw",
  "outputs": [],
  "stateMutability": "nonpayable",
  "type": "function"
}]

acct = Account.from_key(OWNER_PRIVATE_KEY)
contract = w3.eth.contract(address=ATTACKER_CONTRACT, abi=ABI)

# build tx
fn = contract.functions.withdraw(DEPLOYER_ADDR)
tx = fn.build_transaction({
    "from": acct.address,
    "nonce": w3.eth.get_transaction_count(acct.address),
    "gas": 150_000,                    # generous gas limit for safety
    "gasPrice": w3.eth.gas_price,
    "chainId": w3.eth.chain_id
})

# sign and send
signed = acct.sign_transaction(tx)
txh = w3.eth.send_raw_transaction(signed.raw_transaction)
rec = w3.eth.wait_for_transaction_receipt(txh)
print("Withdraw tx:", txh.hex(), "status:", rec.status, "gasUsed:", rec.gasUsed)

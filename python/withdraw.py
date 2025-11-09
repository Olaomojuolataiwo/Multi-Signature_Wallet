import os
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
import json
import time

# --- CONFIGURATION ---

# 1. Web3 Connection
# ⚠️ REPLACE THIS WITH YOUR ACTUAL RPC URL (e.g., Sepolia, Goerli, etc.)
RPC_URL = "https://eth-sepolia.g.alchemy.com/v2/F8X3H2cE64aIbdybBl01B" 
w3 = Web3(Web3.HTTPProvider(RPC_URL))

if not w3.is_connected():
    raise ConnectionError("Failed to connect to Ethereum network. Check RPC_URL.")

w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

# 2. Wallet Addresses & Keys
# MIGRATION PATH: Vulnerable (Old) -> Secure (New)
OLD_MULTISIG_ADDRESS = "0xEbb47ce2855267408188A07CDd909CA6558759b1" 
NEW_MULTISIG_ADDRESS = "0x3986cf51dE65dAEDf7832851d6566F4708bf2A19"

# **OWNER ACCOUNTS & KEYS**
OWNER_DETAILS = {
    "0": { # Proposer & Executor (needs gas)
        "address": "0xcc7a3706Df7FCcFbF99f577382BC62C0e565FcF0",
        "private_key": "0xec534f9f428ae01495037aa3eec0765bc20ae36c905231ad0d87ef53c0f98a6e"
    },
    "1": { # Confirmer 1 (needs gas)
        "address": "0x513B1d92C2CA2d364B9d99ABabA485D298bdCbea",
        "private_key": "0x4c7442b66a4a3b48002cbc677f8ffe1f16107f4274a6e36a388e038bc3d0e868"
    },
    "2": { # Confirmer 2 (needs gas)
        "address": "0xAB168F094e0037eDA6562da1d4784bD44B1860A1",
        "private_key": "0xb77c47227508bf6009582379e281f5fc4e5e5c629d70a797e75d6d122933525c"
    }
}

# Assign accounts and keys for clarity in the script
ACCOUNT_0 = w3.to_checksum_address(OWNER_DETAILS["0"]["address"])
KEY_0 = OWNER_DETAILS["0"]["private_key"]
ACCOUNT_1 = w3.to_checksum_address(OWNER_DETAILS["1"]["address"])
KEY_1 = OWNER_DETAILS["1"]["private_key"]
ACCOUNT_2 = w3.to_checksum_address(OWNER_DETAILS["2"]["address"])
KEY_2 = OWNER_DETAILS["2"]["private_key"]


# 3. Contract ABI (from VulnerableMultiSig.txt)
# We must use the ABI of the contract that *currently holds the funds*.
VULNERABLE_MULTISIG_ABI = [
    {
        "inputs": [
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "value", "type": "uint256"},
            {"internalType": "bytes", "name": "data", "type": "bytes"}
        ],
        "name": "proposeTransaction",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "proposalId", "type": "uint256"}
        ],
        "name": "confirmTransaction",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "proposalId", "type": "uint256"}
        ],
        "name": "executeTransaction",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "proposalId", "type": "uint256"},
            {"indexed": True, "internalType": "address", "name": "proposer", "type": "address"},
            {"indexed": True, "internalType": "address", "name": "to", "type": "address"}, 
            {"indexed": False, "internalType": "uint256", "name": "value", "type": "uint256"},
            {"indexed": False, "internalType": "bytes32", "name": "dataHash", "type": "bytes32"}
        ],
        "name": "ProposalCreated",
        "type": "event"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "proposalId", "type": "uint256"},
            {"indexed": True, "internalType": "address", "name": "confirmer", "type": "address"}
        ],
        "name": "Confirmed",
        "type": "event"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "proposalId", "type": "uint256"},
            {"indexed": True, "internalType": "address", "name": "executor", "type": "address"},
            {"indexed": False, "internalType": "bool", "name": "success", "type": "bool"},
            {"indexed": False, "internalType": "bytes", "name": "result", "type": "bytes"}
        ],
        "name": "Executed",
        "type": "event"
    },
    {
        "inputs": [],
        "name": "getOwners",
        "outputs": [{"internalType": "address[]", "name": "", "type": "address[]"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "uint256", "name": "proposalId", "type": "uint256"}],
        "name": "getProposal",
        "outputs": [
            {"internalType": "address", "name": "proposer", "type": "address"},
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "value", "type": "uint256"},
            {"internalType": "bytes32", "name": "dataHash", "type": "bytes32"},
            {"internalType": "uint256", "name": "confirmations_", "type": "uint256"},
            {"internalType": "bool", "name": "executed", "type": "bool"},
            {"internalType": "uint256", "name": "createdAt", "type": "uint256"},
            {"internalType": "uint256", "name": "executeAfter", "type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "threshold",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    }
]

# --- HELPER FUNCTION ---

def sign_and_send_tx(transaction, private_key, sender_address):
    """Signs a transaction and sends it to the network."""
    print(f"Signing transaction from: {sender_address}")
    
    # 1. Update with Nonce and Chain ID
    transaction.update({
        'nonce': w3.eth.get_transaction_count(sender_address),
        'chainId': w3.eth.chain_id,
    })

    # 2. Gas Estimation (Using EIP-1559 if available, fallback to Legacy)
    try:
        # Use EIP-1559 style for gas
        gas_params = w3.eth.fee_history(10, 'latest', [0])[0]
        max_priority_fee_per_gas = w3.to_wei(2, 'gwei') 
        base_fee = gas_params['baseFeePerGas']
        max_fee_per_gas = base_fee + max_priority_fee_per_gas

        transaction.update({
            'maxFeePerGas': max_fee_per_gas,
            'maxPriorityFeePerGas': max_priority_fee_per_gas,
            'type': 2,
        })

        gas_estimate = w3.eth.estimate_gas(transaction)
        transaction.update({'gas': int(gas_estimate * 1.2)})

    except Exception as e:
        # Fallback to legacy gas
        print(f"EIP-1559 failed: {e}. Falling back to legacy gas...")
        gas_price = w3.eth.gas_price
        # FIX: Explicitly remove EIP-1559 fields 
        # (The 'None' default prevents a KeyError if they weren't set)
        transaction.pop('maxFeePerGas', None)
        transaction.pop('maxPriorityFeePerGas', None) 
        transaction.pop('type', None)
        transaction.update({
            'gasPrice': gas_price,
        })
        gas_estimate = w3.eth.estimate_gas(transaction)
        transaction.update({'gas': int(gas_estimate * 1.2)})

    # 3. Sign the transaction
    signed_tx = w3.eth.account.sign_transaction(transaction, private_key)
    
    # 4. Send and Wait
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"Transaction sent. Hash: {w3.to_hex(tx_hash)}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=600)
    
    if receipt['status'] == 1:
        print(f"Transaction SUCCESS in block {receipt['blockNumber']}!")
        return receipt
    else:
        raise Exception(f"Transaction FAILED. Receipt: {receipt}")

# --- MAIN EXECUTION ---

def migrate_funds():
    print(f"--- 🔑 Starting MultiSig Fund Migration (3 Owners) ---")
    
    # 1. Setup
    old_multisig_contract = w3.eth.contract(address=w3.to_checksum_address(OLD_MULTISIG_ADDRESS), abi=VULNERABLE_MULTISIG_ABI)
    print(f"Source (Old) Contract: {old_multisig_contract.address}")
    
    # 2. Get Old Wallet Balance
    full_balance_wei = w3.eth.get_balance(OLD_MULTISIG_ADDRESS)
    full_balance_eth = w3.from_wei(full_balance_wei, 'ether')
    
    if full_balance_wei == 0:
        print("✅ Success: Old Multisig Wallet is already empty. No funds to migrate.")
        return

    print(f"💰 Funds to Migrate: **{full_balance_eth} ETH** ({full_balance_wei} Wei)")
    print(f"🚀 Target Destination: {NEW_MULTISIG_ADDRESS}")
    
    # --- STEP 1: PROPOSE THE TRANSFER (By OWNER 0) ---
    print("\n--- STEP 1: PROPOSING TRANSFER (Owner 0) ---")
    
    propose_tx = old_multisig_contract.functions.proposeTransaction(
        w3.to_checksum_address(NEW_MULTISIG_ADDRESS), 
        full_balance_wei,                               
        b''                                             
    ).build_transaction({
        'from': ACCOUNT_0,
        'value': 0 
    })
    
    try:
        propose_receipt = sign_and_send_tx(propose_tx, KEY_0, ACCOUNT_0)
        logs = old_multisig_contract.events.ProposalCreated().process_receipt(propose_receipt)
        if not logs:
            raise Exception("ProposalCreated event not found in receipt.")
            
        proposal_id = logs[0]['args']['proposalId']
        print(f"🎉 Proposal successfully created with ID: **{proposal_id}** (1 confirmation met)")

    except Exception as e:
        print(f"🚨 Propose Transaction Failed: {e}")
        return

    # --- STEP 2: CONFIRMATION 1 (By OWNER 1) ---
    print(f"\n--- STEP 2: CONFIRMATION 1 (Owner 1) ---")
    
    confirm_tx_1 = old_multisig_contract.functions.confirmTransaction(
        proposal_id
    ).build_transaction({
        'from': ACCOUNT_1,
        'value': 0 
    })
    
    try:
        sign_and_send_tx(confirm_tx_1, KEY_1, ACCOUNT_1)
        print("   - Confirmation 1 SUCCESSFUL. (2 confirmations met)")
    except Exception as e:
        print(f"🚨 Confirmation 1 Transaction Failed: {e}")
        return

    # --- STEP 3: CONFIRMATION 2 (By OWNER 2) ---
    print(f"\n--- STEP 3: CONFIRMATION 2 (Owner 2) ---")
    
    confirm_tx_2 = old_multisig_contract.functions.confirmTransaction(
        proposal_id
    ).build_transaction({
        'from': ACCOUNT_2,
        'value': 0 
    })
    
    try:
        sign_and_send_tx(confirm_tx_2, KEY_2, ACCOUNT_2)
        print("   - Confirmation 2 SUCCESSFUL. (3 confirmations met - Ready for execution)")
    except Exception as e:
        print(f"🚨 Confirmation 2 Transaction Failed: {e}")
        return

    # --- STEP 4: EXECUTION (By OWNER 0) ---
    print("\n--- STEP 4: EXECUTING TRANSFER (Owner 0) ---")
    
    execute_tx = old_multisig_contract.functions.executeTransaction(
        proposal_id
    ).build_transaction({
        'from': ACCOUNT_0,
        'value': 0 
    })
    
    try:
        execute_receipt = sign_and_send_tx(execute_tx, KEY_0, ACCOUNT_0)
        print("   - Execution SUCCESSFUL. Funds have been sent.")
        
        # Final Verification
        time.sleep(5) 
        final_old_balance = w3.from_wei(w3.eth.get_balance(OLD_MULTISIG_ADDRESS), 'ether')
        new_balance = w3.from_wei(w3.eth.get_balance(NEW_MULTISIG_ADDRESS), 'ether')
        
        print(f"\n--- ✅ FINAL STATUS ---")
        print(f"Old Wallet Balance (After): {final_old_balance} ETH")
        print(f"New Wallet Balance (After): {new_balance} ETH")
        
        if final_old_balance == 0:
            print("🎉 **SUCCESS: Funds have been fully migrated from the old multisig wallet.**")
        else:
            print("⚠️ WARNING: Old wallet is not fully empty. Check logs and gas used.")
            
    except Exception as e:
        print(f"🚨 Execution Transaction FAILED: {e}")


if __name__ == "__main__":
    migrate_funds()

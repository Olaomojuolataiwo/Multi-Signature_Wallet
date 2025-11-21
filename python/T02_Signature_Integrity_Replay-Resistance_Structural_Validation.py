#!/usr/bin/env python3
"""
Unified T-02 + T-04 Test Orchestration Script
---------------------------------------------
Runs all phases of the combined Signature, Replay, Hashing, Arithmetic,
and Input-Sanitization validation suite.

Sequence:
    For each test section:
        1. Run against VulnerableMultiSig
        2. Run against SecureMultiSig
        3. Compare & print divergence

All configuration depends on environment variables.

ENV VARS REQUIRED:
    RPC_URL
    CHAIN_ID
    PRIVATE_KEY                 (ephemeral key to sign)
    SIGNER_ADDRESS              (public address of private key)
    VULNERABLE_ADDRESS
    SECURE_ADDRESS
    BENEFICIARY_ADDRESS         (address that receives funds)
"""

import os
import json
import time
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak, to_bytes, to_hex
from web3 import Web3
from web3.exceptions import ContractLogicError
from eth_account.messages import encode_typed_data
from eth_keys import keys
from eth_account.messages import SignableMessage


# ============================================================
#  Load Configuration from Environment
# ============================================================

RPC_URL = os.getenv("RPC_URL")
CHAIN_ID = int(os.getenv("CHAIN_ID"))
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
SIGNER = os.getenv("SIGNER_ADDRESS")
VULN_ADDR = os.getenv("VULNERABLE_ADDRESS")
SECURE_ADDR = os.getenv("SECURE_ADDRESS")
BENEFICIARY = os.getenv("BENEFICIARY_ADDRESS")

assert RPC_URL and PRIVATE_KEY and SIGNER and VULN_ADDR and SECURE_ADDR, "Missing environment variables"

w3 = Web3(Web3.HTTPProvider(RPC_URL))
acct = Account.from_key(PRIVATE_KEY)
assert acct.address.lower() == SIGNER.lower(), \
    f"Signer mismatch: ENV SIGNER={SIGNER} but PRIVATE_KEY resolves to {acct.address}"
print("\n=== Loaded Environment ===")
print("RPC:", RPC_URL)
print("Chain ID:", CHAIN_ID)
print("Signer:", SIGNER)
print("Vulnerable:", VULN_ADDR)
print("Secure:", SECURE_ADDR)
print("Beneficiary:", BENEFICIARY)
print("==========================\n")


# ============================================================
#  Load ABIs
# ============================================================

def load_abi(name):
    file_path = os.path.join("..", "out", f"{name}.sol", f"{name}.json")
    with open(file_path, 'r') as f:
        compiled_json = json.load(f)
    return compiled_json['abi']

vuln_abi = load_abi("VulnerableMultiSig")
secure_abi = load_abi("SecureMultiSig")

vuln = w3.eth.contract(address=VULN_ADDR, abi=vuln_abi)
secure = w3.eth.contract(address=SECURE_ADDR, abi=secure_abi)


# ============================================================
#  Helper Functions
# ============================================================

def send_tx(tx):
    """Send a signed transaction and wait for receipt."""
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt


def build_tx(to, data, value=0):
    """Prepare unsigned tx dict with gas estimate."""
    return {
        "to": to,
        "value": value,
        "data": data,
        "gas": 8000000,
        "gasPrice": w3.eth.gas_price,
        "nonce": w3.eth.get_transaction_count(SIGNER),
        "chainId": CHAIN_ID
    }


# ------------------------------------------------------------
#  Vulnerable Signature Builder
# ------------------------------------------------------------

def build_vulnerable_signature(to, value, data):
    """Reproduce VULNERABLE signature hash = keccakPacked(to, value, keccak(data))."""
    packed_hash = keccak(to_bytes(hexstr=to) + value.to_bytes(32, "big") + keccak(data))
    message = encode_defunct(primitive=packed_hash)
    signed = Account.sign_message(message, private_key=PRIVATE_KEY)
    sig_bytes = signed.signature
    return sig_bytes


# ------------------------------------------------------------
#  EIP-712 Builder for Secure Contract
# ------------------------------------------------------------

def build_secure_eip712(to, value, data, nonce):
    typed = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Execute": [
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "dataHash", "type": "bytes32"},
                {"name": "nonce", "type": "uint256"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
        },
        "primaryType": "Execute",
        "domain": {
            "name": "SecureMultiSig",
            "version": "1",
            "chainId": CHAIN_ID,
            "verifyingContract": SECURE_ADDR,
        },
        "message": {
            "to": to,
            "value": value,
            "dataHash": w3.keccak(data),
            "nonce": nonce,
            "chainId": CHAIN_ID,
            "verifyingContract": SECURE_ADDR,
        }
    }

    # ✔️ New API (NON-deprecated)
    signable = encode_typed_data(full_message=typed)

    signed = Account.sign_message(signable, private_key=PRIVATE_KEY)

    return typed, signed.signature


# ============================================================
#  Test Phases (Each Shows V→S Divergence)
# ============================================================

def section_header(name):
    print("\n" + "=" * 80)
    print(f"    {name}")
    print("=" * 80 + "\n")


# ------------------------------------------------------------
# Section 1 — Valid Execution (Signature Integrity)
# ------------------------------------------------------------

def test_valid_execution():
    print(f"\n" + "="*80)
    print(f"======== TEST 1: STRUCTURAL VALIDATION (Simple Withdrawal) ========")
    print(f"="*80 + "\n")

    value = 1000
    data = b""

# ----------------------------------
#    ATTACK EXECUTION
# ----------------------------------

    print(f"\n--- VULNERABLE WALLET EXECUTION ---")
    sig_v = build_vulnerable_signature(BENEFICIARY, value, data)
    tx = build_tx(to=VULN_ADDR, data=vuln.functions.executeWithSignature(BENEFICIARY, value, data, sig_v).build_transaction({"from": SIGNER})["data"])
    r_vuln = send_tx(tx)
    if r_vuln.status == 1:
        print("EXPECTED: VALID EXECUTION ON VULNERABLE WALLET SUCCESFUL", r_vuln.transactionHash.hex())
    else:
        print("UNEXPECTED: VALID EXECUTION ON VULNERABLE WALLET FAILED!", r_vuln.transactionHash.hex())

# --------------------------------
#    ATTACK MITIGATION
# --------------------------------

    print(f"\n--- SECURE WALLET EXECUTION ---")
    nonce = secure.functions.nonces(SIGNER).call()
    typed, sig_s = build_secure_eip712(BENEFICIARY, value, data, nonce)
    tx2 = build_tx(to=SECURE_ADDR, data=secure.functions.executeWithSignature( BENEFICIARY, value, data, nonce, sig_s).build_transaction({"from": acct.address})["data"])
    r_sec = send_tx(tx2)
    if r_sec.status == 1:
        print("EXPECTED: VALID EXECUTION ON SECURE WALLET SUCCESFUL", r_sec.transactionHash.hex())
    else:
        print("UNEXPECTED: VALID EXECUTION ON SECURE WALLET FAILED!", r_sec.transactionHash.hex())


# ------------------------------------------------------------
# Section 2 — Replay Test
# ------------------------------------------------------------

def test_replay():
    print(f"\n" + "="*80)
    print(f"======== TEST 2: REPLAY TEST ========")
    print(f"="*80 + "\n")

    value = 1
    data = b""

# ---------------------------------
#    ATTACK EXECUTION
# ---------------------------------

    print(f"\n--- VULNERABLE WALLET EXECUTION ---")
    print("Attempting initial transaction on Vulnerable Wallet")
    sig = build_vulnerable_signature(BENEFICIARY, value, data)

    tx = build_tx(to=VULN_ADDR, data=vuln.functions.executeWithSignature(BENEFICIARY, value, data, sig).build_transaction({"from": SIGNER})["data"])
    r1 = send_tx(tx)
    print("Vulnerable First Tx:", r1.transactionHash.hex())

    print("Attempting replay transaction on Vulnerable Wallet")
    tx_replay = build_tx(to=VULN_ADDR, data=vuln.functions.executeWithSignature(BENEFICIARY, value, data, sig).build_transaction({"from": SIGNER})["data"])
    r2 = send_tx(tx_replay)
    if r2.status == 1:
        print("EXPECTED: REPLAY ATTACK ON VULNERABLE WALLET SUCCESFUL", r2.transactionHash.hex())
    else:
        print("UNEXPECTED: REPLAY ATTACK ON VULNERABLE WALLET FAILED!", r2.transactionHash.hex())

# --------------------------------
#    ATTACK MITIGATION
# --------------------------------

    print(f"\n--- SECURE WALLET EXECUTION ---")
    print("Attempting initial transaction on Secure Wallet")

    nonce = secure.functions.nonces(SIGNER).call()
    typed, sig_s = build_secure_eip712(BENEFICIARY, value, data, nonce)

    func = secure.functions.executeWithSignature(BENEFICIARY, value, data, nonce, sig_s)

    tx_s = func.build_transaction({"from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address), "gas": 300000,})
    r_s1 = send_tx(tx_s)
    print("Secure First Tx:", r_s1.transactionHash.hex())

    print("Attempting replay transaction on Secure Wallet")
    func_replay = secure.functions.executeWithSignature(BENEFICIARY, value, data, nonce, sig_s)

    tx_s_replay = func_replay.build_transaction({"from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address), "gas": 300000,})

    try:
        r_s2 = send_tx(tx_s_replay)
        if r_s2.status == 0:
            print("EXPECTED: REPLAY ATTACK ON SECURE WALLET FAILS", r_s2.transactionHash.hex())
        else:
            print("UNEXPECTED: REPLAY ATTACK ON SECURE WALLET SUCCESSFUL!", r_s2.transactionHash.hex())

    except ContractLogicError as e:
        print("Secure Replay Reverted (caught in except):", e)

# ------------------------------------------------------------
# Section 3 — Mutation / Structural Attacks
# ------------------------------------------------------------

def test_structural_mutation():
    print(f"\n" + "="*80)
    print(f"======== TEST 3: MUTATION TEST ========")
    print(f"="*80 + "\n")

    correct_value = 50
    mutated_value = 9999
    data = b""


# ----------------------------------
#    ATTACK EXECUTION
# ----------------------------------

    print(f"\n--- VULNERABLE WALLET EXECUTION ---")

    sig = build_vulnerable_signature(BENEFICIARY, correct_value, data)
    tx = build_tx(to=VULN_ADDR, data=vuln.functions.executeWithSignature(BENEFICIARY, mutated_value, data, sig).build_transaction({"from": SIGNER})["data"])
    r_v = send_tx(tx)
    if r_v.status == 1:
        print("EXPECTED: MUTATION TEST ON VULNERABLE WALLET SUCCESFUL", r_v.transactionHash.hex())
    else:
        print("UNEXPECTED: MUTATION TEST ON VULNERABLE WALLET FAILED!", r_v.transactionHash.hex())



# -------------------------------
#     ATTACK MITIGATION
# -------------------------------

    print(f"\n--- SECURE WALLET EXECUTION ---")
    nonce = secure.functions.nonces(SIGNER).call()
    _, sig_mut = build_secure_eip712(BENEFICIARY, correct_value, data, nonce)

    func = secure.functions.executeWithSignature(BENEFICIARY, mutated_value, data, nonce, sig_mut)

    tx_mut = func.build_transaction({"from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address), "gas": 300000,})
    try:
        r_mut = send_tx(tx_mut)
        if r_mut.status == 0:
            print("EXPECTED: MUTATION/STRUCTURAL ATTACKS ON SECURE WALLET FAILS", r_mut.transactionHash.hex())
        else:
            print("UNEXPECTED: MUTATION/STRUCTURAL ATTACKS ON SECURE WALLET SUCCESSFUL!", r_mut.transactionHash.hex())
    except ContractLogicError as e:
        print("Secure Mutation Reverted (caught):", e)

# ------------------------------------------------------------
# Section 4 — Arithmetic Attacks
# ------------------------------------------------------------

def test_arithmetic():
    print(f"\n" + "="*80)
    print(f"======== TEST 4: ARITHMETIC ATTACKS TEST ========")
    print(f"="*80 + "\n")
 
    max_uint = (2**256) - 1
    overflow_value = max_uint

    data = b""

# ----------------------------------
#    ATTACK EXECUTION
# ----------------------------------

    print(f"\n--- VULNERABLE WALLET EXECUTION ---")

    sig = build_vulnerable_signature(BENEFICIARY, overflow_value, data)
    tx = build_tx(to=VULN_ADDR, data=vuln.functions.executeWithSignature(BENEFICIARY, overflow_value, data, sig).build_transaction({"from": SIGNER})["data"])
    r_v = send_tx(tx)
    if r_v.status == 1:
        print("EXPECTED: ARITHMETIC ATTACKS TEST ON VULNERABLE WALLET SUCCESFUL", r_v.transactionHash.hex())
    else:
        print("UNEXPECTED: ARITHMETIC ATTACKS TEST ON VULNERABLE WALLET FAILED!", r_v.transactionHash.hex())

# -------------------------------
#     ATTACK MITIGATION
# -------------------------------

    print(f"\n--- SECURE WALLET EXECUTION ---")

    nonce = secure.functions.nonces(SIGNER).call()
    _, sig_s = build_secure_eip712(BENEFICIARY, overflow_value, data, nonce)

    func = secure.functions.executeWithSignature( BENEFICIARY, overflow_value, data, nonce, sig_s)

    tx_ovr = func.build_transaction({"from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address), "gas": 300000,})
    try:
        r_ovr = send_tx(tx_ovr)
        if r_ovr.status == 0:
            print("EXPECTED: ARITHMETIC ATTACKS ON SECURE WALLET FAILS", r_ovr.transactionHash.hex())
        else:
            print("UNEXPECTED: ARITHMETIC ATTACKS ON SECURE WALLET SUCCESSFUL!", r_ovr.transactionHash.hex())
    except ContractLogicError as e:
        print("Secure Overflow Reverted (caught):", e)


# ------------------------------------------------------------
# Section 5 — Input Sanitization
# ------------------------------------------------------------

def test_input_sanitization():
    print(f"\n" + "="*80)
    print(f"======== TEST 5: INPUT SANITIZATION TEST ========")
    print(f"="*80 + "\n")

    zero_addr = "0x0000000000000000000000000000000000000000"
    value = 0
    data = b""

# ----------------------------------
#    ATTACK EXECUTION
# ----------------------------------
    print(f"\n--- VULNERABLE WALLET EXECUTION ---")
    sig = build_vulnerable_signature(zero_addr, value, data)
    tx = build_tx(to=VULN_ADDR, data=vuln.functions.executeWithSignature(zero_addr, value, data, sig).build_transaction({"from": SIGNER})["data"])
    r_v = send_tx(tx)
    if r_v.status == 1:
        print("EXPECTED: INPUT SANITIZATION TEST ON VULNERABLE WALLET SUCCESFUL", r_v.transactionHash.hex())
    else:
        print("UNEXPECTED: INPUT SANITIZATION TEST ON VULNERABLE WALLET FAILED!", r_v.transactionHash.hex())

# -------------------------------
#     ATTACK MITIGATION
# -------------------------------
    print(f"\n--- SECURE WALLET EXECUTION ---")

    nonce = secure.functions.nonces(SIGNER).call()
    _, sig_s = build_secure_eip712(zero_addr, value, data, nonce)

    func = secure.functions.executeWithSignature(zero_addr, value, data, nonce, sig_s)

    tx_zero = func.build_transaction({"from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address), "gas": 300000,})
    try:
        r_zero = send_tx(tx_zero)
        if r_zero.status == 0:
            print("EXPECTED: INPUT SANITIZATION TEST ON SECURE WALLET FAILS", r_zero.transactionHash.hex())
        else:
            print("UNEXPECTED: INPUT SANITIZATION TEST ON SECURE WALLET SUCCESSFUL", r_zero.transactionHash.hex())
    except ContractLogicError as e:
        print("Secure Overflow Reverted (caught):", e)

# ============================================================
#  Run All Sections
# ============================================================

if __name__ == "__main__":
    print("\n========== STARTING T-02 + T-04 TEST SUITE ==========\n")

    test_valid_execution()
    test_replay()
    test_structural_mutation()
    test_arithmetic()
    test_input_sanitization()

    print("\n========== COMPLETED T-02 + T-04 SUITE ==========\n")

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
    with open(f"./abi/{name}.json") as f:
        return json.load(f)

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
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
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
    """Return EIP-712 typed data + final signature."""
    data_hash = keccak(data)

    domain = {
        "name": "SecureMultiSig",
        "version": "1",
        "chainId": CHAIN_ID,
        "verifyingContract": SECURE_ADDR
    }

    types = {
        "Execute": [
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "dataHash", "type": "bytes32"},
            {"name": "nonce", "type": "uint256"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ]
    }

    message = {
        "to": to,
        "value": value,
        "dataHash": data_hash.hex(),
        "nonce": nonce,
        "chainId": CHAIN_ID,
        "verifyingContract": SECURE_ADDR
    }

    from eth_account.messages import encode_structured_data
    typed = {
        "types": {**types, "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ]},
        "domain": domain,
        "primaryType": "Execute",
        "message": message
    }

    encoded = encode_structured_data(typed)
    signed = Account.sign_message(encoded, private_key=PRIVATE_KEY)

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
    section_header("SECTION 1 — VALID EXECUTION: VULNERABLE vs SECURE")

    value = 1000
    data = b""

    # --- Vulnerable ---
    print("[VULNERABLE] Executing valid signed call...")
    sig_v = build_vulnerable_signature(BENEFICIARY, value, data)
    tx = build_tx(
        to=VULN_ADDR,
        data=vuln.functions.executeWithSignature(
            BENEFICIARY, value, data, sig_v
        ).build_transaction({"from": SIGNER})["data"]
    )
    r_vuln = send_tx(tx)
    print("Vulnerable Receipt:", r_vuln.transactionHash.hex())

    # --- Secure ---
    print("\n[SECURE] Executing valid EIP-712 signed call...")
    nonce = secure.functions.nonces(SIGNER).call()
    typed, sig_s = build_secure_eip712(BENEFICIARY, value, data, nonce)

    tx2 = build_tx(
        to=SECURE_ADDR,
        data=secure.functions.executeWithSignature(
            BENEFICIARY, value, data, nonce, sig_s
        ).build_transaction({"from": SIGNER})["data"]
    )
    r_sec = send_tx(tx2)
    print("Secure Receipt:", r_sec.transactionHash.hex())


# ------------------------------------------------------------
# Section 2 — Replay Test
# ------------------------------------------------------------

def test_replay():
    section_header("SECTION 2 — REPLAY: VULNERABLE vs SECURE")

    value = 1
    data = b""

    # --- Vulnerable replay ---
    print("[VULNERABLE] Attempting replay...")
    sig = build_vulnerable_signature(BENEFICIARY, value, data)

    tx = build_tx(
        to=VULN_ADDR,
        data=vuln.functions.executeWithSignature(BENEFICIARY, value, data, sig)
            .build_transaction({"from": SIGNER})["data"]
    )
    r1 = send_tx(tx)
    print("Vulnerable First Tx:", r1.transactionHash.hex())

    tx_replay = build_tx(
        to=VULN_ADDR,
        data=vuln.functions.executeWithSignature(BENEFICIARY, value, data, sig)
            .build_transaction({"from": SIGNER})["data"]
    )
    r2 = send_tx(tx_replay)
    print("Vulnerable Replay Tx:", r2.transactionHash.hex(), " (should SUCCEED)")

    # --- Secure replay ---
    print("\n[SECURE] Attempting replay...")
    nonce = secure.functions.nonces(SIGNER).call()
    typed, sig_s = build_secure_eip712(BENEFICIARY, value, data, nonce)

    # First execution
    tx_s = build_tx(
        to=SECURE_ADDR,
        data=secure.functions.executeWithSignature(
            BENEFICIARY, value, data, nonce, sig_s
        ).build_transaction({"from": SIGNER})["data"]
    )
    r_s1 = send_tx(tx_s)
    print("Secure First Tx:", r_s1.transactionHash.hex())

    # Replay attempt
    tx_s_replay = build_tx(
        to=SECURE_ADDR,
        data=secure.functions.executeWithSignature(
            BENEFICIARY, value, data, nonce, sig_s  # same signature & same nonce
        ).build_transaction({"from": SIGNER})["data"]
    )

    try:
        r_s2 = send_tx(tx_s_replay)
        print("UNEXPECTED: Secure replay succeeded!", r_s2.transactionHash.hex())
    except ContractLogicError as e:
        print("Secure Replay Reverted (expected):", e)


# ------------------------------------------------------------
# Section 3 — Mutation / Structural Attacks
# ------------------------------------------------------------

def test_structural_mutation():
    section_header("SECTION 3 — STRUCTURAL ATTACKS: VULNERABLE vs SECURE")

    # tamper with value
    correct_value = 50
    mutated_value = 9999
    data = b""

    """
    ----------------------------
    VULNERABLE — accepts mutation
    ----------------------------
    """
    print("[VULNERABLE] Mutated value test...")
    sig = build_vulnerable_signature(BENEFICIARY, correct_value, data)

    # But we send a different value in call
    tx = build_tx(
        to=VULN_ADDR,
        data=vuln.functions.executeWithSignature(BENEFICIARY, mutated_value, data, sig)
            .build_transaction({"from": SIGNER})["data"]
    )
    r_v = send_tx(tx)
    print("Vulnerable mutated call:", r_v.transactionHash.hex())

    """
    ----------------------------
    SECURE — rejects mutation
    ----------------------------
    """
    print("\n[SECURE] Mutated value test...")
    nonce = secure.functions.nonces(SIGNER).call()
    _, sig_s = build_secure_eip712(BENEFICIARY, correct_value, data, nonce)

    # sending mutated value to Secure
    tx_s = build_tx(
        to=SECURE_ADDR,
        data=secure.functions.executeWithSignature(
            BENEFICIARY, mutated_value, data, nonce, sig_s
        ).build_transaction({"from": SIGNER})["data"]
    )

    try:
        r_s = send_tx(tx_s)
        print("UNEXPECTED Secure mutated call success:", r_s.transactionHash.hex())
    except ContractLogicError as e:
        print("Secure rejected mutated call (expected):", e)


# ------------------------------------------------------------
# Section 4 — Arithmetic Attacks
# ------------------------------------------------------------

def test_arithmetic():
    section_header("SECTION 4 — ARITHMETIC: VULNERABLE vs SECURE")

    max_uint = (2**256) - 1
    overflow_value = max_uint

    data = b""

    # Vulnerable
    print("[VULNERABLE] Overflow test...")
    sig = build_vulnerable_signature(BENEFICIARY, overflow_value, data)
    tx = build_tx(
        to=VULN_ADDR,
        data=vuln.functions.executeWithSignature(BENEFICIARY, overflow_value, data, sig)
            .build_transaction({"from": SIGNER})["data"]
    )
    r_v = send_tx(tx)
    print("Vulnerable overflow tx:", r_v.transactionHash.hex(), "(wrapped silently)")

    # Secure
    print("\n[SECURE] Overflow test...")
    nonce = secure.functions.nonces(SIGNER).call()
    _, sig_s = build_secure_eip712(BENEFICIARY, overflow_value, data, nonce)

    tx_s = build_tx(
        to=SECURE_ADDR,
        data=secure.functions.executeWithSignature(
            BENEFICIARY, overflow_value, data, nonce, sig_s
        ).build_transaction({"from": SIGNER})["data"]
    )

    try:
        r_s = send_tx(tx_s)
        print("UNEXPECTED Secure overflow success:", r_s.transactionHash.hex())
    except Exception as e:
        print("Secure overflow rejected (expected):", e)


# ------------------------------------------------------------
# Section 5 — Input Sanitization
# ------------------------------------------------------------

def test_input_sanitization():
    section_header("SECTION 5 — INPUT SANITIZATION: VULNERABLE vs SECURE")

    zero_addr = "0x0000000000000000000000000000000000000000"
    value = 0
    data = b""

    # Vulnerable accepts zero-address + zero-value
    print("[VULNERABLE] Zero address test...")
    sig = build_vulnerable_signature(zero_addr, value, data)
    tx = build_tx(
        to=VULN_ADDR,
        data=vuln.functions.executeWithSignature(zero_addr, value, data, sig)
            .build_transaction({"from": SIGNER})["data"]
    )
    r_v = send_tx(tx)
    print("Vulnerable zero-address tx:", r_v.transactionHash.hex())

    # Secure rejects zero address
    print("\n[SECURE] Zero address test...")
    nonce = secure.functions.nonces(SIGNER).call()
    _, sig_s = build_secure_eip712(zero_addr, value, data, nonce)

    tx_s = build_tx(
        to=SECURE_ADDR,
        data=secure.functions.executeWithSignature(zero_addr, value, data, nonce, sig_s)
            .build_transaction({"from": SIGNER})["data"]
    )

    try:
        r_s = send_tx(tx_s)
        print("UNEXPECTED Secure zero-address success:", r_s.transactionHash.hex())
    except Exception as e:
        print("Secure rejected zero-address (expected):", e)


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

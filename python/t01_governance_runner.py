#!/usr/bin/env python3
"""
T-01 Governance & Access Control test runner

Run: python t01_governance_runner.py

Edit CONFIG section before running.
"""

import subprocess
import re
import os
import json
import time
import traceback

from pathlib import Path
from typing import Dict, Optional, Any, List, Tuple
from web3.datastructures import AttributeDict
from hexbytes import HexBytes
from eth_account import Account
from eth_utils import to_checksum_address
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

# Optional compilation support
try:
    import solcx
    SOLCX_AVAILABLE = True
except Exception:
    SOLCX_AVAILABLE = False

# -------------------------
# CONFIG - Edit these
# -------------------------
RPC_URL = os.getenv("RPC_URL")
CHAIN_ID = 11155111
OWNER_PRIVATE_KEYS = os.getenv("OWNER_PRIVATE_KEYS").split()
ATTACKER_PRIVATE_KEY = os.getenv("ATTACKER_PRIVATE_KEY")
VULN_ADDR = os.getenv("VULNERABLE_ADDRESS")
SECURE_ADDR = os.getenv("SECURE_ADDRESS")
vuln_abi = None
secure_abi = None

VULNERABLE_ABI_PATH = "../out/VulnerableMultiSig.sol/VulnerableMultiSig.json"
SECURE_ABI_PATH = "../out/SecureMultiSig.sol/SecureMultiSig.json"


# Transaction parameters
GAS = 5_000_000
GAS_PRICE = None  # in wei; if None web3 will use eth_gasPrice
TX_POLL_INTERVAL = 2  # seconds between receipt polls

# Output
ARTIFACT_DIR = Path("./artifacts/T-01")
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

DEPLOY_CMD = ["forge", "script", "../script/DeployAll.s.sol:DeployAll", "--rpc-url", RPC_URL, "--broadcast", "--slow"]

# -------------------------
# Helper utilities
# -------------------------
def fresh_deploy():
    print(f"[{now_ts()}] Deploying new test instances...")
    out = subprocess.check_output(DEPLOY_CMD, text=True)

    vuln = re.search(r"VulnerableMultiSig deployed at:\s*(0x[a-fA-F0-9]{40})", out).group(1)
    sec  = re.search(r"SecureMultiSig deployed at:\s*(0x[a-fA-F0-9]{40})", out).group(1)

    print(f"  → Vulnerable: {vuln}")
    print(f"  → Secure:     {sec}")

    return vuln, sec

def load_json(path: str):
    with open(path, "r") as f:
        return json.load(f)

def save_json(obj, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(to_jsonable(obj), f, indent=2, sort_keys=True)

def now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

def to_jsonable(obj):
    """Recursively convert Web3 AttributeDict, HexBytes, and other objects into JSON-serializable types."""
    if isinstance(obj, AttributeDict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(x) for x in obj]
    if isinstance(obj, HexBytes):
        return obj.hex()
    if isinstance(obj, bytes):
        return obj.hex()
    return obj

def pretty_print_state(label: str, contract, proposal_id: Optional[int] = None):
    """
    Prints a human-friendly snapshot of the contract state:
      - owner list
      - threshold
      - proposal details (if proposal_id provided)
      - per-owner confirmations if accessible
    """
    try:
        owners = contract.functions.getOwners().call()
    except Exception as e:
        print(f"[{now_ts()}] [WARN] could not read owners for {contract.address}: {e}", flush=True)
        owners = []

    try:
        threshold = contract.functions.threshold().call()
    except Exception as e:
        print(f"[{now_ts()}] [WARN] could not read threshold for {contract.address}: {e}", flush=True)
        threshold = None

    print(f"\n---- {label} ({contract.address}) ----", flush=True)
    print(f"owners ({len(owners)}):", flush=True)
    for i, o in enumerate(owners):
        print(f"  [{i}] {o}", flush=True)
        print(f"threshold: {threshold}", flush=True)

    if proposal_id is not None:
        try:

            p = contract.functions.getProposal(proposal_id).call()
            # Generic tuple handling:
            # Vulnerable getProposal returns (proposer,to,value,data,confirmations,executed,createdAt)
            # Secure getProposal returns (proposer,to,value,dataHash,confirmations,executed,createdAt,executeAfter)
            proposer = p[0] if len(p) > 0 else None
            to = p[1] if len(p) > 1 else None
            value = p[2] if len(p) > 2 else None
            confirmations = p[4] if len(p) > 4 else None
            executed = p[5] if len(p) > 5 else None
            createdAt = p[6] if len(p) > 6 else None
            print(f"proposal {proposal_id}: proposer={proposer}, to={to}, value={value}, confirmations={confirmations}, executed={executed}, createdAt={createdAt}", flush=True)
            # try to print per-owner confirmations if accessible
            for ow in owners:
                try:
                    conf = contract.functions.confirmations(proposal_id, ow).call()
                    print(f"  confirmation[{ow}] = {conf}", flush=True)
                except Exception:
                    # Some contracts store confirmations inside a struct; skip silently for per-owner.
                    pass
        except Exception as e:
            print(f"[{now_ts()}] [WARN] could not read proposal {proposal_id} on {contract.address}: {e}", flush=True)

    print(f"---- end {label} ----\n", flush=True)

# -------------------------
# Setup web3 & accounts
# -------------------------
w3 = Web3(Web3.HTTPProvider(RPC_URL))
# If using PoA chain (like Sepolia), uncomment:
w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)


if not w3.is_connected():
    print("[ERROR] Web3 not connected. Check RPC_URL.")
    raise SystemExit(1)

def acct_from_key(key_hex: str):
    return Account.from_key(key_hex)

OWNER_ACCOUNTS = [acct_from_key(k) for k in OWNER_PRIVATE_KEYS]
ATTACKER_ACCOUNT = acct_from_key(ATTACKER_PRIVATE_KEY) if ATTACKER_PRIVATE_KEY else None

print(f"[{now_ts()}] Connected to {RPC_URL} chainId={CHAIN_ID}")
print(f"[{now_ts()}] Owner accounts loaded: {[a.address for a in OWNER_ACCOUNTS]}")
if ATTACKER_ACCOUNT:
    print(f"[{now_ts()}] Attacker account loaded: {ATTACKER_ACCOUNT.address}")

# -------------------------
# Load ABIs either from file or compile source
# -------------------------
def load_abis():
    global vuln_abi, secure_abi

    vuln_json = load_json("../out/VulnerableMultiSig.sol/VulnerableMultiSig.json")
    sec_json  = load_json("../out/SecureMultiSig.sol/SecureMultiSig.json")

    # Some Forge artifact formats wrap ABI under "abi", some under "output" → ensure correct extraction
    vuln_abi = vuln_json.get("abi") or vuln_json.get("output", {}).get("abi")
    secure_abi = sec_json.get("abi") or sec_json.get("output", {}).get("abi")

    if not isinstance(vuln_abi, list):
        raise RuntimeError("Failed to load vulnerable ABI — not a list")

    if not isinstance(secure_abi, list):
        raise RuntimeError("Failed to load secure ABI — not a list")

    print(f"[{now_ts()}] Loaded vulnerable ABI with {len(vuln_abi)} entries")
    print(f"[{now_ts()}] Loaded secure ABI with {len(secure_abi)} entries")

# -------------------------
# TX helpers: sign, send, wait + save receipts
# -------------------------
def sign_and_send(tx_dict: Dict[str, Any], priv_key: str):
    signed = Account.sign_transaction(tx_dict, priv_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return tx_hash.hex()

def wait_for_receipt(tx_hash: str, timeout: int = 120):
    start = time.time()
    while True:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        if receipt:
            return dict(receipt)
        if time.time() - start > timeout:
            raise TimeoutError(f"Timeout waiting for receipt {tx_hash}")
        time.sleep(TX_POLL_INTERVAL)

def build_tx_and_send(account, to, data, value=0):
    nonce = w3.eth.get_transaction_count(account.address)

    # Basic tx skeleton
    tx = {
        "from": account.address,
        "to": to,
        "value": value,
        "data": data,
        "nonce": nonce,
        "chainId": w3.eth.chain_id,
        "type": 2,
    }

    # ---- Fee estimation (Sepolia EIP-1559 compatible) ----
    fee_history = w3.eth.fee_history(1, "latest", [10])
    max_priority = int(fee_history["reward"][0][0])
    base_fee = int(fee_history["baseFeePerGas"][-1])

    tx["maxPriorityFeePerGas"] = max_priority
    tx["maxFeePerGas"] = base_fee + max_priority * 2

    # ---- Gas estimate ----
    try:
        tx["gas"] = w3.eth.estimate_gas(tx)
    except Exception:
        tx["gas"] = 300000  # fallback

    # ---- Sign and send ----
    signed = Account.sign_transaction(tx, account.key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    print(f"[{now_ts()}] Sent tx {tx_hash.hex()} → mined in block {receipt.blockNumber}")
    return receipt

def safe_call_read(contract, fn_name: str, args: tuple=()):
    try:
        return getattr(contract.functions, fn_name)(*args).call()
    except Exception as e:
        return f"CALL_ERROR: {repr(e)}"

# -------------------------
# Snapshot & diff helpers
# -------------------------
def governance_snapshot(contract):
    snap = {}
    snap['owners'] = safe_call_read(contract, "getOwners", ())
    snap['threshold'] = safe_call_read(contract, "getThreshold", ()) if hasattr(contract.functions, "getThreshold") else safe_call_read(contract, "threshold", ())
    return snap

def save_snapshot(snap, name):
    path = ARTIFACT_DIR / "snapshots" / f"{name}.json"
    save_json(snap, path)
    print(f"[{now_ts()}] Saved snapshot {path}")

def diff_snapshots(before: Dict, after: Dict):
    diffs = {
        "owners_added": [a for a in after.get("owners", []) if a not in before.get("owners", [])],
        "owners_removed": [a for a in before.get("owners", []) if a not in after.get("owners", [])],
        "threshold_before": before.get("threshold"),
        "threshold_after": after.get("threshold")
    }
    return diffs

# -------------------------
# High-level test scenarios
# -------------------------
def scenario_owner_addition(vul_contract, sec_contract, owners_accounts):
    """Scenario 1 — Owner Addition"""
    label = "Attacker addOwner (Vulnerable)"
    # 1. Fresh deployment for this scenario
    vuln_addr, sec_addr = fresh_deploy()

    print(f"\n[SCENARIO] Fresh deployment completed")
    print(f"   Vulnerable wallet: {vuln_addr}")
    print(f"   Secure wallet:     {sec_addr}")

    # 2. Create contract instances
    vul_contract = w3.eth.contract(address=vuln_addr, abi=vuln_abi)
    sec_contract = w3.eth.contract(address=sec_addr, abi=secure_abi)

    results = []
    attacker = ATTACKER_ACCOUNT
    # Vulnerable test: attacker calls addOwner directly (no access control)
    print(f"\n\n[{now_ts()}] SCENARIO 1: Owner Addition — Vulnerable contract")
    print(f"[{now_ts()}] Taking Snapshot on VULNERABLE WALLET before attacker attempts addOwner", flush=True)
    before_v = governance_snapshot(vul_contract)
    save_snapshot(before_v, "vulnerable_case1_before")
    print(f"[{now_ts()}] VULNERABLE WALLET snapshot before attacker addOwner", before_v, flush=True)
    try:
        # direct addOwner
        candidate = attacker.address
        print(f"[{now_ts()}] ATTACKER ATTEMPTING UNAUTHORISED ADD OWNER CALL", flush=True)
        func = vul_contract.functions.addOwner(candidate)
        data = func._encode_transaction_data()
        rec = build_tx_and_send(attacker, vul_contract.address, data)
        receipt = w3.eth.wait_for_transaction_receipt(rec["transactionHash"])
        if receipt.status == 1:
            print(f"[{now_ts()}] [SUCCESS] {label} executed successfully as expected:", rec["transactionHash"].hex(), flush=True)
        else:
            print(f"[{now_ts()}] [REVERT]  {label} reverted unexpectedly:", rec["transactionHash"].hex(), flush=True)
        print(f"[{now_ts()}] Taking Snapshot on VULNERABLE WALLET after attacker attempts addOwner", flush=True)
        after_v = governance_snapshot(vul_contract)
        save_snapshot(after_v, "vulnerable_case1_after")
        pretty_print_state("VULNERABLE AFTER ADD", vul_contract)
        print(f"[{now_ts()}] VULNERABLE WALLET snapshot after attacker addOwner", after_v, flush=True)
        diffs_v = diff_snapshots(before_v, after_v)
        print(f"[{now_ts()}] Vulnerable diffs: {diffs_v}", flush=True)
        results.append(("vuln_add_owner", {"receipt": rec, "diffs": diffs_v}))
    except Exception as e:
        print(f"[{now_ts()}] VULNERABLE scenario error: {e}", flush=True)
        results.append(("vuln_add_owner_error", str(e)))


    # Secure test: attacker attempts to call proposeAddOwner (must be owner-> revert)
    label = "Attacker proposeAddOwner (Secure)"
    print(f"\n\n[{now_ts()}] SCENARIO 1: Owner Addition — Secure contract")
    print(f"[{now_ts()}] Taking Snapshot on SECURE WALLET before attacker attempts addOwner", flush=True)
    before_s = governance_snapshot(sec_contract)
    save_snapshot(before_s, "secure_case1_before")
    print(f"[{now_ts()}] SECURE WALLET snapshot before attacker addOwner", before_s, flush=True)
    try:
        # attacker tries to call proposeAddOwner (should revert or fail)
        candidate = attacker.address
        print(f"[{now_ts()}] ATTACKER ATTEMPTING UNAUTHORISED ADD OWNER CALL", flush=True)
        func = sec_contract.functions.proposeAddOwner(candidate)
        data = func._encode_transaction_data()
        try:
            rec_s = build_tx_and_send(attacker, sec_contract.address, data)
            save_json(rec_s, ARTIFACT_DIR / "receipts" / f"secure_case1_add_{rec_s['transactionHash'].hex()}.json")
            receipt = w3.eth.wait_for_transaction_receipt(rec_s["transactionHash"])
            if receipt.status == 1:
                print(f"[{now_ts()}] [SUCCESS] {label} unexpectedly successfully :", rec_s["transactionHash"].hex(), flush=True)
            else:
                print(f"[{now_ts()}] [REVERT] {label} reverted as expected:", rec_s["transactionHash"].hex(), flush=True)

        except Exception as err:
            # Expected: revert or failure
            print(f"[{now_ts()}] SECURE addOwner reverted/failed as expected: {err}", flush=True)
            exec_outcome = ("reverted_as_expected", str(err))

        print(f"[{now_ts()}] Taking Snapshot on SECURE WALLET after attacker attempts addOwner", flush=True)
        after_s = governance_snapshot(sec_contract)
        save_snapshot(after_s, "secure_case1_after")
        pretty_print_state("SECURE AFTER ADD (ATTEMPT)", sec_contract)
        diffs = diff_snapshots(before_s, after_s)
        print(f"[{now_ts()}] Secure diffs: {diffs}")
        results.append(("secure_add_owner_by_attacker", rec_s, diffs))
    except Exception as e:
        print(f"[{now_ts()}] Secure proposeAddOwner (attacker) failed as expected: {e}")
        results.append(("secure_add_owner_by_attacker_failed", str(e)))
    return results

def scenario_owner_removal(vul_contract, sec_contract, owners_accounts):
    """Scenario 2 — Owner Removal"""
    label = "Attacker removeOwner (Vulnerable)"
    # 1. Fresh deployment for this scenario
    vuln_addr, sec_addr = fresh_deploy()

    print(f"\n[SCENARIO] Fresh deployment completed")
    print(f"   Vulnerable wallet: {vuln_addr}")
    print(f"   Secure wallet:     {sec_addr}")

    # 2. Create contract instances
    vul_contract = w3.eth.contract(address=vuln_addr, abi=vuln_abi)
    sec_contract = w3.eth.contract(address=sec_addr, abi=secure_abi)

    results = []
    attacker = ATTACKER_ACCOUNT
    print(f"\n\n[{now_ts()}] SCENARIO 2: Owner Removal — Vulnerable contract")
    print(f"[{now_ts()}] Taking Snapshot on VULNERABLE WALLET before attacker attempts removeOwner", flush=True)
    before_v = governance_snapshot(vul_contract)
    save_snapshot(before_v, "vulnerable_case2_before")
    print(f"[{now_ts()}] VULNERABLE WALLET snapshot before attacker attempts removeOwner", before_v, flush=True)

    try:
        # attacker removes an existing owner (vulnerable)
        target_owner = owners_accounts[0].address
        func = vul_contract.functions.removeOwner(target_owner)
        data = func._encode_transaction_data()
        rec = build_tx_and_send(attacker, vul_contract.address, data)
        receipt = w3.eth.wait_for_transaction_receipt(rec["transactionHash"])
        if receipt.status == 1:
            print(f"[{now_ts()}] [SUCCESS] {label} executed successfully as expected: {rec['transactionHash'].hex()}", flush=True)
        else:
            print(f"[{now_ts()}] [REVERT]  {label} reverted unexpectedly: {rec['transactionHash'].hex()}", flush=True)

        print(f"[{now_ts()}] Taking Snapshot on VULNERABLE WALLET after attacker attempts removeOwner", flush=True)
        after_v = governance_snapshot(vul_contract); save_snapshot(after_v, "vulnerable_case2_after")
        diffs = diff_snapshots(before_v, after_v)
        print(f"[{now_ts()}] Vulnerable diffs: {diffs}")
        results.append(("vulnerable_remove_owner", rec, diffs))
    except Exception as e:
        print(f"[{now_ts()}] Vulnerable removeOwner failed: {e}")
        results.append(("vulnerable_remove_owner_failed", str(e)))

    print(f"\n\n[{now_ts()}] SCENARIO 2: Owner Removal — Secure contract")
    label = "Attacker proposeRemoveOwner (Secure)"
    before_s = governance_snapshot(sec_contract); save_snapshot(before_s, "secure_case2_before")
    try:
        print(f"[{now_ts()}] ATTACKER ATTEMPTING UNAUTHORISED REMOVE OWNER PROPOSAL", flush=True)
        func = sec_contract.functions.proposeRemoveOwner(target_owner)
        data = func._encode_transaction_data()

        try:
            rec_s = build_tx_and_send(attacker, sec_contract.address, data)
            receipt = w3.eth.wait_for_transaction_receipt(rec_s["transactionHash"])

            if receipt.status == 1:
                print(f"[{now_ts()}] [SUCCESS] {label} UNEXPECTED SUCCESS: {rec_s['transactionHash'].hex()}", flush=True)
            else:
                print(f"[{now_ts()}] [REVERT]  {label} reverted as expected: {rec_s['transactionHash'].hex()}", flush=True)

        except Exception as err:
            print(f"[{now_ts()}] SECURE proposeRemoveOwner reverted/failed as expected: {err}", flush=True)
        print(f"[{now_ts()}] Taking Snapshot on SECURE WALLET after attacker attempts removeOwner", flush=True)
        after_s = governance_snapshot(sec_contract); save_snapshot(after_s, "secure_case2_after")
        diffs = diff_snapshots(before_s, after_s)
        print(f"[{now_ts()}] Secure diffs: {diffs}")
        results.append(("secure_remove_owner_proposal", rec_s, diffs))
    except Exception as e:
        print(f"[{now_ts()}] Secure removeOwner governance flow failed: {e}\n{traceback.format_exc()}")
        results.append(("secure_remove_owner_failed", str(e)))
    return results

def scenario_threshold_change(vul_contract, sec_contract, owners_accounts):
    """Scenario 3 — Threshold Change"""
    label = "Attacker changeThreshold (Vulnerable)"
    # 1. Fresh deployment for this scenario
    vuln_addr, sec_addr = fresh_deploy()

    print(f"\n[SCENARIO] Fresh deployment completed")
    print(f"   Vulnerable wallet: {vuln_addr}")
    print(f"   Secure wallet:     {sec_addr}")

    # 2. Create contract instances
    vul_contract = w3.eth.contract(address=vuln_addr, abi=vuln_abi)
    sec_contract = w3.eth.contract(address=sec_addr, abi=secure_abi)

    results = []
    attacker = ATTACKER_ACCOUNT
    print(f"\n\n[{now_ts()}] SCENARIO 3: Threshold Change — Vulnerable contract")
    print(f"[{now_ts()}] Taking Snapshot on VULNERABLE WALLET before attacker attempts Threshold Change", flush=True) 
    before_v = governance_snapshot(vul_contract)
    save_snapshot(before_v, "vulnerable_case3_before")
    print(f"[{now_ts()}] VULNERABLE WALLET snapshot before attacker attempts thresholdChange", before_v, flush=True)

    try:
        # Attacker attempts to increase threshold from default (1 → 2)
        current = before_v["threshold"]
        new = current + 1
        print(f"[{now_ts()}] ATTACKER ATTEMPTING UNAUTHORISED THRESHOLD INCREASE TO {new}", flush=True)
        func = vul_contract.functions.changeThreshold(new)
        data = func._encode_transaction_data()
        rec = build_tx_and_send(attacker, vul_contract.address, data)
        receipt = w3.eth.wait_for_transaction_receipt(rec["transactionHash"])
        if receipt.status == 1:
            print(f"[{now_ts()}] [SUCCESS] {label} executed successfully as expected: {rec['transactionHash'].hex()}", flush=True)
        else:
            print(f"[{now_ts()}] [REVERT]  {label} reverted unexpectedly: {rec['transactionHash'].hex()}", flush=True)
        print(f"[{now_ts()}] Taking Snapshot on VULNERABLE WALLET after attacker attempts thresholdChange", flush=True)
        after_v = governance_snapshot(vul_contract); save_snapshot(after_v, "vulnerable_case3_after")
        diffs = diff_snapshots(before_v, after_v)
        print(f"[{now_ts()}] Vulnerable diffs: {diffs}")
        results.append(("vulnerable_change_threshold_1", rec, diffs))
    except Exception as e:
        print(f"[{now_ts()}] Vulnerable changeThreshold failed: {e}")
        results.append(("vulnerable_change_threshold_failed", str(e)))

    print(f"\n\n[{now_ts()}] SCENARIO 3: Threshold Change — Secure contract")
    print(f"[{now_ts()}] Taking Snapshot on SECURE WALLET before attacker attempts Threshold Change", flush=True)
    before_s = governance_snapshot(sec_contract)
    save_snapshot(before_s, "secure_case3_before")
    print(f"[{now_ts()}] SECURE WALLET snapshot before attacker attempts thresholdChange", before_s, flush=True)

    try:
        # attacker attempts unauthorized governance proposal
        current = before_s["threshold"]
        new = current + 1

        print(f"[{now_ts()}] ATTACKER ATTEMPTING UNAUTHORISED proposeChangeThreshold({new})", flush=True)

        func = sec_contract.functions.proposeChangeThreshold(new)
        data = func._encode_transaction_data()
        try:
            # this SHOULD revert – attacker is not an owner
            rec_s = build_tx_and_send(attacker, sec_contract.address, data)
            receipt = w3.eth.wait_for_transaction_receipt(rec_s["transactionHash"])

            if receipt.status == 1:
                print(f"[{now_ts()}] [SUCCESS] UNEXPECTED SUCCESS: {rec_s['transactionHash'].hex()}", flush=True)
            else:
                print(f"[{now_ts()}] [REVERT]  proposeChangeThreshold reverted as expected: {rec_s['transactionHash'].hex()}", flush=True)

        except Exception as err:
            print(f"[{now_ts()}] SECURE proposeChangeThreshold reverted/failed as expected: {err}", flush=True)

        print(f"[{now_ts()}] Taking Snapshot on SECURE WALLET after attacker attempts thresholdChange", flush=True)
        after_s = governance_snapshot(sec_contract); save_snapshot(after_s, "secure_case3_after")
        diffs = diff_snapshots(before_s, after_s)
        print(f"[{now_ts()}] Secure diffs: {diffs}")
        results.append(("secure_change_threshold_proposal", rec_s, diffs))
    except Exception as e:
        print(f"[{now_ts()}] Secure proposeChangeThreshold failed: {e}")
        results.append(("secure_change_threshold_failed", str(e)))

    return results

def scenario_inconsistent_proposal_state(vul_contract, sec_contract, owners_accounts):
    """Scenario 4 — Inconsistent Proposal State"""
    # 1. Fresh deployment for this scenario
    vuln_addr, sec_addr = fresh_deploy()

    print(f"\n[SCENARIO] Fresh deployment completed")
    print(f"   Vulnerable wallet: {vuln_addr}")
    print(f"   Secure wallet:     {sec_addr}")

    # 2. Create contract instances
    vul_contract = w3.eth.contract(address=vuln_addr, abi=vuln_abi)
    sec_contract = w3.eth.contract(address=sec_addr, abi=secure_abi)

    results = []
    attacker = ATTACKER_ACCOUNT
    print(f"\n\n[{now_ts()}] SCENARIO 4: Inconsistent Proposal State — Vulnerable contract")
    print(f"[{now_ts()}] Taking Snapshot on VULNERABLE WALLET before attacker attempts to induce Inconsistent Proposal State", flush=True)
    before_v = governance_snapshot(vul_contract)
    save_snapshot(before_v, "vulnerable_case4_before")
    print(f"[{now_ts()}] VULNERABLE WALLET snapshot before attacker attempts to induce Inconsistent Proposal State", before_v, flush=True)

    try:
        print(f"\n\n[{now_ts()}] Owner Creating Proposal for valid transaction on Vulnerable contract")
        # Create a proposal and have attacker cancel or remove owners mid-way
        pid = vul_contract.functions.proposeTransaction(vul_contract.address, 0, b"").call()
        # However vulnerable's proposeTransaction returns id via tx; simpler: call propose then check proposalCount
        func = vul_contract.functions.proposeTransaction(vul_contract.address, 0, b"")
        data = func._encode_transaction_data()
        rec = build_tx_and_send(OWNER_ACCOUNTS[0], vul_contract.address, data)
        print(f"[{now_ts()}] Proposed Transaction", rec["transactionHash"].hex(), flush=True)
        prop_id = vul_contract.functions.proposalCount().call()
        # Attacker removes owner who confirmed earlier
        # Confirm by owner[0]
        print(f"\n\n[{now_ts()}] Owner Confirming Proposal for valid transaction on Vulnerable contract")
        func = vul_contract.functions.confirmTransaction(prop_id)
        data = func._encode_transaction_data()
        rec2 = build_tx_and_send(OWNER_ACCOUNTS[0], vul_contract.address, data)
        print(f"\n\n[{now_ts()}] Confirmed Proposal for valid transaction on Vulnerable contract:", rec2["transactionHash"].hex(), flush=True)
        # Attacker removes that owner
        print(f"\n\n[{now_ts()}] Attacker attempting to remove owner")
        target_owner = OWNER_ACCOUNTS[0].address
        func = vul_contract.functions.removeOwner(target_owner)
        data = func._encode_transaction_data()
        rec3 = build_tx_and_send(attacker, vul_contract.address, data)
        receipt = w3.eth.wait_for_transaction_receipt(rec3["transactionHash"])
        if receipt.status == 1:
            print(f"[{now_ts()}] [SUCCESS] Attacker Successfully Removes Owner as Expected: {rec3['transactionHash'].hex()}", flush=True)
        else:
            print(f"[{now_ts()}] [REVERT]  Attacker attmpt fails unexpectedly: {rec3['transactionHash'].hex()}", flush=True)
        try:
            print(f"[{now_ts()}] Attempting to EXECUTE vulnerable proposal {prop_id}")
            func = vul_contract.functions.executeTransaction(prop_id)
            data = func._encode_transaction_data()
            rec_exec = build_tx_and_send(OWNER_ACCOUNTS[0], vul_contract.address, data)
            receipt_exec = w3.eth.wait_for_transaction_receipt(rec_exec["transactionHash"])
            if receipt_exec.status == 1:
                print(f"[{now_ts()}] [SUCCESS] Vulnerable executeTransaction unexpectedly succeeded: {rec_exec['transactionHash'].hex()}")
            else:
                print(f"[{now_ts()}] [REVERT] Vulnerable executeTransaction reverted: {rec_exec['transactionHash'].hex()}")
        except Exception as e:
            print(f"[{now_ts()}] Vulnerable executeTransaction threw exception: {e}")

        print(f"[{now_ts()}] Taking Snapshot on VULNERABLE WALLET after attacker attempts to induce Inconsistent Proposal State", flush=True)
        after_v = governance_snapshot(vul_contract); save_snapshot(after_v, "vulnerable_case4_after")
        diffs = diff_snapshots(before_v, after_v)
        results.append(("vulnerable_inconsistent", (rec, rec2, rec3), diffs))
    except Exception as e:
        print(f"[{now_ts()}] Vulnerable inconsistent state flow failed: {e}")
        results.append(("vulnerable_inconsistent_failed", str(e)))

    print(f"\n\n[{now_ts()}] SCENARIO 4: Inconsistent Proposal State — Secure contract")
    print(f"[{now_ts()}] Taking Snapshot on SECURE WALLET before attacker attempts to induce Inconsistent Proposal State", flush=True)
    before_s = governance_snapshot(sec_contract); save_snapshot(before_s, "secure_case4_before")
    try:
        print(f"\n\n[{now_ts()}] Owner Creating Proposal for valid transaction on Secure contract")
        proposer = owners_accounts[0]
        target_remove = owners_accounts[1].address

        # Step 1 — proposer creates proposal to remove owner[1]
        func = sec_contract.functions.proposeTransaction(sec_addr, 0, b"")
        data = func._encode_transaction_data()
        rec_prop = build_tx_and_send(proposer, sec_contract.address, data)
        print(f"[{now_ts()}] Proposed Transaction", rec_prop["transactionHash"].hex(), flush=True)
        proposal_id = sec_contract.functions.proposalCount().call()
        print(f"[{now_ts()}] Secure proposal created, ID = {proposal_id}")

        print(f"\n\n[{now_ts()}] Owner Confirming Proposal for valid transaction on Secure contract")

        # Step 2 — target owner confirms
        func = sec_contract.functions.confirmTransaction(proposal_id)
        data = func._encode_transaction_data()
        rec_conf = build_tx_and_send(owners_accounts[1], sec_contract.address, data)
        print(f"\n\n[{now_ts()}] Confirmed Proposal for valid transaction on Secure contract:", rec_conf["transactionHash"].hex(), flush=True)

        # Step 3 — attacker attempts illegal direct removeOwner
        print(f"\n\n[{now_ts()}] Attacker attempting to remove owner")
        attempts = {}
        try:
            func = sec_contract.functions.removeOwner(target_remove)
            data = func._encode_transaction_data()
            rec_remove = build_tx_and_send(attacker, sec_contract.address, data)
            receipt = w3.eth.wait_for_transaction_receipt(rec_remove["transactionHash"])
            if receipt.status == 1:
                print(f"[{now_ts()}] [SUCCESS] Attacker Unexpectedly Successfully in Removing Owner: {rec_remove['transactionHash'].hex()}", flush=True)
            else:
                print(f"[{now_ts()}] [REVERT]  Attacker attempt fails as expected: {rec_remove['transactionHash'].hex()}", flush=True)
            attempts["remove_direct_by_attacker"] = rec_remove
        except Exception as e:
            print(f"[{now_ts()}] Attacker attempt fails as expected: {e}")
            attempts["remove_direct_by_attacker_error"] = str(e)

        # Step 4 — confirm by others to reach threshold
        print(f"\n\n[{now_ts()}] Remaining Owners Confirming Proposal for valid transaction on Secure contract")
        for i in range(2, min(len(owners_accounts), 4)):
            try:
                func = sec_contract.functions.confirmTransaction(proposal_id)
                data = func._encode_transaction_data()
                rec2 = build_tx_and_send(owners_accounts[i], sec_contract.address, data)
                print(f"\n\n[{now_ts()}] Confirmed Proposal for valid transaction on Vulnerable contract:", rec2["transactionHash"].hex(), flush=True)
            except Exception:
                pass

        # Step 5 — wait timelock
        try:
            p = sec_contract.functions.getProposal(proposal_id).call()
            executeAfter = p[7]
            now = int(time.time())
            if executeAfter > now:
                wait_seconds = executeAfter - now + 1
                print(f"[{now_ts()}] Waiting {wait_seconds}s for timelock")
                time.sleep(wait_seconds)
        except Exception:
            pass

        # Step 6 — execute governance
        print(f"\n\n[{now_ts()}] Proposer attempting to execute valid transaction on Secure contract")
        func = sec_contract.functions.executeTransaction(proposal_id)
        data = func._encode_transaction_data()
        rec_exec = build_tx_and_send(proposer, sec_contract.address, data)
        receipt = w3.eth.wait_for_transaction_receipt(rec_exec["transactionHash"])
        if receipt.status == 1:
            print(f"[{now_ts()}] [SUCCESS] Transaction Successfully Executed as Expected: {rec_exec['transactionHash'].hex()}", flush=True)
        else:
            print(f"[{now_ts()}] [REVERT]  Transaction Execution fails as unexpectedly: {rec_exec['transactionHash'].hex()}", flush=True)
        print(f"[{now_ts()}] Taking Snapshot on SECURE WALLET after attacker attempts to induce Inconsistent Proposal State", flush=True)
        after_s = governance_snapshot(sec_contract); save_snapshot(after_s, "secure_case4_after")
        diffs = diff_snapshots(before_s, after_s)
        results.append(("secure_inconsistent", (rec, attempts), diffs))
    except Exception as e:
        print(f"[{now_ts()}] Secure inconsistent proposal state flow failed: {e}\n{traceback.format_exc()}")
        results.append(("secure_inconsistent_failed", str(e)))
    return results

# -------------------------
# Driver: load contracts and run scenarios
# -------------------------
def run_all():
    # Create owners_account objects from private keys
    owners_accounts = OWNER_ACCOUNTS
    vul_contract = None;
    sec_contract = None;
    summary = []
    load_abis()
    print(f"[{now_ts()}] ABIs loaded")
    # Execute scenarios; each scenario returns a list of results
    try:
        summary.extend(scenario_owner_addition(vul_contract, sec_contract, owners_accounts))
        summary.extend(scenario_owner_removal(vul_contract, sec_contract, owners_accounts))
        summary.extend(scenario_threshold_change(vul_contract, sec_contract, owners_accounts))
        summary.extend(scenario_inconsistent_proposal_state(vul_contract, sec_contract, owners_accounts))
    except Exception as e:
        print(f"[{now_ts()}] Error during test run: {e}\n{traceback.format_exc()}")

    # Summarize and write artifacts
    summary_path = ARTIFACT_DIR / "summary.json"
    save_json(summary, summary_path)
    print(f"[{now_ts()}] Finished test run. Summary saved to {summary_path}")

if __name__ == "__main__":
    run_all()

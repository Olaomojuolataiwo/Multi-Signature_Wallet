#!/usr/bin/env python3
"""
T-01 Governance & Access Control test runner

Run: python t01_governance_runner.py

Edit CONFIG section before running.
"""

import os
import json
import time
import traceback
from pathlib import Path
from typing import Dict, Any, List, Tuple
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
CHAIN_ID = 11155111  # example Sepolia chain id; change to your network
OWNER_PRIVATE_KEYS = os.getenv("OWNER_PRIVATE_KEYS").split()
ATTACKER_PRIVATE_KEY = os.getenv("ATTACKER_PRIVATE_KEY")
VULNERABLE_ADDR = os.getenv("VULNERABLE_ADDRESS")
SECURE_ADDR = os.getenv("SECURE_ADDRESS")

VULNERABLE_ABI_PATH = "../out/VulnerableMultiSig.sol/VulnerableMultiSig.json"
SECURE_ABI_PATH = "../out/SecureMultiSig.sol/SecureMultiSig.json"

# If you want the script to compile solidity sources if ABI not provided:
DEFAULT_SECURE_SOURCE = "/mnt/data/SecureMultiSig.txt"  # your uploaded file path
DEFAULT_VULNERABLE_SOURCE = None  # set if you have vulnerable source file locally

# Transaction parameters
GAS = 5_000_000
GAS_PRICE = None  # in wei; if None web3 will use eth_gasPrice
TX_POLL_INTERVAL = 2  # seconds between receipt polls

# Output
ARTIFACT_DIR = Path("./artifacts/T-01")
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

# -------------------------
# Helper utilities
# -------------------------
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
# Compile helpers (optional)
# -------------------------
def compile_sol(source_path: str, contract_name: str = None) -> Dict[str, Any]:
    if not SOLCX_AVAILABLE:
        raise RuntimeError("solcx not available; provide ABI instead or install py-solc-x")
    solcx.install_solc("0.8.30")
    with open(source_path, "r") as f:
        src = f.read()
    # crude compile all contracts in file
    compiled = solcx.compile_source(src, output_values=["abi", "bin"], solc_version="0.8.30")
    # If contract_name provided, select that; otherwise take first
    if contract_name:
        key = None
        for k in compiled:
            if k.endswith(contract_name):
                key = k
                break
        if not key:
            raise RuntimeError(f"Contract {contract_name} not found in compiled output")
    else:
        # take first key
        key = next(iter(compiled.keys()))
    return {
        "abi": compiled[key]["abi"],
        "bin": compiled[key]["bin"]
    }

# -------------------------
# Load ABIs either from file or compile source
# -------------------------
def load_contract_interface(addr: str, abi_path: str, default_source: str, contract_selector: str = None):
    if abi_path and Path(abi_path).exists():
        artifact = load_json(abi_path)
        if isinstance(artifact, dict) and "abi" in artifact:
            abi = artifact["abi"]
        else:
            raise ValueError(f"ABI not found in artifact file: {abi_path}")
        print(f"[{now_ts()}] Loaded ABI from {abi_path}")
    else:
        if default_source is None:
            raise RuntimeError("No ABI and no source path provided for contract.")
        print(f"[{now_ts()}] Compiling source {default_source} to extract ABI...")
        compiled = compile_sol(default_source, contract_selector)
        abi = compiled["abi"]
        print(f"[{now_ts()}] Compiled and extracted ABI from {default_source}")
    return w3.eth.contract(address=to_checksum_address(addr), abi=abi)


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
        "type": 2,  # EIP-1559
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

def call_function_and_log(contract, fn_name: str, args: tuple, sender_acct: Account=None, value=0):
    """
    Call a contract function that writes state (send tx) - signs and sends using sender_acct.
    Logs tx hash and receipt and stores to artifacts.
    """
    func = getattr(contract.functions, fn_name)(*args)
    data = func._encode_transaction_data()
    to = contract.address
    sender = sender_acct if sender_acct else OWNER_ACCOUNTS[0]
    receipt = build_tx_and_send(sender, to, data, value=value)
    # Save receipt
    txh = receipt["transactionHash"].hex()
    save_json(receipt, ARTIFACT_DIR / "receipts" / f"{txh}.json")
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
    results = []
    attacker = ATTACKER_ACCOUNT
    # Vulnerable test: attacker calls addOwner directly (no access control)
    print(f"\n\n[{now_ts()}] CASE 1: Owner Addition — Vulnerable contract")
    before = governance_snapshot(vul_contract)
    save_snapshot(before, "vulnerable_case1_before")
    try:
        # direct addOwner
        func = vul_contract.functions.addOwner(attacker.address)
        data = func._encode_transaction_data()
        rec = build_tx_and_send(attacker, vul_contract.address, data)
        print(f"[{now_ts()}] Vulnerable addOwner tx: {rec['transactionHash'].hex()}")
        after = governance_snapshot(vul_contract)
        save_snapshot(after, "vulnerable_case1_after")
        diffs = diff_snapshots(before, after)
        print(f"[{now_ts()}] Vulnerable diffs: {diffs}")
        results.append(("vulnerable_add_owner", rec, diffs))
    except Exception as e:
        print(f"[{now_ts()}] Vulnerable addOwner failed: {e}")
        results.append(("vulnerable_add_owner_failed", str(e)))

    # Secure test: attacker attempts to call proposeAddOwner (must be owner-> revert)
    print(f"\n\n[{now_ts()}] CASE 1: Owner Addition — Secure contract")
    before = governance_snapshot(sec_contract)
    save_snapshot(before, "secure_case1_before")
    try:
        # attacker tries to call proposeAddOwner (should revert or fail)
        func = sec_contract.functions.proposeAddOwner(attacker.address)
        data = func._encode_transaction_data()
        rec = build_tx_and_send(attacker, sec_contract.address, data)
        print(f"[{now_ts()}] Secure proposeAddOwner by attacker tx: {rec['transactionHash'].hex()}")
        after = governance_snapshot(sec_contract)
        save_snapshot(after, "secure_case1_after")
        diffs = diff_snapshots(before, after)
        print(f"[{now_ts()}] Secure diffs: {diffs}")
        results.append(("secure_add_owner_by_attacker", rec, diffs))
    except Exception as e:
        print(f"[{now_ts()}] Secure proposeAddOwner (attacker) failed as expected: {e}")
        results.append(("secure_add_owner_by_attacker_failed", str(e)))
    return results

def scenario_owner_removal(vul_contract, sec_contract, owners_accounts):
    """Scenario 2 — Owner Removal"""
    results = []
    attacker = ATTACKER_ACCOUNT
    print(f"\n\n[{now_ts()}] SCENARIO 2: Owner Removal — Vulnerable contract")
    before = governance_snapshot(vul_contract); save_snapshot(before, "vulnerable_case2_before")
    try:
        # attacker removes an existing owner (vulnerable)
        target_owner = owners_accounts[0].address
        func = vul_contract.functions.removeOwner(target_owner)
        data = func._encode_transaction_data()
        rec = build_tx_and_send(attacker, vul_contract.address, data)
        print(f"[{now_ts()}] Vulnerable removeOwner tx: {rec['transactionHash'].hex()}")
        after = governance_snapshot(vul_contract); save_snapshot(after, "vulnerable_case2_after")
        diffs = diff_snapshots(before, after)
        print(f"[{now_ts()}] Vulnerable diffs: {diffs}")
        results.append(("vulnerable_remove_owner", rec, diffs))
    except Exception as e:
        print(f"[{now_ts()}] Vulnerable removeOwner failed: {e}")
        results.append(("vulnerable_remove_owner_failed", str(e)))

    print(f"\n\n[{now_ts()}] SCENARIO 2: Owner Removal — Secure contract")
    before = governance_snapshot(sec_contract); save_snapshot(before, "secure_case2_before")
    try:
        # secure: owners must propose+confirm+timelock then executeGovernance
        new_proposal_rcpts = []
        # owner[0] creates proposal
        proposer = owners_accounts[0]
        func = sec_contract.functions.proposeRemoveOwner(target_owner)
        data = func._encode_transaction_data()
        rec = build_tx_and_send(proposer, sec_contract.address, data)
        print(f"[{now_ts()}] Secure proposeRemoveOwner tx: {rec['transactionHash'].hex()}")
        pid = rec.get('logs', [])
        # We'll find the proposalId by reading proposalCount
        prop_count = sec_contract.functions.proposalCount().call()
        proposal_id = prop_count  # last created
        # Confirm by remaining owners up to threshold
        for i in range(1, min(len(owners_accounts), 4)):
            c = owners_accounts[i]
            func = sec_contract.functions.confirmTransaction(proposal_id)
            data = func._encode_transaction_data()
            rec2 = build_tx_and_send(c, sec_contract.address, data)
            print(f"[{now_ts()}] Confirm tx: {rec2['transactionHash'].hex()}")
        # Wait timelock if set
        try:
            p = sec_contract.functions.getProposal(proposal_id).call()
            executeAfter = p[7]  # executeAfter field
            if executeAfter > int(time.time()):
                wait_seconds = executeAfter - int(time.time()) + 1
                print(f"[{now_ts()}] Waiting {wait_seconds}s for timelock")
                time.sleep(wait_seconds)
        except Exception:
            pass
        # Execute governance
        func = sec_contract.functions.executeGovernance(proposal_id)
        data = func._encode_transaction_data()
        rec3 = build_tx_and_send(proposer, sec_contract.address, data)
        print(f"[{now_ts()}] executeGovernance tx: {rec3['transactionHash'].hex()}")
        after = governance_snapshot(sec_contract); save_snapshot(after, "secure_case2_after")
        diffs = diff_snapshots(before, after)
        print(f"[{now_ts()}] Secure diffs: {diffs}")
        results.append(("secure_remove_owner_proposal", rec3, diffs))
    except Exception as e:
        print(f"[{now_ts()}] Secure removeOwner governance flow failed: {e}\n{traceback.format_exc()}")
        results.append(("secure_remove_owner_failed", str(e)))
    return results

def scenario_threshold_change(vul_contract, sec_contract, owners_accounts):
    """Scenario 3 — Threshold Change"""
    results = []
    attacker = ATTACKER_ACCOUNT
    print(f"\n\n[{now_ts()}] SCENARIO 3: Threshold Change — Vulnerable contract")
    before = governance_snapshot(vul_contract); save_snapshot(before, "vulnerable_case3_before")
    try:
        # Attacker sets threshold to 1 directly
        func = vul_contract.functions.changeThreshold(1)
        data = func._encode_transaction_data()
        rec = build_tx_and_send(attacker, vul_contract.address, data)
        print(f"[{now_ts()}] Vulnerable changeThreshold tx: {rec['transactionHash'].hex()}")
        after = governance_snapshot(vul_contract); save_snapshot(after, "vulnerable_case3_after")
        diffs = diff_snapshots(before, after)
        print(f"[{now_ts()}] Vulnerable diffs: {diffs}")
        results.append(("vulnerable_change_threshold_1", rec, diffs))
    except Exception as e:
        print(f"[{now_ts()}] Vulnerable changeThreshold failed: {e}")
        results.append(("vulnerable_change_threshold_failed", str(e)))

    print(f"\n\n[{now_ts()}] SCENARIO 3: Threshold Change — Secure contract")
    before = governance_snapshot(sec_contract); save_snapshot(before, "secure_case3_before")
    try:
        # secure: proposeChangeThreshold -> confirm -> wait -> executeGovernance
        proposer = owners_accounts[0]
        newT = 1
        func = sec_contract.functions.proposeChangeThreshold(newT)
        data = func._encode_transaction_data()
        rec = build_tx_and_send(proposer, sec_contract.address, data)
        print(f"[{now_ts()}] Secure proposeChangeThreshold tx: {rec['transactionHash'].hex()}")
        proposal_id = sec_contract.functions.proposalCount().call()
        # confirm with others
        for i in range(1, min(len(owners_accounts), 4)):
            func = sec_contract.functions.confirmTransaction(proposal_id)
            data = func._encode_transaction_data()
            rec2 = build_tx_and_send(owners_accounts[i], sec_contract.address, data)
            print(f"[{now_ts()}] Confirm tx: {rec2['transactionHash'].hex()}")
        # handle timelock
        try:
            p = sec_contract.functions.getProposal(proposal_id).call()
            executeAfter = p[7]  # executeAfter field
            if executeAfter > int(time.time()):
                wait_seconds = executeAfter - int(time.time()) + 1
                print(f"[{now_ts()}] Waiting {wait_seconds}s for timelock")
                time.sleep(wait_seconds)
        except Exception:
            pass
        # execute
        func = sec_contract.functions.executeGovernance(proposal_id)
        data = func._encode_transaction_data()
        rec3 = build_tx_and_send(proposer, sec_contract.address, data)
        print(f"[{now_ts()}] executeGovernance tx: {rec3['transactionHash'].hex()}")
        after = governance_snapshot(sec_contract); save_snapshot(after, "secure_case3_after")
        diffs = diff_snapshots(before, after)
        print(f"[{now_ts()}] Secure diffs: {diffs}")
        results.append(("secure_change_threshold_proposal", rec3, diffs))
    except Exception as e:
        print(f"[{now_ts()}] Secure proposeChangeThreshold failed: {e}")
        results.append(("secure_change_threshold_failed", str(e)))

    return results

def scenario_unauthorized_attempts(vul_contract, sec_contract):
    """Scenario 4 — Unauthorized Governance Attempts"""
    results = []
    attacker = ATTACKER_ACCOUNT
    print(f"\n\n[{now_ts()}] SCENARIO 4: Unauthorized Governance Attempts — Vulnerable contract")
    before = governance_snapshot(vul_contract); save_snapshot(before, "vulnerable_case4_before")
    try:
        # Vulnerable: attacker can call changeThreshold, addOwner, removeOwner directly
        # attempt addOwner
        recs = {}
        for fn_name, arg in [("addOwner", attacker.address), ("changeThreshold", 1)]:
            func = getattr(vul_contract.functions, fn_name)(arg)
            data = func._encode_transaction_data()
            rec = build_tx_and_send(attacker, vul_contract.address, data)
            recs[fn_name] = rec
            print(f"[{now_ts()}] Vulnerable {fn_name} tx: {rec['transactionHash'].hex()}")
        after = governance_snapshot(vul_contract); save_snapshot(after, "vulnerable_case4_after")
        diffs = diff_snapshots(before, after)
        results.append(("vulnerable_unauthorized", recs, diffs))
    except Exception as e:
        print(f"[{now_ts()}] Vulnerable unauthorized attempts failed: {e}")
        results.append(("vulnerable_unauthorized_failed", str(e)))

    print(f"\n\n[{now_ts()}] SCENARIO 4: Unauthorized Governance Attempts — Secure contract")
    before = governance_snapshot(sec_contract); save_snapshot(before, "secure_case4_before")
    try:
        # attacker tries similar flows on secure: proposeAddOwner (should revert or be blocked)
        attempts = {}
        try:
            func = sec_contract.functions.addOwner(attacker.address)  # if secure accidentally exposes addOwner
            data = func._encode_transaction_data()
            rec = build_tx_and_send(attacker, sec_contract.address, data)
            attempts['addOwner_direct'] = rec
        except Exception as e:
            attempts['addOwner_direct_error'] = str(e)

        # try proposeAddOwner (should revert because onlyOwner)
        try:
            func = sec_contract.functions.proposeAddOwner(attacker.address)
            data = func._encode_transaction_data()
            rec = build_tx_and_send(attacker, sec_contract.address, data)
            attempts['proposeAddOwner'] = rec
        except Exception as e:
            attempts['proposeAddOwner_error'] = str(e)

        after = governance_snapshot(sec_contract); save_snapshot(after, "secure_case4_after")
        diffs = diff_snapshots(before, after)
        results.append(("secure_unauthorized_attempts", attempts, diffs))
    except Exception as e:
        print(f"[{now_ts()}] Secure unauthorized attempts outer failed: {e}")
        results.append(("secure_unauthorized_failed", str(e)))

    return results

def scenario_inconsistent_proposal_state(vul_contract, sec_contract, owners_accounts):
    """Scenario 5 — Inconsistent Proposal State"""
    results = []
    attacker = ATTACKER_ACCOUNT
    print(f"\n\n[{now_ts()}] SCENARIO 5: Inconsistent Proposal State — Vulnerable contract")
    before = governance_snapshot(vul_contract); save_snapshot(before, "vulnerable_case5_before")
    try:
        # Create a proposal and have attacker cancel or remove owners mid-way
        pid = vul_contract.functions.proposeTransaction(vul_contract.address, 0, b"").call()
        # However vulnerable's proposeTransaction returns id via tx; simpler: call propose then check proposalCount
        func = vul_contract.functions.proposeTransaction(vul_contract.address, 0, b"")
        data = func._encode_transaction_data()
        rec = build_tx_and_send(OWNER_ACCOUNTS[0], vul_contract.address, data)
        prop_id = vul_contract.functions.proposalCount().call()
        # Attacker removes owner who confirmed earlier
        # Confirm by owner[0]
        func = vul_contract.functions.confirmTransaction(prop_id)
        data = func._encode_transaction_data()
        rec2 = build_tx_and_send(OWNER_ACCOUNTS[0], vul_contract.address, data)
        # Attacker removes that owner
        func = vul_contract.functions.removeOwner(OWNER_ACCOUNTS[0].address)
        data = func._encode_transaction_data()
        rec3 = build_tx_and_send(attacker, vul_contract.address, data)
        after = governance_snapshot(vul_contract); save_snapshot(after, "vulnerable_case5_after")
        diffs = diff_snapshots(before, after)
        results.append(("vulnerable_inconsistent", (rec, rec2, rec3), diffs))
    except Exception as e:
        print(f"[{now_ts()}] Vulnerable inconsistent state flow failed: {e}")
        results.append(("vulnerable_inconsistent_failed", str(e)))

    print(f"\n\n[{now_ts()}] SCENARIO 5: Inconsistent Proposal State — Secure contract")
    before = governance_snapshot(sec_contract); save_snapshot(before, "secure_case5_before")
    try:
        # Secure: create proposal to remove owner then attempt to remove them directly (should fail)
        proposer = owners_accounts[0]
        func = sec_contract.functions.proposeRemoveOwner(owners_accounts[1].address)
        data = func._encode_transaction_data()
        rec = build_tx_and_send(proposer, sec_contract.address, data)
        proposal_id = sec_contract.functions.proposalCount().call()
        # owner[1] confirms
        rec2 = build_tx_and_send(owners_accounts[1], sec_contract.address, sec_contract.functions.confirmTransaction(proposal_id)._encode_transaction_data())
        # attacker tries to call removeOwner directly (should be rejected)
        try:
            rec3 = build_tx_and_send(attacker, sec_contract.address, sec_contract.functions.removeOwner(owners_accounts[1].address)._encode_transaction_data())
            attempts = {"remove_direct_by_attacker": rec3}
        except Exception as e:
            attempts = {"remove_direct_by_attacker_error": str(e)}
        # Execute governance properly by proposer/threshold after timelock
        # confirm by others
        for i in range(2, min(len(owners_accounts), 4)):
            try:
                build_tx_and_send(owners_accounts[i], sec_contract.address, sec_contract.functions.confirmTransaction(proposal_id)._encode_transaction_data())
            except Exception:
                pass
        try:
            p = sec_contract.functions.getProposal(proposal_id).call()
            executeAfter = p[7]
            if executeAfter > int(time.time()):
                wait_seconds = executeAfter - int(time.time()) + 1
                time.sleep(wait_seconds)
        except Exception:
            pass
        build_tx_and_send(proposer, sec_contract.address, sec_contract.functions.executeGovernance(proposal_id)._encode_transaction_data())
        after = governance_snapshot(sec_contract); save_snapshot(after, "secure_case5_after")
        diffs = diff_snapshots(before, after)
        results.append(("secure_inconsistent", (rec, attempts), diffs))
    except Exception as e:
        print(f"[{now_ts()}] Secure inconsistent proposal state flow failed: {e}\n{traceback.format_exc()}")
        results.append(("secure_inconsistent_failed", str(e)))
    return results

# -------------------------
# Driver: load contracts and run scenarios
# -------------------------
def run_all():
    # Load contracts
    vul_contract = load_contract_interface(VULNERABLE_ADDR, VULNERABLE_ABI_PATH, DEFAULT_VULNERABLE_SOURCE)
    sec_contract = load_contract_interface(SECURE_ADDR, SECURE_ABI_PATH, DEFAULT_SECURE_SOURCE)

    # Quick check: print basic state
    print(f"[{now_ts()}] Vulnerable contract at {vul_contract.address}")
    print(f"[{now_ts()}] Secure contract at {sec_contract.address}")

    # Create owners_account objects from private keys
    owners_accounts = OWNER_ACCOUNTS

    summary = []
    # Execute scenarios; each scenario returns a list of results
    try:
        summary.extend(scenario_owner_addition(vul_contract, sec_contract, owners_accounts))
        summary.extend(scenario_owner_removal(vul_contract, sec_contract, owners_accounts))
        summary.extend(scenario_threshold_change(vul_contract, sec_contract, owners_accounts))
        summary.extend(scenario_unauthorized_attempts(vul_contract, sec_contract))
        summary.extend(scenario_inconsistent_proposal_state(vul_contract, sec_contract, owners_accounts))
    except Exception as e:
        print(f"[{now_ts()}] Error during test run: {e}\n{traceback.format_exc()}")

    # Summarize and write artifacts
    summary_path = ARTIFACT_DIR / "summary.json"
    save_json(summary, summary_path)
    print(f"[{now_ts()}] Finished test run. Summary saved to {summary_path}")

if __name__ == "__main__":
    run_all()

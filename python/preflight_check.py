#!/usr/bin/env python3
"""
preflight_check.py

Checks:
 - VULNERABLE_ADDRESS and SECURE_ADDRESS have runtime bytecode deployed
 - REENTRANCY_ATTACKER_ADDRESS and SINKHOLE_ADDRESS have runtime bytecode deployed
 - runtime bytecode contains the 4-byte selectors for the specified function signatures

Usage:
  export ALCHEMY_URL="https://eth-sepolia.g.alchemy.com/v2/KEY"
  export VULNERABLE_ADDRESS=0x...
  export SECURE_ADDRESS=0x...
  export REENTRANCY_ATTACKER_ADDRESS=0x...
  export SINKHOLE_ADDRESS=0x...
  python preflight_check.py

Output:
  ./artifacts/T-03/preflight_report.json
"""

import os
import sys
import json
from web3 import Web3
from eth_utils import keccak, to_checksum_address

# --- Config / env ---
ALCHEMY_URL = os.getenv("ALCHEMY_URL")
VULNERABLE = os.getenv("VULNERABLE_ADDRESS")
SECURE = os.getenv("SECURE_ADDRESS")
REENTRANCY = os.getenv("REENTRANCY_ATTACKER_ADDRESS")
SINKHOLE = os.getenv("SINKHOLE_ADDRESS")
ARTIFACT_DIR = os.getenv("ARTIFACT_DIR", "./artifacts/T-03")

if not ALCHEMY_URL:
    print("ALCHEMY_URL env var is required", file=sys.stderr)
    sys.exit(2)

addresses = {
    "Vulnerable": VULNERABLE,
    "Secure": SECURE,
    "ReentrancyAttacker": REENTRANCY,
    "Sinkhole": SINKHOLE,
}

# functions to check: map contract role -> list of function signatures
FUNCTION_SIGNATURES = {
    "multisig_core": [
        "proposeTransaction(address,uint256,bytes)",
        "confirmTransaction(uint256)",
        "executeTransaction(uint256)",
        "batchExecute(uint256[] calldata)",
        # optional helpers we may look for
        "proposalCount()",
    ],
    "reentrancy_attacker": [
        "setProposalId(uint256)",
        "withdraw(address)",
        "receive()",  # placeholder; receive() has no selector but we still include for note
    ],
    "sinkhole": [
        "implode(address)",
        "implodeBurn()",
        "withdrawIfUnlocked(address)",
        "unlock()",
        "balance()",
        # receive() can't be checked by selector
    ],
}


def selector_of(sig: str) -> str:
    """
    Return hex selector string like '0xabcdef12' for a function signature.
    For signatures that are 'receive()' we return None because receive/fallback have no selector.
    """
    if sig.strip().lower() in ("receive()", "fallback()"):
        return None
    k = keccak(text=sig)
    return "0x" + k[:4].hex()


def read_runtime_code(w3: Web3, addr_hex: str) -> str:
    addr = to_checksum_address(addr_hex)
    code = w3.eth.get_code(addr)
    # return as hex string with 0x prefix
    return code.hex() if isinstance(code, bytes) else str(code)


def check_selectors_in_code(code_hex: str, selectors: dict) -> dict:
    """
    selectors: mapping sig->selector_hex (or None)
    returns mapping sig -> bool (found)
    """
    res = {}
    # normalise code hex to lower-case
    code = code_hex.lower()
    for sig, sel in selectors.items():
        if sel is None:
            # cannot search for receive/fallback
            res[sig] = None
            continue
        # remove 0x prefix
        needle = sel[2:].lower() if sel.startswith("0x") else sel.lower()
        found = needle in code
        res[sig] = found
    return res


def main():
    w3 = Web3(Web3.HTTPProvider(ALCHEMY_URL))
    if not w3.is_connected():
        print("Failed to connect to RPC at", ALCHEMY_URL, file=sys.stderr)
        sys.exit(2)

    pathlib_artifact = os.path.abspath(ARTIFACT_DIR)
    os.makedirs(pathlib_artifact, exist_ok=True)
    report = {
        "rpc": ALCHEMY_URL,
        "checks": {},
    }

    # Build function selector maps
    multisig_sels = {sig: selector_of(sig) for sig in FUNCTION_SIGNATURES["multisig_core"]}
    reentrancy_sels = {sig: selector_of(sig) for sig in FUNCTION_SIGNATURES["reentrancy_attacker"]}
    sinkhole_sels = {sig: selector_of(sig) for sig in FUNCTION_SIGNATURES["sinkhole"]}

    # For each target, fetch code and check for selectors
    any_missing = False
    for role, addr in addresses.items():
        entry = {"address": addr, "deployed": False, "code_length": 0, "selector_presence": {}}
        if not addr:
            entry["error"] = "address not provided"
            report["checks"][role] = entry
            any_missing = True
            continue
        try:
            checksum = to_checksum_address(addr)
        except Exception as e:
            entry["error"] = f"invalid address: {e}"
            report["checks"][role] = entry
            any_missing = True
            continue

        code = w3.eth.get_code(checksum)
        code_hex = code.hex() if isinstance(code, (bytes, bytearray)) else str(code)
        entry["deployed"] = (len(code_hex) > 2)  # '0x' alone -> no code
        entry["code_length"] = len(code_hex)
        entry["code_hex_prefix"] = code_hex[:200]  # for quick debug

        # choose which set of selectors to test
        if role in ("Vulnerable", "Secure"):
            selmap = multisig_sels
        elif role == "ReentrancyAttacker":
            selmap = reentrancy_sels
        else:
            selmap = sinkhole_sels

        presence = check_selectors_in_code(code_hex, selmap)
        entry["selector_presence"] = presence

        # record if any required selector missing (ignore receive() which returns None)
        for sig, ok in presence.items():
            if ok is False:
                any_missing = True

        report["checks"][role] = entry

    # Write report
    out_path = os.path.join(pathlib_artifact, "preflight_report.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)

    # Print summary
    print("Preflight report saved to", out_path)
    for role, data in report["checks"].items():
        print(f"\n{role}:")
        if "error" in data:
            print("  ERROR:", data["error"])
            continue
        print("  Address:", data["address"])
        print("  Deployed (has runtime code):", data["deployed"])
        print("  Code length (hex chars):", data["code_length"])
        # print selector presence summary
        for sig, ok in data["selector_presence"].items():
            status = "FOUND" if ok is True else ("MISSING" if ok is False else "UNKNOWN")
            print(f"    {sig:40} -> {status}")

    if any_missing:
        print("\nOne or more checks failed (missing selectors or addresses). See the JSON report for details.", file=sys.stderr)
        sys.exit(3)

    print("\nAll checks passed (selectors found where expected).")
    sys.exit(0)


if __name__ == "__main__":
    # small imports placed here to avoid top-level error if not available
    import os
    import pathlib
    main()

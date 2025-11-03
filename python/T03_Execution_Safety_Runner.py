# t03_execution_safety_runner.py
# Test runner / orchestration script. Assumes attacker contracts were deployed separately
# and their addresses exported into environment variables.

# Requirements:
# pip install web3 eth-account python-dotenv

import os
import json
import pathlib
import time
from decimal import Decimal
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv

load_dotenv()

ALCHEMY_URL = os.getenv('ALCHEMY_URL')
VULNERABLE_ADDRESS = os.getenv('VULNERABLE_ADDRESS')
SECURE_ADDRESS = os.getenv('SECURE_ADDRESS')
OWNER_KEYS_RAW = os.getenv('OWNER_PRIVATE_KEYS', '')
ATTACKER_KEY = os.getenv('ATTACKER_PRIVATE_KEY')
REENTRANCY_ATTACKER_ADDRESS = os.getenv('REENTRANCY_ATTACKER_ADDRESS')
SINKHOLE_ADDRESS = os.getenv('SINKHOLE_ADDRESS')
TARGET_X_ETH = Decimal(os.getenv('TARGET_X_ETH', '0.05'))
GAS_PRICE_GWEI = int(os.getenv('GAS_PRICE_GWEI', '20'))
ARTIFACT_DIR = os.getenv('ARTIFACT_DIR', './artifacts/T-03')
DEPLOYER_ADDRESS = os.getenv('DEPLOYER_ADDRESS')
DEPLOYER_PRIVATE_KEY = os.getenv('DEPLOYER_PRIVATE_KEY')

if not ALCHEMY_URL:
    raise SystemExit('ALCHEMY_URL required')
if not VULNERABLE_ADDRESS or not SECURE_ADDRESS:
    raise SystemExit('VULNERABLE_ADDRESS and SECURE_ADDRESS required')
if not REENTRANCY_ATTACKER_ADDRESS or not SINKHOLE_ADDRESS:
    raise SystemExit('REENTRANCY_ATTACKER_ADDRESS and SINKHOLE_ADDRESS required')

owners = [k.strip() for k in OWNER_KEYS_RAW.split(',') if k.strip()]
if len(owners) < 1:
    raise SystemExit('Please provide at least one OWNER_PRIVATE_KEYS')

if not ATTACKER_KEY:
    raise SystemExit('ATTACKER_PRIVATE_KEY required')

w3 = Web3(Web3.HTTPProvider(ALCHEMY_URL))
assert w3.is_connected(), 'Failed to connect to RPC'
chain_id = w3.eth.chain_id
owner_accounts = [Account.from_key(k) for k in owners]
attacker_account = Account.from_key(ATTACKER_KEY)
owner_addresses = [w3.to_checksum_address(acc.address) for acc in owner_accounts]
print("Loaded owner addresses:")
for i, addr in enumerate(owner_addresses):
    print(f"  Owner[{i}] = {addr}")

pathlib.Path(ARTIFACT_DIR).mkdir(parents=True, exist_ok=True)

# Minimal ABI for interactions (use exact ABIs if different)
MIN_ABI = [
    {'inputs': [{'internalType': 'address','name':'to','type':'address'},{'internalType':'uint256','name':'value','type':'uint256'},{'internalType':'bytes','name':'data','type':'bytes'}],'name':'proposeTransaction','outputs':[{'internalType':'uint256','name':'','type':'uint256'}],'stateMutability':'nonpayable','type':'function'},
    {'inputs':[{'internalType':'uint256','name':'proposalId','type':'uint256'}],'name':'confirmTransaction','outputs':[],'stateMutability':'nonpayable','type':'function'},
    {'inputs':[{'internalType':'uint256','name':'proposalId','type':'uint256'}],'name':'executeTransaction','outputs':[],'stateMutability':'nonpayable','type':'function'},
    {'inputs':[{'internalType':'uint256[]','name':'ids','type':'uint256[]'}],'name':'batchExecute','outputs':[],'stateMutability':'nonpayable','type':'function'},
    {'inputs':[],'stateMutability':'view','name':'proposalCount','outputs':[{'internalType':'uint256','name':'','type':'uint256'}],'type':'function'}
]

vuln = w3.eth.contract(address=Web3.to_checksum_address(VULNERABLE_ADDRESS), abi=MIN_ABI)
secure = w3.eth.contract(address=Web3.to_checksum_address(SECURE_ADDRESS), abi=MIN_ABI)

# Attacker contracts ABIs (only needed to call setProposalId or withdraw)
REENTRANCY_ABI = [
    {'inputs':[{'internalType':'uint256','name':'id','type':'uint256'}],'name':'setProposalId','outputs':[],'stateMutability':'nonpayable','type':'function'},
    {'inputs':[{'internalType':'address','name':'to','type':'address'}],'name':'withdraw','outputs':[],'stateMutability':'nonpayable','type':'function'}
]

SINKHOLE_ABI = [
    {"inputs":[{"internalType":"address","name":"to","type":"address"}],"name":"implode","outputs":[],"stateMutability":"payable","type":"function"},
    {"inputs":[],"name":"implodeBurn","outputs":[],"stateMutability":"payable","type":"function"},
]

VUL_MULTISIG_ABI_PATH = "../out/VulnerableMultiSig.sol/VulnerableMultiSig.json"
SEC_MULTISIG_ABI_PATH = "../out/SecureMultiSig.sol/SecureMultiSig.json"
REENTRANCY_ABI_PATH = "../out/ReentrancyAttacker.sol/ReentrancyAttacker.json"
SINKHOLE_ABI_PATH = "../out/Sinkhole.sol/Sinkhole.json"

def load_abi(path):
    with open(path) as f:
        return json.load(f)['abi']

VUL_MULTISIG_ABI = load_abi(VUL_MULTISIG_ABI_PATH)
SEC_MULTISIG_ABI = load_abi(SEC_MULTISIG_ABI_PATH)
SINKHOLE_ABI = load_abi(SINKHOLE_ABI_PATH)
REENTRANCY_ABI = load_abi(REENTRANCY_ABI_PATH)

vuln = w3.eth.contract(address=w3.to_checksum_address(VULNERABLE_ADDRESS), abi=VUL_MULTISIG_ABI)
secure = w3.eth.contract(address=w3.to_checksum_address(SECURE_ADDRESS), abi=SEC_MULTISIG_ABI)
re_att = w3.eth.contract(address=w3.to_checksum_address(REENTRANCY_ATTACKER_ADDRESS), abi=REENTRANCY_ABI)
sink = w3.eth.contract(address=w3.to_checksum_address(SINKHOLE_ADDRESS), abi=SINKHOLE_ABI)

# helpers

def eth(n):
    return Decimal(w3.from_wei(n, 'ether'))

def to_wei_eth(x: Decimal):
    return int(x * (10**18))

def save_json(obj, fname):
    with open(pathlib.Path(ARTIFACT_DIR) / fname, 'w') as f:
        json.dump(obj, f, default=str, indent=2)

def fetch_trace(tx_hash):
    try:
        res = w3.provider.make_request('debug_traceTransaction', [tx_hash, {}])
        return res
    except Exception as e:
        return {'error': str(e)}

def send_tx_signed(account: Account, tx):
    signed = account.sign_transaction(tx)
    txh = w3.eth.send_raw_transaction(signed.raw_transaction)
    rec = w3.eth.wait_for_transaction_receipt(txh)
    return txh.hex(), rec

def build_and_send(account: Account, to, data=b'', value=0, gas=2_000_000):
    tx = {
        'to': to,
        'value': int(value),
        'data': data,
        'gas': gas,
        'gasPrice': GAS_PRICE,
        'nonce': w3.eth.get_transaction_count(account.address),
        'chainId': chain_id
    }
    return send_signed_tx(account, tx)

def call_propose(contract, owner: Account, to_addr, value_eth: Decimal):
    fn = contract.functions.proposeTransaction(to_addr, to_wei_eth(value_eth), b'')
    tx = fn.build_transaction({'from': owner.address, 'nonce': w3.eth.get_transaction_count(owner.address), 'gas': 400_000, 'gasPrice': GAS_PRICE, 'chainId': chain_id})
    return send_signed_tx(owner, tx)

def call_confirm(contract, owner: Account, pid):
    fn = contract.functions.confirmTransaction(pid)
    tx = fn.build_transaction({'from': owner.address, 'nonce': w3.eth.get_transaction_count(owner.address), 'gas': 200_000, 'gasPrice': GAS_PRICE, 'chainId': chain_id})
    return send_signed_tx(owner, tx)

def call_execute(contract, owner: Account, pid, gas=2_000_000):
    fn = contract.functions.executeTransaction(pid)
    tx = fn.build_transaction({'from': owner.address, 'nonce': w3.eth.get_transaction_count(owner.address), 'gas': gas, 'gasPrice': GAS_PRICE, 'chainId': chain_id})
    return send_signed_tx(owner, tx)

def call_batch(contract, owner: Account, ids):
    fn = contract.functions.batchExecute(ids)
    tx = fn.build_transaction({'from': owner.address, 'nonce': w3.eth.get_transaction_count(owner.address), 'gas': 6_000_000, 'gasPrice': GAS_PRICE, 'chainId': chain_id})
    return send_signed_tx(owner, tx)

# Logging helpers
def log_step(name):
    print('\n' + '='*8 + f' {name} ' + '='*8)

def dump_tx_artifact(prefix, txh, receipt):
    save_json({'tx': txh, 'receipt': dict(receipt)}, f'{prefix}_{txh}_receipt.json')
    # fetch trace where available
    trace = fetch_trace(txh)
    save_json(trace, f'{prefix}_{txh}_trace.json')

def fund_wallets():
    FUND_AMOUNT = w3.to_wei(0.01, "ether")
    print(f"\nFunding multisig wallets from deployer ({DEPLOYER_ADDRESS})...")

    for target in [VULNERABLE_ADDRESS, SECURE_ADDRESS]:
        tx = {
            "from": DEPLOYER_ADDRESS,
            "to": target,
            "value": FUND_AMOUNT,
            "nonce": w3.eth.get_transaction_count(DEPLOYER_ADDRESS),
            "gas": 22000,
            "gasPrice": w3.to_wei("3", "gwei"),
        }
        signed = w3.eth.account.sign_transaction(tx, private_key=DEPLOYER_PRIVATE_KEY)
        txh = w3.eth.send_raw_transaction(signed.raw_transaction)
        rec = w3.eth.wait_for_transaction_receipt(txh)
        print(f"  -> Sent 0.01 ETH to {target[:10]}... | tx: {txh.hex()} | gasUsed: {rec.gasUsed}")

    # Post-funding check
    vuln_bal = w3.eth.get_balance(VULNERABLE_ADDRESS)
    sec_bal = w3.eth.get_balance(SECURE_ADDRESS)
    print(f"Balances after funding:")
    print(f"  Vulnerable: {w3.from_wei(vuln_bal, 'ether')} ETH")
    print(f"  Secure:     {w3.from_wei(sec_bal, 'ether')} ETH")

# Run before tests
fund_wallets()

# Prechecks
log_step('PRE-CHECKS')

vulnerable_balance_before = w3.eth.get_balance(VULNERABLE_ADDRESS)
secure_balance_before = w3.eth.get_balance(SECURE_ADDRESS)
attacker_balance_before = w3.eth.get_balance(REENTRANCY_ATTACKER_ADDRESS)
owners_info = []
for addr in owner_addresses:
    owners_info.append({"address": addr, "balance_wei": int(w3.eth.get_balance(addr))})

pre = {
    'chainId': chain_id,
    'vulnerable_balance_before': int(vulnerable_balance_before),
    'secure_balance_before': int(secure_balance_before),
    'attacker_balance_before': int(attacker_balance_before),
    'owners': owners_info
}
save_json(pre, 'pre_checks.json')

# human friendly prints
print('Pre-checks saved -> ./artifacts/T-03/pre_checks.json')
print('Balances (human-readable):')
print(f'  Vulnerable ({VULNERABLE_ADDRESS}): {w3.from_wei(vulnerable_balance_before, "ether")} ETH ({vulnerable_balance_before} wei)')
print(f'  Secure     ({SECURE_ADDRESS}): {w3.from_wei(secure_balance_before, "ether")} ETH ({secure_balance_before} wei)')
print(f'  Attacker   ({REENTRANCY_ATTACKER_ADDRESS}): {w3.from_wei(attacker_balance_before, "ether")} ETH ({attacker_balance_before} wei)')
print('  Owners:')
for oi in owners_info:
    print(f'    {oi["address"]}: {w3.from_wei(oi["balance_wei"], "ether")} ETH ({oi["balance_wei"]} wei)')
# Results collector
summary = {'reentrancy': {}, 'unchecked_external': {}, 'batch': {}}


# ---------------------------------

#        REENTRANCY TEST

# ---------------------------------

# ---------------------------------

#        VULNERABLE FLOW

# ---------------------------------

log_step('REENTRANCY TEST (Vulnerable)')

# --- 1) Propose tx sending TARGET_X_ETH to the attacker contract ---
print('Proposing transaction (Vulnerable -> attacker)')
txh_prop, rec_prop = call_propose(vuln, owners[0], REENTRANCY_ATTACKER_ADDRESS, TARGET_X_ETH)
print('Propose tx:', txh_prop)
dump_tx_artifact('vul_reentrancy_propose', txh_prop, rec_prop)

# --- 2) Derive the proposal id (proposalCount - 1) ---
try:
    pc = vuln.functions.proposalCount().call()
    pid = pc - 1
except Exception:
    pid = 0
print('Derived proposal id:', pid)

# --- 3) IMPORTANT: set the proposal id on the attacker BEFORE execution ---
print('Setting proposalId on attacker contract (must be done before execute)')
tx_set = re_att.functions.setProposalId(pid).build_transaction({
    'from': attacker_account.address,
    'nonce': w3.eth.get_transaction_count(attacker_account.address),
    'gas': 120000,
    'gasPrice': GAS_PRICE,
    'chainId': chain_id
})
txh_set, rec_set = send_signed_tx(attacker_account, tx_set)
print('Set proposalId tx:', txh_set)
dump_tx_artifact('attacker_setProposalId', txh_set, rec_set)

# --- 4) Confirm the proposal with the other owners so it becomes executable ---
print('Confirming transaction with required owners')
for i, acct in enumerate(owners[1:3], start=1):
    txh_c, rec_c = call_confirm(vuln, acct, pid)
    print(f'Confirm tx ({i}):', txh_c)
    dump_tx_artifact(f'vul_reentrancy_confirm_{i}', txh_c, rec_c)

# --- 5) Record balances BEFORE execute (exact wei) for evidence ---
vuln_before = w3.eth.get_balance(VULNERABLE_ADDRESS)
att_before = w3.eth.get_balance(REENTRANCY_ATTACKER_ADDRESS)
print(f'Balances before execute: Vulnerable={eth(vuln_before)} ETH, Attacker={eth(att_before)} ETH')

# --- 6) Execute the proposal (this will call the attacker and potentially re-enter) ---
print('Executing proposal (this triggers the attack if vulnerable)')
txh_exec, rec_exec = call_execute(vuln, owners[0], pid, gas=2_500_000)
print('Execute tx:', txh_exec)
dump_tx_artifact('vul_reentrancy_execute', txh_exec, rec_exec)

# --- 7) Record balances AFTER execute (exact wei) ---
vuln_after = w3.eth.get_balance(VULNERABLE_ADDRESS)
att_after = w3.eth.get_balance(REENTRANCY_ATTACKER_ADDRESS)
print(f'Balances after execute: Vulnerable={eth(vuln_after)} ETH, Attacker={eth(att_after)} ETH')

# --- 8) Compute deltas in wei (safe integer arithmetic) ---
attacker_delta_wei = int(att_after - att_before)
vulnerable_delta_wei = int(vuln_before - vuln_after)

print(f'  Attacker delta: {attacker_delta_wei} wei ({eth(attacker_delta_wei)} ETH)')
print(f'  Vulnerable delta: {vulnerable_delta_wei} wei ({eth(vulnerable_delta_wei)} ETH)')

# --- 9) Success criteria (convert TARGET_X_ETH to wei for comparison) ---
target_wei = to_wei_eth(TARGET_X_ETH)

# Double-dip success: attacker got >= 2 * target
if attacker_delta_wei > target_wei:
    print('RESULT: Expected Scenario Outcome — attacker received >= 2 * TARGET_X_ETH (double-dip).')
    summary['reentrancy']['result'] = 'SUCCESS_DOUBLE_DIP'
# Single transfer: attacker got exactly target or roughly that (allow small gas-related noise)
elif attacker_delta_wei == target_wei:
    print('RESULT: Unexpectd Scenario Outcome — attacker received ~TARGET_X_ETH (no double-dip).')
    summary['reentrancy']['result'] = 'SINGLE_TRANSFER_OR_PARTIAL'
else:
    print('RESULT: Unexpected Scenario FAILURE — attacker received no (or negligible) funds.')
    summary['reentrancy']['result'] = 'NO_FUNDS'

# store details for artifacts
summary['reentrancy'].update({
    'vulnerable_before_wei': int(vuln_before),
    'vulnerable_after_wei': int(vuln_after),
    'attacker_before_wei': int(att_before),
    'attacker_after_wei': int(att_after),
    'attacker_delta_wei': attacker_delta_wei,
    'vulnerable_delta_wei': vulnerable_delta_wei,
    'execute_tx': txh_exec,
    'propose_tx': txh_prop,
    'setProposalId_tx': txh_set,
    'confirm_txs': []  # optionally append the confirm txs if you want them tracked
})

# (optional) Collect confirms into summary['reentrancy']['confirm_txs'] if desired

# ---------------------------------

#        SECURE FLOW

# ---------------------------------

# ---------- REENTRANCY TEST (Secure) ----------

log_step('REENTRANCY TEST (Secure)')

# --- 1) Propose tx sending TARGET_X_ETH to the attacker contract (on Secure wallet) ---
print('Proposing transaction (Secure -> attacker)')
txh_prop_s, rec_prop_s = call_propose(secure, owners[0], REENTRANCY_ATTACKER_ADDRESS, TARGET_X_ETH)
print('Propose tx:', txh_prop_s)
dump_tx_artifact('sec_reentrancy_propose', txh_prop_s, rec_prop_s)

# --- 2) Derive the proposal id (proposalCount - 1) ---
try:
    pc_s = secure.functions.proposalCount().call()
    pid_s = pc_s - 1
except Exception:
    pid_s = 0
print('Derived proposal id (secure):', pid_s)

# --- 3) IMPORTANT: set the proposal id on the attacker BEFORE execution ---
print('Setting proposalId on attacker contract (for secure test)')
tx_set_s = re_att.functions.setProposalId(pid_s).build_transaction({
    'from': attacker_account.address,
    'nonce': w3.eth.get_transaction_count(attacker_account.address),
    'gas': 120000,
    'gasPrice': GAS_PRICE,
    'chainId': chain_id
})
txh_set_s, rec_set_s = send_signed_tx(attacker_account, tx_set_s)
print('Set proposalId tx (secure):', txh_set_s)
dump_tx_artifact('attacker_setProposalId_secure', txh_set_s, rec_set_s)

# --- 4) Confirm the proposal with the other owners so it becomes executable ---
print('Confirming transaction (secure) with required owners')
confirm_txs_secure = []
for i, acct in enumerate(owners[1:3], start=1):
    txh_c_s, rec_c_s = call_confirm(secure, acct, pid_s)
    confirm_txs_secure.append(txh_c_s)
    print(f'Confirm tx (secure {i}):', txh_c_s)
    dump_tx_artifact(f'sec_reentrancy_confirm_{i}', txh_c_s, rec_c_s)

# --- 5) Record balances BEFORE execute (exact wei) for evidence ---
sec_before_r = w3.eth.get_balance(SECURE_ADDRESS)
att_before_r = w3.eth.get_balance(REENTRANCY_ATTACKER_ADDRESS)
print(f'Balances before execute (secure): Secure={eth(vuln_before_s)} ETH, Attacker={eth(att_before_s)} ETH')

# --- 6) Execute the proposal (this will call the attacker; Secure should block re-entry) ---
print('Executing proposal (secure) — should be protected against reentrancy')
txh_exec_s, rec_exec_s = call_execute(secure, owners[0], pid_s, gas=2_500_000)
print('Execute tx (secure):', txh_exec_s)
dump_tx_artifact('sec_reentrancy_execute', txh_exec_s, rec_exec_s)

# --- 7) Record balances AFTER execute (exact wei) ---
sec_after_r = w3.eth.get_balance(SECURE_ADDRESS)
att_after_r = w3.eth.get_balance(REENTRANCY_ATTACKER_ADDRESS)
print(f'Balances after execute (secure): Secure={eth(vuln_after_s)} ETH, Attacker={eth(att_after_s)} ETH')

# --- 8) Compute deltas in wei (safe integer arithmetic) ---
attacker_delta_wei_s = int(att_after_r - att_before_r)
secure_delta_wei = int(sec_before_r - sec_after_r)

print(f'  Attacker delta (secure): {attacker_delta_wei_s} wei ({eth(attacker_delta_wei_s)} ETH)')
print(f'  Secure delta: {secure_delta_wei} wei ({eth(secure_delta_wei)} ETH)')

# --- 9) Success criteria for Secure: attacker MUST NOT receive >= TARGET_X_ETH ---
target_wei = to_wei_eth(TARGET_X_ETH)
if attacker_delta_wei_s > target_wei:
    # attacker got at least the transfer — this is a failure of the secure contract
    print('Unexpected Scenario Outcome: FAILURE — attacker received funds on Secure wallet (vulnerable behavior!).')
    summary['reentrancy']['secure_result'] = 'FAILURE_ATTACKER_RECEIVED_FUNDS'
elif attacker_delta_wei_s == target_wei:
    # secure contract prevented reentrancy (expected)
    print('Expected Scenario Outcome: PASS — attacker did NOT receive beyond the target transfer (reentrancy mitigated).')
    summary['reentrancy']['secure_result'] = 'PASS_NO_FUNDS'
else:
    print('Unexpected Scenario Outcome: NO FUNDS WERE TRANSFERRED') 

# store details for artifacts
summary['reentrancy'].setdefault('secure', {})
summary['reentrancy']['secure'].update({
    'secure_before_wei': int(vuln_before_s),
    'secure_after_wei': int(vuln_after_s),
    'attacker_before_wei': int(att_before_s),
    'attacker_after_wei': int(att_after_s),
    'attacker_delta_wei': attacker_delta_wei_s,
    'secure_delta_wei': secure_delta_wei,
    'execute_tx': txh_exec_s,
    'propose_tx': txh_prop_s,
    'setProposalId_tx': txh_set_s,
    'confirm_txs': confirm_txs_secure
})


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
TARGET_X_ETH = Decimal(os.getenv('TARGET_X_ETH', '0.01'))
GAS_PRICE = int(os.getenv('GAS_PRICE', '20'))
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
EPHEMERAL_DEPLOYER_ABI_PATH = '../out/EphemeralSinkholeDeployer.sol/EphemeralSinkholeDeployer.json'

def load_abi(path):
    with open(path) as f:
        return json.load(f)['abi']

VUL_MULTISIG_ABI = load_abi(VUL_MULTISIG_ABI_PATH)
SEC_MULTISIG_ABI = load_abi(SEC_MULTISIG_ABI_PATH)
SINKHOLE_ABI = load_abi(SINKHOLE_ABI_PATH)
REENTRANCY_ABI = load_abi(REENTRANCY_ABI_PATH)
EPHEMERAL_DEPLOYER_ABI = load_abi(EPHEMERAL_DEPLOYER_ABI_PATH)

vuln = w3.eth.contract(address=w3.to_checksum_address(VULNERABLE_ADDRESS), abi=VUL_MULTISIG_ABI)
secure = w3.eth.contract(address=w3.to_checksum_address(SECURE_ADDRESS), abi=SEC_MULTISIG_ABI)
re_att = w3.eth.contract(address=w3.to_checksum_address(REENTRANCY_ATTACKER_ADDRESS), abi=REENTRANCY_ABI)
sink = w3.eth.contract(address=w3.to_checksum_address(SINKHOLE_ADDRESS), abi=SINKHOLE_ABI)

def load_artifact(artifact_path: str):
    """Loads a contract artifact and extracts raw bytecode object."""
    # Resolve the path relative to the script's directory
    SCRIPT_DIR = pathlib.Path(__file__).parent
    full_path = (SCRIPT_DIR / artifact_path).resolve()

    try:
        with open(full_path, 'r') as f:
            artifact = json.load(f)

            bytecode = artifact['bytecode']['object']

            return  bytecode

    except FileNotFoundError:
        raise SystemExit(f"ERROR: Could not find artifact at {full_path}. Please check path and compilation.")
    except KeyError as e:
        raise SystemExit(f"ERROR: Artifact missing required key {e}. Ensure the contract is fully compiled.")

# --- ARTIFACT SETUP ---
# NOTE: Adjust these relative paths based on your actual file system structure
SINKHOLE_ARTIFACT_PATH = '../out/Sinkhole.sol/Sinkhole.json'
DEPLOYER_ARTIFACT_PATH = '../out/EphemeralSinkholeDeployer.sol/EphemeralSinkholeDeployer.json'


# Load the necessary constants
SINKHOLE_BYTECODE = load_artifact(SINKHOLE_ARTIFACT_PATH)
EPHEMERAL_DEPLOYER_BYTECODE = load_artifact(DEPLOYER_ARTIFACT_PATH)

print(f"Loaded Sinkhole artifact from: {SINKHOLE_ARTIFACT_PATH}")
print(f"Loaded Ephemeral Deployer artifact from: {DEPLOYER_ARTIFACT_PATH}")

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
    return send_tx_signed(account, tx)

def call_propose(contract, owner: Account, to_addr, value_eth: Decimal):
    fn = contract.functions.proposeTransaction(to_addr, to_wei_eth(value_eth), b'')
    tx = fn.build_transaction({'from': owner.address, 'nonce': w3.eth.get_transaction_count(owner.address), 'gas': 400_000, 'gasPrice': GAS_PRICE, 'chainId': chain_id})
    return send_tx_signed(owner, tx)

def call_confirm(contract, owner: Account, pid):
    fn = contract.functions.confirmTransaction(pid)
    tx = fn.build_transaction({'from': owner.address, 'nonce': w3.eth.get_transaction_count(owner.address), 'gas': 200_000, 'gasPrice': GAS_PRICE, 'chainId': chain_id})
    return send_tx_signed(owner, tx)

def call_execute(contract, owner: Account, pid, gas=2_000_000):
    fn = contract.functions.executeTransaction(pid)
    tx = fn.build_transaction({'from': owner.address, 'nonce': w3.eth.get_transaction_count(owner.address), 'gas': gas, 'gasPrice': GAS_PRICE, 'chainId': chain_id})
    return send_tx_signed(owner, tx)

def call_batch(contract, owner: Account, ids):
    fn = contract.functions.batchExecute(ids)
    tx = fn.build_transaction({'from': owner.address, 'nonce': w3.eth.get_transaction_count(owner.address), 'gas': 6_000_000, 'gasPrice': GAS_PRICE, 'chainId': chain_id})
    return send_tx_signed(owner, tx)

def get_owner_account(i):
    return owner_accounts[i]

def log_step(name):
    print('\n' + '='*8 + f' {name} ' + '='*8)

def dump_tx_artifact(prefix, txh, receipt):
    save_json({'tx': txh, 'receipt': dict(receipt)}, f'{prefix}_{txh}_receipt.json')
    # fetch trace where available
    trace = fetch_trace(txh)
    save_json(trace, f'{prefix}_{txh}_trace.json')

def call_withdraw_attacker(attacker_contract, owner: Account, to_addr):
    """Calls the ReentrancyAttacker.withdraw(address to) function."""
    fn = attacker_contract.functions.withdraw(to_addr)
    tx = fn.build_transaction({
        'from': owner.address, 
        'nonce': w3.eth.get_transaction_count(owner.address), 
        'gas': 150000, # Sufficient gas
        'gasPrice': GAS_PRICE, 
        'chainId': chain_id
    })
    return send_tx_signed(owner, tx)

def get_proposal_status(multisig_contract, pid):
    """Fetches the executed status of a proposal (index 5) from getProposal."""
    proposal_data = multisig_contract.functions.getProposal(pid).call()
    return proposal_data[executed_index]

def call_implode_sinkhole(sinkhole_contract, owner: Account, to_addr):
    """Calls the Sinkhole.implode(address to) function."""
    fn = sinkhole_contract.functions.implode(to_addr)
    tx = fn.build_transaction({
        'from': owner.address, 
        'nonce': w3.eth.get_transaction_count(owner.address), 
        'gas': 200000,
        'gasPrice': GAS_PRICE, 
        'chainId': chain_id
    })
    return send_tx_signed(owner, tx)

def deploy_and_implode_sinkhole(deployer_account: Account, recipient_address: str):
    """
    Deploys the EphemeralDeployer and calls deployAndImplode, 
    which handles the one-transaction selfdestruct.
    """
    # 1. Instantiate the Deployer Factory (Bytecode is now a simple string)
    DeployerContract = w3.eth.contract(abi=EPHEMERAL_DEPLOYER_ABI, bytecode=EPHEMERAL_DEPLOYER_BYTECODE)
    current_nonce = w3.eth.get_transaction_count(deployer_account.address)
    print(f"[DEBUG] Starting nonce: {current_nonce}")

    # 2. Deploy the EphemeralDeployer contract itself
    tx_deploy_data = DeployerContract.constructor().build_transaction({
        'from': deployer_account.address,
        'nonce': current_nonce,
        'gas': 1000000, 
        'gasPrice': GAS_PRICE,
        'chainId': chain_id
    })
    txh_deploy, rec_deploy = send_tx_signed(deployer_account, tx_deploy_data)
    print("Broadcasted TX:", txh_deploy)
    current_nonce += 1
    ephemeral_deployer_addr = rec_deploy.contractAddress
    ephemeral_deployer = w3.eth.contract(address=ephemeral_deployer_addr, abi=EPHEMERAL_DEPLOYER_ABI)
    
    # 3. Call the deployAndImplode function on the EphemeralDeployer
    fn = ephemeral_deployer.functions.deployAndImplode(recipient_address)
    tx_implode_data = fn.build_transaction({
        'from': deployer_account.address, 
        'nonce': current_nonce, 
        'gas': 15000000,
        'gasPrice': GAS_PRICE, 
        'chainId': chain_id
    })
    print("[DEBUG] Prepared deployAndImplode TX:")
    print("  From:", deployer_account.address)
    print("  Nonce:", tx_implode_data['nonce'])
    print("  Gas:", tx_implode_data['gas'])
    print("  Gas Price:", tx_implode_data['gasPrice'])
    print("  Chain ID:", tx_implode_data['chainId'])
    print("  Recipient:", recipient_address)

    txh_implode, rec_implode = send_tx_signed(deployer_account, tx_implode_data)
    print("Broadcasted TX:", txh_implode)

    # 4. Get the address of the DESTROYED Sinkhole from the transaction events/logs/simulation.
    # We use a quick simulation call to get the return value (the destroyed address).
    destroyed_addr = ephemeral_deployer.functions.deployAndImplode(recipient_address).call({
        'from': deployer_account.address,
        'gas': 2_000_000,
    })
    
    # The return value is a tuple; we need the first element (the address)
    return destroyed_addr[0], txh_implode, rec_implode
def fund_wallets():
    FUND_AMOUNT = w3.to_wei(0.02, "ether")
    print(f"\nFunding multisig wallets from deployer ({DEPLOYER_ADDRESS})...")
    current_nonce = w3.eth.get_transaction_count(DEPLOYER_ADDRESS)

    for target in [VULNERABLE_ADDRESS, SECURE_ADDRESS]:
        tx = {
            "from": DEPLOYER_ADDRESS,
            "to": target,
            "value": FUND_AMOUNT,
            "nonce": current_nonce,
            "gas": 122000,
            "gasPrice": w3.to_wei("3", "gwei"),
        }
        signed = w3.eth.account.sign_transaction(tx, private_key=DEPLOYER_PRIVATE_KEY)
        txh = w3.eth.send_raw_transaction(signed.raw_transaction)
        rec = w3.eth.wait_for_transaction_receipt(txh)
        print(f"  -> Sent 0.02 ETH to {target[:10]}... | tx: {txh.hex()} | gasUsed: {rec.gasUsed}")

        current_nonce += 1

    # Post-funding check
    vuln_bal = w3.eth.get_balance(VULNERABLE_ADDRESS)
    sec_bal = w3.eth.get_balance(SECURE_ADDRESS)
    print(f"Balances after funding:")
    print(f"  Vulnerable: {w3.from_wei(vuln_bal, 'ether')} ETH")
    print(f"  Secure:     {w3.from_wei(sec_bal, 'ether')} ETH")

# Run before tests
#fund_wallets()

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

#   ATTACK EXECUTION (VULNERABLE)

# ---------------------------------

#log_step('REENTRANCY TEST (Vulnerable)')

# --- 1) Propose tx sending TARGET_X_ETH to the attacker contract ---
#print('Proposing transaction (Vulnerable -> attacker)')
#txh_prop, rec_prop = call_propose(vuln, owner_accounts[0], REENTRANCY_ATTACKER_ADDRESS, TARGET_X_ETH)
#print('Propose tx:', txh_prop)
#dump_tx_artifact('vul_reentrancy_propose', txh_prop, rec_prop)

# --- 2) Derive the proposal id (proposalCount - 1) ---
#try:
#    pc = vuln.functions.proposalCount().call()
#    pid = pc - 1
#except Exception:
#    pid = 0
#print('Derived proposal id:', pid)

# --- 3) IMPORTANT: set the proposal id on the attacker BEFORE execution ---
#print('Setting proposalId on attacker contract (must be done before execute)')
#tx_set = re_att.functions.setProposalId(pid).build_transaction({
#    'from': attacker_account.address,
#    'nonce': w3.eth.get_transaction_count(attacker_account.address),
#    'gas': 120000,
#    'gasPrice': GAS_PRICE,
#    'chainId': chain_id
#})
#txh_set, rec_set = send_tx_signed(attacker_account, tx_set)
#print('Set proposalId tx:', txh_set)
#dump_tx_artifact('attacker_setProposalId', txh_set, rec_set)

# --- 4) Confirm the proposal with the other owners so it becomes executable ---
#print('Confirming transaction with required owners')
#for i, acct in enumerate(owners[1:3], start=1):
#    txh_c, rec_c = call_confirm(vuln, get_owner_account(i), pid)
#    print(f'Confirm tx ({i}):', txh_c)
#    dump_tx_artifact(f'vul_reentrancy_confirm_{i}', txh_c, rec_c)

# --- 5) Record balances BEFORE execute (exact wei) for evidence ---
#vuln_before = w3.eth.get_balance(VULNERABLE_ADDRESS)
#att_before = w3.eth.get_balance(REENTRANCY_ATTACKER_ADDRESS)
#print(f'Balances before execute: Vulnerable={eth(vuln_before)} ETH, Attacker={eth(att_before)} ETH')

# --- 6) Execute the proposal (this will call the attacker and potentially re-enter) ---
#print('Executing proposal (this triggers the attack if vulnerable)')
#txh_exec, rec_exec = call_execute(vuln, owner_accounts[0], pid, gas=2_500_000)
#print('Execute tx:', txh_exec)
#dump_tx_artifact('vul_reentrancy_execute', txh_exec, rec_exec)

# --- 7) Record balances AFTER execute (exact wei) ---
#vuln_after = w3.eth.get_balance(VULNERABLE_ADDRESS)
#att_after = w3.eth.get_balance(REENTRANCY_ATTACKER_ADDRESS)
#print(f'Balances after execute: Vulnerable={eth(vuln_after)} ETH, Attacker={eth(att_after)} ETH')

# --- 8) Compute deltas in wei (safe integer arithmetic) ---
#attacker_delta_wei = int(att_after - att_before)
#vulnerable_delta_wei = int(vuln_before - vuln_after)

#print(f'  Attacker delta: {attacker_delta_wei} wei ({eth(attacker_delta_wei)} ETH)')
#print(f'  Vulnerable delta: {vulnerable_delta_wei} wei ({eth(vulnerable_delta_wei)} ETH)')

# --- 9) Success criteria (convert TARGET_X_ETH to wei for comparison) ---
#target_wei = to_wei_eth(TARGET_X_ETH)

# Double-dip success: attacker got >= 2 * target
#if attacker_delta_wei > target_wei:
#    print('RESULT: Expected Scenario Outcome — attacker received >= 2 * TARGET_X_ETH (double-dip).')
#    summary['reentrancy']['result'] = 'SUCCESS_DOUBLE_DIP'
# Single transfer: attacker got exactly target or roughly that (allow small gas-related noise)
#elif attacker_delta_wei == target_wei:
#    print('RESULT: Unexpectd Scenario Outcome — attacker received ~TARGET_X_ETH (no double-dip).')
#    summary['reentrancy']['result'] = 'SINGLE_TRANSFER_OR_PARTIAL'
#else:
#    print('RESULT: Unexpected Scenario FAILURE — attacker received no (or negligible) funds.')
#    summary['reentrancy']['result'] = 'NO_FUNDS'

# store details for artifacts
#summary['reentrancy'].update({
#    'vulnerable_before_wei': int(vuln_before),
#    'vulnerable_after_wei': int(vuln_after),
#    'attacker_before_wei': int(att_before),
#    'attacker_after_wei': int(att_after),
#    'attacker_delta_wei': attacker_delta_wei,
#    'vulnerable_delta_wei': vulnerable_delta_wei,
#    'execute_tx': txh_exec,
#    'propose_tx': txh_prop,
#    'setProposalId_tx': txh_set,
#    'confirm_txs': []  # optionally append the confirm txs if you want them tracked
#})

# (optional) Collect confirms into summary['reentrancy']['confirm_txs'] if desired

# Reset Reentrancy Contract State to allow further attacks using withdraw function
#log_step('RESET ATTACKER STATE')
#print('Withdrawing funds from attacker contract (resets reentered=false)')

#txh_withdraw, rec_withdraw = call_withdraw_attacker(re_att, attacker_account, attacker_account.address)
#print('Withdraw tx:', txh_withdraw)
#dump_tx_artifact('attacker_withdraw_reset', txh_withdraw, rec_withdraw)


# ---------------------------------

#   MITIGATION EXECUTION (SECURE)

# ---------------------------------

# --- REENTRANCY TEST (Secure) ----

#log_step('REENTRANCY TEST (Secure)')

# --- 1) Propose tx sending TARGET_X_ETH to the attacker contract (on Secure wallet) ---
#print('Proposing transaction (Secure -> attacker)')
#txh_prop_s, rec_prop_s = call_propose(secure, owner_accounts[0], REENTRANCY_ATTACKER_ADDRESS, TARGET_X_ETH)
#print('Propose tx:', txh_prop_s)
#dump_tx_artifact('sec_reentrancy_propose', txh_prop_s, rec_prop_s)

# --- 2) Derive the proposal id (proposalCount - 1) ---
#try:
#    pc_s = secure.functions.proposalCount().call()
#    pid_s = pc_s - 1
#except Exception:
#    pid_s = 0
#print('Derived proposal id (secure):', pid_s)

# --- 3) IMPORTANT: set the proposal id on the attacker BEFORE execution ---
#print('Setting proposalId on attacker contract (for secure test)')
#tx_set_s = re_att.functions.setProposalId(pid_s).build_transaction({
#    'from': attacker_account.address,
#    'nonce': w3.eth.get_transaction_count(attacker_account.address),
#    'gas': 120000,
#    'gasPrice': GAS_PRICE,
#    'chainId': chain_id
#})
#txh_set_s, rec_set_s = send_tx_signed(attacker_account, tx_set_s)
#print('Set proposalId tx (secure):', txh_set_s)
#dump_tx_artifact('attacker_setProposalId_secure', txh_set_s, rec_set_s)

# --- 4) Confirm the proposal with the other owners so it becomes executable ---
#print('Confirming transaction (secure) with required owners')
#confirm_txs_secure = []
#for i, acct in enumerate(owners[1:3], start=1):
#    txh_c_s, rec_c_s = call_confirm(secure, get_owner_account(i), pid_s)
#    confirm_txs_secure.append(txh_c_s)
#    print(f'Confirm tx (secure {i}):', txh_c_s)
#    dump_tx_artifact(f'sec_reentrancy_confirm_{i}', txh_c_s, rec_c_s)

# --- 5) Record balances BEFORE execute (exact wei) for evidence ---
#sec_before_r = w3.eth.get_balance(SECURE_ADDRESS)
#att_before_r = w3.eth.get_balance(REENTRANCY_ATTACKER_ADDRESS)
#print(f'Balances before execute (secure): Secure={eth(sec_before_r)} ETH, Attacker={eth(att_before_r)} ETH')

# --- 6) Execute the proposal (this will call the attacker; Secure should block re-entry) ---
#print('Executing proposal (secure) — should be protected against reentrancy')
#txh_exec_s, rec_exec_s = call_execute(secure, owner_accounts[0], pid_s, gas=2_500_000)
#print('Execute tx (secure):', txh_exec_s)
#dump_tx_artifact('sec_reentrancy_execute', txh_exec_s, rec_exec_s)

# --- 7) Record balances AFTER execute (exact wei) ---
#sec_after_r = w3.eth.get_balance(SECURE_ADDRESS)
#att_after_r = w3.eth.get_balance(REENTRANCY_ATTACKER_ADDRESS)
#print(f'Balances after execute (secure): Secure={eth(sec_after_r)} ETH, Attacker={eth(att_after_r)} ETH')

# --- 8) Compute deltas in wei (safe integer arithmetic) ---
#attacker_delta_wei_s = int(att_after_r - att_before_r)
#secure_delta_wei = int(sec_before_r - sec_after_r)

#print(f'  Attacker delta (secure): {attacker_delta_wei_s} wei ({eth(attacker_delta_wei_s)} ETH)')
#print(f'  Secure delta: {secure_delta_wei} wei ({eth(secure_delta_wei)} ETH)')

# --- 9) Success criteria for Secure: attacker MUST NOT receive >= TARGET_X_ETH ---
#target_wei = to_wei_eth(TARGET_X_ETH)
#if attacker_delta_wei_s > target_wei:
    # attacker got at least the transfer — this is a failure of the secure contract
#    print('Unexpected Scenario Outcome: FAILURE — attacker received funds on Secure wallet (vulnerable behavior!).')
#    summary['reentrancy']['secure_result'] = 'FAILURE_ATTACKER_RECEIVED_FUNDS'
#elif attacker_delta_wei_s == target_wei:
    # secure contract prevented reentrancy (expected)
#    print('UnExpected Scenario Outcome: FAILURE — Secure Contract Atomic Execution guard failed and initial recieve transaction call successful (reentrancy not mitigated as designed).')
#    summary['reentrancy']['secure_result'] = 'FAILURE_ATTACKER_RECEIVED_FUNDS'
#else:
#    print('Expected Scenario Outcome: NO FUNDS WERE TRANSFERRED') 
#    summary['reentrancy']['secure_result'] = 'PASS_NO_FUNDS'

# store details for artifacts
#summary['reentrancy'].setdefault('secure', {})
#summary['reentrancy']['secure'].update({
#    'secure_before_wei': int(sec_before_r),
#    'secure_after_wei': int(sec_after_r),
#    'attacker_before_wei': int(att_before_r),
#    'attacker_after_wei': int(att_after_r),
#    'attacker_delta_wei': attacker_delta_wei_s,
#    'secure_delta_wei': secure_delta_wei,
#    'execute_tx': txh_exec_s,
#    'propose_tx': txh_prop_s,
#    'setProposalId_tx': txh_set_s,
#    'confirm_txs': confirm_txs_secure
#})

# --------------------------------------

#     UNECHECKED EXTERNAL CALL (RECIEVE)

# --------------------------------------

# ---------------------------------

#   ATTACK EXECUTION (VULNERABLE)

# ---------------------------------

log_step('UNCHECKED EXTERNAL CALL (Vulnerable)')

EXEC_INDEX = 5
# --- 1) Propose tx sending TARGET_X_ETH to the attacker contract (on Vulnerable wallet) ---
print('Proposing transaction (Vulnerable -> attacker)')
txh_prop, rec_prop = call_propose(vuln, owner_accounts[0], SINKHOLE_ADDRESS, TARGET_X_ETH)
print('Propose tx:', txh_prop); dump_tx_artifact('vul_sink_propose', txh_prop, rec_prop)

# --- 2) Derive the proposal id (proposalCount - 1) ---
print('Deriving the proposal id')
try:
    pc = vuln.functions.proposalCount().call(); pid = pc - 1
except Exception:
    pid = 0
print('Derived proposal id (vulnerable):', pid)

# --- 3) Confirm the proposal with the other owners so it becomes executable ---
print('Confirming transaction (secure) with required owners')
for i, acct in enumerate(owners[1:3], start=1):
    txh_c, rec_c = call_confirm(vuln, get_owner_account(i), pid)
    print('Confirm tx ({i}):', txh_c); dump_tx_artifact(f'vul_sink_confirm_{i}', txh_c, rec_c)

# --- 4) Execute the proposal (this will activate the malicious recieve function in attacker contract.) ---
print('Executing proposal (vulnerable) — sinkhole attack should succeed')
txh_exec, rec_exec = call_execute(vuln, owner_accounts[0], pid, gas=2_500_000)
print('Execute tx:', txh_exec); dump_tx_artifact('vul_sink_execute', txh_exec, rec_exec)

# --- 5) Record contract state AFTER execute for comparison with secure wallet ---
proposal_vuln = vuln.functions.getProposal(pid).call()
vuln_tx_status = rec_exec.status
summary['unchecked_external']['vuln_executed'] = proposal_vuln[EXEC_INDEX] 
summary['unchecked_external']['vuln_tx_status'] = vuln_tx_status
print('Execution Status per Wallet:', proposal_vuln[EXEC_INDEX])
print('Execution Status per Blockchain:', vuln_tx_status)

# --- 6) VULNERABLE FLOW ASSERTION (After txh_exec_s) ---
# Assert VMS: Proposal is marked executed (CORRUPTED STATE)
if proposal_vuln[EXEC_INDEX] and vuln_tx_status == 1:
    print('VMS Divergence Proof: Proposal is marked executed despite external call uncertainty.')
else:
    print('VMS Failure: Expected proposal to be marked executed.')

# ---------------------------------

#   MITIGATION EXECUTION (SECURE)

# ---------------------------------

log_step('UNCHECKED EXTERNAL CALL (Secure)')

# --- 1) Propose tx sending TARGET_X_ETH to the attacker contract (on Secure wallet) ---
print('Proposing transaction (Secure -> attacker)')
txh_prop, rec_prop = call_propose(secure, owner_accounts[0], SINKHOLE_ADDRESS, TARGET_X_ETH)
print('Propose tx:', txh_prop); dump_tx_artifact('sec_sink_propose', txh_prop, rec_prop)

# --- 2) Derive the proposal id (proposalCount - 1) ---
print('Deriving the proposal id')
try:
    pc = secure.functions.proposalCount().call(); pid_su = pc - 1
except Exception:
    pid = 0
print('Derived proposal id (vulnerable):', pid_su)

# --- 3) Confirm the proposal with the other owners so it becomes executable ---
for i, acct in enumerate(owners[1:3], start=1):
    txh_c, rec_c = call_confirm(secure, get_owner_account(i), pid_su)
    print('Confirm tx:', txh_c); dump_tx_artifact(f'sec_sink_confirm_{i}', txh_c, rec_c)

# --- 4) Execute the proposal (this will activate the malicious recieve function in attacker contract.) ---
print('Executing proposal (secure) — should be protected against sinkhole attack')
txh_exec_s, rec_exec_s = call_execute(secure, owner_accounts[0], pid_su, gas=2_500_000)
print('Execute tx:', txh_exec_s); dump_tx_artifact('sec_sink_execute', txh_exec_s, rec_exec_s)

# --- 5) Record contract state AFTER execute for comparison with Vulnerable wallet ---
# Note: Secure execution should result in a REVERT (status=0)
proposal_secure = secure.functions.getProposal(pid_su).call() 
secure_tx_status = rec_exec_s.status
summary['unchecked_external']['secure_executed'] = proposal_secure[EXEC_INDEX] 
summary['unchecked_external']['secure_tx_status'] = secure_tx_status
print('Execution Status per Wallet:', proposal_secure[EXEC_INDEX])
print('Execution Status per Blockchain:', secure_tx_status)

# --- 6) SECURE FLOW ASSERTION (After txh_exec_s) ---
# Note: Secure execution should result in a REVERT (status=0)
# Assert SMS: Proposal is NOT marked executed (SAFE STATE)

if not proposal_secure[EXEC_INDEX] and secure_tx_status == 0:
    print('SMS Divergence Proof: Proposal is NOT executed because transaction reverted successfully.')
else:
    print('SMS Failure: Secure contract did not revert as expected.')

# ---------------------------------
# UNECHECKED EXTERNAL CALL (IMPLODE)
# ---------------------------------
# This test proves the unchecked external call vulnerability by making the target 
# address a destroyed contract (i.e., address has no code), using Sinkhole.implode(to).

log_step('UNCHECKED EXTERNAL CALL (Post-Destruction)')

# Both contracts use index 5 for the 'executed' status (6th element)
EXEC_INDEX = 5 

# ---------------------------------
#        STAGE 1: DESTROY SINKHOLE
# ---------------------------------
log_step('STAGE 1: DEPLOY & DESTROY NEW SINKHOLE')

# A. Deploy a new Sinkhole contract instance
# The DEPLOYER_ACCOUNT will own the new Sinkhole, so it must be the one to implode it.
print('1. Attacker is deploying the Sinkhole contract (Implode) and will destroy as well...')
destroyed_addr, txh_implode, rec_implode = deploy_and_implode_sinkhole(attacker_account, attacker_account.address)
dump_tx_artifact('sinkhole_atomic_implode', txh_implode, rec_implode)
print('   Sinkhole Implosion Tx:', txh_implode)
print(f'    Destroyed Sinkhole Address: {destroyed_addr}')

# Verification: The Sinkhole address must have no code for the test to be valid.
if w3.eth.get_code(destroyed_addr) == b'':
    print('   VERIFIED: Sinkhole successfully destroyed.')
else:
    raise SystemExit('ERROR: Sinkhole not destroyed. Cannot run post-destruction test.')

# ----------------------------------------------
#        STAGE 2: ATTACK EXECUTION (VULNERABLE)
# ----------------------------------------------
log_step('POST-DESTRUCTION VULNERABLE FLOW')

# --- 1) Propose a 0-ETH call to the destroyed address. The call will fail due to no code. ---
print('Proposing transaction (Vulnerable -> attacker)')
txh_prop, rec_prop = call_propose(vuln, owner_accounts[0], SINKHOLE_ADDRESS, Decimal('0'))
pc = vuln.functions.proposalCount().call(); pid_vuln_dest = pc - 1
print(f'VMS Propose tx: {txh_prop} | PID: {pid_vuln_dest}')

# --- 2) Confirm the proposal with the other owners so it becomes executable ---
for i, acct in enumerate(owners[1:3], start=1):
    tx_vs, rxc = call_confirm(vuln, get_owner_account(i), pid_vuln_dest)
    print('Confirm tx:', tx_vs); dump_tx_artifact(f'vul_sink_dest_confirm_{i}', tx_vs, rxc)

# --- 3) Execute (Expected: TX succeeds at blockchain level, Proposal state is CORRUPTED) ---
txh_exec_dest_v, rec_exec_dest_v = call_execute(vuln, owner_accounts[0], pid_vuln_dest, gas=2_500_000)
dump_tx_artifact('vul_sink_dest_execute', txh_exec_dest_v, rec_exec_dest_v)
print('VMS Execute tx:', txh_exec_dest_v)

# --- ASSERT VULNERABILITY (Divergence Check) ---
vuln_tx_status = rec_exec_dest_v.status
vuln_executed = get_executed_status(vuln, pid_vuln_dest, EXEC_INDEX)

if vuln_tx_status == 1 and vuln_executed:
    print('RESULT: VMS is VULNERABLE. Tx Succeeded (Status=1) and proposal marked EXECUTED, ignoring external call failure.')
    summary['unchecked_external']['post_dest_vuln'] = 'VULNERABLE_CORRUPTED_STATE'
else:
    print('ERROR: VMS did not exhibit expected vulnerable behavior (Tx status or executed flag is wrong).')

# ---------------------------------------------
#        STAGE 3: MITIGATION EXECUTION (SECURE)
# ---------------------------------------------
log_step('POST-DESTRUCTION SECURE FLOW')

# --- 1) Propose a 0-ETH call to the destroyed address. ---
print('Proposing transaction (Secure -> attacker)')
txh_prop, rec_prop = call_propose(secure, owner_accounts[0], SINKHOLE_ADDRESS, Decimal('0'))
pc = secure.functions.proposalCount().call(); pid_secure_dest = pc - 1
print(f'SMS Propose tx: {txh_prop} | PID: {pid_secure_dest}')

# --- 2) Confirm the proposal with the other owners so it becomes executable. ---
for i, acct in enumerate(owners[1:3], start=1):
    tvs, rdx = call_confirm(secure, get_owner_account(i), pid_secure_dest)
    print('Confirm tx:', tvs); dump_tx_artifact(f'sec_sink_dest_confirm_{i}', tvs, rdx)

# --- 3) Execute (Expected: TX REVERTS, Proposal state is SAFE). ---
secure_tx_status = 0
txh_exec_dest_s = 'TX_REVERTED'
try:
    # Attempt to execute. This is expected to throw an exception due to revert.
    txh_exec_dest_s, rec_exec_dest_s = call_execute(secure, owner_accounts[0], pid_secure_dest, gas=2_500_000)
    secure_tx_status = rec_exec_dest_s.status
    dump_tx_artifact('sec_sink_dest_execute', txh_exec_dest_s, rec_exec_dest_s)
except Exception:
    # This is the expected path on revert.
    pass

# Get the final executed status (should be False due to the revert)
secure_executed = get_executed_status(secure, pid_secure_dest, EXEC_INDEX) 
print('SMS Execute tx:', txh_exec_dest_s)

# --- ASSERT MITIGATION (Divergence Check) ---
if secure_tx_status == 0 and not secure_executed:
    print('RESULT: SMS is SECURE. Tx REVERTED (Status=0) and proposal is NOT executed, due to atomic execution check.')
    summary['unchecked_external']['post_dest_secure'] = 'SECURE_SAFE_STATE'
else:
    print('ERROR: SMS did not exhibit expected secure behavior (Tx status or executed flag is wrong).')

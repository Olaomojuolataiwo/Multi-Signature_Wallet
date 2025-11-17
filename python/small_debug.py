import eth_utils
from web3 import Web3
from eth_account import Account
from eth_utils import keccak, to_bytes
from eth_keys import keys
from eth_account.messages import SignableMessage


# =========================================================================
# ⚠️ 1. USER-DEFINED CONSTANTS (REQUIRED)
# =========================================================================

# The signer's private key (already provided)
PRIVATE_KEY = "0xec534f9f428ae01495037aa3eec0765bc20ae36c905231ad0d87ef53c0f98a6e"
LOCAL_ACCOUNT = Account.from_key(PRIVATE_KEY)
SIGNER_ADDRESS = LOCAL_ACCOUNT.address
PRIVATE_KEY_HEX = "0xec534f9f428ae01495037aa3eec0765bc20ae36c905231ad0d87ef53c0f98a6e"
PRIVATE_KEY_BYTES = Web3.to_bytes(hexstr=PRIVATE_KEY_HEX)
PRIVATE_KEY_OBJECT = keys.PrivateKey(PRIVATE_KEY_BYTES)

# ⬅️ REPLACE THESE WITH YOUR ACTUAL VALUES 
CHAIN_ID = 11155111      # Your network's chain ID (e.g., 1, 1337, 31337)
SECURE_ADDR = "0x3C534dB15ca3210FE4C3FD1E3D8Edc2Cb369A765" # Your SecureMultiSig contract address

# Transaction Data (from test_valid_execution)
BENEFICIARY = "0x107d57Fa2D1e147c74701cFf5Dd04cb6f5914078" # The recipient address ('to')
VALUE = 1000
DATA = b""            # The raw transaction data bytes (empty)
NONCE = 0             # The contract nonce (must be 0 for the first call)

# =========================================================================
# 2. TYPE HASHES (Based on SecureMultiSig.sol)
# =========================================================================

# From _buildDomainSeparator
DOMAIN_TYPEHASH = keccak(text="EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")

# From your Python struct
EXECUTE_TYPEHASH = keccak(text="Execute(address to,uint256 value,bytes32 dataHash,uint256 nonce)")

# =========================================================================
# 3. HASH CALCULATION (Replicating Solidity logic)
# =========================================================================

# keccak256(data)
data_hash = keccak(DATA)

# --- Replicate DOMAIN_SEPARATOR (Solidity's _buildDomainSeparator) ---
# keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes("SecureMultiSig")), keccak256(bytes("1")), chainId, address(this)))
DOMAIN_SEPARATOR = Web3.solidity_keccak(
        ["bytes32", "bytes32", "bytes32", "uint256", "address"],
        [
            DOMAIN_TYPEHASH,
            keccak(text="SecureMultiSig"),
            keccak(text="1"),
            CHAIN_ID,
            Web3.to_checksum_address(SECURE_ADDR),
        ],
    )

# --- Replicate structHash (Solidity's non-standard struct hash) ---
# keccak256(abi.encode(EXECUTE_TYPEHASH, to, value, dataHash, nonce, chainId, address(this)))
structHash = Web3.solidity_keccak(
        ["bytes32", "address", "uint256", "bytes32", "uint256", "uint256", "address"],
        [
            EXECUTE_TYPEHASH,
            Web3.to_checksum_address(BENEFICIARY),
            VALUE,
            data_hash,
            NONCE,
            CHAIN_ID, # Non-standard inclusion!
            Web3.to_checksum_address(SECURE_ADDR), # Non-standard inclusion!
        ],
    )


# --- Replicate Final Digest (The input to ecrecover) ---
# keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
DIGEST = keccak(
    to_bytes(hexstr="1901") + DOMAIN_SEPARATOR + structHash
)

# =========================================================================
# 4. SIGNATURE AND RECOVERY (Replicating _splitSignature and ecrecover)
# =========================================================================

signature_obj = PRIVATE_KEY_OBJECT.sign_msg_hash(DIGEST)

# Replicate: address signer = ecrecover(digest, v, r, s);
recovered_public_key = signature_obj.recover_public_key_from_msg_hash(DIGEST)
recovered_signer = recovered_public_key.to_checksum_address()

# =========================================================================
# 5. OUTPUT
# =========================================================================

print("\n--- EIP-712 Contract Recovery Simulation ---")
print(f"Intended Signer:       {SIGNER_ADDRESS}")
print(f"Contract Digest (Hex): {DIGEST.hex()}")
print(f"Recovered Signer:      {recovered_signer}")

if recovered_signer == SIGNER_ADDRESS:
    print("\n✅ **SUCCESS:** The simulated contract recovery matches the intended signer.")
    print("   The digest calculation is correct. Your main script must be updated to use this digest.")
else:
    print("\n❌ **FAILURE:** The recovered signer is incorrect (most likely 0x00...00).")
    print("   This confirms a critical mismatch in the contract's hashing logic or the Python constants.")

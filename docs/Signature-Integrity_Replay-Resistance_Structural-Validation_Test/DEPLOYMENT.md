------------------------------------------------------------------------------
Signature-Integrity_Replay-Resistance_Structural-Validation_Test/Deployment.md
------------------------------------------------------------------------------
Deployment & Transaction Artifacts

# Environment Context

. RPC: https://eth-sepolia.g.alchemy.com/v2/F8X3H2cE64aIbdybBl01B

. Chain ID: 11155111

. Signer: 0xcc7a3706Df7FCcFbF99f577382BC62C0e565FcF0

. VulnerableMultisig: 0xB2166d14b356C1d87DF83924BCA5C51CBB40C409

. SecureMultisig: 0xAaf15e7e821e36122f4F77b73dAbAD05b8A8408F

. Beneficiary: 0x107d57Fa2D1e147c74701cFf5Dd04cb6f5914078

# Scenario-Level Transaction Artifacts

. Test 1 — Structural Validation

Vulnerable success:
f395641fbea9b89a86614dc4953d282b9e5a065673365236950c69ac2828199b

Secure success:
51ecf3188e22a9e3162e5dfa3066f76352689de8cf2197fe9c4cf0f896df64b8

. Test 2 — Replay Attack Test

1. Initial execution:

Vulnerable:
53a1b7e3e2c496a231e265cea969c39571bba8fa5e1052f22630456ae892bd1d

Secure:
ce74c1fc819c9b2fddedd6a668e92ee1d529b09e9f0fb7e841baad91e8932906

2. Replay attempt:

Vulnerable (Replay Succeeds):
864533ca50777304828eaf09a32fd3613aa45668d0abef20dc94f24fdabe56e5

Secure (Replay Fails):
12a6b0e7d3312be5f570b0a2181f9aa3c41dcd8df0a9b6dfdd7d204576dd6c9a

3. Test 3 — Mutation Resistance

Vulnerable accepts mutated payload:
18f8677073369a6e6b521569f3eb1196d8aa7019992255a3c80f4bc3d7353cb8

Secure rejects mutated payload:
2e346308a369666091f19624d0f3f0506bed0e669b92bab94d1c39e610461ee0

4. Test 4 — Arithmetic Manipulation

Vulnerable accepts overflow arithmetic:
fb4113fe9d6b59f281d18219e5773e371eae46bce3cd3c2cc8dc3228da25e236

Secure rejects overflow attempt:
462aa2473156f9904876e9f756177da2b78424e320b90bf6fbb56ffacac9c603

5. Test 5 — Input Sanitization

Vulnerable executes malformed input:
b58bc2ec5a728ab0c724e5c1984713e3b50fb81d369ebb5c70bde50dc067a55b

Secure rejects malformed input:
5238f0c57b5d9f052c842e57e405af6f0eeacc27fac2ae2f0f580dd396b338e5

# Cryptographic Artifacts Captured

. StructHash values

. DigestHash values

. Domain separator

. Per-owner nonce values

. Recovered signer addresses

. Gas usage per scenario

. Revert reasons on secure wallet failures

All retained inside /artifacts/T-02-04/.


EXECUTION SAFETY TEST — Deployment.md
Production-grade deployment and transaction artifact record for Execution Safety Test

Document Purpose
This file enumerates all deployments, contract addresses, and every important transaction hash recorded during the Execution Safety Test suite. These hashes are authoritative artifacts for forensic review and audit.

Chain: Sepolia (11155111)
Artifact Root: artifacts/T-03/

# Section 1 — Deployments (wallets, malicious & helper contracts used in tests)

Primary Wallet Deployments (Fresh Deployment for T-03 Execution Safety Test)

VulnerableMultiSig Address: 0xd2A933e591F19B828Bf669127e446d037B163575

Deploy Tx Hash: 0xd069e963036f8ae69999c0109df400ce19711e2ac8e7b703882620499340dc25

SecureMultiSig Address: 0x3C534dB15ca3210FE4C3FD1E3D8Edc2Cb369A765

Deploy Tx Hash: 0xa099c37a6984bf916346cae639354ad9ff7288a472aba992c470140dbe6141e1

Malicious / Attacker Contract Deployments (initial malicious deployment run)

ReentrancyAttacker contract — Address: 0xd115a16ec3f064D8A19FD6AcDbF5705EC80ab21C

Deploy Tx Hash: 0x7f575b9bf0abefe3975c0a0d18ee6caf985a8feda051c9e39b42603c8fd78c0d

Trace reported bytecode size: 665 bytes

Sinkhole contract — Address: 0x10BB842CB0922bC4b90045Cde05E738E24279b59

Deploy Tx Hash: 0x11086b9a21a4c5993b0c74d2d6a4af2a469c2f4352318ccec4b896ed153d1bc7

Trace reported bytecode size: 524 bytes

Notes: These were created during the malicious deployment script and are used as targets for unchecked external call & sink tests.

# Section 2 — Test Transactions Indexed by Scenario

A. Reentrancy Test (Vulnerable)

Propose (Vulnerable): ab88ed54aa7c9cbad8208f9bcdc54baa5e06372930ad62f5a3002485507b0ad2

Set Proposal ID (Vulnerable): 17319ddd842f1cabf9d946130968f5e49c08b6af935fb69c43d4835307cd1fbe

Confirm (first): 545c9f623bd18911f1bf3a6f855513bc4fab1f7d194ccfc52fc367e8313c86d6

Confirm (second): 14cfee5eefcb4f80feb3112a6f9a123f97074f79dde9ff0d3ae16b675672fb13

Execute (Vulnerable): aebbd4be216798b6441b939b03c49cf56e00c7b30af791abc5ff0b7529cefd50

Withdraw / Reset: 74d793c035b577757b95d42a98519bd04f3977cc3410c65f81c9cae1c3701486

B. Reentrancy Test (Secure)

Propose (Secure): 9dd4fb4f7f209bb3998bdd96634a496d7f99ef42449f49c338247154d0f23cae

Set Proposal ID (Secure): a9730d77ec13de6c9ef17e4afa29340476b004d9eab714eb99b6c54ecd49ab84

Confirm (first): cf6b2b8173b2dd11122acb8e7c57111ceab2692cc60750215e1666dc5c68e5bd

Confirm (second): 7939889b9e483fabdd00a1c83ed133b73e4b9198fc337a2e6aa96efb23483a17

Execute (Secure): 44c6d29ee0fc9841dba5d4df624d6547ba458089df35260fbfec6243a690bea6

C. Unchecked External Call (Vulnerable)

Propose (Vul): f1db57f2968afc1664a3823b73e4c6afe2552f76e2612fe8db55e7266d3012fb

Confirm (first): 0f7c16aad80f855ddd0591e2c50c6e75e79a41e0266c4af539901dfd986f6f5b

Confirm (second): 9e1675de19cb090afd14e0198210b5b00f69eabf3dfd8edf0b6995f3c7819c45

Execute (Vul): 3740d68b5f135eedef9a5ba80c87c3ae007b3ad44cf8d04388a073fed4484cac

D. Unchecked External Call (Secure)

Propose (Sec): 9e52ee845f058bc8adc26c5e1669e9561dd4186e88e5c02f560207aeda9b9e34

Confirm (first): b8a30c1beff1e9a7e6ad56cc05f848420a157e0d40445902ecbde7c3d2a0960b

Confirm (second): 14822d2d0ec32f03ff84a460f6e4a7750e5c371655f209bf4109821b86935d0a

Execute (Sec): f6d805c67fdb96f008b562beb49154d780d4901e27572ee136676c47522afd03

E. Sinkhole Deployment & Implode (important implosion TXs)

Sinkhole deploy / implode TXs recorded: f2983a33a5ef2e4ca92891fcb1aa1f3b9bb9fa53bcd300318184cd53052a4eaf

Additional implode / teardown TX: 7ad1e5eb08912cd773e5005b8891b2f8907da30fbe3d40efc203565cf6a3973b

F. Post-Destruction Vulnerable Flow (after sinkhole destroyed)

Propose (Vul post-destroy): 3e40125e9645cd9a06382505dc8d3521fd1cbe80202d1fea0988a0699194e542

Confirm (1): f410ae5e9e831603c8ccb95a23cefdfc65d5e69b687ac2bf2ddf32f2b5c7969c

Confirm (2): f28ed7c521117b3d6653fcc449a30d13df510365b5922ab915ed29db95d77f64

Execute (Vul post-destroy): dd88a060470720473825f764d66ea68ab32b060fdedea78678be68886cd93db6

G. Post-Destruction Secure Flow

Propose (Secure post-destroy): 6e9053b94391f9cd3195c9eb37906f4529918cc1d66455c1fa2af4d2c25008ef

Confirm (1): 98203d5fb49ce9e74ecaaad4df343850c4ff0b9366b0462fef511be8ce58419b

Confirm (2): 3de372a0875d787ffee7e27b1a5f68531a28262ff23268da691d3a50543d6198

H. Batch Gas Exhaustion — Vulnerable (malicious target & action txs)

Malicious target deployed at: 0x16a20aFD92afc6F7C032d1dDe1c3fbcD5CAAb222

Malicious propose (Vul): 270349de17c009d74f3f3821627c2be9f7fea32b2ad659b187756c84e732ad3f

Confirm (1): 9c74315a4c7eea314f19e6821348b65f5894c8de17db0f839b8693f2872edb89

Confirm (2): 5d52354501c2ededd0048ecf488100773dbaa07fd396f785013fd6249519d47d

I. Batch Gas Exhaustion — Secure (malicious target & action txs)

Malicious target deployed at: 0x9F475db3526e7fE88E8192B6952e9D2b1b8F2A4f

Malicious propose (Sec): e64df27a59e5499c01c080652e138104a1ea161fbad722aa5d598b09aec9d8cc

Confirm (1): 4c9c33175775822068543105152957d2775036f4c2339ade4cfcddd7373218be

Confirm (2): 1fb7f45e80043cf90c6c9df8f3d0500d2987c9755ea220b669054d81bd49383a

Section 3 — Snapshot & Trace File Inventory (explicit list)
All artifacts saved during the run are authoritative and available under artifacts/T-03/. Example directories include:

artifacts/T-03/deployments/ (deploy-run-latest.json and individual run files)

artifacts/T-03/receipts/ (full JSON receipts for each tx above)

artifacts/T-03/traces/ (RPC traces for failing and successful calls)

artifacts/T-03/snapshots/ (pre/post snapshots for vulnerable and secure flows)

artifacts/T-03/summary.json (consolidated assertions and diffs)

Reproducibility and Forensic Guidance

To reproduce a scenario in a clean run, deploy the given malicious helper contracts first (addresses or deploy scripts included), then run the scenario steps in the exact order shown in the logs.

For auditors: reference the tx hash first; then correlate the receipt JSON (artifacts/T-03/receipts/<hash>.json) with the snapshot files and trace JSON to show state transition mapping.

Do not mix deployments across scenarios; some flows assume fresh state.

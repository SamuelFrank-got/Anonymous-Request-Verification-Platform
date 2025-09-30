# AnonReq: Anonymous Request Verification Platform

## Overview

**AnonReq** is a decentralized Web3 platform built on the Stacks blockchain using Clarity smart contracts. It leverages Zero-Knowledge (ZK) proofs to enable anonymous requests for services, aid, or resources while verifying eligibility without compromising user privacy. This solves real-world problems like:

- **Privacy in Sensitive Requests**: Individuals in vulnerable situations (e.g., domestic violence survivors seeking shelter, whistleblowers reporting corporate misconduct, or low-income users applying for micro-grants) can submit requests anonymously. Traditional systems often require identity disclosure, leading to stigma, retaliation, or data breaches.
- **Fraud Prevention**: ZK-proofs allow verifiers (e.g., NGOs, employers, or donors) to confirm claims (e.g., "I am over 18 and in a qualifying zip code") without seeing personal details.
- **Decentralized Trust**: Eliminates reliance on centralized platforms that censor or monetize data, ensuring tamper-proof verification on-chain.

The platform uses Semaphore (a ZK protocol for anonymous signaling) integrated with Stacks for on-chain storage and execution. Users generate ZK-proofs off-chain (via a frontend SDK) and submit them for verification. Successful verifications trigger actions like fund releases or access grants.

Key Features:
- Anonymous request submission with ZK-verified attributes.
- On-chain request matching and fulfillment.
- Reward mechanisms for verifiers/reviewers.
- Audit trails without revealing identities.

## Architecture

The system consists of 6 core Clarity smart contracts, deployed on Stacks mainnet/testnet. They handle identity management, proof verification, request lifecycle, matching, fulfillment, and governance. Contracts interact via cross-contract calls and use traits for modularity.

### High-Level Flow
1. **User Setup**: Join a Semaphore group (anonymous identity) and generate ZK-proof for attributes (e.g., age, location).
2. **Submit Request**: Call `request-submitter` with proof; verify on-chain.
3. **Matching & Review**: Verifiers match requests; approve via ZK.
4. **Fulfillment**: Release funds/assets upon approval.
5. **Governance**: Token holders vote on parameters.

### Smart Contracts

1. **identity-manager.clar**  
   - Manages Semaphore group memberships and nullifiers (prevents double-signaling).  
   - Functions: `join-group`, `generate-nullifier-key`, `verify-membership`.  
   - Storage: Group merkle roots, user commitments (hashed).  
   - Purpose: Establishes anonymous identities.

2. **proof-verifier.clar**  
   - Verifies ZK-proofs for request attributes (e.g., Groth16 proofs for predicates like "age > 18").  
   - Functions: `verify-attribute-proof`, `validate-circuit-inputs`.  
   - Storage: Verification keys (VKs) for circuits.  
   - Purpose: Core ZK verification without revealing inputs.

3. **request-submitter.clar**  
   - Handles anonymous request creation and submission.  
   - Functions: `submit-request`, `update-request-status`, `withdraw-request`.  
   - Storage: Request IDs, hashed payloads, proof hashes, timestamps.  
   - Purpose: Entry point for users to post verified requests.

4. **matcher-reviewer.clar**  
   - Facilitates request matching by verifiers (e.g., matching aid requests to donors).  
   - Functions: `propose-match`, `review-and-approve`, `dispute-match`.  
   - Storage: Match proposals, reviewer stakes, dispute logs.  
   - Purpose: Decentralized review to prevent spam/malicious requests.

5. **fulfillment-executor.clar**  
   - Executes fulfillments (e.g., STX/sFT transfers) upon approval.  
   - Functions: `execute-fulfillment`, `release-funds`, `claim-reward`.  
   - Storage: Escrow balances, fulfillment receipts.  
   - Purpose: Automates payouts with ZK-confirmed conditions.

6. **governance-token.clar**  
   - SIP-010 compliant token for governance (e.g., voting on verification thresholds).  
   - Functions: `mint-gov-tokens`, `vote-on-proposal`, `update-params`.  
   - Storage: Token balances, proposal states, quorum thresholds.  
   - Purpose: Community-driven parameter tuning (e.g., proof validity periods).

### Tech Stack
- **Blockchain**: Stacks (Clarity contracts).
- **ZK Integration**: Semaphore.js for off-chain proof generation; on-chain verifier adapted from Circom/Groth16.
- **Frontend**: React + Stacks.js for wallet integration (Hiro Wallet).
- **Off-Chain**: Node.js backend for circuit compilation; IPFS for request metadata storage.
- **Testing**: Clarinet for unit/integration tests.

## Real-World Impact
- **Use Case 1: Whistleblower Protection** – Employees prove employment tenure via ZK without naming the company; reports trigger anonymous bounties.
- **Use Case 2: Humanitarian Aid** – Refugees verify need (e.g., "displaced within last 6 months") for crypto aid drops.
- **Metrics**: Reduces verification time from days (centralized KYC) to minutes; enhances trust in Web3 aid distribution.

## Setup & Deployment

### Prerequisites
- Node.js v18+, Yarn/NPM.
- Clarinet CLI for local dev.
- Hiro Wallet for testing.

### Local Development
1. Clone repo: `git clone <repo-url> && cd anonreq`.
2. Install deps: `yarn install`.
3. Compile circuits: `cd circuits && yarn build` (generates VKs for `proof-verifier`).
4. Run local Stacks node: `clarinet integrate`.
5. Deploy contracts: `clarinet deploy`.
6. Test: `yarn test` (covers ZK verification, request flows).

### Deployment to Stacks
1. Update `Clarity.toml` with mainnet API keys.
2. Deploy via Hiro CLI: `stacks wallet deploy`.
3. Verify on [Stacks Explorer](https://explorer.stacks.co/).

### Example Contract Snippet (proof-verifier.clar)
```clarity
(define-constant ERR_INVALID_PROOF (err u1001))
(define-data-var verification-key (buff 32) 0x...)  ;; Groth16 VK

(define-public (verify-attribute-proof (proof {a: (buff 32), b: (list 64 uint256), c: (buff 32), ...}) (public-inputs (list 1 uint256)))
  (asserts! (contract-call? ?zk-verifier verify-groth16 proof public-inputs verification-key) (ok true))
  (ok true)
)
```

## Contributing
- Fork and PR for new circuits or use cases.
- Report issues for ZK edge cases.

## License
MIT License. See [LICENSE](LICENSE) for details.
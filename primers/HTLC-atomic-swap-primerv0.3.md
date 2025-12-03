# htlc atomic swap Auditor Primer v0.3

## Overview
This primer contains a general range of critical security patterns, heuristics and vulnerabilities useful for smart contract auditing. It is designed to provide a useful base that can be extended into particular specializations.

**Latest Update Summary**: Added comprehensive cross-chain HTLC bridge system-level analysis including: formal hashlock/timelock models with cryptographic security properties, cross-chain atomicity mechanics (shared secret linking, settlement windows, preimage propagation, finality time differences), full attack taxonomy (preimage racing, refund-griefing, cross-chain timing desync, hash function inconsistencies, meta-transaction attacks, preimage withholding/blackmail, reorg-based atomicity breaks), chain-specific deep-dives (EVM calldata canonicalization, Starknet Pedersen vs SHA-256 bridging, Solana CPI limitations, Sui object ownership), economic/game-theory mechanics (optimal timelock deltas, miner incentive attacks, validator bribing, MEV opportunities, value-of-the-secret model), global invariant set (27 formal invariants for HTLC bridges), and comprehensive auditor checklists (deployment, parameters, multi-chain atomicity, signature correctness, time-delta safety, MEV threat model, economic modeling, shared-secret replay). Expanded property testing to include cross-chain completion exclusivity, finality-aware observation, and multi-hop timelock ordering. Added attack templates for preimage-race timing exploitation, hash function bridging failures, and L1-L2 messaging delay attacks.

**Previous Update**: Added comprehensive HTLC (Hash Time-Locked Contract) atomic swap vulnerabilities across EVM, Solana, Sui, and Starknet implementations. New sections include: timelock overflow/underflow patterns, secret preimage misvalidation, duplicate order ID generation, refund vs redeem race conditions, cross-chain state desync, registry owner misconfiguration, event replay attacks, and async operation sequence violations. Added 20+ attack templates with step-by-step exploits. Expanded property testing invariants for HTLC cross-chain completion, timelock monotonicity, and funds conservation. Added cross-contract interaction failure modes for HTLCRegistry, UDA implementations, and multi-chain deployments. Includes upgradeability risks specific to proxy patterns and storage collisions in HTLC contexts.

**Earlier Update**: Added comprehensive lending/borrowing protocol vulnerabilities from USSD and Beedle audits including oracle manipulation patterns (inverted base/rate tokens, decimal mismatches, price feed issues), reentrancy attacks in lending functions, precision loss exploits, liquidation/auction manipulation, access control flaws in loan management, slippage protection failures, and staking reward vulnerabilities. Expanded audit checklist with lending-specific checks and added new invariants for lending protocols, staking systems, and auction mechanics.

## Critical Vulnerability Patterns

### State Validation Vulnerabilities
1. **Unchecked 2-Step Ownership Transfer** - Second step doesn't verify first step was initiated, allowing attackers to brick ownership by setting to address(0)
2. **Unexpected Matching Inputs** - Functions assume different inputs but fail when receiving identical ones (e.g., swap(tokenA, tokenA))
3. **Unexpected Empty Inputs** - Empty arrays or zero values bypass critical validation logic
4. **Unchecked Return Values** - Functions don't verify return values, leading to silent failures and state inconsistencies
5. **Non-Existent ID Manipulation** - Functions accepting IDs without checking existence return default values, enabling state corruption
6. **Missing Access Control** - Critical functions like `buyLoan()` or `mintRebalancer()` lack proper authorization checks
7. **Inconsistent Array Length Validation** - Functions accepting multiple arrays don't validate matching lengths, causing out-of-bounds errors

### HTLC Timelock Vulnerabilities
1. **Timelock Overflow/Underflow (EVM)** - User-supplied `timelock` treated as absolute block number but frontend passes `block.number + delta`, pushing expiry far into future; arithmetic overflow when computing `block.number + userTimelock` allows instant refunds or permanently locked funds
2. **Timelock Comparison Off-By-One** - Using `>` instead of `>=` in `refund()` checks allows refunds 1 block early or permanently locks funds
3. **Inconsistent Timelock Semantics Across Chains** - EVM stores absolute block numbers, Solana uses slot deltas, Sui uses millisecond timestamps, Starknet uses block numbers; mixed semantics enable cross-chain timing races
4. **Timelock Overflow (Solana)** - `expiry_slot = current_slot + expires_in_slots` overflows when `expires_in_slots` unbounded; using `>` instead of `>=` prevents refund when `expiry_slot == u64::MAX`
5. **Timelock Overflow (Starknet)** - `Order.timelock: u128` plus `initiated_at: u128` overflows if expiry derived as `initiated_at + timelock` without bounds checking
6. **Timelock Overflow (Sui)** - `Order.timelock: u256` millisecond timestamps overflow without bounds; desync between off-chain wall-clock and on-chain `Clock` causes unexpectedly short/long windows
7. **Unbounded Timelock Values** - Missing validation that `timelock > current_time` and `timelock < MAX_SAFE` enables grief with impossibly long expiries
8. **Timelock Delta Misconfiguration** - Setting `T_X - T_Y` smaller than `Δ_net + Δ_final,Y + Δ_mev` breaks atomicity; fast chain expiring before slow chain enables preimage reveal on fast chain followed by refund on slow chain before counterparty redeems
9. **Block Height vs Timestamp Confusion** - Mixing height-based and timestamp-based timelocks across chains without proper conversion; validator timestamp manipulation (±X seconds) enables boundary-griefing on timestamp-based chains
10. **Mempool Variance Not Modeled** - Timelocks set "in blocks" without accounting for mempool congestion, spam attacks, and high block time variance; adversarial delay tactics cause honest parties to miss redeem windows

### HTLC Secret & Preimage Vulnerabilities
1. **Secret Length Misvalidation (EVM)** - `redeem(orderID, bytes secret)` casts `bytes` to `bytes32` with padding/truncation; attacker uses shorter secrets that hash correctly but break cross-chain redemption
2. **Event Logs Truncated Preimage** - `Redeemed(orderID, secret)` event logs first 32 bytes while accepting arbitrary length; cross-chain listeners reconstruct incorrect secret
3. **Variable-Length Preimage Acceptance** - Lack of explicit `require(secret.length == 32)` allows different preimage interpretations across chains
4. **Secret Hash Endianness Mismatch (Solana)** - SHA256 comparison over serialized bytes with incorrect endianness breaks cross-chain secret revelation
5. **Stale Secret Hash Not Cleared** - `SwapAccount.secret_hash` not cleared on redeem allows PDA reuse where redeemer already knows secret
6. **Secret Array Length Mismatch (Starknet)** - `redeem(order_id, secret: Array<u32>)` accepts length != 8 words; serialization from `Array<u32>` to bytes inconsistent with hash computation
7. **Secret Vector Length Not Enforced (Sui)** - `redeem_swap(order_id, secret: vector<u8>)` missing `vector::length(secret) == 32` check causes hash mismatches across chains
8. **Hash Function Algorithm Mismatch** - EVM uses Keccak-256, Bitcoin uses SHA-256, Starknet uses Pedersen/Poseidon; same secret yields incompatible hashes across chains, silently breaking atomicity
9. **ABI Encoding vs Packed Encoding** - `keccak256(abi.encode(...))` vs `keccak256(abi.encodePacked(...))` produce different digests; mixing encoding styles causes preimage domain mismatch
10. **Felt252 Range Restriction** - Cairo's felt252 (mod p ≈ 2^251) vs full 256-bit integers; naive truncation from L1 uint256 → felt252 is non-surjective and can cause non-invertible mappings
11. **BCS Serialization Mismatch (Sui/Move)** - Hash computed over BCS serialization on one chain but over raw bytes on another; cross-chain mismatch occurs

### HTLC Order ID & State Vulnerabilities
1. **Duplicate Order ID Generation (EVM)** - Order IDs computed as `sha256(abi.encode(...))` collide when `timelock` or `amount` truncated; events omit fields needed for reconstruction
2. **Order Overwrite Without Existence Check** - Missing `require(!orders[orderID].exists)` allows overwriting unfinished orders with new parameters, changing `redeemer`
3. **Duplicate Order ID (Solana PDA)** - PDA seeds `[b"swap_account", initiator, secret_hash]` lacking `amount` or `expiry` allow repeated `initiate` to same account, overwriting state
4. **PDA Re-initialization After Closure** - Anchor `init` without realloc protections allows closed PDAs to be reinitialized with stale state
5. **Duplicate Order ID (Starknet)** - `generate_order_id(chain_id, secret_hash, initiator_address)` ignores `redeemer`, `timelock`, `amount`; orders differing only in those fields get identical ID
6. **Order ID Collision Without Guard** - Missing `assert!(!orders::contains(order_id))` before creation enables front-running with same `secret_hash`
7. **Duplicate Order ID (Sui)** - `create_order_id(...)` with truncation of `u256 timelock` or `u64 amount` increases collision risk; dynamic fields allow silent overwrite of previous `Order`
8. **Storage Deletion and ID Reuse** - Deleting HTLC struct (e.g., `delete htlcs[id]`) and later reusing `id` for new swap; logic expecting `redeemedAt==0` as "never used" enables replays

### HTLC Race Condition Vulnerabilities
1. **Refund vs Redeem Race** - Both `refund(orderID)` and `redeem(orderID, secret)` check order state; missing `nonReentrant` modifier or atomic `isFulfilled` flag allows simultaneous execution
2. **Solana Refund vs Redeem at Expiry** - `refund` uses `clock.slot > expiry_slot`, `redeem` omits time check; both can succeed under cluster reorg
3. **Sui Concurrent State Mutation** - `refund_swap` and `redeem_swap` both mutate `Order.is_fulfilled` without proper `if (!order.is_fulfilled)` guards; concurrent transactions double-spend
4. **Starknet Async L2-L1 Messaging Race** - `redeem` on Starknet succeeds while `refund` on counterpart chain still possible due to delayed block sequencing
5. **Cross-Chain Refund/Redeem Coordination** - Different finality profiles (EVM block-based, Solana slots, Sui timestamps) enable preimage censorship on slower chain while fast chain settles
6. **Boundary Block Race** - At exact expiry, both redeem and refund transactions target same HTLC; miners choose ordering based on fees/bribes; refund may be prioritized for griefing/theft
7. **Reorg-Based Double-Claim** - Redeem on chain X reveals secret, counterparty redeems on chain Y; chain X reorgs removing redeem; initiator refunds on X while counterparty claimed on Y

### HTLC Registry & Infrastructure Vulnerabilities
1. **Registry Owner Misconfiguration** - HTLCRegistry owner can set UDA implementation and valid HTLC addresses; incorrect address points to uninitialized/malicious contract
2. **Missing Interface Validation** - Registry doesn't validate new HTLC addresses implement expected interface (`initiate`, `redeem`, `refund`), causing reverts
3. **Missing Registry Update Events** - No events on UDA/registry updates prevents off-chain synchronization; attackers exploit windows of disagreement
4. **Registry Ownership Hijack** - Deployer EOA never transfers ownership; compromise yields full registry control
5. **Unwhitelisted Caller Access to UDA** - Missing checks that registry callers are whitelisted HTLC contracts exposes UDA functions to arbitrary callers

### HTLC Cross-Chain State Vulnerabilities
1. **Cross-Chain State Desync** - Misaligned timelock windows (EVM blocks, Solana slots, Sui ms, Starknet blocks) leave one side refundable while other redeemable
2. **Premature Completion Marking** - Off-chain coordinator treats any `Redeemed` event as final; counterpart `Refunded` fires later, breaking accounting invariants
3. **Order ID Mapping Mismatch** - Different hashing (SHA256 vs Poseidon vs vector bytes) causes cross-chain mapping table to mis-associate `Refunded` and `Redeemed` events
4. **Async Operation Sequence Violation** - Initiator calls `initiate` on EVM, redeemer fails to initiate on Solana; no enforcement of "other side created" before redeem
5. **Instant Refund Sequence Violation** - Instant refund callable before `initiate` fully recorded; signatures replayed against multiple orders
6. **Finality Time Mismatch** - PoW probabilistic finality vs PoS economic finality vs BFT deterministic finality; preimage reveal on probabilistic chain not "final" until k-confirmations but other chain treats as irreversible
7. **L1-L2 Messaging Delay** - Starknet L2→L1 messages have prover latency (minutes to hours); timelocks on L1 must account for worst-case messaging delays and proof failures

### HTLC Event Replay & Logging Vulnerabilities
1. **Incomplete Event Data (EVM)** - `Initiated(bytes32 orderID)` without `secretHash` or `initiator` enables off-chain replay against unrelated orders
2. **Partial State Events (Solana)** - Events log partial state; off-chain listener reconstructing from events instead of account state mis-links cross-chain orders
3. **Event Struct Field Omission (Sui)** - Some deployments omit `secret_hash` from `Initiated` events; replaying from another deployment looks valid to naive watchers
4. **Unbounded Event Identifier (Starknet)** - Events using `felt252 order_id` as sole identifier vulnerable to replay in indexers not binding contract address and chain ID
5. **Fake HTLC Event Emission** - Attacker deploys fake HTLC with same ABI, emits `Redeemed` events without locking funds; off-chain system marks real order complete
6. **Event-State Inconsistency** - Events emitted before state changes finalize; revert causes event logged but state unchanged, desynchronizing off-chain watchers

### Signature-Related Vulnerabilities
1. **Missing Nonce Replay** - Signatures without nonces can be replayed after state changes (e.g., KYC revocation)
2. **Cross Chain Replay** - Signatures without chain_id can be replayed across different chains
3. **Missing Parameter** - Critical parameters not included in signatures can be manipulated by attackers
4. **No Expiration** - Signatures without deadlines grant "lifetime licenses" and can be used indefinitely
5. **Unchecked ecrecover() Return** - Not checking if ecrecover() returns address(0) allows invalid signatures to pass
6. **Signature Malleability** - Elliptic curve symmetry allows computing valid signatures without the private key
7. **Instant Refund Replay (EVM)** - `instantRefund(orderID, signature)` EIP712 digest over only `orderID`; signature replayed against new orders with same/exploitable ID
8. **Instant Refund Replay (Starknet)** - Message hash omits chain ID or contract address; signature from test deployment replayed on main
9. **EIP-712 Domain Separator Missing Fields** - Omitting `chainId`, `verifyingContract`, or version enables cross-chain/cross-contract replay attacks
10. **Incomplete Typed Message Coverage** - Signed payload missing critical fields (amounts, expiry, hash, beneficiary); relayers can substitute unsigned parameters
11. **Non-Canonical Signature Acceptance** - Not enforcing low-S in ECDSA or accepting malleated signatures bypasses deduplication/replay checks

### Precision & Mathematical Vulnerabilities
1. **Division Before Multiplication** - Always multiply before dividing to minimize rounding errors
2. **Rounding Down To Zero** - Small values can round to 0, allowing state changes without proper accounting
3. **No Precision Scaling** - Mixing tokens with different decimals without scaling causes calculation errors
4. **Excessive Precision Scaling** - Re-scaling already scaled values leads to inflated amounts
5. **Mismatched Precision Scaling** - Different modules using different scaling methods (decimals vs hardcoded 1e18)
6. **Downcast Overflow** - Downcasting can silently overflow, breaking pre-downcast invariant checks
7. **Rounding Leaks Value From Protocol** - Fee calculations should round in favor of the protocol, not users
8. **Inverted Base/Rate Token Pairs** - Using opposite token pairs in calculations (e.g., WETH/DAI vs DAI/ETH)
9. **Decimal Assumption Errors** - Assuming all tokens have 18 decimals when some have 6, 8, or 2
10. **Interest Calculation Time Unit Confusion** - Mixing per-second and per-year rates without proper conversion

### Lending & Borrowing Vulnerabilities
1. **Liquidation Before Default** - Borrowers liquidated before payment due dates when paymentDefaultDuration < paymentCycleDuration
2. **Borrower Can't Be Liquidated** - Attackers overwrite collateral amounts to 0, preventing liquidation
3. **Debt Closed Without Repayment** - Calling close() with non-existent IDs decrements counter, marking loans as repaid
4. **Repayments Paused While Liquidations Enabled** - Unfairly prevents borrowers from repaying while allowing liquidation
5. **Token Disallow Stops Existing Operations** - Disallowing tokens prevents existing loans from being repaid/liquidated
6. **No Grace Period After Unpause** - Borrowers immediately liquidated when repayments resume
7. **Liquidator Takes Collateral With Insufficient Repayment** - Incorrect share calculations allow draining collateral
8. **Repayment Sent to Zero Address** - Deleted loan data causes repayments to be sent to address(0)
9. **Forced Loan Assignment** - Malicious actors can force loans onto unwilling lenders via `buyLoan()`
10. **Loan State Manipulation** - Borrowers can cancel auctions via refinancing to extend loans indefinitely
11. **Double Debt Subtraction** - Refinancing incorrectly subtracts debt twice from pool balance
12. **Griefing with Dust Loans** - Bypassing minLoanSize checks to force small loans onto lenders

### Liquidation Incentive Vulnerabilities
1. **No Liquidation Incentive** - Trustless liquidators need rewards/bonuses greater than gas costs
2. **No Incentive To Liquidate Small Positions** - Small positions below gas cost threshold accumulate bad debt
3. **Profitable User Withdraws All Collateral** - Users with positive PNL withdraw collateral, removing liquidation incentive
4. **No Mechanism To Handle Bad Debt** - Insolvent positions have no insurance fund or socialization mechanism
5. **Partial Liquidation Bypasses Bad Debt Accounting** - Liquidators avoid covering bad debt via partial liquidation
6. **No Partial Liquidation Prevents Whale Liquidation** - Large positions exceed individual liquidator capacity

### Liquidation Denial of Service Vulnerabilities
1. **Many Small Positions DoS** - Iterating over unbounded user positions causes OOG revert
2. **Multiple Positions Corruption** - EnumerableSet ordering corruption prevents liquidation
3. **Front-Run Prevention** - Users change nonce or perform small self-liquidation to block liquidation
4. **Pending Action Prevention** - Pending withdrawals equal to balance force liquidation reverts
5. **Malicious Callback Prevention** - onERC721Received or ERC20 hooks revert during liquidation
6. **Yield Vault Collateral Hiding** - Collateral in external vaults not seized during liquidation
7. **Insurance Fund Insufficient** - Bad debt exceeding insurance fund prevents liquidation
8. **Fixed Bonus Insufficient Collateral** - 110% bonus fails when collateral ratio < 110%
9. **Non-18 Decimal Reverts** - Incorrect decimal handling causes liquidation failure
10. **Multiple nonReentrant Modifiers** - Complex liquidation paths hit multiple reentrancy guards
11. **Zero Value Transfer Reverts** - Missing zero checks with tokens that revert on zero transfer
12. **Token Deny List Reverts** - USDC-style blocklists prevent liquidation token transfers
13. **Single Borrower Edge Case** - Protocol incorrectly assumes > 1 borrower for liquidation

### Liquidation Calculation Vulnerabilities
1. **Incorrect Liquidator Reward** - Decimal precision errors make rewards too small/large
2. **Unprioritized Liquidator Reward** - Other fees paid first, removing liquidation incentive
3. **Excessive Protocol Fee** - 30%+ fees on seized collateral make liquidation unprofitable
4. **Missing Liquidation Fees In Requirements** - Minimum collateral doesn't account for liquidation costs
5. **Unaccounted Yield/PNL** - Earned yield or positive PNL not included in collateral value
6. **No Swap Fee During Liquidation** - Protocol loses fees when liquidation involves swaps
7. **Oracle Sandwich Self-Liquidation** - Users trigger price updates for profitable self-liquidation

### Unfair Liquidation Vulnerabilities
1. **Missing L2 Sequencer Grace Period** - Users liquidated immediately when sequencer restarts
2. **Interest Accumulates While Paused** - Users liquidated for interest accrued during pause
3. **Repayment Paused, Liquidation Active** - Users prevented from avoiding liquidation
4. **Late Interest/Fee Updates** - isLiquidatable checks stale values
5. **Lost Positive PNL/Yield** - Profitable positions lose gains during liquidation
6. **Unhealthier Post-Liquidation State** - Liquidator cherry-picks stable collateral
7. **Corrupted Collateral Priority** - Liquidation order doesn't match risk profile
8. **Borrower Replacement Misattribution** - Original borrower repays new owner's debt
9. **No LTV Gap** - Users liquidatable immediately after borrowing
10. **Interest During Auction** - Borrowers accrue interest while being auctioned
11. **No Liquidation Slippage Protection** - Liquidators can't specify minimum acceptable rewards

### Reentrancy Vulnerabilities
1. **Token Transfer Reentrancy** - ERC777/callback tokens allow reentrancy during transfers
2. **State Update After External Call** - Following transfer-before-update pattern enables draining
3. **Cross-Function Reentrancy** - Reentering different functions to manipulate shared state
4. **Read-Only Reentrancy** - Reading stale state during reentrancy for profit

### Slippage Protection Vulnerabilities
1. **No Slippage Parameter** - Hard-coded 0 minimum output allows catastrophic MEV sandwich attacks
2. **No Expiration Deadline** - Transactions can be held and executed at unfavorable times
3. **Incorrect Slippage Calculation** - Using values other than minTokensOut for slippage protection
4. **Mismatched Slippage Precision** - Slippage not scaled to match output token decimals
5. **Hard-coded Slippage Freezes Funds** - Fixed slippage prevents withdrawals during high volatility
6. **MinTokensOut For Intermediate Amount** - Slippage only checked on intermediate, not final output
7. **On-Chain Slippage Calculation** - Using Quoter.quoteExactInput() subject to manipulation
8. **Fixed Fee Tier Assumption** - Hardcoding 3000 (0.3%) fee when pools may use different tiers
9. **Block.timestamp Deadline** - Using current timestamp provides no protection

### Oracle Integration Vulnerabilities
1. **Not Checking Stale Prices** - Missing updatedAt validation against heartbeat intervals
2. **Missing L2 Sequencer Check** - L2 chains require additional sequencer uptime validation
3. **Same Heartbeat For Multiple Feeds** - Different feeds have different heartbeats
4. **Assuming Oracle Precision** - Different feeds use different decimals (8 vs 18)
5. **Incorrect Price Feed Address** - Wrong addresses lead to incorrect pricing
6. **Unhandled Oracle Reverts** - Oracle failures cause complete DoS without try/catch
7. **Unhandled Depeg Events** - Using BTC/USD for WBTC ignores bridge compromise scenarios
8. **Oracle Min/Max Price Issues** - Flash crashes cause oracles to report incorrect minimum prices
9. **Using Slot0 Price** - Uniswap V3 slot0 price manipulable via flash loans
10. **Price Feed Direction Confusion** - Using DAI/USD when protocol needs USD/DAI pricing
11. **Missing Circuit Breaker Checks** - Not checking if price hits minAnswer/maxAnswer bounds

### Concentrated Liquidity Manager Vulnerabilities
1. **Forced Unfavorable Liquidity Deployment** - Missing TWAP checks in some functions allow draining via sandwich attacks
2. **Owner Rug-Pull via TWAP Parameters** - Setting ineffective maxDeviation/twapInterval disables protection
3. **Tokens Permanently Stuck** - Rounding errors accumulate tokens that can never be withdrawn
4. **Stale Token Approvals** - Router updates don't revoke previous approvals
5. **Retrospective Fee Application** - Updated fees apply to previously earned rewards

### Staking & Reward Vulnerabilities
1. **Front-Running First Deposit** - Attacker steals initial WETH rewards via sandwich attack
2. **Reward Dilution via Direct Transfer** - Sending tokens directly increases totalSupply without staking
3. **Precision Loss in Reward Calculation** - Small stakes or frequent updates cause rewards to round to zero
4. **Flash Deposit/Withdraw Griefing** - Large instant deposits dilute rewards for existing stakers
5. **Update Not Called After Reward Distribution** - Stale index causes incorrect reward calculations
6. **Balance Caching Issues** - Claiming updates cached balance incorrectly

### Auction Manipulation Vulnerabilities
1. **Self-Bidding to Reset Auction** - Buying own loan to restart auction timer
2. **Auction Start During Sequencer Downtime** - L2 sequencer issues affect auction timing
3. **Insufficient Auction Length Validation** - Very short auctions (1 second) allow immediate seizure
4. **Auction Can Be Seized During Active Period** - Off-by-one error in timestamp check

### HTLC Storage & Upgradeability Vulnerabilities
1. **Registry Re-initialization** - Missing `initializer` guard allows resetting owner, token, or registry pointers
2. **UDA Implementation Upgrade Breaking Order IDs** - Implementation changes how order IDs computed, breaking off-chain mappings
3. **Storage Slot Collision (Solidity Proxy)** - Misaligned `Order` struct fields between implementations cause wrong `timelock` and `amount` reads
4. **Storage Slot Collision (Cairo)** - Adding fields to `Order` without proper migration reorders serialization
5. **Storage Namespace Collision (Move)** - Different modules defining `Order` with same type name but different semantics share object IDs
6. **UDA Storage Layout Corruption** - Proxy upgrade without storage layout compatibility corrupts `orders` mappings or balances
7. **Sui Storage Namespace Collision** - Multiple modules use `OrdersRegistry` with overlapping field tags, mis-interpreting fields

### HTLC Preimage Racing & Griefing Attacks
1. **Boundary Reveal Attack** - Secret owner reveals preimage on fast chain just before expiry, leaving counterparty minimal time to redeem on slow chain under congestion/censorship
2. **Bribed Miner Race** - Attacker bribes miners to include redeem transaction timing that maximizes counterparty disadvantage or prevents their redeem before refund
3. **Multi-Chain Selective Redemption** - Attacker redeems on chain where asset most valuable at current prices while racing to delay/prevent counterparties on other chains
4. **Withheld Secret for Free Option** - Initiator waits to see price movements before revealing secret; if unfavorable, lets timelocks expire at no cost (American-style free option)
5. **Miner Front-Running Preimage** - Miner observes secret in mempool, constructs higher-fee redeem transaction to claim before legitimate party
6. **Capital Lock-Up Griefing** - Attacker locks large counterparty assets in HTLCs, never redeems, forces wait until expiration for opportunity cost and capital inefficiency
7. **Gas Price Manipulation Griefing** - Spam or MEV strategies inflate gas prices making redeem transactions cost more than value claimable; low-value swaps abandoned
8. **Sequencer Congestion Attack** - On rollups, attacker spams sequencer to increase backlog and reduce feasible time window for honest redeems before expiry
9. **Slippage-Based Griefing** - If HTLC redemption combined with DEX trades, attacker manipulates DEX prices against swapper during redemption window via sandwich attacks
10. **Preimage Withholding Blackmail** - Initiator refuses to reveal secret unless counterparty compensates off-protocol, even if both sides refund; or waits until reveal triggers downstream profitable event

### HTLC Economic & MEV Exploits
1. **Negative Expected Value Windows** - One side holds optionality to complete swap only when market favors them; otherwise timeout, systematically extracting value
2. **Forced Suboptimal Execution Timing** - Adversary manipulates timing (mempool/MEV) so redemption feasible only under poor market conditions for victim
3. **Cross-Chain Arbitrage with Free Option** - HTLC ensures attacker has free/cheap option to arbitrage across DEXs and CEXs on different chains using price differences
4. **MEV Bots Extracting Preimage Value** - Moment secret revealed in any transaction, MEV bots use it to trigger other on-chain actions before original party (liquidations, conditional trades)
5. **Validator Bribery for Censorship** - Attacker bribes validators to censor counterparty's redeem transaction until refund path viable, forcing loss on honest party
6. **High Griefing Factor Exploitation** - Small attacker cost (lock minimal capital, pay minor fees) inflicts large expected cost on counterparties via systematic griefing

## Common Attack Vectors

### State Manipulation Attacks
- Direct ownership zeroing via unchecked 2-step transfers
- Bypassing validation through empty array inputs
- Exploiting functions that assume non-matching inputs with identical parameters
- Silent state corruption through unchecked return values
- Decrementing counters with non-existent IDs to mark loans as repaid
- Force-assigning loans to unwilling lenders via unauthorized `buyLoan()`
- Manipulating auction states through refinancing loops

### HTLC-Specific State Attacks
- Timelock overflow to wrap expiry to instant refund values
- Passing `timelock = block.number` directly for immediate refund eligibility
- Overwriting active orders by reusing order IDs without existence checks
- PDA re-initialization after closure to reuse stale state with known secrets
- Front-running order creation with same `secret_hash` to steal recipient role
- Instant refund before counterpart order creation via sequence violation

### Signature Exploitation
- Replaying old signatures after privilege revocation
- Cross-chain signature replay attacks
- Manipulating unsigned parameters in signed messages
- Using expired signatures indefinitely
- Passing invalid signatures that return address(0)
- Computing alternative valid signatures via malleability
- Replaying instant refund signatures across multiple orders with weak EIP712/SNIP-12 domain separation

### Precision Loss Exploits
- Draining funds through precision loss in invariant calculations
- Repaying loans without reducing collateral via rounding to zero
- Undervaluing LP tokens by ~50% through incorrect precision scaling
- Bypassing time-based checks through downcast overflow
- Extracting value through favorable rounding in fee calculations
- Borrowing without paying interest via calculated zero fees
- Exploiting decimal differences between paired tokens

### Liquidation & Lending Exploits
- Liquidating borrowers before their first payment is due
- Preventing liquidation by zeroing collateral records
- Taking all collateral by repaying only the smallest debt position
- Front-running repayment resumption to liquidate borrowers
- Exploiting paused repayments to force unfair liquidations
- Creating many small positions to cause liquidation DoS
- Using callbacks to revert liquidation transactions
- Hiding collateral in external yield vaults
- Profitable self-liquidation via oracle manipulation
- Cherry-picking stable collateral to leave users with volatile positions
- Forcing dust loans onto lenders to grief them
- Stealing loans via fake pools with worthless tokens

### HTLC Cross-Chain Exploits
- Revealing secret on fast-finality chain (Solana/Sui) then front-running refund on slower chain (EVM) before counterparty redeems
- Exploiting misaligned timelock windows where one chain refundable while other still redeemable
- Censoring preimage revelation on destination chain while claiming on source chain
- Racing refund and redeem at exact expiry block/slot due to comparison operator inconsistencies
- Replaying order IDs across chains due to naive off-chain mapping without chain ID scoping
- Reorg on one chain removes redeem transaction revealing secret; attacker uses secret on other chain then refunds on first chain after reorg

### MEV & Sandwich Attacks
- Zero slippage parameter exploitation in swaps
- Holding transactions via missing deadlines
- Front-running oracle updates for profit
- Manipulating on-chain slippage calculations
- Forcing CLM protocols to deploy liquidity at manipulated prices
- Sandwiching liquidations to extract value
- Front-running position transfers to steal repayments
- Sandwiching borrow/refinance to set unfavorable terms
- Front-running pool creation to steal initial deposits

### Oracle Manipulation
- Exploiting stale price data during high volatility
- Taking advantage of oracle failures without fallbacks
- Profiting from depeg events using mismatched price feeds
- Draining protocols during flash crashes via min/max price boundaries
- Manipulating Uniswap V3 slot0 prices with flash loans
- Exploiting inverted token pair calculations
- Using decimal mismatches between oracle and token

### Reentrancy Attacks
- Draining pools via transfer hooks in ERC777/callback tokens
- Cross-function reentrancy to manipulate shared state
- Exploiting state updates after external calls
- Using read-only reentrancy to trade on stale data
- Recursive calls to multiply rewards or reduce debts

### HTLC Event Replay & Infrastructure Attacks
- Deploying fake HTLC with same ABI to emit fraudulent `Redeemed` events that fool off-chain coordinator
- Replaying legitimate events from test deployment to main deployment when events lack chain ID binding
- Exploiting registry ownership compromise to redirect swaps to malicious HTLC implementations
- Using UDA implementation replacement to corrupt storage layouts and steal funds
- Creating event-based cross-chain order confusion when events log partial state

### HTLC Hash Function & Encoding Attacks
- Exploiting Keccak-256 vs SHA-256 vs Pedersen hash function differences across chains; same secret yields incompatible hashes
- ABI encoding vs packed encoding mismatches causing preimage domain divergence
- Endianness differences (big-endian vs little-endian) in integer-to-bytes interpretation breaking cross-chain hash consistency
- Felt252 range restrictions causing non-invertible mappings from L1 uint256
- BCS serialization on Move vs raw bytes on other chains causing hash mismatches
- Padding and canonicalization differences (bytes32 vs variable-length, leading zeros, trimming)

## Integration Hazards

### External Contract Integration
- Always verify return values from external calls
- Check for address(0) returns from ecrecover()
- Ensure consistent precision scaling across integrated modules
- Validate all inputs even from "trusted" sources
- Handle external contract failures gracefully
- Account for callbacks in token transfers (ERC721, ERC777)
- Consider token deny lists and pausable tokens
- Handle fee-on-transfer and rebasing tokens
- Account for tokens that revert on zero transfers
- Consider approval race conditions with certain tokens

### HTLC Registry & Infrastructure Integration
- Validate registry HTLC addresses implement expected interface before routing swaps
- Emit events on all registry and UDA updates for off-chain synchronization
- Whitelist callers to UDA functions to prevent direct access bypassing registry
- Enforce two-step ownership transfer with time delays for registries
- Verify storage layout compatibility before UDA implementation upgrades
- Prevent registry re-initialization via proper `initializer` guards

### Multi-Chain Deployments
- Include chain_id in all signature schemes
- Consider cross-chain replay vulnerabilities
- Ensure consistent precision handling across chains
- Verify oracle addresses per chain
- Account for different reorg depths per chain
- Check L2 sequencer status for Arbitrum/Optimism
- Handle different block times across chains
- Account for chain-specific token implementations

### HTLC Cross-Chain Integration
- **Timelock Window Alignment** - Ensure destination chain expiry strictly later than source chain; account for different time units (EVM blocks vs Solana slots vs Sui ms vs Starknet blocks)
- **Order ID Domain Separation** - Include chain ID and contract address in order ID generation; use consistent hashing (SHA256 vs Poseidon vs vector bytes) across chains
- **Event Schema Consistency** - Ensure all chains emit events with sufficient data for reconstruction; include `secret_hash`, `initiator`, `redeemer`, `amount`, and `timelock` in all events
- **Finality Profiles** - Account for different finality guarantees (EVM probabilistic, Solana optimistic, Sui checkpoint, Starknet sequencer) when setting timelock buffers
- **State Synchronization** - Off-chain coordinator must track state from all chains and prevent premature completion marking when only one side has settled
- **Async Operation Sequencing** - Enforce "counterpart order created" before allowing redemption to prevent one-sided locks
- **Preimage Propagation Delay** - Account for cross-chain observation latency (Δ_net), finality delay (Δ_final), and MEV/censorship buffer (Δ_mev) when setting timelock deltas
- **Reorg Resilience** - Use only post-finality events (k-confirmations on PoW, economic finality on PoS) to trigger cross-chain actions; avoid naive mempool watching
- **L1-L2 Messaging** - For Starknet L2→L1 messages, incorporate prover latency (minutes to hours) and potential proof failures into timelock calculations

### Token Integration
- Account for varying token decimals (2, 6, 8, 18)
- Scale all calculations to common precision before operations
- Handle tokens with non-standard decimals
- Consider fee-on-transfer tokens
- Account for rebasing tokens
- Handle tokens that revert on zero transfer
- Consider tokens with transfer hooks
- Account for tokens with deny lists (USDC)
- Handle deflationary/inflationary tokens
- Consider pausable tokens
- Account for tokens with multiple addresses
- Handle upgradeable token contracts

### Oracle Integration
- Implement proper staleness checks per feed
- Handle oracle reverts with try/catch
- Monitor for depeg events in wrapped assets
- Consider min/max price boundaries
- Implement fallback price sources
- Check L2 sequencer uptime on L2s
- Use correct decimals for each feed
- Validate price feed addresses
- Account for oracle-specific heartbeats
- Handle multi-hop price calculations
- Consider oracle manipulation windows
- Implement circuit breaker mechanisms

### AMM & DEX Integration
- Always allow user-specified slippage
- Implement proper deadline parameters
- Check slippage on final, not intermediate amounts
- Scale slippage to output token precision
- Allow users to specify fee tiers for UniV3
- Handle multi-hop swaps appropriately
- Account for concentrated liquidity positions
- Consider impermanent loss scenarios
- Handle liquidity migration events

### Liquidation System Integration
- Ensure liquidation incentives exceed gas costs
- Support partial liquidation for large positions
- Handle bad debt via insurance fund or socialization
- Implement grace periods after unpause
- Account for all collateral locations (vaults, farms)
- Update all fee accumulators before liquidation checks
- Allow liquidators to specify minimum rewards
- Handle multiple collateral types appropriately
- Account for price impact during liquidation
- Consider flash loan liquidation attacks

### Lending Protocol Integration
- Validate loan token and collateral token compatibility
- Ensure proper decimal scaling for all calculations
- Handle interest rate updates appropriately
- Account for paused states in all operations
- Implement proper auction length bounds
- Handle pool balance updates atomically
- Validate borrower and lender permissions
- Account for outstanding loans in balance calculations
- Handle edge cases in loan lifecycle
- Implement proper fee distribution

### Staking System Integration
- Prevent reward token from being staking token
- Handle direct token transfers appropriately
- Update indices before balance changes
- Account for precision loss in reward calculations
- Implement minimum stake amounts
- Handle reward distribution timing
- Prevent sandwich attacks on deposits/withdrawals
- Account for total supply manipulation

## Audit Checklist

### State Validation
- [ ] All multi-step processes verify previous steps were initiated
- [ ] Functions validate array lengths > 0 before processing
- [ ] All function inputs are validated for edge cases (matching inputs, zero values)
- [ ] Return values from all function calls are checked
- [ ] State transitions are atomic and cannot be partially completed
- [ ] ID existence is verified before use
- [ ] Array parameters have matching length validation
- [ ] Access control modifiers on all administrative functions
- [ ] State variables updated before external calls (CEI pattern)

### HTLC-Specific State Validation
- [ ] Order ID existence checked before state writes (`require(!orders[orderID].exists)`)
- [ ] Timelock values bounded (`timelock > current_time && timelock < MAX_SAFE`)
- [ ] Secret length enforced (`require(secret.length == 32)` or fixed-length array)
- [ ] PDA seeds include uniqueness parameters (amount, expiry, or nonce)
- [ ] Closed/refunded orders cannot be re-initialized with same seeds
- [ ] Order fulfillment status atomically updated (before external calls)
- [ ] Cross-chain order ID includes chain ID and contract address

### HTLC Timelock Security
- [ ] Timelock comparison uses correct operator (`>=` not `>` for refund checks)
- [ ] Timelock overflow prevented (bounded relative to current block/slot/timestamp)
- [ ] Timelock semantics consistent across chain implementations (absolute vs relative)
- [ ] Timelock stored correctly without re-adding current block/slot/timestamp
- [ ] Frontend/SDK timelock encoding matches contract expectations
- [ ] Redeem enforces `current_time < timelock`
- [ ] Refund enforces `current_time >= timelock`
- [ ] Timelock windows aligned across chains for atomic swaps (destination expiry > source expiry)
- [ ] Timelock deltas account for Δ_net + Δ_final + Δ_mev safety margins
- [ ] Block variance and mempool congestion modeled in timelock calculations
- [ ] Height-based vs timestamp-based semantics not mixed without conversion

### HTLC Secret & Preimage Security
- [ ] Secret hash cleared or marked consumed after redeem
- [ ] Secret hash comparison includes correct endianness and serialization
- [ ] Events log complete preimage (not truncated)
- [ ] Variable-length secrets rejected (explicit length check)
- [ ] Secret hashing consistent with cross-chain counterparts
- [ ] Preimage reveal doesn't expose secrets before counterpart order created
- [ ] Hash function (SHA256/Keccak/Pedersen) identical across all chains
- [ ] ABI encoding vs packed encoding consistent across chains
- [ ] Felt252/uint256 mappings validated for surjectivity and invertibility
- [ ] BCS serialization matches raw byte expectations across Move and non-Move chains

### HTLC Race Condition Prevention
- [ ] NonReentrant modifier on redeem and refund functions
- [ ] Fulfillment flag set before token transfers
- [ ] Refund and redeem cannot both succeed for same order
- [ ] Timelock checks consistent between redeem and refund (no overlap at expiry)
- [ ] Cross-chain settlement sequencing enforced (cannot refund source before destination initiates)
- [ ] Boundary conditions use inclusive/exclusive semantics consistently across chains

### HTLC Registry & Infrastructure
- [ ] Registry validates HTLC addresses implement required interface
- [ ] Registry emits events on all HTLC and UDA updates
- [ ] Registry whitelists callers to UDA functions
- [ ] Registry uses two-step ownership transfer with time delays
- [ ] UDA implementation upgrades check storage layout compatibility
- [ ] Registry re-initialization prevented via `initializer` guard

### HTLC Event Security
- [ ] Events include all parameters needed for cross-chain reconstruction (secret_hash, initiator, redeemer, timelock, amount)
- [ ] Events include chain ID or contract address for replay prevention
- [ ] Events log full secret (not truncated) on redeem
- [ ] Off-chain systems validate event source contract is whitelisted
- [ ] Event emission occurs only after successful state transitions (no event-before-state)

### Signature Security
- [ ] All signatures include and verify nonces
- [ ] chain_id is included in signature verification
- [ ] All relevant parameters are included in signed messages
- [ ] Signatures have expiration timestamps
- [ ] ecrecover() return values are checked for address(0)
- [ ] Using OpenZeppelin's ECDSA library to prevent malleability
- [ ] Instant refund signatures include order-specific parameters (not just orderID)
- [ ] EIP712/SNIP-12 domain separation includes contract address and chain ID
- [ ] Domain separator includes name, version, chainId, verifyingContract/programId
- [ ] Signed payload covers all critical fields (hash, amounts, expiry, participants, beneficiary)

### Mathematical Operations
- [ ] Multiplication always performed before division
- [ ] Checks for rounding to zero with appropriate reverts
- [ ] Token amounts scaled to common precision before calculations
- [ ] No double-scaling of already scaled values
- [ ] Consistent precision scaling across all modules
- [ ] SafeCast used for all downcasting operations
- [ ] Protocol fees round up, user amounts round down
- [ ] Decimal assumptions documented and validated
- [ ] Interest calculations use correct time units
- [ ] Token pair directions consistent across calculations

### Lending & Borrowing
- [ ] Liquidation only possible after payment deadline + grace period
- [ ] Collateral records cannot be zeroed after loan creation
- [ ] Loan closure requires full repayment
- [ ] Repayment pause also pauses liquidations
- [ ] Token disallow only affects new loans
- [ ] Grace period exists after repayment resumption
- [ ] Liquidation shares calculated from total debt, not single position
- [ ] Repayments sent to correct addresses (not zero)
- [ ] Minimum loan size enforced to prevent dust attacks
- [ ] Maximum loan ratio validated on all loan operations
- [ ] Interest calculations cannot result in zero due to precision
- [ ] Borrower can specify expected pool parameters
- [ ] Auction length has reasonable minimum (not 1 second)
- [ ] Pool balance updates are atomic with loan operations
- [ ] Outstanding loans tracked accurately

### Liquidation Incentives
- [ ] Liquidation rewards/bonuses implemented for trustless liquidators
- [ ] Minimum position size enforced to ensure profitable liquidation
- [ ] Users cannot withdraw all collateral while maintaining positions
- [ ] Bad debt handling mechanism implemented (insurance fund/socialization)
- [ ] Partial liquidation supported for large positions
- [ ] Bad debt properly accounted during partial liquidations

### Liquidation Security
- [ ] No unbounded loops over user-controlled arrays
- [ ] Data structures prevent liquidation DoS via gas limits
- [ ] Liquidatable users cannot front-run to prevent liquidation
- [ ] Pending actions don't block liquidation
- [ ] Token callbacks cannot revert liquidation
- [ ] All collateral locations checked during liquidation
- [ ] Liquidation works when bad debt exceeds insurance fund
- [ ] Fixed liquidation bonus doesn't exceed available collateral
- [ ] Correct decimal handling for all token precisions
- [ ] No conflicting nonReentrant modifiers in liquidation path
- [ ] Zero value checks before token transfers
- [ ] Handle tokens with deny lists appropriately
- [ ] Auction end timestamp validated correctly (no off-by-one)

### Liquidation Calculations
- [ ] Liquidator rewards correctly calculated with proper decimals
- [ ] Liquidator reward prioritized over other fees
- [ ] Protocol fees don't make liquidation unprofitable
- [ ] Liquidation costs included in minimum collateral requirements
- [ ] Yield and positive PNL included in collateral valuation
- [ ] Swap fees charged during liquidation if applicable
- [ ] Self-liquidation via oracle manipulation prevented

### Fair Liquidation
- [ ] Grace period after L2 sequencer restart
- [ ] Interest doesn't accumulate while protocol paused
- [ ] Repayment and liquidation pause states synchronized
- [ ] All fees updated before liquidation checks
- [ ] Positive PNL/yield credited during liquidation
- [ ] Liquidation improves borrower health score
- [ ] Collateral liquidation follows risk-based priority
- [ ] Position transfers don't misattribute repayments
- [ ] Gap between borrow and liquidation LTV ratios
- [ ] Interest paused during liquidation auctions
- [ ] Liquidators can specify slippage protection

### Slippage Protection
- [ ] User can specify minTokensOut for all swaps
- [ ] User can specify deadline for time-sensitive operations
- [ ] Slippage calculated correctly (not modified)
- [ ] Slippage precision matches output token
- [ ] Hard-coded slippage can be overridden by users
- [ ] Slippage checked on final output amount
- [ ] Slippage calculated off-chain, not on-chain
- [ ] Fee tiers not hardcoded (allow multiple options)
- [ ] Proper deadline validation (not block.timestamp)

### Oracle Security
- [ ] Stale price checks against appropriate heartbeats
- [ ] L2 sequencer uptime checked on L2 deployments
- [ ] Each feed uses its specific heartbeat interval
- [ ] Oracle precision not assumed, uses decimals()
- [ ] Price feed addresses verified correct
- [ ] Oracle calls wrapped in try/catch
- [ ] Depeg monitoring for wrapped assets
- [ ] Min/max price validation implemented
- [ ] TWAP used instead of spot price where appropriate
- [ ] Price direction (quote/base) verified correct
- [ ] Circuit breaker checks for min/maxAnswer

### Concentrated Liquidity
- [ ] TWAP checks in ALL functions that deploy liquidity
- [ ] TWAP parameters have min/max bounds
- [ ] No token accumulation in intermediate contracts
- [ ] Token approvals revoked before router updates
- [ ] Fees collected before fee structure updates

### Reentrancy Protection
- [ ] State changes before external calls (CEI pattern)
- [ ] NonReentrant modifiers on vulnerable functions
- [ ] No assumptions about token transfer behavior
- [ ] Cross-function reentrancy considered
- [ ] Read-only reentrancy risks evaluated

### Token Compatibility
- [ ] Fee-on-transfer tokens handled correctly
- [ ] Rebasing tokens accounted for
- [ ] Tokens with callbacks (ERC777) considered
- [ ] Zero transfer reverting tokens handled
- [ ] Pausable tokens won't brick protocol
- [ ] Token decimals properly scaled
- [ ] Deflationary/inflationary tokens supported

### Access Control
- [ ] Critical functions have appropriate modifiers
- [ ] Two-step ownership transfer implemented
- [ ] Role-based permissions properly segregated
- [ ] Emergency pause functionality included
- [ ] Time delays for critical operations

### Staking Security
- [ ] Reward token cannot be staking token
- [ ] Direct transfers don't affect reward calculations
- [ ] First depositor cannot steal rewards
- [ ] Index updated before reward calculations
- [ ] Minimum stake to prevent rounding exploits
- [ ] Anti-sandwich mechanisms for deposits/withdrawals

### HTLC Cross-Chain Coordination
- [ ] Destination chain timelock expires strictly after source chain
- [ ] Time unit conversions correct (blocks vs slots vs ms)
- [ ] Order ID hashing consistent or properly mapped across chains
- [ ] Events on all chains include sufficient data for off-chain reconstruction
- [ ] Off-chain coordinator enforces "counterpart initiated" before redemption
- [ ] Finality differences accounted for in timelock buffers
- [ ] Chain ID and contract address included in all cross-chain identifiers
- [ ] k-confirmation safety margins on reorg-prone chains
- [ ] BFT threshold assumptions and liveness validated

### HTLC Economic & MEV Security
- [ ] Free option value analyzed for each side of swap
- [ ] Griefing factor computed (attacker cost vs victim cost)
- [ ] Bribery cost vs expected profit from censorship evaluated
- [ ] Multi-hop capital inefficiencies and lock-up durations analyzed
- [ ] Preimage revelation points identified as MEV/front-running risk
- [ ] Sandwich attack resistance on HTLC-triggered DEX interactions
- [ ] Protocol safety does not assume neutral transaction ordering

## Invariant Analysis

### Critical Invariants to Verify

1. **Ownership Invariants**
   - `owner != address(0)` after any ownership operation
   - `pendingOwner != address(0)` implies transfer was initiated

2. **Balance Invariants**
   - `sum(userBalances) == totalSupply`
   - `collateral > 0` when `loanAmount > 0`
   - `totalShares * sharePrice == totalAssets`
   - `tokens in == tokens out + fees` for all operations
   - `sum(allDeposits) - sum(allWithdrawals) == contractBalance`
   - `poolBalance + outstandingLoans == initialDeposit + profits - losses`

3. **HTLC Order Uniqueness Invariants**
   - For all `orderID`, at most one `Order` struct exists and `Initiated(orderID)` emitted at most once before `Redeemed` or `Refunded`
   - For Solana PDA `[b"swap_account", initiator, secret_hash]`, exactly one `SwapAccount` exists and state not overwritten by second `initiate`
   - For Sui `OrdersRegistry`, storing new `Order` with same `order_id` either aborts or preserves original
   - For Starknet, only one `Order` can be created per `(chain_id, secret_hash, initiator_address)` tuple

4. **HTLC Funds Conservation Invariants**
   - EVM: `sum(token balances of HTLC) + sum(unredeemed order amounts) == total deposited - total redeemed - total refunded`
   - Solana: `SwapAccount.amount_lamports + vault PDA lamports == initial deposit` until closure
   - Sui: `Order.coins` fully held in `Order` or fully transferred; at most one terminal state per order
   - Starknet: `token.balanceOf(contract) + sum(unfulfilled Order.amount) == deposits - withdrawals`

5. **HTLC Secret Preimage Invariants**
   - EVM: For all successful `redeem`, enforce `secret.length == 32` and `sha256(secret) == secretHash`
   - Solana: `secret: [u8; 32]` constant length; any flipped bit causes revert
   - Sui: For all `redeem_swap`, require `vector::length(secret) == 32` and SHA256 matches
   - Starknet: `secret.len() == 8` and serialization matches `secret_hash`

6. **HTLC Timelock Monotonicity Invariants**
   - EVM: For any `Order`, `timelock > initiatedAt` and never decreases
   - Solana: `expiry_slot >= current slot at initiate` and never changes until closure
   - Sui: `timelock >= initiated_at` and never moves backward
   - Starknet: `timelock >= initiated_at` and remains constant

7. **HTLC Cross-Chain Completion Invariant**
   - For logical `orderID` representing atomic swap, at most one holds across all chains: "fully redeemed on source", "fully refunded on source", "fully redeemed on destination", "fully refunded on destination"
   - Coordinator tracks events from all chains; no state where both `Redeemed` and `Refunded` for same logical order

8. **HTLC Refund-Only-After-Expiry Invariant**
   - EVM: `block.number >= orders[orderID].timelock` and `fulfilledAt == 0` for successful `refund`
   - Solana: `clock.slot >= expiry_slot` and `SwapAccount` not redeemed
   - Sui: `clock.timestamp_ms >= timelock` and `Order.is_fulfilled == false`
   - Starknet: `get_block_number() >= order.timelock` and `order.is_fulfilled == false`

9. **HTLC Redeem-Only-Before-Expiry Invariant**
   - EVM: `block.number < orders[orderID].timelock` and `fulfilledAt == 0` for successful `redeem`
   - Solana: `clock.slot < expiry_slot` at `redeem`
   - Sui: `clock.timestamp_ms < timelock` on `redeem_swap`
   - Starknet: `get_block_number() < order.timelock` on `redeem`

10. **Signature Invariants**
    - `usedNonces[nonce] == false` before signature verification
    - `block.timestamp <= signature.deadline`
    - `signature.chainId == block.chainid`

11. **Precision Invariants**
    - `scaledAmount >= originalAmount` when scaling up precision
    - `(a * b) / c >= ((a / c) * b)` for same inputs
    - `outputPrecision == expectedPrecision` after calculations
    - `convertedAmount * outputDecimals / inputDecimals == originalAmount` (with rounding consideration)

12. **State Transition Invariants**
    - Valid state transitions only (e.g., PENDING → ACTIVE, never INACTIVE → ACTIVE without PENDING)
    - No partial state updates (all-or-nothing execution)
    - `loanStatus != CLOSED` when `remainingDebt > 0`

13. **Lending Invariants**
    - `canLiquidate == false` when `block.timestamp < nextPaymentDue`
    - `loanStatus != REPAID` when `remainingDebt > 0`
    - `collateralValue >= minCollateralRatio * debtValue` for healthy positions
    - `liquidationThreshold < minCollateralRatio`
    - `sum(allLoans.principal) <= sum(allPools.balance)`
    - `pool.outstandingLoans == sum(loans[pool].debt)` for each pool
    - `loan.lender` must own the pool from which loan was taken
    - `loanRatio <= pool.maxLoanRatio` for all active loans

14. **Liquidation Invariants**
    - `liquidationReward > gasCoast` for all liquidatable positions
    - `positionSize > minPositionSize` after any position modification
    - `collateralBalance > 0` when user has open positions (unless fully covered by PNL)
    - `insuranceFund + collateral >= badDebt` for insolvent positions
    - `healthScoreAfter > healthScoreBefore` after liquidation
    - `sum(allDebt) <= sum(allCollateral) + insuranceFund`
    - `liquidationIncentive <= availableCollateral`
    - `cannotLiquidate` when protocol is paused
    - `noDoubleLiquidation` within same block/cooldown period
    - `auctionStartTime + auctionLength >= block.timestamp` during active auction

15. **Slippage Invariants**
    - `outputAmount >= minOutputAmount` for all swaps
    - `executionTime <= deadline` for time-sensitive operations
    - `finalOutput >= userSpecifiedMinimum`
    - `actualSlippage <= maxSlippageTolerance`

16. **Oracle Invariants**
    - `block.timestamp - updatedAt <= heartbeat`
    - `minAnswer < price < maxAnswer`
    - `sequencerUptime == true` on L2s
    - `priceDiff / price <= maxDeviation` for multi-oracle setup
    - `twapPrice` within deviation of `spotPrice`

17. **CLM Invariants**
    - `tickLower < currentTick < tickUpper` after deployment
    - `sum(distributed fees) + accumulated fees == total fees collected`
    - `token.balanceOf(contract) == 0` for pass-through contracts

18. **Staking Invariants**
    - `sum(stakedBalances) == stakingToken.balanceOf(contract)` (if no direct transfers)
    - `claimableRewards <= rewardToken.balanceOf(contract)`
    - `index_new >= index_old` (monotonically increasing)
    - `userIndex <= globalIndex` for all users
    - `sum(userShares) == totalShares`
    - `rewardPerToken_new >= rewardPerToken_old`

19. **Auction Invariants**
    - `currentPrice <= startPrice` during Dutch auction
    - `currentPrice >= reservePrice` if reserve price set
    - `auctionEndTime > auctionStartTime`
    - `highestBid_new >= highestBid_old + minBidIncrement`
    - `loan.auctionStartTimestamp == type(uint256).max` when not in auction

20. **HTLC Hash Consistency Invariant**
    - For every swap: `∀ i,j: hash_i = hash_j = H(encode(secret))` where `encode` is fully specified and identical across chains
    - Hash function H (SHA256/Keccak/Pedersen) must be identical across all participating chains
    - Preimage encoding (endianness, padding, serialization) must be byte-for-byte identical

21. **HTLC Timelock Ordering Invariant (Multi-Hop)**
    - For multi-hop swaps, every hop's expiry must satisfy: `expiry_downstream < expiry_upstream - (Δ_net + Δ_final + Δ_mev)`
    - Downstream HTLCs (closer to final receiver) have earlier expiries; upstream HTLCs have later expiries

22. **HTLC Single-Resolution Invariant**
    - For any HTLC instance, at most one of {REDEEMED, REFUNDED} is reachable; no double-spend or dual outcomes
    - `redeemedAt > 0` implies `refundedAt == 0` and vice versa

23. **HTLC Finality-Aware Observation Invariant**
    - Protocol atomicity reasoning relies only on events considered final under relevant chain's finality model
    - k-confirmation depth on PoW chains before acting on preimage reveals
    - Economic finality checkpoints on PoS chains before cross-chain actions

24. **HTLC No-Reinitialization Invariant**
    - HTLC instances must not be reinitialized in-place once created; identifiers must be single-use
    - For Solana: `is_initialized` flag prevents re-init; for EVM: storage deletion doesn't enable ID reuse

25. **HTLC Event-State Consistency Invariant**
    - Events emitted (`Redeemed`, `Refunded`) must always match final state; no paths where event emitted but state reverts or diverges
    - Event emission occurs only after successful state transitions

26. **HTLC Secret Non-Leak Invariant**
    - Secret must not be leaked off-chain except via intended redeem transaction
    - Any side-channels or logging of secrets are disallowed; mempool visibility considered public after submission

27. **HTLC Gas/Fee Boundedness Invariant**
    - Redeem and refund paths designed to avoid unbounded gas costs; otherwise attacker can DoS by engineering worst-case execution
    - No unbounded loops over user-controlled data structures in settlement paths

### Invariant Breaking Patterns
- Look for ways to make denominators zero
- Find paths that skip state validation
- Identify precision loss accumulation over multiple operations
- Test boundary conditions (0, max values, equal values)
- Verify invariants hold across all function execution paths
- Check for asymmetries in symmetric operations
- Test state consistency during paused/unpaused transitions
- Verify liquidation cannot create bad debt
- Ensure no profitable self-liquidation paths exist
- Check position health improves post-liquidation
- Test refinancing doesn't break loan accounting
- Verify auction state transitions are consistent
- Ensure reward calculations don't overflow/underflow
- Check that pool updates maintain balance consistency
- **HTLC-Specific**: Test order ID collisions via input manipulation, timelock overflow at `type(uint256).max` or `u64::MAX`, secret length variations, concurrent refund/redeem at exact expiry, PDA re-initialization after closure, cross-chain event replay without chain ID binding
- **HTLC Cross-Chain**: Test hash function mismatches (Keccak vs SHA256 vs Pedersen), endianness differences, ABI encoding vs packed encoding, timelock window misalignment, reorg scenarios on one chain while other settled, L1-L2 messaging delay edge cases

## Code Analysis Approach

The Code Analysis approach combines:
- Deep technical analysis of contract implementations
- Pattern recognition across multiple audit findings
- Proactive vulnerability detection
- Collaborative problem-solving methodology
- **Invariant Analysis (Additional Step)**: After completing the standard vulnerability analysis, ALWAYS perform an additional invariant analysis step - identifying all invariants that shoul
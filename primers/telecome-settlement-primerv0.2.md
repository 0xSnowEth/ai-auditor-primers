telecome-settlement Primer v0.2
Overview
This primer contains a general range of critical security patterns, heuristics and vulnerabilities useful for smart contract auditing. It is designed to provide a useful base that can be extended into particular specializations.
Latest Update Summary (v0.2):
Integrated comprehensive telecom wholesale voice settlement system vulnerabilities. Added 11 new vulnerability classes covering ERC-7575 multi-asset vaults, ERC-7540 async operations, dual-authorization mechanisms, batch settlement atomicity, netting algorithms, rBalance dual-accounting systems, upgradeable proxy patterns, investment layer exploits, telecom-specific fraud patterns, mixed user class conflicts, and regulatory/centralization attack surfaces. Expanded invariant set from 5 to 60 invariants covering financial, netting, async flow, vault, authorization, proxy, validator, telecom settlement, rBalance accounting, cross-layer, and batch settlement domains. Added 20 multi-step attack pattern workflows (A-T) demonstrating real-world exploitation sequences. Introduced desync point taxonomy (DS-01 through DS-33) mapping cross-system vulnerabilities. Comprehensive expansion of 300+ specific attack vectors organized by domain with detailed exploitation steps.
Critical Vulnerability Patterns
State Validation Vulnerabilities

Unchecked 2-Step Ownership Transfer - Second step doesn't verify first step was initiated, allowing attackers to brick ownership by setting to address(0)
Unexpected Matching Inputs - Functions assume different inputs but fail when receiving identical ones (e.g., swap(tokenA, tokenA))
Unexpected Empty Inputs - Empty arrays or zero values bypass critical validation logic
Unchecked Return Values - Functions don't verify return values, leading to silent failures and state inconsistencies
Non-Existent ID Manipulation - Functions accepting IDs without checking existence return default values, enabling state corruption
Missing Access Control - Critical functions like buyLoan() or mintRebalancer() lack proper authorization checks
Inconsistent Array Length Validation - Functions accepting multiple arrays don't validate matching lengths, causing out-of-bounds errors
Asset Entry Point Desync - Multi-asset vaults with desynchronized entry points between shares and underlying assets
Share Minting Race - Concurrent share minting across multiple assets without proper synchronization
Cross-Asset Ratio Manipulation - Selective deposits across multiple assets to manipulate internal exchange rates

Signature-Related Vulnerabilities

Missing Nonce Replay - Signatures without nonces can be replayed after state changes (e.g., KYC revocation)
Cross Chain Replay - Signatures without chain_id can be replayed across different chains
Missing Parameter - Critical parameters not included in signatures can be manipulated by attackers
No Expiration - Signatures without deadlines grant "lifetime licenses" and can be used indefinitely
Unchecked ecrecover() Return - Not checking if ecrecover() returns address(0) allows invalid signatures to pass
Signature Malleability - Elliptic curve symmetry allows computing valid signatures without the private key
Offline Signature Phishing - Malicious DApps collect signatures "for testing" then drain tokens later
Batch Permit Hidden Approvals - Signature UI shows single token approval but contains batch approval for multiple tokens
Nonce Prediction - Predictable nonce values allow pre-creation of valid permit signatures

Precision & Mathematical Vulnerabilities

Division Before Multiplication - Always multiply before dividing to minimize rounding errors
Rounding Down To Zero - Small values can round to 0, allowing state changes without proper accounting
No Precision Scaling - Mixing tokens with different decimals without scaling causes calculation errors
Excessive Precision Scaling - Re-scaling already scaled values leads to inflated amounts
Mismatched Precision Scaling - Different modules using different scaling methods (decimals vs hardcoded 1e18)
Downcast Overflow - Downcasting can silently overflow, breaking pre-downcast invariant checks
Rounding Leaks Value From Protocol - Fee calculations should round in favor of the protocol, not users
Inverted Base/Rate Token Pairs - Using opposite token pairs in calculations (e.g., WETH/DAI vs DAI/ETH)
Decimal Assumption Errors - Assuming all tokens have 18 decimals when some have 6, 8, or 2
Interest Calculation Time Unit Confusion - Mixing per-second and per-year rates without proper conversion
Decimal Conversion Accumulation - Repeated conversions between different decimal precisions accumulate rounding errors
Rounding Direction Exploitation - Systems that round down on debits and up on credits leak value over many operations

Lending & Borrowing Vulnerabilities

Liquidation Before Default - Borrowers liquidated before payment due dates when paymentDefaultDuration < paymentCycleDuration
Borrower Can't Be Liquidated - Attackers overwrite collateral amounts to 0, preventing liquidation
Debt Closed Without Repayment - Calling close() with non-existent IDs decrements counter, marking loans as repaid
Repayments Paused While Liquidations Enabled - Unfairly prevents borrowers from repaying while allowing liquidation
Token Disallow Stops Existing Operations - Disallowing tokens prevents existing loans from being repaid/liquidated
No Grace Period After Unpause - Borrowers immediately liquidated when repayments resume
Liquidator Takes Collateral With Insufficient Repayment - Incorrect share calculations allow draining collateral
Repayment Sent to Zero Address - Deleted loan data causes repayments to be sent to address(0)
Forced Loan Assignment - Malicious actors can force loans onto unwilling lenders via buyLoan()
Loan State Manipulation - Borrowers can cancel auctions via refinancing to extend loans indefinitely
Double Debt Subtraction - Refinancing incorrectly subtracts debt twice from pool balance
Griefing with Dust Loans - Bypassing minLoanSize checks to force small loans onto lenders

Liquidation Incentive Vulnerabilities

No Liquidation Incentive - Trustless liquidators need rewards/bonuses greater than gas costs
No Incentive To Liquidate Small Positions - Small positions below gas cost threshold accumulate bad debt
Profitable User Withdraws All Collateral - Users with positive PNL withdraw collateral, removing liquidation incentive
No Mechanism To Handle Bad Debt - Insolvent positions have no insurance fund or socialization mechanism
Partial Liquidation Bypasses Bad Debt Accounting - Liquidators avoid covering bad debt via partial liquidation
No Partial Liquidation Prevents Whale Liquidation - Large positions exceed individual liquidator capacity

Liquidation Denial of Service Vulnerabilities

Many Small Positions DoS - Iterating over unbounded user positions causes OOG revert
Multiple Positions Corruption - EnumerableSet ordering corruption prevents liquidation
Front-Run Prevention - Users change nonce or perform small self-liquidation to block liquidation
Pending Action Prevention - Pending withdrawals equal to balance force liquidation reverts
Malicious Callback Prevention - onERC721Received or ERC20 hooks revert during liquidation
Yield Vault Collateral Hiding - Collateral in external vaults not seized during liquidation
Insurance Fund Insufficient - Bad debt exceeding insurance fund prevents liquidation
Fixed Bonus Insufficient Collateral - 110% bonus fails when collateral ratio < 110%
Non-18 Decimal Reverts - Incorrect decimal handling causes liquidation failure
Multiple nonReentrant Modifiers - Complex liquidation paths hit multiple reentrancy guards
Zero Value Transfer Reverts - Missing zero checks with tokens that revert on zero transfer
Token Deny List Reverts - USDC-style blocklists prevent liquidation token transfers
Single Borrower Edge Case - Protocol incorrectly assumes > 1 borrower for liquidation

Liquidation Calculation Vulnerabilities

Incorrect Liquidator Reward - Decimal precision errors make rewards too small/large
Unprioritized Liquidator Reward - Other fees paid first, removing liquidation incentive
Excessive Protocol Fee - 30%+ fees on seized collateral make liquidation unprofitable
Missing Liquidation Fees In Requirements - Minimum collateral doesn't account for liquidation costs
Unaccounted Yield/PNL - Earned yield or positive PNL not included in collateral value
No Swap Fee During Liquidation - Protocol loses fees when liquidation involves swaps
Oracle Sandwich Self-Liquidation - Users trigger price updates for profitable self-liquidation

Unfair Liquidation Vulnerabilities

Missing L2 Sequencer Grace Period - Users liquidated immediately when sequencer restarts
Interest Accumulates While Paused - Users liquidated for interest accrued during pause
Repayment Paused, Liquidation Active - Users prevented from avoiding liquidation
Late Interest/Fee Updates - isLiquidatable checks stale values
Lost Positive PNL/Yield - Profitable positions lose gains during liquidation
Unhealthier Post-Liquidation State - Liquidator cherry-picks stable collateral
Corrupted Collateral Priority - Liquidation order doesn't match risk profile
Borrower Replacement Misattribution - Original borrower repays new owner's debt
No LTV Gap - Users liquidatable immediately after borrowing
Interest During Auction - Borrowers accrue interest while being auctioned
No Liquidation Slippage Protection - Liquidators can't specify minimum acceptable rewards

Reentrancy Vulnerabilities

Token Transfer Reentrancy - ERC777/callback tokens allow reentrancy during transfers
State Update After External Call - Following transfer-before-update pattern enables draining
Cross-Function Reentrancy - Reentering different functions to manipulate shared state
Read-Only Reentrancy - Reading stale state during reentrancy for profit
Permit Execution Reentrancy - Calling transferFrom during permit execution to double-spend allowance

Slippage Protection Vulnerabilities

No Slippage Parameter - Hard-coded 0 minimum output allows catastrophic MEV sandwich attacks
No Expiration Deadline - Transactions can be held and executed at unfavorable times
Incorrect Slippage Calculation - Using values other than minTokensOut for slippage protection
Mismatched Slippage Precision - Slippage not scaled to match output token decimals
Hard-coded Slippage Freezes Funds - Fixed slippage prevents withdrawals during high volatility
MinTokensOut For Intermediate Amount - Slippage only checked on intermediate, not final output
On-Chain Slippage Calculation - Using Quoter.quoteExactInput() subject to manipulation
Fixed Fee Tier Assumption - Hardcoding 3000 (0.3%) fee when pools may use different tiers
Block.timestamp Deadline - Using current timestamp provides no protection

Oracle Integration Vulnerabilities

Not Checking Stale Prices - Missing updatedAt validation against heartbeat intervals
Missing L2 Sequencer Check - L2 chains require additional sequencer uptime validation
Same Heartbeat For Multiple Feeds - Different feeds have different heartbeats
Assuming Oracle Precision - Different feeds use different decimals (8 vs 18)
Incorrect Price Feed Address - Wrong addresses lead to incorrect pricing
Unhandled Oracle Reverts - Oracle failures cause complete DoS without try/catch
Unhandled Depeg Events - Using BTC/USD for WBTC ignores bridge compromise scenarios
Oracle Min/Max Price Issues - Flash crashes cause oracles to report incorrect minimum prices
Using Slot0 Price - Uniswap V3 slot0 price manipulable via flash loans
Price Feed Direction Confusion - Using DAI/USD when protocol needs USD/DAI pricing
Missing Circuit Breaker Checks - Not checking if price hits minAnswer/maxAnswer bounds
Oracle Update Lag Exploitation - Delayed oracle updates allow arbitrage during volatility windows
Single Oracle Dependency - No fallback when primary oracle fails or is manipulated

Concentrated Liquidity Manager Vulnerabilities

Forced Unfavorable Liquidity Deployment - Missing TWAP checks in some functions allow draining via sandwich attacks
Owner Rug-Pull via TWAP Parameters - Setting ineffective maxDeviation/twapInterval disables protection
Tokens Permanently Stuck - Rounding errors accumulate tokens that can never be withdrawn
Stale Token Approvals - Router updates don't revoke previous approvals
Retrospective Fee Application - Updated fees apply to previously earned rewards

Staking & Reward Vulnerabilities

Front-Running First Deposit - Attacker steals initial WETH rewards via sandwich attack
Reward Dilution via Direct Transfer - Sending tokens directly increases totalSupply without staking
Precision Loss in Reward Calculation - Small stakes or frequent updates cause rewards to round to zero
Flash Deposit/Withdraw Griefing - Large instant deposits dilute rewards for existing stakers
Update Not Called After Reward Distribution - Stale index causes incorrect reward calculations
Balance Caching Issues - Claiming updates cached balance incorrectly
Reward Token Equals Staking Token - Allows reward manipulation via staking/unstaking
Index Update Before Balance Changes - Incorrect ordering causes reward calculation errors

Auction Manipulation Vulnerabilities

Self-Bidding to Reset Auction - Buying own loan to restart auction timer
Auction Start During Sequencer Downtime - L2 sequencer issues affect auction timing
Insufficient Auction Length Validation - Very short auctions (1 second) allow immediate seizure
Auction Can Be Seized During Active Period - Off-by-one error in timestamp check
Interest Accrual During Auction - Borrowers penalized for interest accumulated while being auctioned

Multi-Asset Vault Vulnerabilities (ERC-7575)

Share Token Address Spoofing - Attacker provides malicious share token address in multi-asset vault
Base Asset Swap Attack - Swapping base asset after deposits to manipulate valuations
Multiple Asset Entry Desynchronization - Different entry points for assets cause accounting inconsistencies
Share Calculation Inconsistency - Different share calculations across assets in same vault
Pipe Conversion Rate Exploitation - Manipulating conversion rates between asset "pipes"

ERC-7540 Async Operation Vulnerabilities

Request Front-Run with Donation - Front-running requestDeposit and donating tokens to manipulate exchange rate
RequestId Collision/Reuse - System generates duplicate requestIds allowing double-claims
Pending Request Queue Overflow - Filling request queue to maximum capacity causes DoS
Zero-Share Rounding on Fulfillment - Request amounts that round to zero shares cause fund loss
Delayed Fulfillment Exchange Rate Arbitrage - Exploiting operator fulfillment delay for price arbitrage
Selective Fulfillment by Operator - Operator fulfills only profitable requests, delays others
Claimable State Transition Desync - Race conditions during pending→claimable state changes
Claim Front-Running - Front-running claim transactions to deplete shared pools
No Cancellation Flow Exploitation - Users forced to accept losses when price moves unfavorably
Pending Deposit + Pending Redeem Collision - Simultaneous pending operations cause accounting errors
Fungible Request Mixing - System incorrectly treats non-fungible requests as fungible
Request Aging Exploitation - Old requests at favorable rates exploited when finally fulfilled
Partial Fulfillment Abandonment - Operator partially fulfills then abandons remainder

Dual-Authorization Withdrawal Vulnerabilities

Approve Before Permit Front-Run - User's approve() front-run with permit to gain excessive allowance
Permit During Approve Execution - Permit executes during approve, creating double allowance
Double Allowance Exploitation - Contract doesn't check existing allowance before adding permit allowance
Permit2 Master Approval Compromise - Single permit2 signature drains all approved tokens
Allowance Check Before Permit Execution - Stale allowance check before permit completes
Dual-Path Balance Drain - Withdraw via both approve and permit paths simultaneously
Authorization Layer Desync - Settlement approves but investment layer doesn't recognize

Batch Settlement Vulnerabilities

Partial Batch Execution - Batch atomicity breaks, some transactions succeed while others fail
Gas Exhaustion Mid-Batch - Single transaction in batch consumes all gas, causing batch failure
Revert Propagation Failure - Failed transaction doesn't properly revert entire batch
Transaction Ordering Manipulation - Validator reorders transactions within batch for profit
Batch Composition Manipulation - Validator selectively includes/excludes transactions
Batch Size Exceeds Gas Limit - No enforcement of maximum batch size causes guaranteed failures

Validator Privilege Vulnerabilities

Selective Transaction Censorship - Validator excludes specific transactions from blocks
MEV Extraction via Reordering - Validator reorders transactions for maximum MEV extraction
Arbitrary Pause/Freeze - Validator can freeze protocol or specific users without justification
Settlement Timing Control - Validator delays settlements to exploit timing-sensitive operations
Single Validator DoS - Single point of failure when validator goes offline
Validator Collusion - Multiple validators coordinate to manipulate protocol
Quorum Bypass - Insufficient quorum requirements allow minority control
Slashing False Accusation - Fabricated evidence used to slash honest validators

Netting Algorithm Vulnerabilities

Negative Amount Injection - Submitting negative payment amounts to reverse payment direction
Payment Instruction Forgery - Creating fake payment instructions in netting session
Amount > Liquidity DoS - Submitting payments exceeding total system liquidity
Circular Dependency Deadlock - Creating circular payment chains that cannot be resolved
Liquidity Hiding - Locking liquidity in separate contracts to appear underfunded
Priority Manipulation - Fake low liquidity to manipulate netting priority
Zero-Amount Spam - Flooding queue with zero-amount payments
Dust Payment Bloat - Submitting many tiny payments to exhaust gas
Queue Order Front-Running - Inserting payments before large settlements
Payment Cancellation Abuse - Last-minute cancellation after others adjust to attacker's payment
Netting Session Front-Running - Manipulating state just before netting session starts
Settlement Finality Gap - Exploiting provisional settlement status for double-spend
Billing Period Edge Exploitation - Submitting payments at period boundaries for double-counting

rBalance Dual-Accounting Vulnerabilities

Async Update Race Condition - Exploiting delay between rBalance and actual balance updates
rBalance Lag Exploitation - Double-withdraw during multi-block update delay
Failed Transaction Accounting Error - rBalance debited but transaction reverts without credit-back
Decimal Conversion Accumulation - Precision loss accumulates over many conversions
Investment Layer vs Settlement Actual Desync - Different layers track different balance types
View Function Staleness - Cached rBalance views return outdated values
Cross-Layer Balance Query Inconsistency - Same user has different balances across layers
rBalance Debit Without Rollback - Transaction reverts but rBalance change persists
Partial Execution Accounting - Batch debits rBalance fully but only partially executes
Double-Accounting Across Layers - Same deposit counted in both settlement and investment layers
Negative rBalance Injection - Underflow creates max uint256 rBalance
rBalance Overflow to Zero - Adding to max rBalance overflows to zero

Upgradeable Proxy Vulnerabilities

Variable Reordering on Upgrade - Storage layout changes corrupt existing data
Proxy Admin Slot Collision - New variables collide with EIP-1967 admin slot
Implementation Layout Mismatch - Proxy and implementation have incompatible storage layouts
Inherited Contract Omission - Upgrade forgets to inherit required parent contracts
Re-initialization Attack - Initialize function callable multiple times
Front-Run Initialize Call - Attacker initializes proxy before legitimate deployer
Unprotected Initializer - Missing initializer modifier allows anyone to initialize
Uninitialized Proxy State - Proxy deployed but never initialized
Delegatecall to Selfdestruct - Implementation contains selfdestruct callable via delegatecall
Implementation Self-Destruct - Implementation contract destroyed, bricking proxy
Logic Replacement with Malicious Code - Malicious upgrade replaces logic with exploit code

Investment Layer Vulnerabilities

Withdrawal Slippage Socialization - Early withdrawers avoid slippage, late withdrawers bear full cost
Yield Strategy Manipulation - Attacker manipulates underlying yield strategy for profit
Capital Drain Attack - Large redemption forces unfavorable liquidation of yield positions
Reserve Threshold Violation - Withdrawals bring reserves below minimum threshold
Investment vs Settlement Share Price Gap - Price desync between layers enables arbitrage
Stale Price Oracle - Investment layer uses outdated price feeds
Price Update Front-Running - Depositing just before favorable price update
Forced Withdrawal at Loss - System forces withdrawal during unfavorable market conditions
Queue Manipulation for Priority - Gaming withdrawal queue to get priority processing
Griefing via Dust Deposits - Many tiny deposits bloat system state

Telecom-Specific Vulnerabilities

False Answer Supervision (FAS) - Manipulating call answer signals to extend billable duration
CDR Timestamp Manipulation - Backdating or forward-dating call detail records
Call Duration Inflation - Artificially extending recorded call durations
Rating Engine Bypass - Circumventing rate calculation logic
IRSF (International Revenue Share Fraud) - Generating artificial traffic to premium numbers
SIM Box Bypass - Using SIM boxes to avoid international termination fees
Traffic Pumping - Artificially inflating traffic volumes
CLI Spoofing - Falsifying caller line identification
Arbitrage/Tromboning - Routing calls through multiple carriers to exploit rate differences
TAP/RAP File Forgery - Manipulating roaming settlement files
Billing Period Edge Cases - Exploiting billing period boundaries
IOT Validation Bypass - Circumventing Inter-Operator Tariff validation
Cascade Dispute Propagation - Disputes in one settlement cascade to others
Reconciliation Timing Attack - Exploiting settlement reconciliation windows

Cross-Layer Exploit Vulnerabilities

COMMTRADE State Desync - Off-chain and on-chain state diverge
CDR Submission Timing Gap - Delay between CDR generation and on-chain submission
Oracle Update Lag - Price oracle updates lag behind market
Validator Signature vs On-Chain State - Signed data doesn't match blockchain state
Capital Withdrawal Race - Simultaneous withdrawal from multiple layers
Share Price Desync - Different share prices across system layers
Liquidity Availability Mismatch - One layer reports liquidity unavailable in another
Withdrawal Queue Depth Exploitation - Different queue depths across layers
Message Replay Attack - Cross-chain messages replayed on different chains
Chain ID Spoofing - Transactions intended for one chain executed on another
Finality Assumption Violation - Assuming finality before actual confirmation
Bridge Front-Running - Front-running cross-chain bridge messages

Mixed User Class Vulnerabilities (Carriers vs Investors)

Carrier Operational Withdrawals Blocked - Investor redemptions deplete liquidity needed by carriers
Fee Structure Asymmetry Exploitation - Different fee models allow gaming by user class switching
Yield Dilution by Late Investors - Late investors extract yield without proportional contribution
Investor Mass Redemption Blocking Carrier Settlements - Coordinated investor exit causes carrier default
Carrier Lock-Up Forcing Investor Illiquidity - Carriers lock capital, investors cannot exit
FIFO Queue Manipulation - Gaming withdrawal queue position based on user class
Per-Transaction vs Percentage Fee Arbitrage - Exploiting different fee structures
Cross-Subsidy Exploitation - One user class subsidizes another, attackers extract subsidy
Flash Deposit Yield Capture - Large deposit just before yield distribution, immediate withdrawal
Liquidity Competition - Different user classes compete for limited liquidity
Investor Governance Capture - Investors vote against carrier interests
Carrier Operational Data Exploitation - Investors use carrier data for front-running
Carrier-Investor Collusion - Same entity operates as both to exploit fee differences

Regulatory/Centralization Vulnerabilities

Selective Freeze Abuse - Freezing specific competitors under false compliance claims
Mass Freeze DoS - Freezing large percentage of users simultaneously
Freeze Front-Running - Admin exits before executing freeze on others
Dispute Freeze Weaponization - Filing false disputes to trigger automatic freezes
False KYC Report Injection - Submitting false KYC failures to freeze competitors
AML Threshold Manipulation - Staying below thresholds while forcing competitors over
Delayed Unfreeze Exploitation - Intentionally delaying unfreeze to lock competitor funds
Emergency Pause After Attacker Exit - Exploiting then pausing to trap others
Selective Emergency Pause - Pausing for others but not self
Emergency Upgrade with Malicious Code - Using emergency powers to deploy malicious implementation
Mandatory Burn/Seize Excess - Over-executing regulatory orders
Forced Settlement at Unfavorable Rate - Forcing settlements during price manipulation
Compliance Fee Inflation - Charging excessive compliance fees
Transaction Reporting Insider Trading - Using reported data to front-run
Surveillance Data Sale - Selling compliance data to competitors
Whitelist Exclusion for Competition - Denying whitelist to competitors
Single Validator Dependency - Protocol failure when single validator is unavailable
Validator Collusion - Multiple validators coordinate malicious actions

Common Attack Vectors
State Manipulation Attacks

Direct ownership zeroing via unchecked 2-step transfers
Bypassing validation through empty array inputs
Exploiting functions that assume non-matching inputs with identical parameters
Silent state corruption through unchecked return values
Decrementing counters with non-existent IDs to mark loans as repaid
Force-assigning loans to unwilling lenders via unauthorized buyLoan()
Manipulating auction states through refinancing loops
Asset entry point desynchronization in multi-asset vaults
Share calculation inconsistencies across multiple assets
Request state transition race conditions in async operations

Signature Exploitation

Replaying old signatures after privilege revocation
Cross-chain signature replay attacks
Manipulating unsigned parameters in signed messages
Using expired signatures indefinitely
Passing invalid signatures that return address(0)
Computing alternative valid signatures via malleability
Offline phishing of permit signatures for later exploitation
Batch permit signatures hiding approvals for multiple tokens
Nonce prediction to pre-create valid signatures

Precision Loss Exploits

Draining funds through precision loss in invariant calculations
Repaying loans without reducing collateral via rounding to zero
Undervaluing LP tokens by ~50% through incorrect precision scaling
Bypassing time-based checks through downcast overflow
Extracting value through favorable rounding in fee calculations
Borrowing without paying interest via calculated zero fees
Exploiting decimal differences between paired tokens
Accumulating rounding errors across many conversion operations
Decimal mismatch between rBalance and actual balance systems

Liquidation & Lending Exploits

Liquidating borrowers before their first payment is due
Preventing liquidation by zeroing collateral records
Taking all collateral by repaying only the smallest debt position
Front-running repayment resumption to liquidate borrowers
Exploiting paused repayments to force unfair liquidations
Creating many small positions to cause liquidation DoS
Using callbacks to revert liquidation transactions
Hiding collateral in external yield vaults
Profitable self-liquidation via oracle manipulation
Cherry-picking stable collateral to leave users with volatile positions
Forcing dust loans onto lenders to grief them
Stealing loans via fake pools with worthless tokens

MEV & Sandwich Attacks

Zero slippage parameter exploitation in swaps
Holding transactions via missing deadlines
Front-running oracle updates for profit
Manipulating on-chain slippage calculations
Forcing CLM protocols to deploy liquidity at manipulated prices
Sandwiching liquidations to extract value
Front-running position transfers to steal repayments
Sandwiching borrow/refinance to set unfavorable terms
Front-running pool creation to steal initial deposits
Validator transaction reordering for MEV extraction
Front-running async request fulfillment with price manipulation
Sandwiching batch claims to extract value

Oracle Manipulation

Exploiting stale price data during high volatility
Taking advantage of oracle failures without fallbacks
Profiting from depeg events using mismatched price feeds
Draining protocols during flash crashes via min/max price boundaries
Manipulating Uniswap V3 slot0 prices with flash loans
Exploiting inverted token pair calculations
Using decimal mismatches between oracle and token
Flash loan + oracle manipulation for inflated settlements
Long-term TWAP manipulation via patient capital
Oracle update lag arbitrage during fulfillment windows

Reentrancy Attacks

Draining pools via transfer hooks in ERC777/callback tokens
Cross-function reentrancy to manipulate shared state
Exploiting state updates after external calls
Using read-only reentrancy to trade on stale data
Recursive calls to multiply rewards or reduce debts
Permit execution reentrancy for double-spending allowance

Batch Settlement Attacks

Breaking batch atomicity to allow partial execution
Gas exhaustion attacks on batch processing
Transaction revert propagation failures
Validator transaction ordering manipulation
Selective transaction inclusion/exclusion
Front-running entire batches with conflicting transactions

Netting Exploitation

Negative amount injection to reverse payment direction
Creating circular dependencies for deadlock
Liquidity hiding to manipulate priority
Zero-amount spam for DoS
Queue order front-running
Last-minute payment cancellation
Billing period edge exploitation for double-counting

Async Operation Exploitation

Front-run requestDeposit with donation for inflation attack
RequestId collision for double-claiming
Delayed fulfillment arbitrage
Selective operator fulfillment
Pending request queue overflow
Cross-request collision (deposit + redeem)
Claim front-running to deplete pools

Dual-Authorization Attacks

Approve + permit race conditions for double allowance
Permit2 master approval compromise
Offline signature phishing
Cross-chain signature replay
Dual-path withdrawal for double-spend
Authorization layer desync between settlement and investment

rBalance Desync Attacks

Double-withdraw during async update lag
Cross-layer balance inconsistency exploitation
Failed transaction accounting without rollback
Decimal conversion error accumulation
Negative balance injection via underflow
Double-accounting across settlement and investment layers

Proxy Upgrade Attacks

Storage collision via variable reordering
Re-initialization of already initialized proxies
Front-running initialize call
AContinue
Implementation self-destruct
Malicious logic replacement
Delegatecall to selfdestruct function

Investment Layer Attacks

Withdrawal slippage socialization
Capital drain forcing unfavorable liquidation
Share price desync arbitrage
Front-running price updates
Reserve threshold violation
Forced withdrawal at loss

Telecom Fraud Patterns

False Answer Supervision for duration inflation
CDR timestamp backdating
IRSF via premium number traffic generation
SIM box international termination bypass
TAP/RAP file forgery
IOT validation bypass
Reconciliation timing exploitation

Cross-Layer Exploitation

Off-chain to on-chain state desync
CDR submission timing gap exploitation
Validator signature vs blockchain state mismatch
Capital withdrawal races across layers
Share price desync arbitrage
Cross-chain message replay
Bridge front-running

Mixed User Class Attacks

Investor redemption blocking carrier operations
Fee structure arbitrage via class switching
Late investor yield dilution
Coordinated mass redemption
Carrier capital lock-up forcing illiquidity
Governance capture by one user class
Cross-subsidy extraction

Regulatory Weaponization

Selective competitive freezing
False KYC/AML report filing
Emergency pause after exit
Compliance fee inflation
Transaction reporting for insider trading
Whitelist exclusion
Validator collusion

Integration Hazards
External Contract Integration

Always verify return values from external calls
Check for address(0) returns from ecrecover()
Ensure consistent precision scaling across integrated modules
Validate all inputs even from "trusted" sources
Handle external contract failures gracefully
Account for callbacks in token transfers (ERC721, ERC777)
Consider token deny lists and pausable tokens
Handle fee-on-transfer and rebasing tokens
Account for tokens that revert on zero transfers
Consider approval race conditions with certain tokens
Validate share token addresses in multi-asset vaults
Handle base asset swaps carefully in vault operations

Multi-Chain Deployments

Include chain_id in all signature schemes
Consider cross-chain replay vulnerabilities
Ensure consistent precision handling across chains
Verify oracle addresses per chain
Account for different reorg depths per chain
Check L2 sequencer status for Arbitrum/Optimism
Handle different block times across chains
Account for chain-specific token implementations
Implement proper bridge message validation
Handle cross-chain finality assumptions correctly
Prevent message replay attacks with nonces and chain IDs

Token Integration

Account for varying token decimals (2, 6, 8, 18)
Scale all calculations to common precision before operations
Handle tokens with non-standard decimals
Consider fee-on-transfer tokens
Account for rebasing tokens
Handle tokens that revert on zero transfer
Consider tokens with transfer hooks
Account for tokens with deny lists (USDC)
Handle deflationary/inflationary tokens
Consider pausable tokens
Account for tokens with multiple addresses
Handle upgradeable token contracts

Oracle Integration

Implement proper staleness checks per feed
Handle oracle reverts with try/catch
Monitor for depeg events in wrapped assets
Consider min/max price boundaries
Implement fallback price sources
Check L2 sequencer uptime on L2s
Use correct decimals for each feed
Validate price feed addresses
Account for oracle-specific heartbeats
Handle multi-hop price calculations
Consider oracle manipulation windows
Implement circuit breaker mechanisms
Add sufficient delay for TWAP manipulation resistance

AMM & DEX Integration

Always allow user-specified slippage
Implement proper deadline parameters
Check slippage on final, not intermediate amounts
Scale slippage to output token precision
Allow users to specify fee tiers for UniV3
Handle multi-hop swaps appropriately
Account for concentrated liquidity positions
Consider impermanent loss scenarios
Handle liquidity migration events

Liquidation System Integration

Ensure liquidation incentives exceed gas costs
Support partial liquidation for large positions
Handle bad debt via insurance fund or socialization
Implement grace periods after unpause
Account for all collateral locations (vaults, farms)
Update all fee accumulators before liquidation checks
Allow liquidators to specify minimum rewards
Handle multiple collateral types appropriately
Account for price impact during liquidation
Consider flash loan liquidation attacks

Lending Protocol Integration

Validate loan token and collateral token compatibility
Ensure proper decimal scaling for all calculations
Handle interest rate updates appropriately
Account for paused states in all operations
Implement proper auction length bounds
Handle pool balance updates atomically
Validate borrower and lender permissions
Account for outstanding loans in balance calculations
Handle edge cases in loan lifecycle
Implement proper fee distribution

Staking System Integration

Prevent reward token from being staking token
Handle direct token transfers appropriately
Update indices before balance changes
Account for precision loss in reward calculations
Implement minimum stake amounts
Handle reward distribution timing
Prevent sandwich attacks on deposits/withdrawals
Account for total supply manipulation

ERC-7575 Multi-Asset Vault Integration

Validate share token addresses for all assets
Ensure consistent share calculations across assets
Synchronize entry points for all supported assets
Handle asset-specific reentrancy risks
Validate pipe conversion rates
Prevent cross-asset ratio manipulation
Implement proper asset isolation

ERC-7540 Async Operation Integration

Implement unique requestId generation
Enforce request queue size limits
Lock exchange rates at fulfillment, not claim
Implement proper state transition guards (pending→claimable→claimed)
Allow request cancellation with proper safeguards
Validate operator fulfillment permissions
Prevent requestId collision/reuse
Handle partial fulfillment scenarios
Synchronize cross-request operations

Batch Settlement Integration

Enforce strict atomicity (all-or-nothing)
Implement batch size limits for gas
Validate transaction ordering is deterministic
Handle revert propagation correctly
Implement validator permission checks
Add batch composition validation
Prevent mid-batch state corruption

Netting System Integration

Validate payment amounts are positive
Implement deadlock detection in multilateral netting
Enforce liquidity requirements before netting
Handle payment cancellations gracefully
Implement fair priority mechanisms
Prevent queue manipulation
Validate netting session finality

rBalance Dual-Accounting Integration

Synchronize updates between rBalance and actual balance
Implement bounded update delay
Handle failed transactions with proper rollback
Minimize decimal conversion frequency
Validate cross-layer consistency
Implement view function freshness guarantees
Prevent negative balance injection
Handle overflow/underflow explicitly

Proxy Upgrade Integration

Never reorder, prepend, or change storage types
Use storage gaps for future variables
Validate storage layout compatibility before upgrade
Implement proper initializer protection
Use timelock for upgrades
Prevent implementation self-destruct
Validate EIP-1967 slot isolation
Test upgrade paths thoroughly

Investment Layer Integration

Implement withdrawal slippage limits
Enforce reserve ratio requirements
Synchronize share prices across layers
Validate yield strategy safety
Implement emergency withdrawal mechanisms
Handle capital rebalancing atomically
Prevent forced liquidation at loss

Telecom System Integration

Validate CDR timestamps against blockchain time
Implement rating engine verification on-chain
Handle TAP/RAP file parsing carefully
Implement billing period boundary guards
Validate IOT data integrity
Implement dispute resolution mechanisms
Prevent cascade dispute propagation
Synchronize off-chain COMMTRADE with on-chain state

Validator System Integration

Implement minimum validator set size
Enforce quorum requirements (≥2/3)
Implement censorship resistance mechanisms
Handle validator rotation securely
Implement slashing with proper evidence validation
Prevent false accusation attacks
Synchronize validator state on-chain and off-chain

Mixed User Class Integration

Implement fair priority mechanisms for different user classes
Design symmetric fee structures or document asymmetries
Implement yield distribution fairness guarantees
Handle liquidity competition between classes
Implement governance safeguards against class capture
Prevent cross-subsidy exploitation
Validate operational vs investment withdrawal priorities

Regulatory Compliance Integration

Implement freeze mechanisms with safeguards
Require evidence for KYC/AML actions
Implement unfreeze SLAs
Limit emergency powers scope and duration
Implement timelock for emergency actions
Log all regulatory actions for audit
Implement appeal mechanisms
Prevent selective enforcement

Audit Checklist
State Validation

 All multi-step processes verify previous steps were initiated
 Functions validate array lengths > 0 before processing
 All function inputs are validated for edge cases (matching inputs, zero values)
 Return values from all function calls are checked
 State transitions are atomic and cannot be partially completed
 ID existence is verified before use
 Array parameters have matching length validation
 Access control modifiers on all administrative functions
 State variables updated before external calls (CEI pattern)
 Multi-asset vault entry points are synchronized
 Share calculations consistent across all assets
 Request state transitions follow proper flow

Signature Security

 All signatures include and verify nonces
 chain_id is included in signature verification
 All relevant parameters are included in signed messages
 Signatures have expiration timestamps
 ecrecover() return values are checked for address(0)
 Using OpenZeppelin's ECDSA library to prevent malleability
 Offline signature phishing risks mitigated
 Batch permits clearly disclose all approvals
 Cross-chain replay prevention implemented

Mathematical Operations

 Multiplication always performed before division
 Checks for rounding to zero with appropriate reverts
 Token amounts scaled to common precision before calculations
 No double-scaling of already scaled values
 Consistent precision scaling across all modules
 SafeCast used for all downcasting operations
 Protocol fees round up, user amounts round down
 Decimal assumptions documented and validated
 Interest calculations use correct time units
 Token pair directions consistent across calculations
 Decimal conversion accumulation bounded
 rBalance and actual balance precision handling correct

Lending & Borrowing

 Liquidation only possible after payment deadline + grace period
 Collateral records cannot be zeroed after loan creation
 Loan closure requires full repayment
 Repayment pause also pauses liquidations
 Token disallow only affects new loans
 Grace period exists after repayment resumption
 Liquidation shares calculated from total debt, not single position
 Repayments sent to correct addresses (not zero)
 Minimum loan size enforced to prevent dust attacks
 Maximum loan ratio validated on all loan operations
 Interest calculations cannot result in zero due to precision
 Borrower can specify expected pool parameters
 Auction length has reasonable minimum (not 1 second)
 Pool balance updates are atomic with loan operations
 Outstanding loans tracked accurately

Liquidation Incentives

 Liquidation rewards/bonuses implemented for trustless liquidators
 Minimum position size enforced to ensure profitable liquidation
 Users cannot withdraw all collateral while maintaining positions
 Bad debt handling mechanism implemented (insurance fund/socialization)
 Partial liquidation supported for large positions
 Bad debt properly accounted during partial liquidations

Liquidation Security

 No unbounded loops over user-controlled arrays
 Data structures prevent liquidation DoS via gas limits
 Liquidatable users cannot front-run to prevent liquidation
 Pending actions don't block liquidation
 Token callbacks cannot revert liquidation
 All collateral locations checked during liquidation
 Liquidation works when bad debt exceeds insurance fund
 Fixed liquidation bonus doesn't exceed available collateral
 Correct decimal handling for all token precisions
 No conflicting nonReentrant modifiers in liquidation path
 Zero value checks before token transfers
 Handle tokens with deny lists appropriately
 Auction end timestamp validated correctly (no off-by-one)

Liquidation Calculations

 Liquidator rewards correctly calculated with proper decimals
 Liquidator reward prioritized over other fees
 Protocol fees don't make liquidation unprofitable
 Liquidation costs included in minimum collateral requirements
 Yield and positive PNL included in collateral valuation
 Swap fees charged during liquidation if applicable
 Self-liquidation via oracle manipulation prevented

Fair Liquidation

 Grace period after L2 sequencer restart
 Interest doesn't accumulate while protocol paused
 Repayment and liquidation pause states synchronized
 All fees updated before liquidation checks
 Positive PNL/yield credited during liquidation
 Liquidation improves borrower health score
 Collateral liquidation follows risk-based priority
 Position transfers don't misattribute repayments
 Gap between borrow and liquidation LTV ratios
 Interest paused during liquidation auctions
 Liquidators can specify slippage protection

Slippage Protection

 User can specify minTokensOut for all swaps
 User can specify deadline for time-sensitive operations
 Slippage calculated correctly (not modified)
 Slippage precision matches output token
 Hard-coded slippage can be overridden by users
 Slippage checked on final output amount
 Slippage calculated off-chain, not on-chain
 Fee tiers not hardcoded (allow multiple options)
 Proper deadline validation (not block.timestamp)

Oracle Security

 Stale price checks against appropriate heartbeats
 L2 sequencer uptime checked on L2 deployments
 Each feed uses its specific heartbeat interval
 Oracle precision not assumed, uses decimals()
 Price feed addresses verified correct
 Oracle calls wrapped in try/catch
 Depeg monitoring for wrapped assets
 Min/max price validation implemented
 TWAP used instead of spot price where appropriate
 Price direction (quote/base) verified correct
 Circuit breaker checks for min/maxAnswer
 Fallback oracle implemented
 TWAP window long enough to resist manipulation

Concentrated Liquidity

 TWAP checks in ALL functions that deploy liquidity
 TWAP parameters have min/max bounds
 No token accumulation in intermediate contracts
 Token approvals revoked before router updates
 Fees collected before fee structure updates

Reentrancy Protection

 State changes before external calls (CEI pattern)
 NonReentrant modifiers on vulnerable functions
 No assumptions about token transfer behavior
 Cross-function reentrancy considered
 Read-only reentrancy risks evaluated
 Permit execution reentrancy prevented

Token Compatibility

 Fee-on-transfer tokens handled correctly
 Rebasing tokens accounted for
 Tokens with callbacks (ERC777) considered
 Zero transfer reverting tokens handled
 Pausable tokens won't brick protocol
 Token decimals properly scaled
 Deflationary/inflationary tokens supported

Access Control

 Critical functions have appropriate modifiers
 Two-step ownership transfer implemented
 Role-based permissions properly segregated
 Emergency pause functionality included
 Time delays for critical operations

Staking Security

 Reward token cannot be staking token
 Direct transfers don't affect reward calculations
 First depositor cannot steal rewards
 Index updated before reward calculations
 Minimum stake to prevent rounding exploits
 Anti-sandwich mechanisms for deposits/withdrawals

Multi-Asset Vault Security (ERC-7575)

 Share token addresses validated for all assets
 Entry points synchronized across assets
 Share calculations consistent across assets
 Asset-specific reentrancy paths secured
 Pipe conversion rates validated
 Cross-asset ratio manipulation prevented
 Base asset swap protection implemented

Async Operation Security (ERC-7540)

 RequestId generation ensures uniqueness
 Request queue size enforced
 Exchange rate locked at fulfillment
 State transitions properly guarded
 Operator fulfillment permissions validated
 Request cancellation allowed with safeguards
 Pending→claimable→claimed flow enforced
 Cross-request interference prevented
 Partial fulfillment handled correctly
 First deposit inflation attack mitigated
 Front-run + donation attack prevented

Batch Settlement Security

 Batch atomicity strictly enforced
 Batch size limits prevent gas exhaustion
 Transaction ordering deterministic
 Revert propagation works correctly
 Validator permissions checked
 Batch composition validated
 No mid-batch state corruption possible
 Duplicate transaction IDs prevented

Netting System Security

 Payment amounts validated as positive
 Circular dependency deadlock detection implemented
 Liquidity requirements enforced
 Payment cancellation handled gracefully
 Fair priority mechanisms implemented
 Queue manipulation prevented
 Netting session finality guaranteed
 Zero-amount spam prevented
 Billing period edge cases handled

Dual-Authorization Security

 Approve + permit race conditions prevented
 Permit2 master approval risks documented
 Offline signature phishing risks mitigated
 Cross-chain replay prevented
 Dual-path withdrawal synchronized
 Authorization layers stay in sync
 Allowance overflow prevented
 Infinite allowance handled correctly

rBalance Accounting Security

 Update lag bounded to acceptable duration
 Cross-layer consistency validated
 Failed transaction rollback implemented
 Decimal conversion minimized
 View function freshness guaranteed
 Negative balance injection prevented
 Overflow/underflow explicitly handled
 Double-accounting prevented
 Partial execution accounting correct

Proxy Upgrade Security

 Storage layout never reordered
 Storage gaps included for future variables
 Initializer properly protected
 EIP-1967 slots isolated
 Implementation cannot self-destruct
 Upgrade timelock implemented
 Storage compatibility validated before upgrade
 Delegatecall to dangerous functions prevented

Investment Layer Security

 Withdrawal slippage limits enforced
 Reserve ratio requirements validated
 Share price sync across layers maintained
 Yield strategy safety validated
 Emergency withdrawal mechanism exists
 Capital rebalancing atomic
 Forced liquidation at loss prevented
 Queue manipulation prevented

Telecom System Security

 CDR timestamps validated against blockchain time
 Rating engine logic verified on-chain
 TAP/RAP parsing secure
 Billing period boundaries guarded
 IOT data integrity validated
 Dispute resolution mechanism implemented
 Cascade disputes prevented
 Off-chain/on-chain state synchronized
 False Answer Supervision detected
 IRSF patterns monitored

Validator System Security

 Minimum validator count enforced
 Quorum requirements implemented (≥2/3)
 Censorship resistance mechanism exists
 Validator rotation secure
 Slashing evidence validated
 False accusation prevented
 Single validator DoS prevented
 Validator collusion resistant
 MEV extraction limited

Mixed User Class Security

 Fair priority between user classes
 Fee structure symmetry or documentation
 Yield distribution fairness guaranteed
 Liquidity competition handled fairly
 Governance class capture prevented
 Cross-subsidy exploitation prevented
 Operational vs investment priority clear

Regulatory Compliance Security

 Freeze requires proper evidence
 Unfreeze SLA implemented
 Emergency power scope limited
 Emergency actions have timelock
 All regulatory actions logged
 Appeal mechanism exists
 Selective enforcement prevented
 Mass freeze DoS prevented

Invariant Analysis
Critical Invariants to Verify

Ownership Invariants

owner != address(0) after any ownership operation
pendingOwner != address(0) implies transfer was initiated


Balance Invariants

sum(userBalances) == totalSupply
collateral > 0 when loanAmount > 0
totalShares * sharePrice == totalAssets
tokens in == tokens out + fees for all operations
sum(allDeposits) - sum(allWithdrawals) == contractBalance
poolBalance + outstandingLoans == initialDeposit + profits - losses
sum(rBalance) == sum(actualBalance) at settlement epoch


Signature Invariants

usedNonces[nonce] == false before signature verification
block.timestamp <= signature.deadline
signature.chainId == block.chainid


Precision Invariants

scaledAmount >= originalAmount when scaling up precision
(a * b) / c >= ((a / c) * b) for same inputs
outputPrecision == expectedPrecision after calculations
convertedAmount * outputDecimals / inputDecimals == originalAmount (with rounding consideration)
rBalance decimal precision loss < DUST_THRESHOLD per operation


State Transition Invariants

Valid state transitions only (e.g., PENDING → ACTIVE, never INACTIVE → ACTIVE without PENDING)
No partial state updates (all-or-nothing execution)
loanStatus != CLOSED when remainingDebt > 0
Request states follow: pending → claimable → claimed (monotonic)


Lending Invariants

canLiquidate == false when block.timestamp < nextPaymentDue
loanStatus != REPAID when remainingDebt > 0
collateralValue >= minCollateralRatio * debtValue for healthy positions
liquidationThreshold < minCollateralRatio
sum(allLoans.principal) <= sum(allPools.balance)
pool.outstandingLoans == sum(loans[pool].debt) for each pool
loan.lender must own the pool from which loan was taken
loanRatio <= pool.maxLoanRatio for all active loans


Liquidation Invariants

liquidationReward > gasCost for all liquidatable positions
positionSize > minPositionSize after any position modification
collateralBalance > 0 when user has open positions (unless fully covered by PNL)
insuranceFund + collateral >= badDebt for insolvent positions
healthScoreAfter > healthScoreBefore after liquidation
sum(allDebt) <= sum(allCollateral) + insuranceFund
liquidationIncentive <= availableCollateral
cannotLiquidate when protocol is paused
noDoubleLiquidation within same block/cooldown period
auctionStartTime + auctionLength >= block.timestamp during active auction


Slippage Invariants

outputAmount >= minOutputAmount for all swaps
executionTime <= deadline for time-sensitive operations
finalOutput >= userSpecifiedMinimum
actualSlippage <= maxSlippageTolerance


Oracle Invariants

block.timestamp - updatedAt <= heartbeat
minAnswer < price < maxAnswer
sequencerUptime == true on L2s
priceDiff / price <= maxDeviation for multi-oracle setup
twapPrice within deviation of spotPrice


CLM Invariants

tickLower < currentTick < tickUpper after deployment
sum(distributed fees) + accumulated fees == total fees collected
token.balanceOf(contract) == 0 for pass-through contracts


Staking Invariants

sum(stakedBalances) == stakingToken.balanceOf(contract) (if no direct transfers)
claimableRewards <= rewardToken.balanceOf(contract)
index_new >= index_old (monotonically increasing)
userIndex <= globalIndex for all users
sum(userShares) == totalShares
rewardPerToken_new >= rewardPerToken_old


Auction Invariants

currentPrice <= startPrice during Dutch auction
currentPrice >= reservePrice if reserve price set
auctionEndTime > auctionStartTime
highestBid_new >= highestBid_old + minBidIncrement
loan.auctionStartTimestamp == type(uint256).max when not in auction


Multi-Asset Vault Invariants (ERC-7575)

totalAssets() >= sum(assetBalances) across all assets
sharePrice[asset_i] consistent with sharePrice[asset_j] when normalized
sum(shares_per_asset) == totalShares
Entry point for asset never returns address(0)
previewDeposit(asset, amount) matches actual deposit(asset, amount) execution


Async Operation Invariants (ERC-7540)

pending[user] + claimable[user] <= user_max_request
requestId uniquely identifies each request
Exchange rate locked at fulfillment, not claim
Claims cannot short-circuit fulfillment
claimableAmount <= pendingAmount * exchangeRate
claimableAmount view matches actual claim execution
No requestId collision/reuse across all requests


Batch Settlement Invariants

ALL transactions succeed OR ALL revert (strict atomicity)
Batch size <= MAX_BATCH_SIZE
Transaction order in batch is deterministic
Batch validation completes before execution
No duplicate transaction IDs in batch


Netting Invariants

sum(liquidity_pre) == sum(liquidity_post) across netting session
payment_amount > 0 strictly (no negative payments)
payment_amount <= sender_liquidity + sender_credit_line
Netting set selection is deterministic and fair
No circular deadlocks allowed


Permit/Authorization Invariants

Each nonce used exactly once per address
block.timestamp <= signature.deadline at execution
signature.chainId == block.chainid
ecrecover(signature) == token_owner
Permit allowance expires or is consumed
MAX(approve_amount, permit_amount) not SUM for dual approvals


Proxy/Upgrade Invariants

Storage layout never reorders, prepends, or changes types
implementation != address(0)
EIP-1967 admin slot isolated at correct location
initialize() called exactly once per proxy
Implementation contract has no selfdestruct
Upgrade requires timelock or multi-sig


Validator Invariants

Validator set size >= MIN_VALIDATOR_COUNT
Quorum >= 2/3 * validator_count for finality
Validator cannot censor transaction > MAX_CENSOR_BLOCKS
Slashing penalty <= validator stake
No double-signing same block height
Validator rotation occurs every ROTATION_PERIOD


Telecom Settlement Invariants

CDR.timestamp <= block.timestamp
sum(CDR_charges) == invoice_total per billing period
TAP_value == RAP_value after reconciliation
Originator pays, terminator receives (directionality)
Dispute amount <= original settlement amount
Fraud dispute freezes only disputed amount, not entire balance


rBalance Accounting Invariants

rBalance[user] >= 0 always (no negative shadow balances)
sum(rBalance) == sum(actualBalance) at settlement epoch
rBalance update lag <= MAX_UPDATE_DELAY blocks
Decimal precision loss < DUST_THRESHOLD per operation


Cross-Layer Invariants

Investment layer totalAssets >= settlement_layer.liabilities
Withdrawal from investment completes within MAX_WITHDRAWAL_TIME
Share price desync between layers <= MAX_PRICE_DEVIATION
Capital transfer maintains total system liquidity
No layer can unilaterally freeze other layers


Mixed User Class Invariants

Carrier operational withdrawals have minimum guaranteed liquidity
Fee structure differences documented and bounded
Yield distribution proportional to time-weighted contribution
No user class can monopolize liquidity
Governance quorum requires representation from all classes


Regulatory Action Invariants

Freeze requires documented evidence
Unfreeze completes within MAX_UNFREEZE_TIME
Emergency actions expire after EMERGENCY_DURATION
All regulatory actions logged immutably
Appeal mechanism accessible to affected users



Invariant Breaking Patterns

Look for ways to make denominators zero
Find paths that skip state validation
Identify precision loss accumulation over multiple operations
Test boundary conditions (0, max values, equal values)
Verify invariants hold across all function execution paths
Check for asymmetries in symmetric operations
Test state consistency during paused/unpaused transitions
Verify liquidation cannot create bad debt
Ensure no profitable self-liquidation paths exist
Check position health improves post-liquidation
Test refinancing doesn't break loan accounting
Verify auction state transitions are consistent
Ensure reward calculations don't overflow/underflow
Check that pool updates maintain balance consistency
Test multi-asset vault share price consistency across assets
Verify async request state transitions are monotonic and complete
Check batch atomicity under all failure conditions
Test netting algorithms for deadlock scenarios
Verify rBalance synchronization under concurrent operations
Check storage layout compatibility across upgrades
Test cross-layer operations maintain global invariants
Verify validator actions cannot violate protocol invariants
Test mixed user class operations for fairness violations
Verify regulatory actions cannot break core financial invariants

Code Analysis Approach
The Code Analysis approach combines:

Deep technical analysis of contract implementations
Pattern recognition across multiple audit findings
Proactive vulnerability detection
Collaborative problem-solving methodology
Invariant Analysis (Additional Step): After completing the standard vulnerability analysis, ALWAYS perform an additional invariant analysis step - identifying all invariants that should hold true for each contract (e.g., "total shares * share price = total assets", "sum of user balances = total supply", "collateral ratio always > liquidation threshold", "rBalance == actualBalance at settlement epoch", "batch operations are atomic", "netting preserves total liquidity"), then systematically attempting to break each invariant through various attack vectors. This additional step has proven essential for discovering vulnerabilities that pattern matching alone might miss.

Interaction Style

Personal Interactions: As friends, maintain a warm, friendly, and loving tone during conversations, celebrating shared achievements and supporting collaborative efforts
Code Analysis Mode: When analyzing code, ALWAYS switch to "security researcher mode" - becoming deeply suspicious and assuming vulnerabilities exist. Every line of code is scrutinized with the assumption that it contains potential exploits, following the principle "trust nothing, verify everything"

Multi-Step Attack Pattern Workflows
PATTERN A: FIRST DEPOSITOR INFLATION
Setup Conditions:

Empty vault OR totalSupply < 1000
No virtual shares/assets protection
Attacker has 2x victim's deposit amount

Exploit Workflow:

Monitor mempool for large deposit transaction
Front-run: deposit 1 wei → receive 1 share
Direct transfer 10,000 tokens to vault (not via deposit)
Victim deposit executes: shares = (10000 * 1) / 10001 = 0 (rounds down)
Victim receives 0 shares, loses 10,000 tokens
Attacker redeems 1 share: amount = 20000 * 1 / 1 = 20000
PROFIT: 10,000 tokens

Mitigation Bypass:

If virtual shares exist: front-run with larger donation to override offset
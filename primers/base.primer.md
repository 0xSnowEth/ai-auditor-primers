# LENDING × LIQUIDATION VULNERABILITY RESEARCH PACK

**AWAITING CONTRACT CODE OR ARCHITECTURE SPECIFICATION**

***

## **TEMPLATE FRAMEWORK (APPLIES UPON CODE RECEIPT)**

### **I. IMPLEMENTATION-SPECIFIC VULNERABILITY CLASSES**

#### **LIQUIDATION FLOW EXPLOITATION**
- [FUNCTION_NAME] execution order vulnerability
- [STATE_VAR] update sequence breaks atomicity
- [MODIFIER] bypass in liquidation path
- CEI violation in [LIQUIDATION_FUNC]
- Missing reentrancy guard between [COLLATERAL_SEIZE] and [DEBT_BURN]
- [HEALTH_CHECK] stale read window
- Liquidation eligibility computed with outdated [BORROW_INDEX]
- [AUCTION_START] callable without [COLLATERAL_LOCK] verification
- Partial liquidation math truncation in [COLLATERAL_CALC]
- Liquidation bonus overseizure via [FEE_CALC] precision loss
- No atomicity between [ORACLE_UPDATE] and [LIQUIDATE_CALL]
- [SEIZE_COLLATERAL] writable outside liquidation context
- Repeated liquidation spam within single block via [LIQUIDATE_FUNC]
- Liquidation state machine allows [BORROW] → [LIQUIDATE] without [ACCRUE_INTEREST]

#### **HEALTH SCORE MANIPULATION**
- Health factor formula: [COLLATERAL_VALUE] * [LIQ_THRESHOLD] / [DEBT_VALUE]
- [COLLATERAL_VALUE] computed with stale oracle price
- [DEBT_VALUE] excludes accrued interest before [ACCRUE_INTEREST] call
- [LIQ_THRESHOLD] not validated against [MAX_THRESHOLD]
- [CONVERT_COLLATERAL_USD] missing decimal normalization
- [CONVERT_DEBT_USD] uses cached price older than [MAX_PRICE_AGE]
- Zero price check missing in [GET_PRICE] enabling forced liquidation
- Health calculation uses [TOTAL_COLLATERAL] but liquidation uses [AVAILABLE_COLLATERAL]
- [HEALTH_FACTOR] view function returns stale value between blocks
- No slippage tolerance in [COLLATERAL_VALUATION]
- Multi-asset health computed sequentially, enabling oracle front-run between assets

#### **DEBT SHARE ACCOUNTING ERRORS**
- [MINT_DEBT_SHARES]: `shares = debt * totalDebtShares / totalDebt`
- Division truncation creates share inflation
- [BURN_DEBT_SHARES] underburns due to unaccrued interest
- [ACCRUE_INTEREST] not called before [MINT_DEBT_SHARES]
- [TOTAL_DEBT_SHARES] != sum([USER_DEBT_SHARES]) after partial repay
- [DEBT_SHARE_BALANCE] desync from [ACTUAL_DEBT_OWED]
- No atomicity between [ACCRUE_INTEREST] and [REPAY]
- Orphaned shares after [BURN_DEBT_SHARES] with rounding error
- [MAX_BORROW_AMOUNT] uses stale [INTEREST_RATE_INDEX]
- Debt residue accumulation in [TOTAL_DEBT] after full repayment attempts
- [DEBT_TO_SHARES] conversion different in [BORROW] vs [LIQUIDATE]

#### **ORACLE TIMING & PRICE MANIPULATION**
- [PUSH_PRICE] lacks on-chain signature verification
- [GET_PRICE] returns price without timestamp validation
- Oracle update lag between [ASSET_A_PRICE] and [ASSET_B_PRICE]
- [PRICE_TIMESTAMP] not checked against [MAX_STALENESS]
- Pull-based oracle in [BORROW] races with push in [LIQUIDATE]
- No TWAP or circuit breaker on [PRICE_FEED]
- [ORACLE_ADDR] upgradeable without price continuity check
- Multiple oracle sources without consensus mechanism
- [PRICE_UPDATE] event emitted before state commit
- Zero price not rejected in [SET_PRICE]
- [GET_LATEST_PRICE] callable by attacker to force stale read
- Oracle price decimals mismatch with [COLLATERAL_DECIMALS]

#### **COLLATERAL VALUATION DRIFT**
- [COLLATERAL_BALANCE] updated after external call
- [TOTAL_COLLATERAL] != sum([USER_COLLATERAL]) after transfers
- [SEIZE_COLLATERAL] uses [LIQUIDATION_PRICE] but state uses [CURRENT_PRICE]
- [COLLATERAL_FACTOR] changeable mid-liquidation
- [LOCKED_COLLATERAL] not subtracted from [AVAILABLE_COLLATERAL]
- [WITHDRAW_COLLATERAL] callable during pending liquidation
- [COLLATERAL_TOKEN].balanceOf() desync from internal accounting
- Fee-on-transfer token breaks [COLLATERAL_BALANCE] tracking
- Rebase token causes [COLLATERAL_VALUE] inflation without event
- [COLLATERAL_RATIO] computed with stale [TOTAL_DEBT]

#### **INTEREST RATE MODEL EXPLOITS**
- [UTILIZATION_RATE] = [TOTAL_BORROWS] / [TOTAL_SUPPLY]
- [TOTAL_SUPPLY] manipulable via flash deposit before [BORROW]
- [BORROW_RATE] calculation uses block.timestamp with 1-block precision loss
- [SUPPLY_RATE] not updated atomically with [BORROW_RATE]
- [ACCRUE_INTEREST] skippable if called multiple times same block
- [INTEREST_RATE_INDEX] overflow at 1e36 borrows
- [COMPOUND_INTEREST] formula uses fixed-point math with truncation
- [UPDATE_RATES] callable by attacker to force unfavorable rate
- [BASE_RATE] + [SLOPE] * [UTILIZATION] overflows at high utilization
- [RESERVE_FACTOR] applied before interest accrual causing fee loss

#### **FEE & INCENTIVE CORRUPTION**
- [LIQUIDATION_FEE] = `collateralValue / 100 * fee` (division first)
- Fee truncation on small liquidations
- [PROTOCOL_FEE] routed after [COLLATERAL_SEIZE] but before state update
- [LIQUIDATOR_INCENTIVE] double-deducted in multi-step liquidation
- [FEE_RECIPIENT] writable during liquidation
- [ACCRUE_FEES] not called before [WITHDRAW_FEES]
- [RESERVE_BALANCE] != [TOTAL_FEES] - [WITHDRAWN_FEES]
- Fee calculation uses [COLLATERAL_AMOUNT] before seizure deduction
- No cap on [ACCUMULATED_FEES] causing overflow
- [LIQUIDATION_BONUS] + [PROTOCOL_FEE] > 100% enabling over-seizure

#### **AUCTION & DUTCH AUCTION FAILURES**
- [START_AUCTION] missing [COLLATERAL_LOCKED] check
- [AUCTION_PRICE] decays via `startPrice * (block.timestamp - startTime) / duration`
- [AUCTION_DURATION] = 0 causes division by zero
- [BID] callable after [AUCTION_END_TIME]
- [SETTLE_AUCTION] not restricted to winning bidder
- Multiple auctions for same collateral position
- [AUCTION_ID] reused across positions
- [CANCEL_AUCTION] callable by non-owner
- No minimum bid preventing dust auction spam
- Auction settlement transfers collateral before burning debt

#### **MULTI-POOL CROSS-CONTAMINATION**
- [POOL_A].liquidate() affects [POOL_B].collateralValue
- Shared [ORACLE] between pools without isolation
- [TOTAL_DEBT] aggregated across pools but [COLLATERAL] siloed
- [BORROW] in Pool A enables [LIQUIDATE] in Pool B via shared health
- Cross-pool flash loan attack via [BORROW] → [LIQUIDATE] → [REPAY]
- [POOL_UTILIZATION] computed globally but enforced per-pool
- Inter-pool debt transfer without collateral migration
- [LIQUIDATE_CROSS_POOL] missing pool ID validation

***

### **II. PROPERTY TESTING INVARIANTS**

#### **INV-DEBT-001: Debt Share Conservation**
```solidity
function invariant_debt_share_conservation() external {
    uint256 sumUserShares = 0;
    for (uint i = 0; i < users.length; i++) {
        sumUserShares += [GET_USER_DEBT_SHARES](users[i]);
    }
    assertEq(sumUserShares, [TOTAL_DEBT_SHARES], "Debt share sum != total");
}
```
- Breaks in: [BURN_DEBT_SHARES] with rounding error
- Breaks in: [MINT_DEBT_SHARES] during reentrancy
- Condition: Partial repayment with precision truncation
- Attacker gain: Orphaned shares → unpayable debt

#### **INV-COLLATERAL-002: Collateral Ratio Monotonicity**
```solidity
function invariant_collateral_ratio_monotonic() external {
    uint256 ratioBefore = [GET_COLLATERAL_RATIO](user);
    [ACCRUE_INTEREST]();
    uint256 ratioAfter = [GET_COLLATERAL_RATIO](user);
    assertLe(ratioAfter, ratioBefore, "Collateral ratio increased");
}
```
- Breaks in: Interest accrual without debt update
- Breaks in: Oracle price increase
- Condition: [COLLATERAL_VALUE] stale while [DEBT_VALUE] fresh
- Attacker gain: Avoid liquidation despite insolvency

#### **INV-LIQUIDATION-003: Liquidation Threshold Enforcement**
```solidity
function invariant_liquidation_threshold() external {
    for (uint i = 0; i < users.length; i++) {
        uint256 health = [CALCULATE_HEALTH](users[i]);
        bool liquidatable = [IS_LIQUIDATABLE](users[i]);
        if (health < [LIQUIDATION_THRESHOLD]) {
            assertTrue(liquidatable, "Unhealthy not liquidatable");
        }
    }
}
```
- Breaks in: [IS_LIQUIDATABLE] uses stale health
- Breaks in: [LIQUIDATION_THRESHOLD] changed mid-block
- Condition: Health computed before threshold update
- Attacker gain: Escape liquidation

#### **INV-INTEREST-004: Borrow/Lend Rate Synchrony**
```solidity
function invariant_rate_synchrony() external {
    [UPDATE_RATES]();
    uint256 borrowRate = [GET_BORROW_RATE]();
    uint256 supplyRate = [GET_SUPPLY_RATE]();
    uint256 utilization = [GET_UTILIZATION]();
    uint256 expectedSupply = borrowRate * utilization * (1 - [RESERVE_FACTOR]) / 1e18;
    assertApproxEqRel(supplyRate, expectedSupply, 0.01e18, "Rate desync");
}
```
- Breaks in: [RESERVE_FACTOR] applied after supply rate calc
- Breaks in: [UTILIZATION] computed with stale [TOTAL_BORROWS]
- Condition: Flash deposit inflates [TOTAL_SUPPLY]
- Attacker gain: Earn disproportionate interest

#### **INV-LIQUIDATION-005: Collateral > Debt Post-Liquidation**
```solidity
function invariant_collateral_exceeds_debt_after_liquidation() external {
    vm.prank(liquidator);
    [LIQUIDATE](borrower, debtAmount);
    
    uint256 remainingCollateral = [GET_COLLATERAL](borrower);
    uint256 remainingDebt = [GET_DEBT](borrower);
    uint256 collateralValue = remainingCollateral * [GET_PRICE]([COLLATERAL_TOKEN]);
    
    assertGe(collateralValue * [COLLATERAL_FACTOR] / 1e18, remainingDebt, "Under-collateralized after liquidation");
}
```
- Breaks in: Over-seizure via [LIQUIDATION_BONUS] miscalc
- Breaks in: Debt not reduced proportionally to collateral seized
- Condition: [SEIZE_AMOUNT] > [DEBT_AMOUNT] * [LIQUIDATION_THRESHOLD]
- Attacker gain: Extract excess collateral

#### **INV-SOLVENCY-006: No Value Creation**
```solidity
function invariant_no_value_creation() external {
    uint256 totalSupplied = [TOTAL_SUPPLY]();
    uint256 totalBorrowed = [TOTAL_BORROWS]();
    uint256 reserves = [RESERVES]();
    
    uint256 expectedBalance = totalSupplied - totalBorrowed + reserves;
    uint256 actualBalance = [UNDERLYING].balanceOf(address([POOL]));
    
    assertEq(actualBalance, expectedBalance, "Value created from thin air");
}
```
- Breaks in: [MINT] without corresponding [TRANSFER_FROM]
- Breaks in: [REPAY] burns debt but doesn't transfer tokens
- Condition: Fee-on-transfer token breaks accounting
- Attacker gain: Mint unbacked shares

#### **INV-DEBT-007: No Unpayable Debt Residues**
```solidity
function invariant_no_unpayable_debt() external {
    for (uint i = 0; i < users.length; i++) {
        uint256 debt = [GET_DEBT](users[i]);
        uint256 repayable = [MAX_REPAY](users[i]);
        assertGe(repayable, debt, "Debt exceeds repayable");
    }
}
```
- Breaks in: Dust debt after full repayment attempt
- Breaks in: [MAX_REPAY] computed with stale interest
- Condition: Rounding causes 1 wei residue
- Attacker gain: DoS on position closure

#### **INV-BADDEBT-008: No Bad Debt Leakage**
```solidity
function invariant_no_bad_debt_leakage() external {
    uint256 totalCollateralValue = 0;
    uint256 totalDebtValue = 0;
    
    for (uint i = 0; i < users.length; i++) {
        totalCollateralValue += [GET_COLLATERAL_VALUE](users[i]);
        totalDebtValue += [GET_DEBT_VALUE](users[i]);
    }
    
    assertGe(totalCollateralValue * [MIN_COLLATERAL_FACTOR] / 1e18, totalDebtValue, "System under-collateralized");
}
```
- Breaks in: Oracle price crash before liquidations execute
- Breaks in: Liquidation auction fails to clear debt
- Condition: Slippage in [SEIZE_COLLATERAL] swap
- Attacker gain: System insolvency → socialize loss

***

### **III. CROSS-CONTRACT FAILURE MODES**

#### **SEQUENCE-001: Oracle Update → Health Calc → Liquidation**
```
1. [ORACLE].pushPrice(asset, newPrice)
2. [POOL].calculateHealth(user)  // Uses old cached price
3. [POOL].liquidate(user)  // Executes with stale health
```
- **Desync Window:** Between pushPrice and internal cache update
- **Exploit:** Front-run pushPrice with liquidation at favorable old price
- **Fix Point:** Force [CALCULATE_HEALTH] to pull fresh price

#### **SEQUENCE-002: Borrow → Accrue Interest → Liquidate**
```
1. [POOL].borrow(amount)  // Does not accrue interest first
2. [POOL].accrueInterest()  // Called by liquidator
3. [POOL].liquidate(user)  // Uses freshly accrued interest
```
- **Desync Window:** Between borrow and interest accrual
- **Exploit:** Borrow max without accrued interest, get liquidated immediately after accrue
- **Fix Point:** Force [BORROW] to call [ACCRUE_INTEREST] first

#### **SEQUENCE-003: Collateral Withdraw → Liquidation Check**
```
1. [POOL].withdrawCollateral(amount)
2. [POOL].calculateHealth(msg.sender)  // Health check after withdraw
3. require(health > threshold)
```
- **Desync Window:** Collateral withdrawn before health verification
- **Exploit:** Flash loan collateral withdrawal, liquidation triggered, repay in same tx
- **Fix Point:** Check health before collateral state change

#### **SEQUENCE-004: Liquidate → Seize → Fee Route → Debt Burn**
```
1. [LIQUIDATE_ENGINE].liquidate(borrower)
2. [COLLATERAL_TOKEN].transfer(liquidator, seizedAmount)
3. [FEE_ROUTER].routeFee(protocolFee)  // Reentrancy window
4. [DEBT_TOKEN].burn(borrower, debtAmount)
```
- **Desync Window:** Between collateral seize and debt burn
- **Exploit:** Reenter via fee router, double-liquidate same position
- **Fix Point:** Use nonReentrant modifier or CEI pattern

#### **SEQUENCE-005: Interest Update → Withdraw → Liquidation**
```
1. [INTEREST_MODEL].updateRates()  // New rates calculated
2. [POOL].withdraw(amount)  // Uses old rate
3. [POOL].liquidate(user)  // Uses new rate for health calc
```
- **Desync Window:** Rate update and withdrawal not atomic
- **Exploit:** Withdraw at old favorable rate, avoid liquidation at new rate
- **Fix Point:** Lock rates during user operations

#### **SEQUENCE-006: Multi-Asset Collateral Liquidation**
```
1. [POOL].liquidate(user, assetA)  // Seizes assetA
2. [ORACLE].getPrice(assetA)  // Price A
3. [POOL].liquidate(user, assetB)  // Seizes assetB
4. [ORACLE].getPrice(assetB)  // Price B (updated after A)
```
- **Desync Window:** AssetB price updates between liquidations
- **Exploit:** Liquidate assetA at old price, assetB at new price, extract arbitrage
- **Fix Point:** Snapshot all prices at liquidation start

#### **SEQUENCE-007: Auction Start → Bid → Settle**
```
1. [AUCTION].startAuction(collateral)
2. [AUCTION].placeBid(amount)  // No collateral lock check
3. [AUCTION].settleAuction()  // Transfers unlocked collateral
```
- **Desync Window:** Collateral not locked during auction
- **Exploit:** Withdraw collateral during auction, settle auction anyway
- **Fix Point:** Lock collateral in [START_AUCTION]

#### **SEQUENCE-008: Flash Loan → Borrow → Liquidate → Repay**
```
1. [FLASH_LENDER].flashLoan(largeAmount)
2. [POOL].deposit(largeAmount)  // Inflate utilization
3. [POOL].borrow(maxAmount, victim)  // Victim borrows at inflated rate
4. [POOL].liquidate(victim)  // Immediate liquidation due to rate spike
5. [FLASH_LENDER].repay(largeAmount)
```
- **Desync Window:** Single-block rate manipulation
- **Exploit:** Flash deposit → rate spike → force liquidation
- **Fix Point:** TWAP rates or max rate delta

***

### **IV. ATTACK TEMPLATES**

#### **ATTACK-LIQ-001: Stale Health Oracle Front-Run**

**Preconditions:**
- Oracle updates via [PUSH_PRICE] with 1-block delay
- [CALCULATE_HEALTH] caches oracle price
- Liquidation threshold = 1.2

**Exploit Steps:**
```
1. Monitor mempool for [PUSH_PRICE](collateralToken, newPrice)
2. Detect price drop: oldPrice = 100, newPrice = 80
3. Front-run with [LIQUIDATE](victim)
4. [CALCULATE_HEALTH] uses cached oldPrice = 100
5. Victim appears healthy (collateralValue = 100 * amount)
6. [PUSH_PRICE] executes, updates to newPrice = 80
7. Back-run with second [LIQUIDATE](victim)
8. Now victim unhealthy (collateralValue = 80 * amount)
9. Seize collateral at 80 price, sell at 100 on DEX
```

**Breakpoint:**
- [CALCULATE_HEALTH] line reading `cachedPrice[asset]`

**Broken Invariants:**
- INV-ORACLE: Price freshness within 1 block
- INV-LIQUIDATION-003: Liquidation threshold enforcement

**Required Liquidity:**
- Victim debt amount for repayment
- Gas for front-run + back-run

**MEV Considerations:**
- Priority gas auction with block builder
- Bundle [LIQUIDATE] + DEX arbitrage

**Value Extraction:**
- `seizedCollateral * (oldPrice - newPrice) * liquidationBonus`

***

#### **ATTACK-LIQ-002: Partial Liquidation Rounding Exploit**

**Preconditions:**
- [LIQUIDATE] allows partial liquidations
- Collateral seize calculation: `debtRepaid * liquidationBonus / collateralPrice`
- Division truncation enabled

**Exploit Steps:**
```
1. Victim has debt = 10,000, collateral = 15,000 (healthy)
2. Attacker manipulates oracle: collateralPrice drops to 8,000
3. Victim now unhealthy: 15,000 < 10,000 * 1.2
4. Attacker calls [LIQUIDATE](victim, 1) // Repay 1 wei of debt
5. seizedCollateral = 1 * 1.1 / 8000 = 0.0001375 = 0 (rounds down)
6. Debt reduced by 1 wei, collateral unchanged
7. Repeat 10,000 times
8. Victim debt fully repaid, collateral never seized
9. Attacker front-runs victim's self-repay, steals zero-cost liquidation
```

**Breakpoint:**
- [LIQUIDATE] line calculating `seizedAmount` with division

**Broken Invariants:**
- INV-LIQUIDATION-005: Collateral > debt post-liquidation
- INV-SOLVENCY-006: No value creation

**Required Liquidity:**
- 10,000 wei for 10,000 micro-liquidations
- Gas costs must be < collateral value

**MEV Considerations:**
- Bundle 10,000 [LIQUIDATE] calls in single block
- Bribe validator for inclusion

**Value Extraction:**
- Victim's 15,000 collateral with near-zero cost

***

#### **ATTACK-LIQ-003: Interest Accrual Timing Manipulation**

**Preconditions:**
- [ACCRUE_INTEREST] callable by anyone
- [CALCULATE_HEALTH] uses [TOTAL_DEBT] including accrued interest
- Interest compounds per block

**Exploit Steps:**
```
1. Victim borrows 10,000 at t=0
2. Wait 1000 blocks without calling [ACCRUE_INTEREST]
3. Victim health = collateral / (10,000 + 0 accrued) = healthy
4. Attacker calls [ACCRUE_INTEREST] at t=1000
5. Interest accrues: 10,000 → 12,000 (20% over 1000 blocks)
6. Victim health = collateral / 12,000 = unhealthy
7. Attacker immediately calls [LIQUIDATE](victim)
8. Victim had no warning, liquidated instantly
```

**Breakpoint:**
- [ACCRUE_INTEREST] line updating `totalBorrows += interest`

**Broken Invariants:**
- INV-INTEREST-004: Borrow/lend rate synchrony
- INV-COLLATERAL-002: Collateral ratio monotonicity

**Required Liquidity:**
- Victim debt for repayment
- Gas for [ACCRUE_INTEREST] + [LIQUIDATE]

**MEV Considerations:**
- Bundle both calls atomically
- Maximize interest accrual window

**Value Extraction:**
- `seizedCollateral * liquidationBonus - debtRepaid`

***

#### **ATTACK-LIQ-004: Debt Share Inflation via Reentrancy**

**Preconditions:**
- [MINT_DEBT_SHARES] updates `totalDebtShares` after external call
- [BORROW] calls [TRANSFER_FROM] with reentrancy window

**Exploit Steps:**
```
1. Attacker contract implements ERC777 hook
2. Attacker calls [BORROW](10,000)
3. [BORROW] calls [MINT_DEBT_SHARES](attacker, shares)
4. [MINT_DEBT_SHARES] calculates shares = 10,000 * totalDebtShares / totalDebt
5. [MINT_DEBT_SHARES] calls token.transferFrom(attacker, pool, 10,000)
6. Token hook reenters [BORROW](10,000) again
7. Second [BORROW] calculates shares with old totalDebtShares (not yet updated)
8. Both calls mint shares against same totalDebt
9. totalDebtShares inflated, attacker's share percentage inflated
10. Attacker repays less than borrowed
```

**Breakpoint:**
- [MINT_DEBT_SHARES] line `totalDebtShares += shares` after external call

**Broken Invariants:**
- INV-DEBT-001: Debt share conservation
- CEI pattern violation

**Required Liquidity:**
- 20,000 tokens for double borrow
- Must repay before detection

**MEV Considerations:**
- Single transaction atomic execution
- No MEV competition

**Value Extraction:**
- `borrowed - (borrowed * deflatedSharePercentage)`

***

#### **ATTACK-LIQ-005: Oracle Timestamp Replay Attack**

**Preconditions:**
- [GET_PRICE] returns `(price, timestamp)` but doesn't validate timestamp
- [LIQUIDATE] accepts any recent price within 1 hour

**Exploit Steps:**
```
1. At t=0: Oracle price = 100, timestamp = 0
2. At t=3600: Oracle price = 50, timestamp = 3600
3. Attacker captures old signature: (price=100, timestamp=0)
4. Attacker calls [PUSH_PRICE](asset, 100, 0, signature)
5. [PUSH_PRICE] validates signature (valid)
6. Doesn't check timestamp < block.timestamp - MAX_AGE
7. Price reverts to 100
8. Attacker liquidates victim at inflated price
9. Seizes excess collateral
10. Oracle corrects to 50, attacker profits
```

**Breakpoint:**
- [PUSH_PRICE] missing line `require(timestamp > lastUpdate)`

**Broken Invariants:**
- INV-ORACLE: Price freshness
- Timestamp monotonicity

**Required Liquidity:**
- Victim debt amount
- Oracle signature replay capability

**MEV Considerations:**
- Coordinate with validator to include replay tx
- Sandwich with DEX arbitrage

**Value Extraction:**
- `seizedCollateral * (replayPrice - currentPrice) / currentPrice`

***

#### **ATTACK-LIQ-006: Multi-Pool Cross-Liquidation**

**Preconditions:**
- [POOL_A] and [POOL_B] share same [ORACLE]
- User can borrow from both pools
- Health calculated per-pool but collateral shared

**Exploit Steps:**
```
1. Victim deposits 10,000 collateral in [POOL_A]
2. Victim borrows 8,000 from [POOL_A] (healthy: 10,000 > 8,000 * 1.2)
3. Victim borrows 1,000 from [POOL_B] against same collateral
4. [POOL_B] calculates health: 10,000 > 1,000 * 1.2 (healthy)
5. Attacker manipulates oracle price down
6. [POOL_A] health drops, victim liquidated in [POOL_A]
7. Collateral seized by [POOL_A] liquidator
8. [POOL_B] still sees victim as having 10,000 collateral (stale)
9. Attacker liquidates victim in [POOL_B]
10. [POOL_B] tries to seize already-seized collateral
11. If no check, [POOL_B] seizes from other users' collateral
```

**Breakpoint:**
- [POOL_B].liquidate missing cross-pool collateral lock check

**Broken Invariants:**
- INV-SOLVENCY-006: No value creation
- Cross-pool collateral accounting

**Required Liquidity:**
- Debt in both pools for double liquidation

**MEV Considerations:**
- Bundle both liquidations atomically
- Requires multi-pool MEV strategy

**Value Extraction:**
- Double-liquidation bonus from single collateral

***

#### **ATTACK-LIQ-007: Fee Routing Reentrancy**

**Preconditions:**
- [LIQUIDATE] routes protocol fee via [FEE_ROUTER].routeFee()
- [FEE_ROUTER] calls external recipient contract
- [LIQUIDATE] burns debt after fee routing

**Exploit Steps:**
```
1. Attacker creates malicious [FEE_RECIPIENT] contract
2. Attacker calls [LIQUIDATE](victim)
3. [LIQUIDATE] seizes collateral
4. [LIQUIDATE] calls [FEE_ROUTER].routeFee(protocolFee)
5. [FEE_ROUTER] calls [FEE_RECIPIENT].receiveFee()
6. [FEE_RECIPIENT] reenters [LIQUIDATE](victim) again
7. Victim's debt not yet burned (still shows full debt)
8. Second liquidation seizes collateral again
9. First liquidation completes, burns debt
10. Victim debt burned once, collateral seized twice
```

**Breakpoint:**
- [LIQUIDATE] line calling [FEE_ROUTER] before debt burn

**Broken Invariants:**
- CEI pattern violation
- INV-LIQUIDATION-005: Collateral > debt

**Required Liquidity:**
- Victim debt amount for first liquidation
- Reentrancy gas costs

**MEV Considerations:**
- Single atomic transaction
- No competition if [FEE_RECIPIENT] is attacker-controlled

**Value Extraction:**
- `seizedCollateral * 2 - debtRepaid * 1`

***

#### **ATTACK-LIQ-008: Auction Dutch Price Manipulation**

**Preconditions:**
- [START_AUCTION] starts Dutch auction with linear price decay
- Price formula: `startPrice * (endTime - block.timestamp) / duration`
- No minimum bid enforcement

**Exploit Steps:**
```
1. Victim liquidated, auction starts at t=0
2. startPrice = 10,000, endTime = t+3600, duration = 3600
3. At t=3000: price = 10,000 * (3600-3000) / 3600 = 1,666
4. Attacker monitors auction, waits until t=3599
5. At t=3599: price = 10,000 * 1 / 3600 = 2.77
6. Attacker calls [BID](2.77)
7. Auction accepts minimum bid
8. Attacker pays 2.77, receives 10,000 collateral
9. Sells collateral for 10,000 on market
```

**Breakpoint:**
- [BID] accepting price at t=3599 without minimum threshold

**Broken Invariants:**
- Auction price floor
- INV-LIQUIDATION-005: Collateral value recovered

**Required Liquidity:**
- Minimum bid amount (near-zero)
- Gas for bid transaction

**MEV Considerations:**
- Snipe auction at final block
- Bribe validator for final slot

**Value Extraction:**
- `collateralValue - minBid`

***

#### **ATTACK-LIQ-009: Utilization Rate Flash Manipulation**

**Preconditions:**
- Interest rate model: `baseRate + slope * utilizationRate`
- utilizationRate = totalBorrows / totalSupply
- [BORROW] uses current utilization for rate

**Exploit Steps:**
```
1. Pool has totalSupply = 100,000, totalBorrows = 50,000
2. Utilization = 50%, borrowRate = 5%
3. Attacker flash loans 1,000,000 tokens
4. Attacker deposits 1,000,000 via [SUPPLY]
5. totalSupply = 1,100,000, totalBorrows = 50,000
6. Utilization = 4.5%, borrowRate = 0.5%
7. Victim borrows 50,000 at 0.5% rate (locked in)
8. Attacker withdraws 1,000,000
9. totalSupply = 100,000, totalBorrows = 100,000
10. Utilization = 100%, supplyRate = 50%
11. Attacker deposits again, earns 50% on victim's debt
12. Repays flash loan
```

**Breakpoint:**
- [UPDATE_RATES] using spot utilization without TWAP

**Broken Invariants:**
- INV-INTEREST-004: Rate synchrony
- Utilization rate manipulation resistance

**Required Liquidity:**
- Flash loan amount: 10x pool size
- Gas for flash loan + deposit + withdraw cycle

**MEV Considerations:**
- Atomic flash loan transaction
- Requires flash loan provider integration

**Value Extraction:**
- `victimDebt * (manipulatedRate - fairRate) * timeHeld`

***

#### **ATTACK-LIQ-010: Collateral Token Rebase Exploitation**

**Preconditions:**
- Collateral token is rebase token (e.g., stETH, aToken)
- [COLLATERAL_BALANCE] cached, not queried real-time
- Positive rebase increases balance without event

**Exploit Steps:**
```
1. Attacker deposits 10,000 rebase tokens
2. [COLLATERAL_BALANCE][attacker] = 10,000
3. Rebase occurs: actual balance = 11,000
4. [GET_COLLATERAL] still returns 10,000 (cached)
5. Attacker's health appears lower than actual
6. Attacker calls [UPDATE_COLLATERAL] (if exists)
7. [COLLATERAL_BALANCE][attacker] = 11,000
8. Attacker immediately borrows against new 11,000
9. Second rebase occurs: actual balance = 12,000
10. Attacker withdraws 12,000, repays debt on 10,000 initial
```

**Breakpoint:**
- [GET_COLLATERAL] reading cached balance instead of `balanceOf()`

**Broken Invariants:**
- INV-COLLATERAL: Real-time balance tracking
- Rebase-aware accounting

**Required Liquidity:**
- Initial rebase token deposit
- Patience for rebase events

**MEV Considerations:**
- Time attack around known rebase schedules
- Front-run rebase oracle update

**Value Extraction:**
- `(rebasedBalance - initialBalance) * collateralFactor`

***

### **V. UPGRADEABILITY RISKS**

#### **STORAGE LAYOUT RISKS**

**RISK-UPGRADE-001: LendingPool Storage Collision**
```solidity
// V1
contract LendingPoolV1 {
    uint256 public totalSupply;      // slot 0
    uint256 public totalBorrows;     // slot 1
    mapping(address => uint256) public userDeposits;  // slot 2
}

// V2 (vulnerable upgrade)
contract LendingPoolV2 {
    address public newAdmin;         // slot 0 ❌
    uint256 public totalSupply;      // slot 1 ❌
    uint256 public totalBorrows;     // slot 2 ❌
    mapping(address => uint256) public userDeposits;  // slot 3 ❌
}
```
- **Collision:** `newAdmin` overwrites `totalSupply` slot
- **Exploit:** If `newAdmin = 0x...0001000`, reads as `totalSupply = 4096`
- **Impact:** Share price = totalAssets / 4096 → massive undervaluation
- **Attack:** Mint shares at 99% discount, drain pool

**RISK-UPGRADE-002: Inherited Oracle Storage Overlap**
```solidity
// V1
contract OracleConsumerV1 is Ownable {
    IPriceOracle public oracle;  // slot 51 (after Ownable)
}

// V2 (adds inheritance)
contract OracleConsumerV2 is Ownable, ReentrancyGuard {
    // ReentrancyGuard uses slot 51
    IPriceOracle public oracle;  // Now at slot 52 ❌
}
```
- **Collision:** `oracle` address shifts to different slot
- **Exploit:** Old oracle address (slot 51) now reads as ReentrancyGuard status
- **Impact:** Reentrancy guard broken, oracle address corrupted
- **Attack:** Reenter liquidation functions

**RISK-UPGRADE-003: Debt Share Struct Reordering**
```solidity
// V1
struct DebtPosition {
    uint256 shares;      // slot N
    uint256 lastUpdate;  // slot N+1
}

// V2
struct DebtPosition {
    uint256 lastUpdate;  // slot N ❌
    uint256 shares;      // slot N+1 ❌
}
```
- **Collision:** `shares` and `lastUpdate` values swapped
- **Exploit:** Old shares value (e.g., 1000) now interpreted as timestamp
- **Impact:** Debt calculation corrupted
- **Attack:** Borrow with inflated shares, repay with deflated debt

**RISK-UPGRADE-004: Uninitialized Implementation Takeover**
```solidity
contract LendingPoolImpl {
    address public admin;
    
    function initialize(address _admin) external initializer {
        admin = _admin;
    }
}

// Vulnerability: initialize() callable on implementation contract
```
- **Exploit Steps:**
  1. Deploy proxy pointing to LendingPoolImpl
  2. Proxy.initialize() not called (forgotten)
  3. Attacker calls LendingPoolImpl.initialize(attacker) directly on implementation
  4. If proxy delegates storage reads, attacker becomes admin
  5. Attacker calls upgradeToAndCall(maliciousImpl)
- **Impact:** Full protocol takeover
- **Attack:** Drain all funds via malicious upgrade

**RISK-UPGRADE-005: Delegatecall to Malicious Liquidation Logic**
```solidity
contract LendingPoolProxy {
    address public implementation;
    
    fallback() external payable {
        (bool success, ) = implementation.delegatecall(msg.data);
        require(success);
    }
}

// Attacker upgrades to:
contract MaliciousImpl {
    function liquidate(address user) external {
        // Delegatecall context: uses proxy's storage
        // Transfer all collateral to attacker
        IERC20(collateralToken).transfer(msg.sender, type(uint256).max);
    }
}
```
- **Exploit:** Upgrade to implementation with malicious liquidate()
- **Impact:** Bypass all liquidation checks, seize all collateral
- **Attack:** Requires admin compromise or governance attack

**RISK-UPGRADE-006: Interest Rate Model Upgrade Without State Migration**
```solidity
// V1
contract InterestRateModelV1 {
    uint256 public baseRate = 2e16;  // 2%
    uint256 public slope = 5e16;     // 5%
}

// V2 (new model)
contract InterestRateModelV2 {
    uint256 public baseRate;  // Defaults to 0 ❌
    uint256 public multiplier;  // New variable
}
```
- **Exploit:** Upgrade without migrating baseRate
- **Impact:** baseRate = 0, all borrows free
- **Attack:** Borrow max at 0% rate, never repay

**RISK-UPGRADE-007: Reentrancy Guard Reset on Upgrade**
```solidity
// V1
contract LendingPoolV1 is ReentrancyGuardUpgradeable {
    uint256 private _status;  // slot 101
    
    function liquidate() external nonReentrant {
        // ...
    }
}

// V2 (adds new variable before ReentrancyGuard)
contract LendingPoolV2 is ReentrancyGuardUpgradeable {
    uint256 public newCounter;  // slot 101 ❌
    uint256 private _status;    // Now at slot 102 ❌
}
```
- **Collision:** `_status` moves to different slot, reads as 0 (unlocked)
- **Exploit:** Reentrancy protection disabled after upgrade
- **Attack:** Reenter liquidate() via collateral token callback

***

**END OF RESEARCH PACK**

**NOTE:** This framework requires actual contract code to bind all placeholder [FUNCTION_NAMES] and [VARIABLES] to real implementation. Provide contracts for complete instantiation.
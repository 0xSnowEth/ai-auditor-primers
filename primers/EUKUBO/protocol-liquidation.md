# EUKUBO Liquidation Auditing Primer
## Debt Resolution, Solvency, and Flash Liquidation Security

---

## TABLE OF CONTENTS
1. Health Factor Derivation
2. Debt and Solvency Mechanics
3. Liquidation Engine & FlashAccountant Integration
4. Liquidation Attack Templates
5. Liquidation Invariants
6. Test Cases & Foundry Skeletons

---

## 1. HEALTH FACTOR DERIVATION

### 1.1 Solvency Formulas Across Core Dimensions

EUKUBO likely does not use a "health factor" directly (common in lending platforms), but instead uses **solvency** as the core metric:

```
Solvency(position) = CollateralValue(position) - DebtValue(position)

CollateralValue = collateral_amount × price[collateral]
DebtValue = debtShares × (totalDebt / totalDebtShares)
```

For the **protocol level**:

```
ProtocolSolvency = Σ(collateral value of all positions) - Σ(debt value of all positions)

If ProtocolSolvency < 0, the protocol is under-collateralized
```

### 1.2 Solvency Under Extreme Deltas

When a large swap occurs, prices move, and collateral values change:

```
CollateralValue_new = collateral_amount × price_new
ΔValue = price_new - price_old

If ΔValue < 0 (price drop):
  CollateralValue_new < CollateralValue_old
  Solvency decreases → position may become liquidatable
```

**Attack Vector**: An attacker with a position in a high-beta asset can orchestrate a price drop (via a large swap or oracle manipulation) to trigger cascading liquidations of other positions.

### 1.3 Mixed-State Solvency Under Stale Tick

If the core's slot0.tick is not updated immediately after a swap:

```
// During swap:
price_actual = 1.0001^(newTick)
price_stale = 1.0001^(oldTick)  // not yet updated

CollateralValue_calc = collateral × price_stale
CollateralValue_real = collateral × price_actual

If newTick < oldTick (price decrease):
  CollateralValue_calc > CollateralValue_real
  Liquidation check uses inflated collateral value
  → Position should be liquidated but isn't
```

### 1.4 Solvency Under Negative Liquidity Edge

In rare edge cases, if cumulative liquidity computation produces a negative intermediate state:

```
cumLiquidity = 0
for each tick in swap path:
    cumLiquidity += tickState[tick].liquidityNet
    if cumLiquidity < 0:
        // Price impact calculation becomes nonsensical
        amountOut = (price_delta) × cumLiquidity  // negative!
```

With negative liquidity, swap outputs are mispriced or reversed, causing solvency calculations to be inverted.

### 1.5 Solvency Formula Under Delta-Based Adjustments

When debt is dynamically adjusted (e.g., accrued interest or flash fees):

```
Solvency = CollateralValue - (DebtValue + InterestDelta + FeeDelta)

InterestDelta = debtShares × (interestRate × timeElapsed / YEAR_IN_SECONDS)
FeeDelta = debtShares × (flashFeeRate) [if in flash]

If deltas are computed using stale state (e.g., old time or old rate):
  Solvency calculation is off
  → Liquidation may not trigger when needed
```

---

## 2. DEBT AND SOLVENCY MECHANICS

### 2.1 Debt Share Mis-accounting

EUKUBO uses a **debt share system** to track borrowers' pro-rata debt:

```solidity
mapping(uint256 => Position) positions;

struct Position {
    uint96 liquidity;
    uint96 debtShares;      // borrower's share of totalDebt
    int256 feesOwed;        // accumulated fees
}

uint96 totalDebtShares;
uint256 totalDebt;          // total stablecoin outstanding

function getDebtValue(uint256 posId) public view returns (uint256) {
    Position storage pos = positions[posId];
    return (pos.debtShares * totalDebt) / totalDebtShares;
}
```

**Vulnerability: Debt Share Inflation**

```solidity
function borrowAgainstCollateral(uint256 posId, uint256 amount) external {
    require(canBorrow(posId, amount), "INSUFFICIENT_COLLATERAL");
    
    uint96 sharesToMint = (amount * totalDebtShares) / totalDebt;
    // ⚠️ ROUNDING: If amount * totalDebtShares < totalDebt:
    //    sharesToMint rounds down to 0
    //    But borrower receives the full amount!
    
    positions[posId].debtShares += sharesToMint;
    totalDebt += amount;
    _transfer(borrower, amount);
}
```

**Attack**:
1. Attacker borrows with `amount = 1` (wei)
2. `sharesToMint = (1 * totalDebtShares) / totalDebt` → rounds to 0
3. Attacker gains 1 wei of debt-free borrowing
4. Repeat for many microborrows → accumulate substantial debt-free funds

### 2.2 TempDebt + RealDebt Desync

When a position is inside a flash loan:

```
realDebt = positions[posId].debtShares × (totalDebt / totalDebtShares)
tempDebt = flashState.tmpDebt  [if in flash]
totalExposure = realDebt + tempDebt
```

**Vulnerability: Desync During Liquidation**

```solidity
function liquidate(uint256 posId) external {
    Position storage pos = positions[posId];
    
    // Calculate debt at liquidation time
    uint256 debtToRepay = getDebtValue(posId);
    
    // ⚠️ If position is inside a flash callback (flashState.inFlash == true)
    //    and tmpDebt exists, debtToRepay might not include it
    //    (depends on whether liquidation is aware of flash state)
    
    _repayDebt(debtToRepay);
    _claimCollateral(pos.collateral, debtToRepay);
}
```

If liquidation is triggered while a flash loan is still executing, and the liquidation logic doesn't account for `tmpDebt`, the liquidation amount is incorrect:
- Liquidation repays only `realDebt`
- `tmpDebt` remains unpaid
- Flash callback continues, but position is already liquidated (stale state)

### 2.3 Extension-Induced Solvency Drift

Extensions can call back into core, potentially modifying solvency state:

```
Phase 1: Core reads solvency(posA) = positive
Phase 2: Core calls Extension
Phase 3: Extension calls Core._updateDebt(posB) [unintended]
Phase 4: totalDebt increases, solvency(posA) decreases
Phase 5: Core's liquidation logic executes with stale solvency value
```

### 2.4 Invalid Pool Solvency Under Extreme States

When multiple positions are liquidated in a cascade:

```
Liquidation 1: Repay debt for posA, seize collateral
Liquidation 2: Repay debt for posB, seize collateral
...

Each liquidation changes totalDebt and totalCollateral.
If liquidations are not atomic, intermediate states can be invalid:
  → totalDebt < 0 (impossible, but rounding artifacts)
  → totalCollateral < 0 (impossible, but representation issues)
```

---

## 3. LIQUIDATION ENGINE & FLASHACCOUNTANT INTEGRATION

### 3.1 Liquidation Call Ordering

A liquidation typically follows this sequence:

```
1. liquidate(posId)
2.   Check: isSolvent(posId) == false
3.   Calculate: debtToRepay = getDebtValue(posId)
4.   Repay debt: _transfer(creditToken, debtToRepay)
5.   Update: totalDebt -= debtToRepay
6.   Update: positions[posId].debtShares = 0
7.   Seize collateral: _transfer(collateral to liquidator)
8.   Emit: Liquidation event
```

**Vulnerability: Gap Between Debt Calculation and Repayment**

```solidity
function liquidate(uint256 posId) external {
    // Step 2: Check solvency
    require(!isSolvent(posId), "POSITION_SOLVENT");
    
    // Step 3: Calculate debt (reads totalDebt, totalDebtShares from storage)
    uint256 debtToRepay = getDebtValue(posId);
    
    // ⚠️ GAP: Between calculation and repayment, state can change
    // If another liquidation TX is mined in parallel, totalDebt changes
    // debtToRepay is now stale
    
    // Step 4: Repay debt
    _transfer(msg.sender, debtToRepay);
}
```

If two liquidations are included in the same block, the second one uses stale `debtToRepay`.

### 3.2 Extension Calls Inside Liquidations

If an extension is called during liquidation:

```solidity
function liquidate(uint256 posId) external {
    require(!isSolvent(posId), "SOLVENT");
    uint256 debt = getDebtValue(posId);
    
    _callExtension(extensionLiquidation, LIQUIDATE, abi.encode(posId, debt));
    // ⚠️ Extension can:
    //   - Modify liquidation amount
    //   - Trigger another liquidation (reentrancy)
    //   - Update collateral values (oracle feedback)
    
    _repayDebt(debt);
    _claimCollateral(posId, debt);
}
```

If the extension modifies the position's collateral value or debt, the repayment and seizure amounts are now stale.

### 3.3 Stale Tick Abuse During Liquidation

An attacker can:
1. Maintain a position just above the liquidation threshold
2. Execute a large swap (not yet settled, i.e., slot0.tick not updated)
3. Trigger liquidation, which uses slot0.tick (old) to calculate collateral value
4. Collateral value is overstated → liquidation doesn't fully repay debt

```
Time T1: price = 100, posA.collateral = 10, required = 8 (solvency = 2)
Time T2: Attacker swaps, price drops to 80 (but slot0.tick not updated)
Time T3: Liquidator calls liquidate(posA)
         - Solvency check: reads stale slot0.tick = original tick
         - Calculates collateral value = 10 × price_old = 10 × 100 = 1000
         - Solvency = 1000 - 8 = positive
         - Liquidation fails!
Time T4: slot0.tick updated to reflect new price
         - Real solvency = 10 × 80 - 8 = 792 (still positive, but much closer)
         - Liquidation finally triggers, but liquidator has less profit margin
```

### 3.4 Liquidation Profitability Attack Templates

Liquidators are incentivized to liquidate positions via a **discount**:

```
Liquidator repays: debt × 1.0 (full debt)
Liquidator receives: collateral × (1 - liquidationDiscount)

Profit = collateral × (1 - discount) - debt

If price is stable and position is healthy:
  collateral × price > debt
  Profit = (collateral × price × (1 - discount) - debt) × price^-1
```

**Attack: Liquidation Sandwich**

```
Attacker monitors mempool for liquidation TXs.
1. Attacker's TX (pre-liquidation): Large swap, drops price
2. Liquidator's TX: Liquidates position at lower price
3. Attacker's TX (post-liquidation): Raises price back, profits from arbitrage
```

---

## 4. LIQUIDATION ATTACK TEMPLATES

### ATTACK #1: Stale Tick → Underpriced Liquidation

**Severity**: CRITICAL  
**Category**: Oracle / State Staleness

**Description**:
An attacker exploits a gap between actual price movement (from a swap) and the updated slot0.tick. Liquidation calculations use the stale tick, resulting in underpriced liquidations.

**Vulnerability**:
```solidity
function swap(uint256 amountIn, bytes calldata data) external returns (uint256) {
    // Swap executes, price moves, slot0.tick updated AFTER swap logic
    uint256 amountOut = _executeSwap(amountIn);
    
    // ⚠️ GAP: Between _executeSwap and slot0 update
    //    Extensions or other callers see stale price
    
    _callExtension(extensionSwap, SWAP, data);
    
    slot0.tick = computeNewTick(...);  // NOW updated
}

function liquidate(uint256 posId) external {
    // Reads slot0.tick, which is stale if called during above gap
    uint256 collateralValue = position.collateral * priceFromTick(slot0.tick);
    
    if (collateralValue < position.debt) {
        _repayDebtAndSeizeCollateral(posId);
    }
}
```

**Attack**:
1. Attacker has a margin position: collateral=1000, debt=900, tick=100 (price=100)
2. Attacker triggers a large swap that moves tick to 90 (price=90)
3. During the swap, before slot0 is updated, attacker calls liquidate()
4. Liquidation calculates: collateral_value = 1000 × 100 = 100k (using stale tick)
5. Solvency = 100k - 900 = 99.1k (positive, should be liquidated)
6. Liquidation fails due to stale price

Then, after slot0 is updated:
7. Actual solvency = 1000 × 90 - 900 = 89.1k (still positive)
8. Position remains unliquidated, attacker keeps the leverage

**Test Case**:
```foundry
function testStaleTick_Underpriced_Liquidation() public {
    // Setup: position at edge of liquidation
    uint256 posId = core.openPosition(user, 1000e18, 900e18);  // collateral, debt
    
    // Initial price: 100 (tick = 0)
    core.setTickPrice(0);
    
    // Verify position is healthy
    assertGt(core.getCollateralValue(posId), core.getDebtValue(posId));
    
    // Attacker executes swap that moves price to 90
    // But BEFORE slot0 is updated:
    vm.prank(attacker);
    
    // Snapshot: slot0 still at old tick
    (int24 tickBefore, , ) = core.decodeSlot0();
    
    // Trigger large swap (moves price down)
    core.swap(100000e18, abi.encode(...));  // causes tick move
    
    // In the middle of swap, try liquidation with stale tick
    // This requires a custom extension that liquidates mid-swap
    
    // After swap, verify position is actually insolvent
    uint256 actualCollateralValue = core.getCollateralValue(posId);
    uint256 actualDebt = core.getDebtValue(posId);
    
    // With real price, should be liquidatable
    if (actualCollateralValue < actualDebt) {
        // Now liquidate with correct price
        core.liquidate(posId);
        // Should succeed
        assertEq(core.positions(posId).debtShares, 0);
    }
}
```

---

### ATTACK #2: Debt-Share Inflation via Rounding

**Severity**: HIGH  
**Category**: Debt Accounting

**Description**:
An attacker crafts borrowing amounts to exploit rounding in debt-share minting, allowing them to borrow with minimal debt-share registration.

**Vulnerability**:
```solidity
function borrowAgainstCollateral(uint256 posId, uint256 amount) external {
    require(isSolvent(posId, amount), "INSOLVENCY");
    
    // Calculate shares to mint
    uint96 sharesToMint = (amount * totalDebtShares) / totalDebt;
    // ⚠️ Integer division: if amount * totalDebtShares < totalDebt, rounds to 0
    
    positions[posId].debtShares += sharesToMint;
    totalDebt += amount;
    _transfer(borrower, amount);
}

function getDebtValue(uint256 posId) public view returns (uint256) {
    return (positions[posId].debtShares * totalDebt) / totalDebtShares;
}
```

**Attack**:
1. Total debt: 1000e18, total shares: 1000e18 (1:1 ratio)
2. Attacker borrows: 0.5e18
3. Shares minted: `(0.5e18 * 1000e18) / 1000e18 = 0.5e18` (OK, no rounding)
4. But if Attacker crafts to borrow with precision loss:
   - totalDebtShares = 3, totalDebt = 10
   - Borrow amount = 1
   - Shares = (1 * 3) / 10 = 0 (due to rounding down!)
   - Attacker gains 1 unit of debt-free funds

**Liquidation Impact**:
When liquidating the attacker's position, `getDebtValue` returns:
```
debtValue = (0 * totalDebt) / totalDebtShares = 0
```
Even though the attacker borrowed funds, their debt is recorded as 0.

**Test Case**:
```foundry
function testDebtShareInflationRounding() public {
    // Setup: create initial debt-share ratio
    core.setTotalDebt(10e18);
    core.setTotalDebtShares(3e18);
    
    // Attacker borrows amount such that shares round to 0
    uint256 borrowAmount = 1;  // 1 wei
    
    uint256 expectedShares = (borrowAmount * 3e18) / 10e18;
    assertEq(expectedShares, 0);  // rounds down
    
    // Attacker can borrow without registering debt
    uint256 debtBefore = core.totalDebt();
    
    vm.prank(attacker);
    core.borrowAgainstCollateral(attackerPosId, borrowAmount);
    
    uint256 debtAfter = core.totalDebt();
    assertEq(debtAfter, debtBefore + borrowAmount);
    
    // But attacker's debtShares is 0!
    (uint96 debtShares, , ) = core.positions(attackerPosId);
    assertEq(debtShares, 0);
    
    // Attacker is unborrowed and untrackable
    uint256 debtValue = core.getDebtValue(attackerPosId);
    assertEq(debtValue, 0);
    
    // Liquidation cannot be triggered (debt = 0)
}
```

---

### ATTACK #3: TempDebt Double-Count Exploit

**Severity**: CRITICAL  
**Category**: Flash + Liquidation

**Description**:
An attacker borrows via flash loan and simultaneously liquidates a position, causing tmpDebt to be counted twice in solvency calculations.

**Vulnerability**:
```solidity
function flashBorrow(uint256 amount, bytes calldata data) external {
    flashState.tmpDebt = amount;
    flashState.inFlashCallback = true;
    _transfer(msg.sender, amount);
    
    IFlashBorrower(msg.sender).onFlashBorrow(amount, data);
    
    // ⚠️ If liquidation is called during onFlashBorrow:
    // totalExposure = realDebt + tmpDebt (counted twice)
    
    require(flashState.tmpDebt == 0, "NOT_REPAID");
}

function liquidate(uint256 posId) external {
    Position storage pos = positions[posId];
    
    // Calculate total debt (including tmpDebt if any)
    uint256 debt = getDebtValue(posId);
    if (flashState.inFlashCallback && flashState.tmpCaller == pos.owner) {
        debt += flashState.tmpDebt;  // double-count!
    }
    
    _repayDebtAndSeizeCollateral(posId, debt);
}
```

**Attack**:
1. Attacker's position: debt=100, collateral=150 (solvent)
2. Attacker calls flashBorrow(50)
3. In onFlashBorrow callback, attacker triggers liquidate(myPos)
4. Liquidation calculates debt = 100 + 50 = 150 (including tmpDebt double-count)
5. Collateral = 150, solvency = 0 (liquidatable by thin margin)
6. Liquidation executes, seizes collateral, pays debt
7. But tmpDebt is temporary—after flash ends, the 50 is "repaid" automatically
8. Attacker now has 150 collateral paid + 50 flash funds = 200 units of free value

**Test Case**:
```foundry
function testTempDebtDoubleCountExploit() public {
    // Setup: attacker's position
    uint256 posId = core.openPosition(attacker, 150e18, 100e18);  // collateral, debt
    
    // Attacker is solvent
    assertGt(core.getCollateralValue(posId), core.getDebtValue(posId));
    
    // Attacker calls flashBorrow with a callback that triggers liquidation
    uint256 flashAmount = 50e18;
    
    vm.prank(attacker);
    core.flashBorrow(flashAmount, abi.encode(
        address(liquidationCallback),
        posId
    ));
    
    // In onFlashBorrow callback (called by attacker):
    // liquidate(posId) is triggered
    // debt is calculated as: realDebt (100) + tmpDebt (50) = 150
    // collateral = 150, solvency = 0
    // liquidation executes
    
    // After flashBorrow ends:
    // Position is liquidated (collateral seized)
    // But tmpDebt is cleared automatically (part of flash cleanup)
    // Attacker keeps some of the seized collateral as profit
    
    // Verify: position is liquidated
    (uint96 debtShares, , ) = core.positions(posId);
    assertEq(debtShares, 0);  // liquidated
    
    // Verify: attacker profited from the exploit
    uint256 seizedAmount = 150e18;
    // Attacker repaid 100 (real debt) + 50 (flash) = 150 (covered by collateral)
    // But collateral was 150, so attacker is even? Actually, liquidation should impose a loss.
    // This test verifies that the exploit doesn't occur (properly validates tmpDebt).
}
```

---

### ATTACK #4: Invalid Solvency State Due to Extension Cleanup Failure

**Severity**: CRITICAL  
**Category**: Extension + Liquidation

**Description**:
An extension modifies core state during a liquidation callback, leaving the solvency invariant broken.

**Vulnerability**:
```solidity
function liquidate(uint256 posId) external {
    Position storage pos = positions[posId];
    uint256 debtToRepay = getDebtValue(posId);
    
    _callExtension(extensionLiquidation, LIQUIDATE, abi.encode(posId, debtToRepay));
    // ⚠️ Extension can modify state:
    //   - Update totalDebt
    //   - Update totalDebtShares
    //   - Trigger another liquidation (reentrancy)
    
    _repayDebtAndSeizeCollateral(posId, debtToRepay);
    
    // After extension call, debtToRepay is now stale
    // If totalDebt was modified, the repayment doesn't match
}
```

**Attack**:
1. Core initiates liquidation of position A
2. Extension is called with posA's debt = 100
3. Extension (attacker-controlled) modifies totalDebt:
   - `totalDebt` decreases from 1000 to 500
4. Extension returns
5. Core repays debt = 100 (based on original calculation)
6. But totalDebt is now 500, so 100/500 = 20% of total debt
7. The repayment ratio is wrong; debt-share holders' claims are misaligned

**Test Case**:
```foundry
function testInvalidSolvencyExtensionCleanupFailure() public {
    // Setup: multiple positions
    uint256 posA = core.openPosition(userA, 500e18, 100e18);
    uint256 posB = core.openPosition(userB, 500e18, 100e18);
    
    uint256 totalDebtBefore = core.totalDebt();  // 200
    
    // Register malicious liquidation extension
    address malExt = address(new MaliciousLiquidationExtension(address(core)));
    core.registerExtension(malExt, CALLPOINT_LIQUIDATE);
    
    // Trigger liquidation of posA
    uint256 debtA = core.getDebtValue(posA);
    
    vm.prank(liquidator);
    core.liquidate(posA, malExt);
    
    // Extension modified totalDebt during callback
    uint256 totalDebtAfter = core.totalDebt();
    
    // If extension decreased totalDebt, repayment is misaligned
    if (totalDebtAfter < totalDebtBefore) {
        // Debt-share ratio changed, liquidation repayment is stale
        uint256 debtB = core.getDebtValue(posB);
        
        // debtB should be unchanged, but if totalDebt decreased,
        // debtB effectively increased (in share terms)
        assertGt(debtB, 100e18);  // inflated due to totalDebt manipulation
    }
}
```

---

### ATTACK #5: Tick Boundary Liquidation

**Severity**: MEDIUM  
**Category**: Tick Crossing + Liquidation

**Description**:
An attacker exploits price movements around tick boundaries to time liquidation profitably.

**Vulnerability**:
Tick crossing causes discrete liquidity changes. A liquidator can monitor when prices approach a tick boundary and liquidate just as the price crosses, potentially capturing the liquidity jump as profit.

```solidity
// Pseudo: liquidation profit calculation
liquidationProfit = seizedCollateral - debtRepaid - liquidationCost

// If liquidation is triggered just after a tick crosses:
// seizedCollateral might include a liquidity jump bonus (if swaps use the new tick)
```

**Test Case**:
```foundry
function testTickBoundaryLiquidation() public {
    // Setup: position liquidatable at tick boundary
    uint256 posId = core.openPosition(user, 1000e18, 900e18);
    
    // Price approaching tick 100 (boundary)
    core.setCurrentTick(99);
    
    // Initialize tick 100 with large liquidityNet
    core.setTickLiquidity(100, 1e18);
    
    // Attacker monitors: price is about to cross tick 100
    // Liquidator prepares TX to liquidate at tick 100
    
    // Swap that moves price to tick 101 (crosses boundary)
    core.swap(10000e18, abi.encode(...));
    
    // Now liquidate
    core.liquidate(posId);
    
    // Check: did attacker/liquidator capture extra value?
    uint256 liquidationReward = core.getLiquidationReward(posId);
    assertGt(liquidationReward, expectedReward);  // excess due to tick boundary
}
```

---

### ATTACK #6: Delta-Rounding Liquidation Attack

**Severity**: CRITICAL  
**Category**: Accounting

**Description**:
Similar to the core delta-rounding attack, but applied specifically to liquidation calculations.

**Vulnerability**:
```solidity
function liquidate(uint256 posId) external {
    uint256 debtToRepay = (positions[posId].debtShares * totalDebt) / totalDebtShares;
    // ⚠️ Rounding down can make liquidation unprofitable or impossible
    
    require(debtToRepay > 0, "NO_DEBT");
    _repayDebtAndSeizeCollateral(posId, debtToRepay);
}
```

**Attack**:
1. Position has debtShares = 1 wei
2. totalDebt = 2, totalDebtShares = 3
3. debtToRepay = (1 * 2) / 3 = 0 (rounds down)
4. Liquidation reverts: "NO_DEBT"
5. Position remains open and unliquidated, despite being insolvent

**Test Case**:
```foundry
function testDeltaRoundingLiquidationAttack() public {
    core.setTotalDebt(2e18);
    core.setTotalDebtShares(3e18);
    
    uint256 posId = core.openPosition(user, 10e18, 2e18);
    
    // Craft position with 1 wei of debt shares
    core.setPositionDebtShares(posId, 1);
    
    uint256 debtValue = core.getDebtValue(posId);
    assertEq(debtValue, 0);  // rounds to 0!
    
    // Position is insolvent (collateral < debt in real terms)
    // But debt rounds to 0, so liquidation is blocked
    
    vm.expectRevert("NO_DEBT");
    core.liquidate(posId);
}
```

---

## 5. LIQUIDATION INVARIANTS

| ID | Invariant | Formula | Notes |
|----|-----------|---------|-------|
| INV_LIQ_001 | Liquidation triggers insolvency | isSolvent(posId) == false → canLiquidate(posId) == true | Guard against liquidation of solvent positions |
| INV_LIQ_002 | Debt shares consistency | debtShares > 0 ⇔ debtValue(posId) > 0 | Avoid zero-debt positions |
| INV_LIQ_003 | Liquidation reduces debt | After liquidate: totalDebt(after) < totalDebt(before) | Debt must decrease |
| INV_LIQ_004 | Liquidation resets shares | After liquidate: positions[posId].debtShares == 0 | Clean liquidation |
| INV_LIQ_005 | Collateral seized | After liquidate: seizedAmount == debtRepaid + liquidationDiscount | Fair seizure |
| INV_LIQ_006 | Liquidation discount applied | liquidationDiscount ∈ [0, MAX_DISCOUNT] | Bounded incentive |
| INV_LIQ_007 | Flash debt cleared after liquidation | After liquidate in flash: tmpDebt == 0 | Ephemeral debt constraint |
| INV_LIQ_008 | Solvency improvement | After liquidate: protocol solvency(after) >= solvency(before) | Liquidations improve health |
| INV_LIQ_009 | No cascade from liquidation | Liquidation of posA doesn't trigger posB liquidation (if posB solvency unaffected) | Isolation |
| INV_LIQ_010 | Tick consistency | Liquidation uses same tick as swap during liquidation | No stale price |

---

## 6. TEST CASES & FOUNDRY SKELETONS

### Test Folder Structure

```
tests/liquidation/
├── test_health_factor.sol
├── test_debt_solvency.sol
├── test_liquidation_mechanics.sol
├── test_flash_liquidation.sol
├── test_liquidation_attacks.sol
└── test_liquidation_invariants.sol
```

### Test #1: Stale Tick Liquidation Bypass

```solidity
pragma solidity ^0.8.0;

import "foundry/Test.sol";
import "../src/EUKUBOCore.sol";

contract TestStaleTick_LiquidationBypass is Test {
    EUKUBOCore core;
    MockToken collateral;
    
    function setUp() public {
        core = new EUKUBOCore();
        collateral = new MockToken();
        core.initialize(address(collateral));
    }
    
    function testLiquidation_StaleTickAllowsEvasion() public {
        // Setup: position at liquidation threshold
        uint256 posId = core.openPosition(borrower, 1000e18, 950e18);
        
        // Current price: 1.0 (tick = 0)
        core.setTickPrice(0);
        
        // Verify: position is solvent (barely)
        assertTrue(core.isSolvent(posId));
        
        // Attacker executes swap that moves price down
        // But between swap execution and slot0 update, liquidation is called
        
        // Create extension that liquidates mid-swap
        address liquidationExtension = address(new LiquidationExtension(address(core)));
        core.registerExtension(liquidationExtension, CALLPOINT_SWAP);
        
        // Trigger swap with embedded liquidation
        core.swap(5000e18, abi.encode(liquidationExtension, posId));
        
        // After swap:
        // Real price = 0.95, collateral value = 950, debt = 950
        // Real solvency = 0 (insolvent by thin margin)
        
        // Verify: position was NOT liquidated (due to stale tick during swap)
        (uint96 debtShares, , ) = core.positions(posId);
        assertGt(debtShares, 0);  // still open
    }
}
```

### Test #2: Debt Inflation & Liquidation

```solidity
contract TestDebtInflation_Liquidation is Test {
    EUKUBOCore core;
    
    function setUp() public {
        core = new EUKUBOCore();
        core.initialize();
    }
    
    function testDebtInflation_UnliquidatablePosition() public {
        // Setup: debt shares with rounding
        core.setTotalDebt(10e18);
        core.setTotalDebtShares(3e18);
        
        // Attacker position
        uint256 posId = core.openPosition(attacker, 100e18, 0);  // no debt yet
        
        // Attacker borrows with amount that rounds shares to 0
        uint256 borrowAmount = 1;
        core.borrowAgainstCollateral(posId, borrowAmount);
        
        // Position has debt in totalDebt but debtShares = 0
        uint256 debtValue = core.getDebtValue(posId);
        assertEq(debtValue, 0);  // invisible debt!
        
        // Price drops, position becomes insolvent
        // But liquidation check uses debtValue = 0
        core.setPriceMultiplier(0.5e18);  // price drops 50%
        
        // Liquidation should fail (debtValue = 0)
        vm.expectRevert();
        core.liquidate(posId);
    }
}
```

### Test #3: Flash-Liquidation Reentrancy Boundary

```solidity
contract TestFlashLiquidation_Reentrancy is Test {
    EUKUBOCore core;
    
    function setUp() public {
        core = new EUKUBOCore();
        core.initialize();
    }
    
    function testFlashLiquidation_ReentrancyBoundary() public {
        // Setup: two positions
        uint256 posA = core.openPosition(userA, 500e18, 400e18);
        uint256 posB = core.openPosition(userB, 500e18, 400e18);
        
        // Attacker calls flashBorrow with liquidation callback
        uint256 flashAmount = 200e18;
        
        vm.prank(attacker);
        core.flashBorrow(flashAmount, abi.encode(
            address(liquidationCallback),
            posA
        ));
        
        // In onFlashBorrow:
        // liquidate(posA) is called
        // Debt is calculated with tmpDebt included (double-count scenario)
        
        // After flash ends, tmpDebt is cleared
        // But if liquidation was executed, position is already liquidated
        
        // Verify: liquidation was correctly bounded by reentrancy guard
        (uint96 debtSharesA, , ) = core.positions(posA);
        // If liquidation succeeded: debtSharesA == 0
        // If reentrancy was blocked: debtSharesA > 0
        
        assertGt(debtSharesA, 0);  // reentrancy guard should prevent liquidation
    }
}
```

---

✓ Module Complete.

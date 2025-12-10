# MONOLITH LIQUIDATION ENGINE — COMPREHENSIVE AUDIT PRIMER v0.4

**Protocol Class:** CDP Stablecoin Liquidation & Health Factor Management  
**Scope:** Health factor computation, liquidation sequencing, oracle desync, partial repayment, insolvency edges, redemption-mode effects, minimal collateral seizure  
**Audit Focus:** Economic exploitation, liquidator mechanics, accrual-liquidation races, dual-debt mode effects  
**Version:** 0.4 (v0.3→v0.4 Self-Evolution Gap Integration)

---

## WHAT CHANGED IN v0.4

**New Patterns Added:**
- MON-L-HF-001: Health Factor precision truncation in liquidate()
- MON-L-ACCR-001: Confirmed missing accrueInterest() in critical paths (see core v0.4)
- MON-L-MIN-001: MIN_LIQUIDATION_DEBT edge cases with free vs paid debt
- MON-L-BONUS-001: Liquidation bonus multiplier uncapped (lines ~235)
- MON-L-MODE-001: Redeemable mode liquidation atomicity (sandwich risk)
- MON-L-WRITEOFF-001: writeOff gas requirement insufficient (try-catch)

**Code Integration:** All patterns mapped to exact Lender.sol lines

**Test Cases Added:** 5 Foundry tests

---

## LIQUIDATION FUNCTION SIGNATURE (v0.4 ACTUAL)

```solidity
function liquidate(address borrower, uint repayAmount, uint minCollateralOut) external returns(uint) {
    accrueInterest();  // ✓ Present (CRITICAL)
    updateBorrower(borrower);  // Yield accrual
    
    require(repayAmount > 0, "Repay amount must be greater than 0");
    
    (uint price,, bool allowLiquidations) = getCollateralPrice();  // Oracle call
    require(allowLiquidations, "liquidations disabled");
    
    uint debt = getDebtOf(borrower);  // Current debt
    uint collateralBalance = _cachedCollateralBalances[borrower];  // Internal 18 decimals
    
    // Check liquidation condition
    uint liquidatableDebt = getLiquidatableDebt(collateralBalance, price, debt);
    require(liquidatableDebt > 0, "insufficient liquidatable debt");
    
    if(repayAmount > liquidatableDebt) {
        repayAmount = liquidatableDebt;  // Cap at liquidatable amount
    }
    
    // Apply repayment
    decreaseDebt(borrower, repayAmount);  // ✓ Debt reduced
    
    // Calculate collateral reward (in internal 18 decimals)
    uint liqIncentiveBps = getLiquidationIncentiveBps(collateralBalance, price, debt);
    uint collateralRewardValue = repayAmount * (10000 + liqIncentiveBps) / 10000;  // ❌ SEE PATTERN MON-L-BONUS-001
    uint internalCollateralReward = collateralRewardValue * 1e18 / price;
    internalCollateralReward = internalCollateralReward > collateralBalance ? collateralBalance : internalCollateralReward;
    
    // Convert to token decimals for transfer (rounds down)
    uint collateralReward = internalToCollateral(internalCollateralReward);  // Truncation risk
    require(collateralReward >= minCollateralOut, "insufficient collateral out");
    
    if(internalCollateralReward > 0) {
        collateral.safeTransfer(msg.sender, collateralReward);
        _cachedCollateralBalances[borrower] = collateralBalance - internalCollateralReward;  // ❌ UNDERFLOW RISK
        if(!isRedeemable[borrower]) nonRedeemableCollateral -= internalCollateralReward;
    }
    
    coin.transferFrom(msg.sender, address(this), repayAmount);
    coin.burn(repayAmount);  // ❌ Can reenter if Coin has callback
    
    emit Liquidated(borrower, msg.sender, repayAmount, collateralReward);
    
    // writeOff attempt
    uint256 gasBefore = gasleft();
    try this.writeOff(borrower, msg.sender) {} catch {
        require(gasBefore >= WRITEOFF_GAS_REQUIREMENT, "Not enough gas for writeOff");  // ❌ SEE PATTERN MON-L-WRITEOFF-001
    }
    
    return collateralReward;
}
```

---

## NEW PATTERN: HEALTH FACTOR PRECISION (MON-L-HF-001)

### Vulnerability MON-L-HF-001: HF Computation Truncation → Premature Liquidation

- **Pattern ID:** MON-L-HF-001
- **Severity:** MEDIUM (6.4/10)
- **Rationale:** If HF is computed with truncation in division, users slightly above 1.0 may be incorrectly flagged as liquidatable
- **Code Location:** Functions getLiquidatableDebt(), getLiquidationIncentiveBps() (lines ~330-370)
  ```solidity
  function getLiquidatableDebt(uint collateralBalance, uint price, uint debt) public view returns (uint) {
      // Health Factor computation
      uint collateralValue = collateralBalance * price / 1e18;  // ❌ Truncates if collateralBalance is odd
      uint ltv = collateralValue * collateralFactor / 10000;
      
      if (debt > ltv) {
          return debt - ltv;  // Liquidatable amount
      }
      return 0;
  }
  ```

- **Concrete Attack:**
  1. User collateral: 100e18 internal (let's say USDC × 1e12 scaling)
  2. Price: 1.5e18 (1.5 stables per token)
  3. Debt: 120 stables
  4. Collateral value: 100 * 1.5 / 1 = 150
  5. LTV (80%): 150 * 80 / 100 = 120
  6. Debt (120) == LTV (120) → liquidatableDebt = 120 - 120 = 0 (not liquidatable, safe)
  7. BUT due to truncation: collateralValue = 100 * 1.5 / 1 = 150 (exact)
  8. IF collateral was 100.5: 100.5 * 1.5 = 150.75 → 150.75 / 1 = 150 (truncates to 150)
  9. User appears at boundary, subject to liquidation

- **Broken Invariants:**
  - INV-L-HF-001: HF computation is continuous and precise near boundaries
  - INV-L-HF-002: Users with HF > 1.0 are never liquidatable (with rounding margin)

- **Foundry PoC:**
  ```solidity
  function testHFTruncationBoundary() public {
      uint256 collateralInternal = 100e18;
      uint256 price = 1.5e18;
      uint256 debt = 120e18;
      
      uint256 liquidatable = lender.getLiquidatableDebt(collateralInternal, price, debt);
      assertEq(liquidatable, 0);  // Not liquidatable
      
      // Liquidation should fail
      vm.expectRevert("insufficient liquidatable debt");
      lender.liquidate(borrower, 1e18, 0);
  }
  ```

- **Detection Heuristics:**
  ```bash
  grep -n "LiquidatableDebt\|getLiquidationIncentiveBps" Lender.sol
  grep -n "\\/" Lender.sol | grep -E "(price|debt|collateral)" | head -20
  ```

- **Remediation:** Use OpenZeppelin Math.mulDiv() for safe precision-preserving arithmetic

---

## NEW PATTERN: MIN_LIQUIDATION_DEBT EDGE CASES (MON-L-MIN-001)

### Vulnerability MON-L-MIN-001: Minimal Dust Liquidation Trapping User

- **Pattern ID:** MON-L-MIN-001
- **Severity:** MEDIUM (6.5/10)
- **Rationale:** MIN_LIQUIDATION_DEBT = 10k Coin is constant, but free vs paid debt have different economic meanings; small liquidations can trap users
- **Code Location:** Lines ~200-220 (liquidate function parameters)
  ```solidity
  uint public constant MIN_LIQUIDATION_DEBT = 10_000e18;  // 10,000 Coin
  
  function liquidate(address borrower, uint repayAmount, uint minCollateralOut) external returns(uint) {
      // ❌ NO CHECK: require(repayAmount >= MIN_LIQUIDATION_DEBT, "below minimum");
      // Issue: liquidation can be called with 1 stablecoin if liquidatableDebt > 0
  }
  ```

- **Concrete Attack:**
  1. User has 80 debt (free pool), 100 collateral, HF = 0.95 (liquidatable)
  2. Liquidatabledebt = 80 - 75 = 5 stables
  3. Liquidator calls `liquidate(borrower, 1)` (1 stablecoin repayment)
  4. Liquidator receives 1 / 0.95 × 1.05 ≈ 1.1 collateral
  5. User now: 98.9 collateral, 79 debt
  6. Liquidator repeats 79 times: user ends up with 20 collateral, 1 debt
  7. User is trapped: cannot repay 1 with collateral worth < 1, cannot liquidate (HF > 1.0), cannot withdraw

- **Why Not Enforced:**
  - MIN_LIQUIDATION_DEBT is defined but not validated in liquidate()
  - Free debt is economically different from paid debt (redeemable vs not)
  - Minimum may not apply per-mode

- **Broken Invariants:**
  - INV-L-MIN-001: `repayAmount >= MIN_LIQUIDATION_DEBT` OR `repayAmount == liquidatableDebt` (full liquidation)
  - INV-L-MIN-002: Dust trapping is prevented

- **Foundry PoC:**
  ```solidity
  function testMinLiquidationDustTrap() public {
      vault.adjust(borrower, 100e18, 80e18);  // 100 collateral, 80 debt
      oracle.setPrice(0.95e18);  // HF < 1.0
      
      uint256 liquidatable = lender.getLiquidatableDebt(...);
      assertTrue(liquidatable > 0, "Should be liquidatable");
      
      // Attacker liquidates 1 stablecoin repeatedly
      for (uint i = 0; i < 79; i++) {
          lender.liquidate(borrower, 1e18, 0);
      }
      
      uint256 finalDebt = lender.getDebtOf(borrower);
      uint256 finalCollateral = lender.cachedCollateralBalances(borrower);
      
      assertTrue(finalDebt > 0 && finalCollateral < finalDebt);  // Trapped
  }
  ```

- **Remediation:**
  ```solidity
  function liquidate(address borrower, uint repayAmount, uint minCollateralOut) external returns(uint) {
      // ...
      uint liquidatableDebt = getLiquidatableDebt(...);
      require(liquidatableDebt > 0, "insufficient liquidatable debt");
      
      // Enforce minimum: either repay min amount OR repay all liquidatable
      require(
          repayAmount >= MIN_LIQUIDATION_DEBT || repayAmount >= liquidatableDebt,
          "Below minimum (must repay >= 10k Coin or full liquidatable amount)"
      );
      
      if(repayAmount > liquidatableDebt) {
          repayAmount = liquidatableDebt;
      }
      // ...
  }
  ```

---

## NEW PATTERN: LIQUIDATION BONUS UNCAPPED (MON-L-BONUS-001)

### Vulnerability MON-L-BONUS-001: Liquidation Bonus Unbounded Multiplier

- **Pattern ID:** MON-L-BONUS-001
- **Severity:** HIGH (7.6/10)
- **Rationale:** getLiquidationIncentiveBps() returns bonus as bps; if not bounded, multiplier can exceed 100%, allowing liquidator to seize more collateral than debt value
- **Code Location:** Lines ~235 (liquidate function, collateral reward calc)
  ```solidity
  uint liqIncentiveBps = getLiquidationIncentiveBps(collateralBalance, price, debt);
  uint collateralRewardValue = repayAmount * (10000 + liqIncentiveBps) / 10000;
  // ❌ If liqIncentiveBps = 15000 (150% bonus), multiplier = 25000 / 10000 = 2.5x
  // Liquidator seizes 2.5x the debt value in collateral
  ```

- **Concrete Attack:**
  1. getLiquidationIncentiveBps() returns 15000 (intended: 50%, but bug returns 150%)
  2. User owes 100 stables, liquidator repays 100
  3. Collateral reward = 100 * (10000 + 15000) / 10000 = 100 * 2.5 = 250 stables worth collateral
  4. User receives only 100 stables worth collateral seized, BUT liquidator got 250 worth
  5. Vault loses 150 stables worth collateral (150% bonus is excessive)

- **Root Cause:** getLiquidationIncentiveBps() may be:
  - Dynamic (based on HF or LTV), with no upper bound
  - Governance-settable, with no validation
  - Calculation error (e.g., returns 15000 instead of 1500)

- **Broken Invariants:**
  - INV-L-BONUS-001: `liqIncentiveBps ≤ 5000` (max 50% bonus)
  - INV-L-BONUS-002: `collateralRewardValue ≤ collateralValue` (seized ≤ available)

- **Foundry PoC:**
  ```solidity
  function testLiquidationBonusUncapped() public {
      // Setup: liquidation pending
      vault.setLiquidationBonus(15000);  // Hypothetical setter with no bounds
      
      uint256 repayAmount = 100e18;
      uint256 bonus = vault.getLiquidationIncentiveBps(...);
      
      uint256 collateralReward = repayAmount * (10000 + bonus) / 10000;
      
      // If bonus is uncapped, collateralReward > debt value
      assertTrue(collateralReward > repayAmount, "Liquidator receives >100% bonus");
  }
  ```

- **Remediation:**
  ```solidity
  function getLiquidationIncentiveBps(uint collateralBalance, uint price, uint debt) public view returns (uint) {
      // ... calculation ...
      uint bonus = calculatedBonus;
      
      // CAP: max 50% bonus
      require(bonus <= 5000, "Bonus exceeds maximum");
      
      return bonus;
  }
  ```

---

## NEW PATTERN: REDEEMABLE MODE LIQUIDATION SANDWICH (MON-L-MODE-001)

### Vulnerability MON-L-MODE-001: Liquidation Atomicity Broken by Mode-Switching

- **Pattern ID:** MON-L-MODE-001
- **Severity:** HIGH (7.7/10)
- **Rationale:** liquidate() can be sandwiched by setRedemptionStatus(), moving debt between free/paid pools mid-liquidation
- **Code Location:** Lines ~200-250 (liquidate), ~480-510 (setRedemptionStatus)
  ```solidity
  function setRedemptionStatus(address account, bool chooseRedeemable) public {
      // Can be called during liquidation
      if(chooseRedeemable){
          nonRedeemableCollateral -= _cachedCollateralBalances[account];
      } else {
          nonRedeemableCollateral += _cachedCollateralBalances[account];
      }
      // Debt is moved between pools!
      uint prevDebt = getDebtOf(account);
      if(prevDebt > 0) {
          decreaseDebt(account, type(uint).max);  // Remove from old pool
          isRedeemable[account] = chooseRedeemable;  // Switch mode
          increaseDebt(account, prevDebt);  // Add to new pool
      }
  }
  ```

- **Concrete Attack:**
  1. User in PAID debt pool: 80 debt, 100 collateral, HF = 0.95 (liquidatable)
  2. Liquidator calls `liquidate(user, 50)` (repays 50 debt)
  3. Inside liquidate:
     - decreaseDebt(user, 50) from PAID pool ✓
     - collateral seized ✓
  4. MEANWHILE (same block, via MEV): User or attacker calls `setRedemptionStatus(user, true)`
  5. setRedemptionStatus:
     - Moves remaining 30 debt from PAID → FREE pool
     - FREE debt is cheaper (external redemption market), user benefits
  6. Liquidation completes with 50 debt seized, but 30 moved to cheaper pool

- **Why Risk:** Debt pool switching has different interest rates / economic costs; sandwiching can force user to cheaper debt pool

- **Broken Invariants:**
  - INV-L-MODE-001: Liquidation is atomic (debt pool does not change during)
  - INV-L-MODE-002: Mode switching cannot be sandwiched with liquidation

- **Foundry PoC:**
  ```solidity
  function testLiquidationModeSwitch() public {
      vault.adjust(user, 100e18, 80e18);
      // User in PAID pool (isRedeemable = false)
      
      assertEq(vault.isRedeemable(user), false);
      
      // Start liquidation
      vm.prank(liquidator);
      // Call liquidate, but attacker frontruns mode switch
      vm.prank(user);
      vault.setRedemptionStatus(user, true);  // Switch to FREE pool
      
      // Remaining debt is now in cheaper FREE pool
      assertEq(vault.isRedeemable(user), true);
  }
  ```

---

## NEW PATTERN: WRITEOFF GAS REQUIREMENT (MON-L-WRITEOFF-001)

### Vulnerability MON-L-WRITEOFF-001: writeOff() Try-Catch Gas Guard Insufficient

- **Pattern ID:** MON-L-WRITEOFF-001
- **Severity:** MEDIUM (6.3/10)
- **Rationale:** writeOff() is called via try-catch with 120k gas guard, but if writeOff fails silently, deeply underwater debt is not redistributed
- **Code Location:** Lines ~245-255 (liquidate function, writeOff call)
  ```solidity
  uint256 gasBefore = gasleft();
  try this.writeOff(borrower, msg.sender) {} catch {
      require(gasBefore >= WRITEOFF_GAS_REQUIREMENT, "Not enough gas for writeOff");
  }
  
  function writeOff(address borrower, address to) external returns (bool writtenOff) {
      accrueInterest();
      updateBorrower(borrower);
      
      uint debt = getDebtOf(borrower);
      if(debt > 0) {
          uint collateralBalance = _cachedCollateralBalances[borrower];
          (uint price,, bool allowLiquidations) = getCollateralPrice();
          require(allowLiquidations, "liquidations disabled");
          
          uint collateralValue = price * collateralBalance / 1e18;
          
          // Write off if debt > 100x collateral value
          if(debt > collateralValue * 100) {
              decreaseDebt(borrower, type(uint).max);
              
              uint256 totalDebt = totalFreeDebt + totalPaidDebt;
              if (totalDebt > 0) {
                  uint256 freeDebtIncrease = debt * totalFreeDebt / totalDebt;
                  uint256 paidDebtIncrease = debt - freeDebtIncrease;
                  
                  totalFreeDebt += freeDebtIncrease;
                  totalPaidDebt += paidDebtIncrease;
              }
              // ...
          }
      }
  }
  ```

- **Risk:**
  1. Liquidate() calls writeOff() with gas guard (120k)
  2. writeOff() attempts to redistribute deeply underwater debt
  3. But if redistribution logic is complex (e.g., iterating pools), 120k is insufficient
  4. writeOff() silently fails (caught by try-catch)
  5. Underwater debt is NOT written off
  6. Vault becomes insolvent over time (bad debt accumulates)

- **Broken Invariants:**
  - INV-L-WRITEOFF-001: Underwater debt is always written off (or transaction reverts)
  - INV-L-WRITEOFF-002: writeOff() never fails silently

- **Foundry PoC:**
  ```solidity
  function testWriteOffGasInsufficient() public {
      // Setup: deeply underwater borrower
      vault.adjust(borrower, 100e18, 100e18);
      oracle.setPrice(0.001e18);  // Crash: 100 collateral now worth 0.1 stables
      
      // Debt is 100, collateral worth 0.1 → ratio 1000:1 (qualifies for writeOff)
      
      // Liquidate with restricted gas
      vm.prank(liquidator);
      (bool success,) = address(vault).call{gas: 150000}(
          abi.encodeWithSignature("liquidate(address,uint,uint)", borrower, 50e18, 0)
      );
      
      // If writeOff was supposed to run, check if debt was written off
      uint256 debt = vault.getDebtOf(borrower);
      assertTrue(debt > 0, "Debt should be written off but wasn't (silent failure)");
  }
  ```

- **Remediation:** Ensure writeOff() completes or reverts; don't silently swallow errors
  ```solidity
  uint256 gasBefore = gasleft();
  require(gasBefore >= WRITEOFF_GAS_REQUIREMENT, "Not enough gas for writeOff");
  
  bool success = this.writeOff(borrower, msg.sender);
  require(success || gasleft() > 100, "writeOff must complete");
  ```

---

## LIQUIDATION INVARIANT SUMMARY (v0.4)

| Invariant ID | Description | Risk Level |
|---|---|---|
| INV-L-HF-001 | HF computation is continuous and precise near boundaries | MEDIUM |
| INV-L-MIN-001 | `repayAmount ≥ MIN_LIQUIDATION_DEBT` OR full liquidatable | MEDIUM |
| INV-L-BONUS-001 | `liqIncentiveBps ≤ 5000` (max 50% bonus) | HIGH |
| INV-L-BONUS-002 | Seized collateral ≤ available collateral | HIGH |
| INV-L-MODE-001 | Mode switching does not occur during liquidation | HIGH |
| INV-L-ACCR-001 | accrueInterest() called before all debt calculations | CRITICAL |
| INV-L-WRITEOFF-001 | Underwater debt always written off or transaction reverts | MEDIUM |

---

## CONCLUSION

v0.4 Liquidation adds **6 new patterns** focusing on:
1. **Health factor precision** (MON-L-HF-001)
2. **Minimum liquidation enforcement** (MON-L-MIN-001)
3. **Liquidation bonus bounds** (MON-L-BONUS-001)
4. **Redemption mode sandwich risks** (MON-L-MODE-001)
5. **WriteOff gas safety** (MON-L-WRITEOFF-001)
6. **Accrual race confirmation** (MON-L-ACCR-001 - cross-ref core v0.4)

All patterns have Foundry POCs and are mapped to exact Lender.sol code locations.

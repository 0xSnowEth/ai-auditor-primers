# MONOLITH LIQUIDATION ENGINE — COMPREHENSIVE AUDIT PRIMER

**Protocol Class:** CDP Stablecoin Liquidation & Health Factor Management  
**Scope:** Health factor computation, liquidation sequencing, oracle desync, partial repayment, insolvency edges  
**Audit Focus:** Economic exploitation, liquidator mechanics, accrual-liquidation races

---

## HEALTH FACTOR DERIVATION & COMPUTATION

### HF Formula (Overcollateralization Model)

**Health Factor Definition:**
```
HF = (Collateral Value × Liquidation LTV) / Total Debt Value
```

Where:
- **Collateral Value** = sum(assetShares[user] × assetPrice × assetIndex / PRECISION) for each collateral type (in single-collateral: simple)
- **Liquidation LTV** = maximum allowed debt-to-collateral ratio (e.g., 80%)
- **Total Debt Value** = debtShares[user] × debtIndex / PRECISION

**Numerical Example:**
```
User deposits 100 USDC worth $100
User borrows 75 stablecoins (75% LTV)
debtIndex = 1e27, assetIndex = 1e27

HF = (100 × 0.80) / 75 = 80 / 75 = 1.067

// Safe (HF > 1.0)
```

**Critical Invariant:**
```
HF >= 1.0  ↔  Not liquidatable
HF < 1.0   ↔  Liquidatable
HF → 0     ↔  Underwater (debt > collateral value)
```

### Vulnerability MON-L-001: Oracle Staleness → Liquidation Delay

- **Pattern ID:** MON-L-001
- **Severity:** HIGH (7.8/10)
- **Rationale:** If oracle price is stale (not updated recently), liquidators cannot trigger in time; collateral may crash while liquidation is delayed
- **Preconditions:** Oracle feed has staleness window (e.g., 1 hour); collateral price crashes mid-window; no fallback oracle
- **Concrete Call Sequence:**
  1. Oracle last updated 50 minutes ago: ETH = $2000, assetIndex stale
  2. ETH crashes to $1000 in real-time
  3. Liquidator calls `liquidate(user)` but oracle rejects: "price too old"
  4. User's position is actually insolvent (ETH @ $1000 < debt), but HF calculation uses $2000 price
  5. Liquidator retries after 1-hour window expires; meanwhile, user withdraws collateral or repays partially
  6. Vault becomes undercollateralized by the time liquidation fires
- **Vulnerable Code (Pseudo):**
  ```
  <computeHealthFactor(address user)> {
    uint256 collateralValue = 0;
    uint256 price = oracle.getPrice();  // ❌ No staleness check
    if (price == 0) revert("no price");  // But zero-check doesn't catch stale price
    uint256 debtValue = debtShares[user] * debtIndex / PRECISION;
    uint256 collateralValue = assetShares[user] * price * assetIndex / PRECISION;
    return (collateralValue * liquidationLtv) / debtValue;
  }
  
  <liquidate(address user)> {
    uint256 hf = <computeHealthFactor(user)>;
    require(hf < 1e18, "not liquidatable");  // ❌ HF computed with stale price
    // ... liquidation proceeds
  }
  ```
- **Broken Invariants:** INV-L-001 (oracle price is recent), INV-L-002 (liquidation fires within 1 block of insolvency)
- **Exploit Economics:** If vault holds 1M ETH and price crashes 50%, attacker can be insolvent for up to 1 hour without liquidation → $500k+ loss to vault
- **Foundry Repro:**
  ```solidity
  function testOracleStalenessBypass() public {
    // Oracle: ETH = 2000, updated 50 min ago (within 1-hour window)
    oracle.setPrice(2000e18, block.timestamp - 3000);
    
    vault.deposit(1 ether, 1500e18);  // User 75% LTV
    
    // Real price crashes to 1000
    oracle.setPrice(1000e18, block.timestamp - 3000);  // Stale timestamp
    
    uint256 hf = vault.computeHealthFactor(user);
    assertTrue(hf < 1e18);  // Insolvent
    
    // But liquidator cannot act until staleness window expires
    vm.expectRevert("price too old");
    vault.liquidate(user);
  }
  ```
- **Fix Suggestion:**
  ```
  <computeHealthFactor(address user)> {
    (uint256 price, uint256 timestamp) = oracle.getPriceWithTimestamp();
    require(block.timestamp - timestamp <= STALENESS_WINDOW, "price stale");
    // ... rest of HF logic
  }
  ```
- **Detection Heuristics:** Grep for oracle.getPrice() calls lacking staleness validation; check TWAP integration points

---

### Vulnerability MON-L-002: Health Factor Rounding Down → Premature Liquidation

- **Pattern ID:** MON-L-002
- **Severity:** MEDIUM (6.4/10)
- **Rationale:** If HF computation truncates (rounds down), users just above liquidation threshold may be incorrectly flagged
- **Preconditions:** HF calculation uses fixed-point division with truncation; user is in "fuzzy zone" near HF = 1.0
- **Concrete Call Sequence:**
  1. User HF calculated as: (100 * 80) / 8000 = 1.000000000000000001e18 (true value)
  2. But computation: (100 * 80) / 8000 = 1e18 (truncated, lost precision)
  3. User's actual HF is safely above 1.0, but code sees HF = 1.0 (boundary)
  4. Liquidator calls `liquidate(user)` with require(hf < 1.0) OR require(hf <= 1.0)?
  5. If `<=`, liquidation fires on safe user
  6. If `<`, safe user bypasses, but users with HF = 1.000...001 still liquidatable
- **Vulnerable Code (Pseudo):**
  ```
  <computeHealthFactor(address user)> returns (uint256) {
    uint256 collateralValue = assetShares[user] * price * assetIndex / PRECISION;
    uint256 debtValue = debtShares[user] * debtIndex / PRECISION;
    uint256 hf = (collateralValue * liquidationLtv * 1e18) / debtValue;  // ❌ Truncates
    return hf;  // Loses sub-wei precision
  }
  ```
- **Broken Invariants:** INV-L-003 (HF computation preserves precision at boundary)
- **Exploit Economics:** Liquidators may incorrectly target safe users; users near boundary suffer false liquidations
- **Foundry Repro:**
  ```solidity
  function testHFRoundingBoundary() public {
    // Craft params so true HF = 1.00000000001e18
    vault.deposit(10000e18, 8000e18);  // 80% LTV, just safe
    
    uint256 hf = vault.computeHealthFactor(user);
    assertTrue(hf >= 1e18);  // Should be safe
    
    // Slight price movement
    oracle.setPrice(999e15);  // Minor decrease
    
    uint256 hf2 = vault.computeHealthFactor(user);
    // If rounding is aggressive, hf2 may round down to 999...999, crossing 1.0 threshold
  }
  ```
- **Fix Suggestion:**
  ```
  <computeHealthFactor(address user)> returns (uint256) {
    uint256 collateralValue = assetShares[user] * price * assetIndex / PRECISION;
    uint256 debtValue = debtShares[user] * debtIndex / PRECISION;
    // Use uint256(collateralValue * liquidationLtv * 1e18 / debtValue) with care for overflow
    // OR use OpenZeppelin's Math.mulDiv(collateralValue * liquidationLtv, 1e18, debtValue)
    uint256 hf = Math.mulDiv(collateralValue * liquidationLtv, 1e18, debtValue);
    return hf;
  }
  ```
- **Detection Heuristics:** Audit all division operations in HF calculation; use static analysis to detect truncation points

---

## LIQUIDATION SEQUENCING & MECHANICS

### Partial Liquidation Flow

**Function Signature (Placeholder):**
```
<liquidatePartial(address user, uint256 debtToRepay)>
  requires: user is liquidatable (HF < 1.0)
  requires: debtToRepay > 0
  requires: debtToRepay <= debtOwed[user]
  requires: caller has sufficient stablecoin balance
```

**Execution Sequence:**
1. Verify user is underwater: `require(computeHealthFactor(user) < 1e18, "not liquidatable")`
2. Calculate debt repaid (with accrual): `<accrueInterest()>`
3. Convert stablecoin repayment to debt shares: `sharesToReduce = debtToRepay / debtIndex`
4. Validate partial repay doesn't leave user in "bad state": (optional, protocol-specific)
5. Calculate collateral seized: `collateralSeized = debtToRepay / price × liquidationBonus`
6. Transfer stablecoin from liquidator to vault (burn): `stablecoin.transferFrom(liquidator, vault, debtToRepay); stablecoin.burn(vault, debtToRepay);`
7. Reduce user's debt shares: `debtShares[user] -= sharesToReduce`
8. Reduce user's asset shares: `assetShares[user] -= collateralSeized / assetIndex` (in share units)
9. Transfer seized collateral to liquidator: `collateral.transfer(liquidator, collateralSeized)`
10. Emit `LiquidationPartial(user, debtRepaid, collateralSeized, liquidator)`

---

### Vulnerability MON-L-003: Partial Liquidation Dust Trapping

- **Pattern ID:** MON-L-003
- **Severity:** MEDIUM (6.6/10)
- **Rationale:** If partial liquidation can be called repeatedly with tiny amounts, liquidator can force user into underwater state while leaving user with minimal collateral
- **Preconditions:** No minimum repayment enforced; liquidationBonus is low (e.g., 5%); user position has high debt-to-collateral ratio
- **Concrete Call Sequence:**
  1. User position: 100 collateral, 80 debt (HF = 1.0, just safe)
  2. Collateral price drops to 0.95: HF = (95 × 80) / 80 = 0.95 < 1.0 (liquidatable)
  3. Liquidator calls `liquidatePartial(user, 1 stablecoin)` with 5% bonus
  4. Seize collateral: 1 / 0.95 × 1.05 ≈ 1.1 collateral seized
  5. User now: 98.9 collateral, 79 debt; HF = (98.9 × 80) / 79 ≈ 1.00 (borderline safe again)
  6. Liquidator repeats 79 more times: each call seizes ~1.1 collateral, repays 1 debt
  7. Final state: User has ~2 collateral, 1 debt; HF → 2.0 (safe, but trapped with dust)
  8. User cannot repay 1 debt with 2 collateral worth only 1.9 after fees; user is locked in
- **Vulnerable Code (Pseudo):**
  ```
  <liquidatePartial(address user, uint256 debtToRepay)> {
    require(<computeHealthFactor(user)> < 1e18, "not liquidatable");
    require(debtToRepay > 0, "zero repay");  // ❌ No minimum
    
    uint256 collateralSeized = (debtToRepay / price) * (1 + liquidationBonus) / 100;
    // ... seizure logic
  }
  ```
- **Broken Invariants:** INV-L-004 (partial liquidation leaves user in sane state), INV-L-005 (liquidation bonus does not systematically undercut user liquidity)
- **Exploit Economics:** Liquidator extracts minimal MEV per tx but can farm small liquidations; user loses 5-10% per liquidation cycle
- **Foundry Repro:**
  ```solidity
  function testPartialLiquidationDustTrapping() public {
    vault.deposit(100e18, 80e18);
    oracle.setPrice(0.95e18);  // Underwater
    
    for (uint i = 0; i < 50; i++) {
      liquidator.liquidatePartial(user, 1e18);
    }
    
    uint256 userCollateral = vault.assetShares(user) * vault.assetIndex() / 1e27;
    uint256 userDebt = vault.debtShares(user) * vault.debtIndex() / 1e27;
    
    assertLt(userCollateral, 10e18);  // Collateral drained to dust
    assertGt(userDebt, 0.1e18);  // Still has debt
  }
  ```
- **Fix Suggestion:**
  ```
  <liquidatePartial(address user, uint256 debtToRepay)> {
    require(debtToRepay >= MIN_LIQUIDATION_AMOUNT, "below minimum");
    // OR
    require(debtToRepay >= debtOwed / 10, "must liquidate >10% of debt");
  }
  ```
- **Detection Heuristics:** Search for liquidatePartial functions lacking minimum repayment checks; flag liquidation bonus calculations

---

### Vulnerability MON-L-004: Liquidation Bonus Overflow → Negative Seizure

- **Pattern ID:** MON-L-004
- **Severity:** HIGH (7.9/10)
- **Rationale:** If liquidation bonus is applied incorrectly (e.g., bonus > 100%), collateral seized can exceed debt value → attacker "earns" free collateral
- **Preconditions:** Liquidation bonus configuration error; bonus stored as percentage without normalization
- **Concrete Call Sequence:**
  1. Liquidation bonus set to 150 (meaning 150% bonus, not 15%)
  2. User underwater: 100 collateral, 80 debt
  3. Liquidator calls `liquidatePartial(user, 80)`
  4. Collateral seized = 80 / 1.0 × 150 / 100 = 120 collateral
  5. BUT user only has 100 collateral → system mints/allows seizure of non-existent 20 collateral
  6. Liquidator receives 120 collateral; vault loses 20 collateral from thin air
- **Vulnerable Code (Pseudo):**
  ```
  <liquidatePartial(address user, uint256 debtToRepay)> {
    uint256 collateralSeized = debtToRepay / price;
    collateralSeized = collateralSeized * (100 + liquidationBonus) / 100;  // ❌ Unchecked
    
    // If liquidationBonus = 150, collateralSeized multiplied by 2.5x
    assetShares[user] -= collateralSeized / assetIndex;  // ❌ Can go negative or exceed available
    collateral.transfer(liquidator, collateralSeized);  // ❌ May transfer non-existent collateral
  }
  ```
- **Broken Invariants:** INV-L-006 (liquidation bonus ≤ 50%), INV-L-007 (seized collateral ≤ available collateral)
- **Exploit Economics:** Attacker can steal entire vault liquidity via 1-2 liquidations if bonus overflows
- **Foundry Repro:**
  ```solidity
  function testLiquidationBonusOverflow() public {
    vault.setLiquidationBonus(150);  // 150% bonus
    vault.deposit(100e18, 80e18);
    
    oracle.setPrice(0.95e18);  // Underwater
    
    uint256 collateralBefore = collateral.balanceOf(address(vault));
    liquidator.liquidatePartial(user, 80e18);
    uint256 collateralAfter = collateral.balanceOf(address(vault));
    
    assertLt(collateralAfter, collateralBefore - 100e18);  // Negative transfer!
  }
  ```
- **Fix Suggestion:**
  ```
  <setLiquidationBonus(uint256 bonus)> {
    require(bonus <= 5000, "max 50%");  // Cap at 50%
    liquidationBonus = bonus;
  }
  
  <liquidatePartial(address user, uint256 debtToRepay)> {
    uint256 collateralValue = debtToRepay / price;
    uint256 bonusAmount = collateralValue * liquidationBonus / 10000;
    uint256 collateralSeized = collateralValue + bonusAmount;
    
    require(assetShares[user] * assetIndex / PRECISION >= collateralSeized, "insufficient collateral");
  }
  ```
- **Detection Heuristics:** Audit liquidation bonus configuration; check for uncapped setter functions; validate seized ≤ available

---

## DEBT-SHARE / SEIZE-SHARE MATH

### Vulnerability MON-L-005: Accrual Window Race → Stale Liquidation Price

- **Pattern ID:** MON-L-005
- **Severity:** HIGH (7.7/10)
- **Rationale:** If liquidation can occur without re-accruing interest, user's debt is stale; liquidator seizes collateral based on outdated debt value
- **Preconditions:** `accrueInterest()` not called before liquidation; accrual period is long (days/weeks); interest rates are high
- **Concrete Call Sequence:**
  1. User borrows 100 stablecoins at 50% annual rate (unrealistic, but illustrative)
  2. 1 week passes without accrual call
  3. Expected debt = 100 × (1 + 0.50 × 7 / 365) ≈ 100.96 stablecoins (should have accrued)
  4. But debtIndex remains 1e27 (no accrual)
  5. Liquidator calls `liquidatePartial(user, 100)` using stale debtIndex
  6. User's shares reduced by 100 / 1e27 shares
  7. BUT user's ACTUAL debt obligation is 100.96 (0.96 unaccounted for)
  8. Liquidator seizes collateral for repayment of 100, but actual debt is 100.96 → user benefits (less debt captured)
  9. Vault's debt-to-collateral ratio worsens
- **Vulnerable Code (Pseudo):**
  ```
  <liquidatePartial(address user, uint256 debtToRepay)> {
    // ❌ Missing <accrueInterest()>
    uint256 sharesToReduce = debtToRepay / debtIndex;  // Uses stale index
    debtShares[user] -= sharesToReduce;
    // ... seizure logic
  }
  ```
- **Broken Invariants:** INV-L-008 (liquidation uses current debtIndex), INV-L-009 (all debt mutations preceded by accrual)
- **Exploit Economics:** If vault hasn't accrued for 1 week at 50% rate, ~0.96% of debt is invisible; with 1B stables outstanding, ~9.6M stables escape liquidation accounting
- **Foundry Repro:**
  ```solidity
  function testStaleAccrualDuringLiquidation() public {
    vault.setRate(50e4);  // 50% annual
    vault.deposit(1000e18, 100e18);
    
    vm.roll(block.number + 200000);  // ~1 week of blocks
    // Do NOT call accrueInterest()
    
    uint256 debtStale = vault.debtShares(user) * vault.debtIndex() / 1e27;
    
    // Now liquidate
    liquidator.liquidatePartial(user, uint256(debtStale));  // Repay stale debt amount
    
    // User's shares reduced, but actual debt is higher
    uint256 remainingShares = vault.debtShares(user);
    vault.accrueInterest();  // Force accrual now
    uint256 remainingDebt = remainingShares * vault.debtIndex() / 1e27;
    
    assertGt(remainingDebt, 0);  // User has unaccounted debt
  }
  ```
- **Fix Suggestion:**
  ```
  <liquidatePartial(address user, uint256 debtToRepay)> {
    <accrueInterest()>;  // Always accrue first
    require(<computeHealthFactor(user)> < 1e18, "not liquidatable");
    // ... rest of logic
  }
  ```
- **Detection Heuristics:** Trace all liquidation functions; verify accrueInterest() is called before HF/debt calculations

---

## LIQUIDATION BONUS EXPLOITATION

### Vulnerability MON-L-006: Liquidation Bonus Extraction via Collateral Price Manipulation

- **Pattern ID:** MON-L-006
- **Severity:** MEDIUM (6.5/10)
- **Rationale:** If liquidation bonus is calculated as (seizedCollateral - debtValue), and collateral price is oracle-dependent, attacker can manipulate price to inflate bonus
- **Preconditions:** Collateral price is volatile (e.g., illiquid token); oracle accepts price updates from multiple sources; bonus = seizedCollateral - repaymentValue
- **Concrete Call Sequence:**
  1. User position: 100 collateral (price = 1.0, value = 100), debt = 80
  2. Attacker (controlling oracle) reports collateral price = 10.0 (inflated)
  3. Liquidator sees user underwater (HF using inflated price) and calls liquidate
  4. Bonus calculated: (100 × 10.0) - 80 = 920 (attacker's reward)
  5. Liquidator receives 100 collateral tokens worth 100 (true price = 1.0)
  6. Attacker's bonus = liquidator's collateral (100 tokens) - expected (8 tokens) = 92 tokens profit
  7. Attacker can repeat across multiple users to drain entire vault
- **Vulnerable Code (Pseudo):**
  ```
  <liquidatePartial(address user, uint256 debtToRepay)> {
    uint256 price = oracle.getPrice();  // ❌ Trusts oracle implicitly
    uint256 debtValue = debtToRepay;
    uint256 collateralValue = debtValue / price;  // Inflated if price high
    uint256 bonus = (collateralValue * liquidationBonus / 100) - debtValue;
    // bonus can be arbitrary if price is arbitrary
  }
  ```
- **Broken Invariants:** INV-L-010 (liquidation bonus ≤ percentage of debt), INV-L-011 (oracle price is validated against external sources)
- **Exploit Economics:** Attacker profits 100% per liquidation if bonus = collateralValue - debt; with 10M vault, steal entire pool
- **Foundry Repro:**
  ```solidity
  function testLiquidationBonusFromPriceInflation() public {
    vault.deposit(100e18, 80e18);
    
    // Attacker controls oracle
    oracle.setPrice(10e18);  // Inflate price 10x
    
    uint256 hf = vault.computeHealthFactor(user);
    assertTrue(hf < 1e18);  // Looks underwater
    
    uint256 seizedBefore = collateral.balanceOf(liquidator);
    liquidator.liquidatePartial(user, 80e18);
    uint256 seizedAfter = collateral.balanceOf(liquidator);
    
    uint256 bonus = seizedAfter - seizedBefore;
    assertGt(bonus, 80e18 * 0.05);  // Bonus should be small, but is huge
  }
  ```
- **Fix Suggestion:**
  ```
  <liquidatePartial(address user, uint256 debtToRepay)> {
    (uint256 price, uint256 confidence) = oracle.getPriceWithConfidence();
    require(confidence > MIN_CONFIDENCE, "price unreliable");
    
    uint256 collateralSeized = Math.mulDiv(debtToRepay, 1e18, price);
    uint256 maxBonus = collateralSeized * liquidationBonus / 10000;
    
    require(maxBonus <= VAULT_MAX_BONUS_PER_TX, "bonus cap");
  }
  ```
- **Detection Heuristics:** Audit bonus calculations; verify they are capped per-transaction; check oracle validation

---

## INSOLVENCY & UNDERWATER SCENARIOS

### Vulnerability MON-L-007: Full Liquidation Leaves User Collateral on Table

- **Pattern ID:** MON-L-007
- **Severity:** MEDIUM (6.3/10)
- **Rationale:** If full liquidation doesn't account for remaining collateral after debt is repaid, collateral can be seized excessively or left unclaimed
- **Preconditions:** Full liquidation function repays all debt + bonus, but does not adjust remaining collateral allocation
- **Concrete Call Sequence:**
  1. User: 100 collateral, 50 debt, HF = 1.6 (safe)
  2. Price crashes: HF = 0.8 (underwater)
  3. Liquidator calls `liquidateFull(user)` to close position entirely
  4. Seize collateral = 50 / 1.0 × 1.05 ≈ 52.5 (with 5% bonus)
  5. User should retain: 100 - 52.5 = 47.5 collateral
  6. BUT if function has bug, it seizes all 100 collateral + bonus (transferring 152.5 tokens)
  7. User's remaining collateral = 0; user loses 47.5 collateral
- **Vulnerable Code (Pseudo):**
  ```
  <liquidateFull(address user)> {
    uint256 debtOwed = debtShares[user] * debtIndex / PRECISION;
    uint256 collateralOwed = assetShares[user] * assetIndex / PRECISION;
    
    uint256 collateralSeized = (debtOwed / price) * (1 + liquidationBonus / 100);
    
    if (collateralSeized > collateralOwed) {
      // ❌ User is insolvent; seize all and mark uncovered loss
      assetShares[user] = 0;
      collateral.transfer(liquidator, collateralOwed);  // Transfer all, not seized amount
      // Uncovered loss = debtOwed - collateralOwed (in value)
    } else {
      // ❌ But if seized < owned, this branch might over-transfer
      assetShares[user] -= collateralSeized / assetIndex;
      collateral.transfer(liquidator, collateralSeized);
      // User retains: collateralOwed - collateralSeized
    }
  }
  ```
- **Broken Invariants:** INV-L-012 (user retains max(0, collateralOwed - seizedAmount)), INV-L-013 (total seized ≤ collateralOwed + socializedLoss)
- **Exploit Economics:** Liquidator or attacker can force seizure of excess collateral; vault becomes insolvent
- **Foundry Repro:**
  ```solidity
  function testFullLiquidationExcessSeizure() public {
    vault.deposit(100e18, 50e18);
    oracle.setPrice(0.8e18);  // Underwater
    
    uint256 collateralBefore = collateral.balanceOf(liquidator);
    vault.liquidateFull(user);
    uint256 collateralAfter = collateral.balanceOf(liquidator);
    
    uint256 seized = collateralAfter - collateralBefore;
    // Should be ~52.5e18 (50 debt / 0.8 + 5% bonus)
    assertLt(seized, 100e18);  // Not the entire vault
  }
  ```
- **Fix Suggestion:**
  ```
  <liquidateFull(address user)> {
    uint256 debtOwed = debtShares[user] * debtIndex / PRECISION;
    uint256 collateralOwed = assetShares[user] * assetIndex / PRECISION;
    
    uint256 collateralSeized = Math.min(
      Math.mulDiv(debtOwed, 1e18, price) * (10000 + liquidationBonus) / 10000,
      collateralOwed
    );
    
    debtShares[user] = 0;
    assetShares[user] = 0;
    
    collateral.transfer(liquidator, collateralSeized);
    
    if (collateralSeized < collateralOwed) {
      // Remaining collateral goes to insurance/recovery
      collateral.transfer(recoveryPool, collateralOwed - collateralSeized);
    }
  }
  ```
- **Detection Heuristics:** Audit liquidateFull logic; verify seized ≤ available; check for missing insurance fund routing

---

## LIQUIDATOR GRIEFING & MEV ATTACKS

### Vulnerability MON-L-008: Frontrunning Liquidation with Tiny Repay

- **Pattern ID:** MON-L-008
- **Severity:** MEDIUM (6.1/10)
- **Rationale:** Attacker can frontrun liquidator's transaction with partial repayment (1 wei) to push HF back above 1.0, blocking liquidation
- **Preconditions:** No delay between liquidation eligibility and execution; user can repay before block includes liquidation
- **Concrete Call Sequence:**
  1. User becomes liquidatable at block N (HF = 0.99)
  2. Liquidator creates liquidation tx in mempool
  3. Attacker (MEV searcher) sees tx, frontruns with `repay(1 stablecoin)`
  4. User's debt decreases by 1 stablecoin
  5. User's HF improves to 1.001 (now safe)
  6. Liquidator's tx reverts with "not liquidatable"
  7. Attacker can repeat: wait for HF to dip, frontrun with minimal repay, repeat infinitely
- **Vulnerable Code (Pseudo):**
  ```
  <liquidatePartial(address user, uint256 debtToRepay)> {
    require(<computeHealthFactor(user)> < 1e18, "not liquidatable");
    // ... liquidation proceeds
    // ❌ No snapshot of HF at block start; HF can improve between HF check and liquidation
  }
  ```
- **Broken Invariants:** INV-L-014 (liquidation is atomic once tx is included)
- **Exploit Economics:** Liquidators waste gas on reverted txs; user can avoid liquidation indefinitely with 1 wei per block
- **Foundry Repro:**
  ```solidity
  function testFrontrunLiquidationWithTinyRepay() public {
    vault.deposit(100e18, 80e18);
    oracle.setPrice(0.95e18);  // HF = 0.95, liquidatable
    
    // Attacker frontruns with repay(1)
    vm.prank(user);
    vault.repay(1e18);
    
    // Now HF improves
    uint256 hf = vault.computeHealthFactor(user);
    assertTrue(hf >= 1e18);  // Safe
    
    // Liquidator's tx reverts
    vm.expectRevert("not liquidatable");
    liquidator.liquidatePartial(user, 10e18);
  }
  ```
- **Fix Suggestion:**
  ```
  <liquidatePartial(address user, uint256 debtToRepay)> {
    // Snapshot HF at tx start, then liquidate atomically
    // OR implement flash liquidation (single tx to repay + seize)
    uint256 hfAtBlockStart = <computeHealthFactor(user)>;
    require(hfAtBlockStart < 1e18, "not liquidatable");
    
    // ... liquidation logic
    // HF may improve mid-tx, but HF was liquidatable at block start
  }
  ```
- **Detection Heuristics:** Check if liquidation uses current HF vs. block-start snapshot; audit for atomic liquidation patterns

---

## CROSSCUT: ORACLE DESYNC & LIQUIDATION TIMING

### Vulnerability MON-L-009: TWAP Oracle Sandwich Attack During Liquidation

- **Pattern ID:** MON-L-009
- **Severity:** HIGH (7.6/10)
- **Rationale:** If liquidation price is derived from TWAP (time-weighted average price), attacker can sandwich liquidation with large swaps to manipulate TWAP
- **Preconditions:** Oracle uses TWAP from DEX; liquidation is called mid-sandwich; attacker controls liquidity pool
- **Concrete Call Sequence:**
  1. Current TWAP: ETH = $2000
  2. User position: 100 ETH, 150,000 debt (HF = 1.33, safe)
  3. Attacker dumps 10,000 ETH on Uniswap
  4. Spot price crashes to $1000; but TWAP = $1500 (weighted average)
  5. Liquidator calls liquidate(user) using TWAP
  6. HF now = (100 × $1500 × 0.8) / 150,000 = 0.8 (liquidatable!)
  7. Liquidator repays 150,000, seizes collateral at TWAP price
  8. Attacker buys back 10,000 ETH at crashed spot price ($1000)
  9. Attacker profits from TWAP-spot spread; user is unnecessarily liquidated
- **Vulnerable Code (Pseudo):**
  ```
  <liquidatePartial(address user, uint256 debtToRepay)> {
    uint256 price = twapOracle.getPrice();  // ❌ Vulnerable to sandwich
    uint256 collateralSeized = debtToRepay / price;
    // ... liquidation at TWAP, not spot
  }
  ```
- **Broken Invariants:** INV-L-015 (liquidation price resistant to spot manipulation)
- **Exploit Economics:** Attacker gains ETH acquisition spread (e.g., $1000 vs. $1500 = 5% × 100 ETH = 5 ETH ≈ $5000 profit)
- **Foundry Repro:**
  ```solidity
  function testTWAPSandwichLiquidation() public {
    // Setup TWAP oracle backed by Uniswap V3
    vault.deposit(100e18, 150000e18);
    
    // Attacker dumps collateral
    attacker.swapToCollateral(1000e18);  // Crash spot price
    
    // TWAP lags; still ~1500
    uint256 twapPrice = oracle.getTWAP();
    
    // Liquidator uses TWAP
    liquidator.liquidatePartial(user, 150000e18);
    
    // User unfairly liquidated at TWAP, but spot is lower
    // Attacker profits on rebalance
  }
  ```
- **Fix Suggestion:**
  ```
  <liquidatePartial(address user, uint256 debtToRepay)> {
    uint256 twapPrice = oracle.getTWAP();
    uint256 spotPrice = oracle.getSpotPrice();
    
    // Use minimum of TWAP and spot, or reject if spread > threshold
    uint256 price = Math.min(twapPrice, spotPrice);
    require(Math.abs(twapPrice, spotPrice) <= MAX_PRICE_SPREAD, "oracle spread too wide");
    
    // ... liquidation at defended price
  }
  ```
- **Detection Heuristics:** Identify TWAP oracle usage; check for spot-price validation; audit liquidation price source

---

## INVARIANT CATALOG (LIQUIDATION MODULE)

| ID | Invariant | Violation Impact |
|---|---|---|
| INV-L-001 | Oracle price is recent (within staleness window) | Stale liquidation, insolvency delay |
| INV-L-002 | HF computation preserves precision at boundary (HF ≈ 1.0) | False liquidations or delayed liquidation |
| INV-L-003 | Partial liquidation leaves user in sane state (HF > 0 or zero debt) | Dust trapping, user immobility |
| INV-L-004 | Liquidation bonus ≤ X% of debt (e.g., 5%) | Over-seizure, vault insolvency |
| INV-L-005 | Liquidation uses current debtIndex (accrued) | Debt undertracking, liquidation undercharge |
| INV-L-006 | Liquidation bonus ≤ 50% | Attacker profiteering via inflated bonus |
| INV-L-007 | Seized collateral ≤ available collateral | Phantom seizure, negative collateral |
| INV-L-008 | All debt mutations in liquidation atomic (accrual + repay + seize) | Race conditions, partial state updates |
| INV-L-009 | User retains max(0, collateralValue - seizedValue) after liquidation | User fund loss, vault overseizure |
| INV-L-010 | Liquidation is not bypassable with 1-wei repay | MEV liquidation griefing |
| INV-L-011 | Oracle price validated against external sources or confidence interval | Price manipulation during liquidation |
| INV-L-012 | HF is monotonic w.r.t. collateral price (dHF/dPrice > 0) | HF inversion, inverted liquidation logic |
| INV-L-013 | Liquidation bonus cap per transaction | Liquidator MEV extraction |
| INV-L-014 | TWAP-spot spread is monitored; liquidation rejects if spread > threshold | Sandwich liquidation attacks |
| INV-L-015 | User HF cannot improve retroactively after liquidation begins | Liquidation reversal, griefing |
| INV-L-016 | Liquidator must repay debt in stablecoin (not collateral) | Circular liquidation, collateral doublecount |
| INV-L-017 | Insolvency flag prevents further borrowing/withdrawal | Insolvent users cannot evade liquidation |
| INV-L-018 | Liquidation bonus source is tracked (insurance fund, protocol, liquidator) | Fee misrouting during liquidation |
| INV-L-019 | Collateral seizure respects assetShares precision | Rounding losses in seized amount |
| INV-L-020 | Partial liquidation repay amount is audited against available debt | Over-repayment, negative debt shares |

---

## FOUNDRY TEST SKELETONS (LIQUIDATION)

### Skeleton 1: Health Factor Boundary Testing
```solidity
contract MonolithLiquidationHFTest is Test {
  Vault vault;
  address user = address(0x111);
  address liquidator = address(0x222);
  
  function setUp() public {
    // Deploy vault, set oracle, rate controller, etc.
  }
  
  function testHFAtBoundary() public {
    vault.deposit(100e18, 75e18);  // 75% LTV, HF = 1.067
    
    // Price movement to HF = 1.0 exactly
    uint256 targetPrice = 75e18 * 1.067 / 100;  // Solve for price where HF = 1.0
    oracle.setPrice(targetPrice);
    
    uint256 hf = vault.computeHealthFactor(user);
    assertTrue(hf >= 1e18);  // Should be safe or boundary
  }
  
  function testLiquidationTriggersUnderThreshold() public {
    vault.deposit(100e18, 80e18);  // Just below safe
    oracle.setPrice(0.95e18);  // Underwater
    
    assertTrue(vault.computeHealthFactor(user) < 1e18);
    
    // Liquidation should succeed
    vm.prank(liquidator);
    vault.liquidatePartial(user, 10e18);
    
    assertEq(vault.debtShares(user), vault.debtShares(user) - 10e18 / vault.debtIndex() * vault.debtIndex() / 1e27);
  }
}
```

### Skeleton 2: Accrual-Liquidation Race
```solidity
contract MonolithAccrualLiquidationRaceTest is Test {
  Vault vault;
  address user = address(0x111);
  
  function testStaleAccrualDuringLiquidation() public {
    vault.setRate(50e4);  // 50% APY
    vault.deposit(1000e18, 100e18);
    
    vm.roll(block.number + 100000);  // 1 week, no accrual
    
    uint256 expectedDebt = 100e18 + 100e18 * 50e4 / 10000 / 52;  // Rough accrued
    
    // Liquidate with stale debtIndex
    liquidator.liquidatePartial(user, 50e18);
    
    // Force accrual
    vault.accrueInterest();
    uint256 remainingDebt = vault.debtShares(user) * vault.debtIndex() / 1e27;
    
    // Verify debt tracking
    assertTrue(remainingDebt > 0);
  }
}
```

### Skeleton 3: Partial Liquidation Edge Cases
```solidity
contract MonolithPartialLiquidationEdgeTest is Test {
  Vault vault;
  
  function testMinimalRepaymentGuard() public {
    vault.deposit(100e18, 80e18);
    oracle.setPrice(0.95e18);
    
    // Attempt to liquidate 1 wei
    vm.expectRevert("below minimum");
    liquidator.liquidatePartial(user, 1);
  }
  
  function testExcessRepaymentRejection() public {
    vault.deposit(100e18, 80e18);
    oracle.setPrice(0.95e18);
    
    // Attempt to liquidate more than owed
    vm.expectRevert("exceeds debt");
    liquidator.liquidatePartial(user, 100e18);  // More than 80 borrowed
  }
}
```

---

✓ **Module Complete.**

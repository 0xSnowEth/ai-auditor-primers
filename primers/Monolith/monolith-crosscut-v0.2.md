# MONOLITH CROSSCUTTING CONCERNS — ADVANCED AUDIT PRIMER v0.2

**Protocol Class:** Oracle Integration, Rate Control, Factory-Vault Sync, State Desync  
**Scope:** Multi-oracle consensus, rate controller exploits, reentrancy, upgradeability, race conditions  
**Audit Focus:** System-wide invariants, state desynchronization, cross-contract attacks  
**Version:** 0.2 (Self-Evolved with Research Integration)

---

## ORACLE ARCHITECTURE & THREAT SURFACE

### Multi-Feed Oracle Design

**Oracle Pattern (Monolith Standard):**
```
Oracle Interface:
  - getPrice() → uint256
  - getPriceWithTimestamp() → (uint256 price, uint256 timestamp)
  - getPrices() → uint256[] (multi-feed)
  - getMedianPrice() → uint256 (consensus)
  - isStale(uint256 threshold) → bool
```

**Common Implementations:**
- Chainlink (decentralized feed)
- Uniswap V3 TWAP (liquidity-based)
- Pyth/Band Protocol (oracle aggregator)
- Curve Oracle (LP price)

---

### Vulnerability MON-X-001: Stale Medianizer → Liquidation Desync

- **Pattern ID:** MON-X-001
- **Severity:** HIGH (7.9/10)
- **Rationale:** If oracle returns median of prices where some sources are stale, median itself can be stale without detection
- **Preconditions:** Multi-feed oracle (e.g., Chainlink nodes); some nodes update slowly; staleness check on median, not individual feeds
- **Concrete Call Sequence:**
  1. Oracle has 5 price feeds: [2000, 2010, 2020, 2030, 1500 (stale, 2 hours old)]
  2. Median = 2010 (middle value)
  3. Staleness check: block.timestamp - 2010_updateTime = 10 minutes (within window)
  4. BUT one feed is 2 hours stale; market has crashed to 1900 in reality
  5. Liquidator uses price 2010 (stale median)
  6. User appears safe with this inflated price
  7. Vault becomes undercollateralized when price discovers crash
- **Vulnerable Code (Pseudo):**
  ```
  <getMedianPrice()> {
    uint256[] prices = new uint256[](feeds.length);
    for (uint i = 0; i < feeds.length; i++) {
      (uint256 price, uint256 timestamp) = feeds[i].getPrice();
      prices[i] = price;
      // ❌ No per-feed staleness check
    }
    uint256 medianPrice = calculateMedian(prices);
    
    require(block.timestamp - lastUpdate < STALENESS_WINDOW, "median stale");  // ❌ Checks lastUpdate, not individual timestamps
    return medianPrice;
  }
  ```
- **Broken Invariants:** INV-X-001 (all price feeds are recent), INV-X-002 (median computed from non-stale prices only)
- **Exploit Economics:** Attacker can delay reporting from 2-3 feeds, causing median to incorporate stale data; liquidation delays compound vault losses
- **Foundry Repro:**
  ```solidity
  function testStaleMedianizerDetection() public {
    // 5 feeds: 4 recent, 1 stale
    oracle.updateFeed(0, 2000e18, block.timestamp);
    oracle.updateFeed(1, 2010e18, block.timestamp);
    oracle.updateFeed(2, 2020e18, block.timestamp);
    oracle.updateFeed(3, 2030e18, block.timestamp);
    oracle.updateFeed(4, 1500e18, block.timestamp - 2 hours);  // Stale
    
    uint256 median = oracle.getMedianPrice();
    assertEq(median, 2010e18);  // Median is recent price
    
    assertFalse(oracle.isStale(1 hours));  // Median passes staleness check
    // But one feed is 2 hours stale!
  }
  ```
- **Fix Suggestion:**
  ```
  <getMedianPrice()> {
    uint256[] prices = new uint256[](feeds.length);
    uint256 mostRecentTimestamp = 0;
    
    for (uint i = 0; i < feeds.length; i++) {
      (uint256 price, uint256 timestamp) = feeds[i].getPrice();
      require(block.timestamp - timestamp <= STALENESS_WINDOW, "feed stale");  // Per-feed check
      prices[i] = price;
      mostRecentTimestamp = max(mostRecentTimestamp, timestamp);
    }
    
    // Require majority of feeds within stricter window
    uint256 recentCount = 0;
    for (uint i = 0; i < feeds.length; i++) {
      if (block.timestamp - feeds[i].timestamp() <= STALENESS_WINDOW / 2) {
        recentCount++;
      }
    }
    require(recentCount >= feeds.length / 2 + 1, "insufficient recent feeds");
    
    return calculateMedian(prices);
  }
  ```
- **Detection Heuristics:** Audit oracle median logic; verify per-feed staleness checks; check for "most recent" timestamp tracking

---

### Vulnerability MON-X-002: Medianizer Manipulation via Feed Deviation

- **Pattern ID:** MON-X-002
- **Severity:** MEDIUM (6.7/10)
- **Rationale:** Attacker controlling one price feed can skew median by reporting extreme prices, especially if adjacent feeds cluster
- **Preconditions:** Multi-feed oracle with no outlier-rejection logic; attacker controls or compromises one feed
- **Concrete Call Sequence:**
  1. Feeds report: [2000, 2010, 2020]
  2. Median = 2010
  3. Attacker's feed (previously trusted) reports: 3000 (fake spike)
  4. New feeds: [2000, 2010, 2020, 3000, 3100] (attacker can update multiple times)
  5. After sorting: [2000, 2010, 2020, 3000, 3100]; median = 2020
  6. Attacker then reports even higher: [2000, 2010, 2020, 5000]
  7. Median = 2020 still, but attacker is "pushing" the boundary
  8. If attacker controls 2 feeds: [2000, 3000, 3100]; median = 3000 (inflated 50%)
  9. Attacker deposits collateral at inflated prices, liquidates others unfairly
- **Vulnerable Code (Pseudo):**
  ```
  <updatePriceFromFeed(uint256 feedId, uint256 newPrice)> {
    require(msg.sender == feedOwner[feedId], "unauthorized");
    prices[feedId] = newPrice;  // ❌ No sanity check, no deviation limit
    lastUpdate[feedId] = block.timestamp;
  }
  ```
- **Broken Invariants:** INV-X-003 (price feed changes are bounded per-block), INV-X-004 (price is resistant to single-feed manipulation)
- **Exploit Economics:** If attacker controls 2/5 feeds and median is simple midpoint, attacker can move median 20-50% in preferred direction
- **Foundry Repro:**
  ```solidity
  function testMedianManipulationViaFeedDeviation() public {
    oracle.updateFeed(0, 2000e18, block.timestamp);
    oracle.updateFeed(1, 2010e18, block.timestamp);
    oracle.updateFeed(2, 2020e18, block.timestamp);
    
    uint256 median1 = oracle.getMedianPrice();
    assertEq(median1, 2010e18);
    
    // Attacker controls feed 3, reports fake spike
    vm.prank(feedOwner3);
    oracle.updateFeed(3, 3000e18, block.timestamp);  // Extreme
    
    // Add feed 4 (attacker-controlled)
    oracle.addFeed(attackerOracle);
    vm.prank(attacker);
    oracle.updateFeed(4, 3100e18, block.timestamp);  // Extreme
    
    uint256 median2 = oracle.getMedianPrice();
    assertGt(median2, 2020e18);  // Median shifted upward despite attacker not controlling majority
  }
  ```
- **Fix Suggestion:**
  ```
  <updatePriceFromFeed(uint256 feedId, uint256 newPrice)> {
    require(msg.sender == feedOwner[feedId], "unauthorized");
    
    uint256 oldPrice = prices[feedId];
    uint256 change = Math.abs(newPrice - oldPrice) * 100 / oldPrice;
    require(change <= MAX_DEVIATION_PER_UPDATE, "price deviation too high");  // e.g., 10% per update
    
    prices[feedId] = newPrice;
    lastUpdate[feedId] = block.timestamp;
  }
  ```
- **Detection Heuristics:** Search for price feed update functions lacking deviation caps; audit feed-weighting logic

---

### Vulnerability MON-X-003: TWAP Oracle Sandwich Attack (Detailed)

- **Pattern ID:** MON-X-003
- **Severity:** HIGH (7.7/10)
- **Rationale:** TWAP oracles can be manipulated by large swaps that temporarily move spot price, affecting time-weighted calculation
- **Preconditions:** Oracle uses Uniswap V3 TWAP; attacker has capital for large swap; liquidation uses TWAP price
- **Concrete Call Sequence:**
  1. Uniswap V3 pool: 1,000,000 ETH / 1,000,000,000 USDC (1 ETH = 1000 USDC)
  2. TWAP over last hour = 1000 USDC/ETH (stable)
  3. User position: 100 ETH, 75,000 USDC debt (HF = 1.33, safe)
  4. Attacker swaps 100,000 USDC for ~95 ETH (large impact, price moves to 950 USDC/ETH)
  5. Liquidator observes HF < 1.0 (using TWAP ≈ 975 USDC/ETH)
  6. Liquidator calls liquidate(user), seizing collateral at TWAP price
  7. Attacker immediately reverses: swaps 95 ETH back to market, pockets fee differential
  8. User unfairly liquidated; attacker profits on swap arbs + liquidation bonus
- **Vulnerable Code (Pseudo):**
  ```
  <liquidatePartial(address user, uint256 debtToRepay)> {
    (uint128 liquidity, uint256 timestamp) = uniswapPool.observe(TWAP_INTERVAL);
    uint256 twapPrice = liquidity.toPrice();  // ❌ Uses TWAP directly without spot validation
    
    uint256 collateralSeized = debtToRepay / twapPrice;
    // ... seizure
  }
  ```
- **Broken Invariants:** INV-X-005 (liquidation price is sandwich-resistant), INV-X-006 (TWAP-spot spread is monitored)
- **Exploit Economics:** Attacker profits on swap arb (0.3-1% fee on ~100k USDC) + liquidation bonus (5% of seized collateral) = ~1000 USDC + 5 ETH ≈ $6000+
- **Foundry Repro:**
  ```solidity
  function testTWAPSandwichLiquidation() public {
    // Setup: Uniswap V3 pool with ETH/USDC
    // User: 100 ETH, 75k USDC debt
    vault.deposit(100e18, 75000e18);
    
    // Attacker swaps to crash spot price
    attacker.swapExactInputForOutput(100000e18, minOutput, path);  // Sell 100k USDC for ETH
    
    // TWAP lags; still ~975 USDC/ETH
    uint256 twap = oracle.getTWAPPrice();
    
    // User appears borderline insolvent at TWAP
    liquidator.liquidatePartial(user, 40000e18);
    
    // Attacker reverses, pockets arb
    attacker.swapExactInputForOutput(minInput, 100000e18, path);  // Buy back USDC
  }
  ```
- **Fix Suggestion:**
  ```
  <liquidatePartial(address user, uint256 debtToRepay)> {
    uint256 twapPrice = uniswapOracle.getTWAPPrice();
    uint256 spotPrice = uniswapPool.getSpotPrice();
    
    // Reject if spread is too wide
    uint256 spread = Math.abs(twapPrice, spotPrice) * 100 / twapPrice;
    require(spread <= MAX_ORACLE_SPREAD, "oracle spread exceeded");  // e.g., 2%
    
    // Use more conservative price
    uint256 liquidationPrice = Math.min(twapPrice, spotPrice);
    
    uint256 collateralSeized = debtToRepay / liquidationPrice;
    // ... rest of liquidation
  }
  ```
- **Detection Heuristics:** Grep for TWAP oracle usage in liquidation; check for spot-price validation; audit oracle spread handling

---

## FACTORY-VAULT-CONTROLLER DESYNC

### Vulnerability MON-X-004: Factory Parameter Change Without Vault Update

- **Pattern ID:** MON-X-004
- **Severity:** MEDIUM (6.4/10)
- **Rationale:** If factory parameters (LTV, liquidation threshold) change after vault deployment, old vaults retain stale parameters
- **Preconditions:** Factory is upgradeable or has mutable parameters; deployed vaults do not track factory state
- **Concrete Call Sequence:**
  1. Factory deploys vault-A with LTV = 80%, liquidationThreshold = 75%
  2. Months later, governance updates factory to LTV = 70% (risk adjustment)
  3. Vault-A still uses 80% LTV (immutable at deployment time)
  4. New deposits to vault-A assume 80% LTV, but protocol expects 70%
  5. Attacker can exploit the gap: deposit at 80%, then protocol rebalances expecting 70%
  6. Attacker is over-leveraged relative to updated risk model
- **Vulnerable Code (Pseudo):**
  ```
  <deployVault(
    address _collateral,
    uint256 _ltv,
    uint256 _liquidationThreshold
  )> {
    Vault vault = new Vault();
    vault.initialize(
      _collateral,
      address(stablecoin),
      address(oracle),
      address(rateController),
      _ltv,              // ❌ Copied at deployment, not factory reference
      _liquidationThreshold,
      borrowFee
    );
    return address(vault);
  }
  ```
- **Broken Invariants:** INV-X-007 (all vaults use consistent risk parameters)
- **Exploit Economics:** If LTV changes from 80% to 70%, attacker can borrow at 80% for 1-2 blocks before governance realizes, extracting value from newer users
- **Foundry Repro:**
  ```solidity
  function testFactoryParameterDrift() public {
    (address vault1, ) = factory.deployVault(collateral, "STAB-A", 8000, 7500, 100);  // 80% LTV
    
    // Factory updates parameters
    factory.setDefaultLTV(7000);  // 70% LTV
    
    // Deployed vault still uses 80%
    assertEq(vault1.ltv(), 8000);  // Unchanged
    
    // New vault gets 70%
    (address vault2, ) = factory.deployVault(collateral, "STAB-B", 7000, 6500, 100);
    assertEq(vault2.ltv(), 7000);
  }
  ```
- **Fix Suggestion:**
  ```
  <Vault.initialize(
    ...,
    address _factory,
    ...
  )> {
    factory = _factory;  // Store factory reference
  }
  
  <getCurrentLTV()> returns (uint256) {
    return factory.getDefaultLTV();  // Dynamic reference
  }
  
  <deposit(uint256 collateral, uint256 debt)> {
    uint256 currentLTV = <getCurrentLTV()>;
    require(<computeHealthFactor(user, currentLTV)> >= 1e18, "exceeds LTV");
  }
  ```
- **Detection Heuristics:** Check if vaults store factory reference or copy parameters; audit parameter update logic in factory

---

### Vulnerability MON-X-005: Rate Controller Update Races

- **Pattern ID:** MON-X-005
- **Severity:** MEDIUM (6.5/10)
- **Rationale:** If rate controller can be updated mid-block, accrual logic can use two different rates in single block, causing divergence
- **Preconditions:** RateController upgrade not gated by timelock; multiple accrual calls in single block
- **Concrete Call Sequence:**
  1. RateController set to 5% annual
  2. Block N: Attacker calls `vault.accrueInterest()` at 5%
  3. Block N (same): Attacker calls `factory.setRateController(newController)` (with 50% rate)
  4. Block N (same): Attacker calls `vault.accrueInterest()` again, but vault references old controller (5%)
  5. OR: If vault updates immediately, attacker's second accrual uses 50%, doubling interest
  6. Attacker can selectively update rate before borrowing (set to 0%) or after (set to 1000%), depending on position
- **Vulnerable Code (Pseudo):**
  ```
  <setRateController(address newController)> {
    require(msg.sender == owner, "unauthorized");
    rateController = newController;  // ❌ Immediate update, no delay
  }
  
  <accrueInterest()> {
    uint256 rate = rateController.getRate();  // Uses live controller
    // ... accrual with rate
  }
  ```
- **Broken Invariants:** INV-X-008 (rate controller changes require timelock), INV-X-009 (interest rate is fixed per block)
- **Exploit Economics:** Attacker can borrow at 0% rate, then set rate to 1000%, forcing others to pay high interest while attacker escapes
- **Foundry Repro:**
  ```solidity
  function testRateControllerUpdateRace() public {
    vault.setRateController(address(controller1));  // 5%
    vault.setRate(500);
    
    vault.deposit(100e18, 50e18);  // Borrow at 5%
    
    // Same block: update controller to 50%
    vault.setRateController(address(controller2));
    controller2.setRate(5000);
    
    // Which rate was used? Vulnerability if inconsistent
    uint256 debtBefore = vault.debtShares(attacker) * vault.debtIndex() / 1e27;
    
    vault.accrueInterest();
    
    uint256 debtAfter = vault.debtShares(attacker) * vault.debtIndex() / 1e27;
    
    // If using old rate: debtAfter ≈ debtBefore * 1.000002 (small jump)
    // If using new rate: debtAfter ≈ debtBefore * 1.000052 (larger jump)
    // Inconsistency = vulnerability
  }
  ```
- **Fix Suggestion:**
  ```
  <setRateController(address newController)> {
    require(msg.sender == owner, "unauthorized");
    pendingRateController = newController;
    rateControllerUpdateTime = block.timestamp + CONTROLLER_UPDATE_DELAY;
  }
  
  <accrueInterest()> {
    if (block.timestamp >= rateControllerUpdateTime && pendingRateController != address(0)) {
      rateController = pendingRateController;
      pendingRateController = address(0);
    }
    // Use rateController (locked at block start)
    uint256 rate = rateController.getRate();
  }
  ```
- **Detection Heuristics:** Check rate controller setters for timelock; verify accrual uses consistent controller per block

---

## REENTRANCY & STATE DESYNC

### Vulnerability MON-X-006: Reentrancy in Deposit via ERC20 Callback

- **Pattern ID:** MON-X-006
- **Severity:** CRITICAL (9.2/10)
- **Rationale:** If collateral is ERC20-with-callbacks (e.g., ERC777, ERC1363), reentrancy during transferFrom can allow attacker to manipulate state mid-operation
- **Preconditions:** Collateral implements onTransferReceived hook; vault does not use reentrancy guard
- **Concrete Call Sequence:**
  1. Attacker deploys ERC777 token as collateral (or compromised token)
  2. Attacker calls `vault.deposit(1000 tokens, 100 debt)`
  3. Vault: transfers 1000 tokens to vault: `collateral.transferFrom(attacker, vault, 1000)`
  4. ERC777 callback triggered: `tokensReceived(vault, attacker, 1000)`
  5. Attacker's callback reenters `vault.deposit(0, 50)` (0 collateral, 50 debt)
  6. Second deposit: assetShares increase (using original 1000 tokens), debtShares increase by 50
  7. Second deposit completes, callback returns
  8. First deposit continues: debtShares increased by 100, but assetShares already counted for second deposit
  9. Final state: assetShares counted for 50 debt, but totalDebtShares increased by 150
  10. Vault is under-collateralized (shares out of sync)
- **Vulnerable Code (Pseudo):**
  ```
  <deposit(uint256 collateralAmount, uint256 debtAmount)> {
    // ❌ No reentrancy guard
    collateralToken.transferFrom(msg.sender, address(this), collateralAmount);  // ← Callback here
    assetShares[msg.sender] += collateralAmount / assetIndex;  // Can be called reentrantly
    debtShares[msg.sender] += debtAmount / debtIndex;
    stablecoin.mint(msg.sender, debtAmount);
  }
  ```
- **Broken Invariants:** INV-X-010 (deposit is atomic, no reentrancy)
- **Exploit Economics:** Attacker can double-mint debt without proportional collateral; with 1000 collateral, borrow 200 debt instead of 100
- **Foundry Repro:**
  ```solidity
  contract MaliciousCollateral is ERC777 {
    Vault vault;
    
    function tokensReceived(
      address operator,
      address from,
      address to,
      uint256 amount,
      bytes calldata userData,
      bytes calldata operatorData
    ) external {
      // Reenter vault
      if (amount == 1000e18) {  // First deposit
        vault.deposit(0, 50e18);  // Reentrant deposit
      }
    }
  }
  
  function testReentrancyViaBorrow() public {
    MaliciousCollateral evil = new MaliciousCollateral(vault);
    
    vm.prank(attacker);
    evil.approve(address(vault), 1000e18);
    
    vm.prank(attacker);
    vault.deposit(1000e18, 100e18);  // Triggers reentrant callback
    
    uint256 totalDebt = vault.debtShares(attacker) * vault.debtIndex() / 1e27;
    assertGt(totalDebt, 100e18);  // Borrow increased without collateral
  }
  ```
- **Fix Suggestion:**
  ```
  contract Vault {
    uint256 private locked;
    
    modifier nonReentrant() {
      require(locked == 0, "reentrancy");
      locked = 1;
      __;
      locked = 0;
    }
    
    <deposit(uint256 collateralAmount, uint256 debtAmount)> nonReentrant {
      collateralToken.transferFrom(msg.sender, address(this), collateralAmount);
      assetShares[msg.sender] += collateralAmount / assetIndex;
      debtShares[msg.sender] += debtAmount / debtIndex;
      stablecoin.mint(msg.sender, debtAmount);
    }
  }
  ```
- **Detection Heuristics:** Identify all external calls (transferFrom, transfer, mint); check for reentrancy guards; flag ERC777 or callback-enabled tokens

---

### Vulnerability MON-X-007: State Divergence in Liquidation via Reentrancy

- **Pattern ID:** MON-X-007
- **Severity:** HIGH (7.8/10)
- **Rationale:** If liquidation transfers collateral without reentrancy guard, attacker can reenter to check HF before state is fully updated
- **Preconditions:** Collateral implements callback; liquidation transfers before clearing debt shares
- **Concrete Call Sequence:**
  1. Liquidator calls `liquidatePartial(user, 50)`
  2. Vault transfers collateral: `collateral.transfer(liquidator, 52.5)` (with bonus)
  3. Attacker's callback reenters: `liquidatePartial(user, 50)` again
  4. Second liquidation checks HF, but user's debt hasn't been reduced yet (transfer was first)
  5. User still appears underwater; second liquidation proceeds
  6. User gets liquidated twice with same collateral
- **Vulnerable Code (Pseudo):**
  ```
  <liquidatePartial(address user, uint256 debtToRepay)> {
    require(<computeHealthFactor(user)> < 1e18, "not liquidatable");
    
    uint256 collateralSeized = (debtToRepay / price) * (1 + liquidationBonus / 100);
    collateral.transfer(liquidator, collateralSeized);  // ← Callback triggers here, before state update
    
    debtShares[user] -= debtToRepay / debtIndex;  // ❌ State mutation AFTER external call
  }
  ```
- **Broken Invariants:** INV-X-011 (liquidation is atomic, no reentrant calls)
- **Exploit Economics:** Attacker can double-liquidate to extract 2x bonus; with 100 collateral and 80 debt, steal 105 collateral total
- **Foundry Repro:**
  ```solidity
  function testLiquidationReentrancy() public {
    vault.deposit(100e18, 80e18);
    oracle.setPrice(0.95e18);
    
    uint256 seizedBefore = collateral.balanceOf(liquidator);
    
    // Create reentrant liquidator
    ReentrantLiquidator evil = new ReentrantLiquidator(vault);
    evil.liquidatePartial(user, 40e18);
    
    uint256 seizedAfter = collateral.balanceOf(liquidator);
    uint256 seized = seizedAfter - seizedBefore;
    
    // Should be ~42e18 (40 debt / 0.95 + 5% bonus)
    assertLt(seized, 100e18);  // But if reentrancy successful, seized > 100e18
  }
  ```
- **Fix Suggestion:**
  ```
  <liquidatePartial(address user, uint256 debtToRepay)> nonReentrant {
    require(<computeHealthFactor(user)> < 1e18, "not liquidatable");
    
    // Update state BEFORE external call
    debtShares[user] -= debtToRepay / debtIndex;
    assetShares[user] -= ...;
    
    // Now transfer (callback cannot reenter because locked)
    uint256 collateralSeized = ...;
    collateral.transfer(liquidator, collateralSeized);
  }
  ```
- **Detection Heuristics:** Check liquidation functions for external calls before state updates; verify reentrancy guards

---

### Vulnerability MON-X-008: Storage Slot Collision in Proxy Upgrades

- **Pattern ID:** MON-X-008
- **Severity:** HIGH (9.3/10)
- **Rationale:** If vault is upgraded and new implementation has different storage layout, critical variables can be overwritten
- **Preconditions:** Vault is UUPS proxy; new implementation adds/removes variables without care for slot ordering
- **Concrete Call Sequence:**
  1. VaultV1 storage: [debtIndex (slot 0), assetIndex (slot 1), lastAccrualBlock (slot 2)]
  2. VaultV2 adds `newVariable` at slot 1: [debtIndex (slot 0), newVariable (slot 1), assetIndex (slot 2), lastAccrualBlock (slot 3)]
  3. Upon upgrade, proxy delegates to VaultV2
  4. Old assetIndex value (stored in slot 1) is now interpreted as newVariable
  5. New assetIndex is in slot 2 (was lastAccrualBlock), containing old lastAccrualBlock value
  6. Collateral valuations become corrupted
- **Vulnerable Code (Pseudo):**
  ```
  // VaultV1
  contract Vault {
    uint256 public debtIndex;          // slot 0
    uint256 public assetIndex;         // slot 1
    uint256 public lastAccrualBlock;   // slot 2
  }
  
  // VaultV2 (WRONG)
  contract VaultV2 {
    uint256 public debtIndex;          // slot 0 ✓
    uint256 public newVariable;        // slot 1 ❌ Overwrites assetIndex
    uint256 public assetIndex;         // slot 2 ❌ Reads lastAccrualBlock value
    uint256 public lastAccrualBlock;   // slot 3
  }
  ```
- **Broken Invariants:** INV-X-012 (storage layout immutable across upgrades)
- **Exploit Economics:** Corrupted assetIndex/debtIndex leads to insolvency; vault can be drained
- **Foundry Repro:**
  ```solidity
  function testStorageSlotCollision() public {
    Vault v1 = new Vault();
    v1.initialize(...);
    
    // Set values
    vm.store(address(v1), bytes32(uint256(0)), bytes32(uint256(1e27)));  // debtIndex
    vm.store(address(v1), bytes32(uint256(1)), bytes32(uint256(2e27)));  // assetIndex
    
    // Upgrade (VaultV2 has wrong layout)
    proxy.upgradeTo(address(vaultV2Impl));
    
    // Read values from proxy
    uint256 debtIndex = vm.load(address(proxy), bytes32(uint256(0)));
    uint256 assetIndex = vm.load(address(proxy), bytes32(uint256(1)));
    
    assertEq(debtIndex, 1e27);  // Still correct
    assertNotEq(assetIndex, 2e27);  // CORRUPTED!
  }
  ```
- **Fix Suggestion:**
  ```
  // VaultV2 (CORRECT)
  contract VaultV2 {
    uint256 public debtIndex;          // slot 0 ✓
    uint256 public assetIndex;         // slot 1 ✓ Keep in same slot
    uint256 public lastAccrualBlock;   // slot 2 ✓
    uint256 public newVariable;        // slot 3 ✓ Add at the end
  }
  
  // OR use gaps
  contract VaultV2 {
    uint256 public debtIndex;
    uint256 public assetIndex;
    uint256 public lastAccrualBlock;
    uint256[48] private __gap;  // Reserve space for future variables
    uint256 public newVariable;
  }
  ```
- **Detection Heuristics:** Audit storage layout before/after upgrades; use vm.load() to verify slot occupancy matches expectations

---

### Vulnerability MON-X-009: Uninitialized Proxy Implementation Takeover

- **Pattern ID:** MON-X-009
- **Severity:** CRITICAL (9.5/10)
- **Rationale:** If vault implementation is stored in proxy but initialize() is not locked, attacker can call initialize on implementation directly
- **Preconditions:** Vault is UUPS proxy; initialize() in implementation is not locked; attacker can call implementation address directly
- **Concrete Call Sequence:**
  1. Factory deploys proxy pointing to Vault implementation
  2. Proxy calls initialize() via proxy delegatecall
  3. BUT if implementation contract is also deployed separately (accessible at address), attacker can call initialize directly on implementation
  4. Attacker calls `vaultImplementation.initialize(attacker_oracle, attacker_controller, ...)`
  5. Implementation storage (oracle, controller) is now attacker-controlled
  6. If vault proxy later calls implementation (after upgrade), it uses attacker-set values
  7. OR: If implementation initializer is not locked and proxy calls non-init functions, implementation state diverges
- **Vulnerable Code (Pseudo):**
  ```
  // Vault implementation (standalone)
  contract Vault {
    uint256 debtIndex;
    address oracle;
    bool initialized;
    
    <initialize(address _oracle)> {
      require(!initialized, "already init");
      oracle = _oracle;  // ❌ Anyone can call on impl directly
      initialized = true;
    }
  }
  
  // Proxy
  contract VaultProxy {
    address implementation;
    
    fallback() external {
      delegatecall(implementation);
    }
  }
  ```
- **Broken Invariants:** INV-X-013 (initialize can only be called on proxy, not implementation)
- **Exploit Economics:** Attacker gains oracle/controller control, can drain all vault liquidity
- **Foundry Repro:**
  ```solidity
  function testImplementationInitializationTakeover() public {
    Vault vaultImpl = new Vault();  // Standalone implementation
    VaultProxy proxy = new VaultProxy(address(vaultImpl));
    
    // Attacker calls initialize on standalone impl
    vm.prank(attacker);
    vaultImpl.initialize(attacker_oracle, attacker_controller, ...);
    
    // Implementation now has attacker-controlled values
    assertEq(vaultImpl.oracle(), attacker_oracle);
  }
  ```
- **Fix Suggestion:**
  ```solidity
  contract Vault {
    address private implementation;
    
    <initialize(...)> {
      require(msg.sender == address(proxy), "only proxy");  // Verify caller is proxy
      require(!initialized, "already init");
      oracle = _oracle;
      initialized = true;
    }
  }
  
  // Better: use initializer modifier from OpenZeppelin
  <initialize(...)> initializer {
    oracle = _oracle;
  }
  ```
- **Detection Heuristics:** Verify initialize() calls on standalone implementations; check for initializer modifiers; audit UUPS patterns

---

## FOUNDRY TEST SKELETONS (CROSSCUT)

### Skeleton 1: Oracle Consensus & Staleness
```solidity
contract MonolithOracleTest is Test {
  Vault vault;
  
  function testMedianizerStaleFeedDetection() public {
    oracle.updateFeed(0, 2000e18, block.timestamp);
    oracle.updateFeed(1, 2010e18, block.timestamp);
    oracle.updateFeed(2, 2020e18, block.timestamp);
    oracle.updateFeed(3, 2030e18, block.timestamp - 2 hours);  // Stale
    
    uint256 median = oracle.getMedianPrice();
    
    // Should revert or return conservative price
    vm.expectRevert("insufficient recent feeds");
    oracle.validateMedianPrice();
  }
  
  function testTWAPSpotSpreadValidation() public {
    uint256 twap = oracle.getTWAPPrice();
    uint256 spot = oracle.getSpotPrice();
    
    uint256 spread = Math.abs(twap - spot) * 100 / twap;
    assertTrue(spread <= 200);  // Max 2% spread
  }
}
```

### Skeleton 2: Reentrancy Protection
```solidity
contract MonolithReentrancyTest is Test {
  Vault vault;
  MaliciousCollateral evil;
  
  function testDepositReentrancyBlocked() public {
    evil = new MaliciousCollateral(vault);  // ERC777 with callback
    
    vm.expectRevert("reentrancy");
    vm.prank(attacker);
    vault.deposit(1000e18, 100e18);
  }
  
  function testLiquidationReentrancyBlocked() public {
    vault.deposit(100e18, 80e18);
    oracle.setPrice(0.95e18);
    
    ReentrantLiquidator reentrant = new ReentrantLiquidator(vault);
    
    vm.expectRevert("reentrancy");
    reentrant.liquidatePartial(user, 40e18);
  }
}
```

### Skeleton 3: Storage Slot Audit
```solidity
contract MonolithStorageAuditTest is Test {
  function testStorageSlotConsistency() public {
    // Deploy V1
    Vault v1 = new Vault();
    
    // Read slot 0, 1, 2 via low-level vm.load()
    bytes32 slot0_v1 = vm.load(address(v1), bytes32(uint256(0)));
    bytes32 slot1_v1 = vm.load(address(v1), bytes32(uint256(1)));
    bytes32 slot2_v1 = vm.load(address(v1), bytes32(uint256(2)));
    
    // Deploy V2
    VaultV2 v2 = new VaultV2();
    
    // Verify slots match
    bytes32 slot0_v2 = vm.load(address(v2), bytes32(uint256(0)));
    bytes32 slot1_v2 = vm.load(address(v2), bytes32(uint256(1)));
    
    assertEq(slot0_v1, slot0_v2);  // debtIndex
    assertEq(slot1_v1, slot1_v2);  // assetIndex
  }
}
```

---

## ATTACK VECTOR PRIORITIZATION

**Immediate Risk (CRITICAL/HIGH):**
1. MON-X-006: Reentrancy in Deposit (9.2/10)
2. MON-X-009: Implementation Takeover (9.5/10)
3. MON-X-008: Storage Slot Collision (9.3/10)
4. MON-X-003: TWAP Sandwich (7.7/10)
5. MON-X-007: Liquidation Reentrancy (7.8/10)
6. MON-X-001: Stale Medianizer (7.9/10)

**Medium-Term Risk (MEDIUM):**
7. MON-X-002: Medianizer Deviation (6.7/10)
8. MON-X-005: Rate Controller Race (6.5/10)
9. MON-X-004: Factory Parameter Drift (6.4/10)

---

## SUMMARY: CROSSCUT MODULE ATTACK SURFACE (v0.2)

**Total Vulnerabilities Catalogued:** 9 (MON-X-001 through MON-X-009)  
**Total Invariants Identified:** 13 (INV-X-001 through INV-X-013)  
**Test Skeletons Provided:** 3

**Critical (9.0+):** 3 vulnerabilities (reentrancy in deposit, implementation takeover, storage collision)  
**High (7.0–8.9):** 3 vulnerabilities (TWAP sandwich, liquidation reentrancy, stale medianizer)  
**Medium (4.0–6.9):** 3 vulnerabilities (medianizer deviation, rate controller race, factory drift)

**Key Defensive Practices (v0.2):**
- Implement reentrancy guards on all external-call-bearing functions
- Use OpenZeppelin's initializer modifier for proxy setup
- Validate oracle feeds per-feed for staleness, not just aggregate
- Monitor TWAP-spot spread in liquidations; reject if spread exceeds threshold
- Store factory reference in vaults for dynamic parameter queries
- Implement timelock on rate controller + oracle/factory upgrades
- Verify storage layout consistency before/after proxy upgrades
- Never allow initialize() calls on standalone implementations

---

LATEST UPDATE SUMMARY (v0.2):
- Added 9 comprehensive crosscutting vulnerabilities (MON-X-001 through MON-X-009)
- Added 13 system-wide invariants (INV-X-001 through INV-X-013)
- Added detailed TWAP sandwich attack patterns with numerical examples
- Added storage layout collision detection and prevention strategies
- Added reentrancy attack vectors for deposit and liquidation
- Added factory-vault parameter desync analysis
- Added rate controller race condition exploitation patterns
- Added multi-feed oracle manipulation and staleness validation
- Added 3 comprehensive Foundry test skeletons for system-wide testing
- Added per-feed staleness checking patterns and medianizer robust design
- Integrated cross-contract state desynchronization analysis

Version: 0.2
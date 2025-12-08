# MONOLITH CROSSCUTTING CONCERNS — ADVANCED AUDIT PRIMER v0.3

**Protocol Class:** Oracle Integration, Rate Control, Factory-Vault Sync, State Desync, Cross-Chain, Bridge Security  
**Scope:** Multi-oracle consensus, rate controller exploits, reentrancy, upgradeability, race conditions, bridge protocols, L2 desync, borrower mode races  
**Audit Focus:** System-wide invariants, state desynchronization, cross-contract attacks, cross-chain failure modes  
**Version:** 0.3 (Self-Evolved, v0.2→v0.3 Gap Integration)

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
- **Fix Suggestion:**
  ```
  contract Vault {
    uint256 private locked;
    
    modifier nonReentrant() {
      require(locked == 0, "reentrancy");
      locked = 1;
      ___;
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

### Vulnerability MON-X-007: State Divergence in Liquidation via Reentrancy (ENHANCED v0.3)

- **Pattern ID:** MON-X-007
- **Severity:** HIGH (7.8/10)
- **Rationale:** During liquidation, if stablecoin burn reenters vault, attacker can modify debt/collateral state mid-seizure
- **Preconditions:** Stablecoin.burn() calls external hooks; vault lacks reentrancy guard on liquidation
- **Concrete Call Sequence:**
  1. Liquidator calls `liquidatePartial(user, 100)`
  2. Vault: `stablecoin.burn(vault, 100)` triggers callback
  3. Callback reenters: calls `vault.repay(50)` (user repays early)
  4. User's debt reduced during liquidation
  5. Collateral seizure calculated based on original 100, but debt is now only 50
  6. Attacker pockets extra collateral worth 50 stables
- **Vulnerable Code (Pseudo):**
  ```
  <liquidatePartial(address user, uint256 debtToRepay)> {
    // ❌ No reentrancy guard
    stablecoin.burn(vault, debtToRepay);  // Callback reenters here
    debtShares[user] -= debtToRepay / debtIndex;  // Can be skipped if reentered
    assetShares[user] -= collateralSeized / assetIndex;
    collateral.transfer(liquidator, collateralSeized);
  }
  ```
- **Broken Invariants:** INV-X-011 (liquidation is atomic, debt reduction and seizure synchronized)
- **Exploit Economics:** Attacker can extract collateral value equal to debt avoidance; with 1000 stables liquidated, save 500 stables interest = steal 500 stables worth collateral
- **Fix Suggestion:** Add nonReentrant modifier to all liquidation functions
- **Detection Heuristics:** Audit liquidation for reentrancy guards; check stablecoin.burn() callback handling

---

## PROXY & INITIALIZATION SECURITY (NEW v0.3 SECTION)

### Vulnerability MON-X-008: Implementation Upgrade Without Governance (NEW)

- **Pattern ID:** MON-X-008
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
- **Broken Invariants:** INV-X-012 (initialize can only be called on proxy, not implementation)
- **Exploit Economics:** Attacker gains oracle/controller control, can drain all vault liquidity
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

## CROSS-CHAIN FAILURES (NEW v0.3 SECTION)

### Vulnerability MON-X-009: Bridge Receive Replay → Double-Mint (NEW)

- **Pattern ID:** MON-X-009
- **Severity:** CRITICAL (9.3/10)
- **Rationale:** If bridge message (e.g., Axelar, LayerZero) is replayed or executed multiple times, attacker can mint debt twice with single collateral deposit
- **Preconditions:** Cross-chain bridge protocol with message retry logic; vault on multiple chains with same collateral token; no replay protection
- **Concrete Call Sequence:**
  1. User deposits 100 USDC on Chain A, mints 80 stablecoins
  2. Bridge message: "User on Chain A deposited 100 USDC, mint 80 stables on Chain B"
  3. Axelar transmits message to Chain B
  4. Transaction fails on Chain B (e.g., out of gas), but retries activated
  5. Bridge replays message: Chain B vault mints 80 stables again for same user
  6. User now has: 80 stables (Chain A) + 80 stables (Chain B) = 160 stables total
  7. BUT only 100 USDC collateral deposited on Chain A
  8. Attacker redeems on Chain B, receives 80 USDC equivalent (collateral doesn't exist)
  9. Chain B vault becomes insolvent
- **Vulnerable Code (Pseudo):**
  ```
  <receiveDepositMessage(
    address user,
    uint256 collateralAmount,
    uint256 debtAmount,
    bytes32 messageId
  )> {
    require(msg.sender == bridge, "unauthorized");
    // ❌ No replay protection / message ID tracking
    
    assetShares[user] += collateralAmount / assetIndex;
    debtShares[user] += debtAmount / debtIndex;
    stablecoin.mint(user, debtAmount);  // Can mint twice if message replayed
  }
  ```
- **Broken Invariants:** INV-X-013 (bridge messages are not replayed), INV-X-014 (each message processed exactly once)
- **Exploit Economics:** Attacker can mint debt on all chains for single collateral; with 100 USDC on Chain A, mint 160 stables across 2 chains
- **Fix Suggestion:**
  ```
  <receiveDepositMessage(
    address user,
    uint256 collateralAmount,
    uint256 debtAmount,
    bytes32 messageId
  )> {
    require(msg.sender == bridge, "unauthorized");
    require(!processedMessages[messageId], "already processed");  // Replay protection
    processedMessages[messageId] = true;
    
    assetShares[user] += collateralAmount / assetIndex;
    debtShares[user] += debtAmount / debtIndex;
    stablecoin.mint(user, debtAmount);
  }
  ```
- **Detection Heuristics:** Audit cross-chain message handling; check for messageId tracking; verify replay protection

---

### Vulnerability MON-X-010: Delayed Bridge Message → Factory Desync (NEW)

- **Pattern ID:** MON-X-010
- **Severity:** MEDIUM (6.3/10)
- **Rationale:** If bridge message is delayed (hours/days), factory parameters may change mid-transit, causing cross-chain vault desync
- **Preconditions:** Bridge has variable latency (e.g., waiting for quorum); factory parameters change during transit
- **Concrete Call Sequence:**
  1. User initiates cross-chain deposit on Chain A with message: "Create vault pair for USDC-STAB with LTV=80%"
  2. Factory on Chain A sets LTV=80%
  3. Bridge message delayed for 12 hours
  4. Governance updates Chain A factory: LTV = 70%
  5. Bridge message arrives on Chain B, vault created with LTV=80% (stale parameter)
  6. Chain A vaults now have LTV=70%, Chain B vaults have LTV=80% (out of sync)
  7. Arbitrageurs exploit the gap: borrow at 80% on Chain B, repay at 70% cost equivalent on Chain A
- **Vulnerable Code (Pseudo):**
  ```
  <initiateVaultCreation(
    address _collateral,
    uint256 _ltv,
    uint256 _liquidationThreshold
  )> {
    bytes memory message = abi.encode(_collateral, _ltv, _liquidationThreshold);
    bridge.send("Chain B", abi.encodePacked(message));  // ❌ Hardcodes parameters in message
  }
  
  <receiveVaultCreation(bytes memory data)> {
    (address _collateral, uint256 _ltv, uint256 _liquidationThreshold) = abi.decode(data, ...);
    factory.deployVault(_collateral, ..., _ltv, _liquidationThreshold);  // Parameters from bridge message
  }
  ```
- **Broken Invariants:** INV-X-015 (cross-chain vaults have synchronized parameters)
- **Exploit Economics:** Attacker can exploit 10% LTV difference to arbitrage interest rates; with $1M vault, capture $100k+ in interest differential
- **Fix Suggestion:**
  ```
  <initiateVaultCreation(address _collateral)> {
    // Don't hardcode parameters
    bytes memory message = abi.encode(_collateral, nonce);
    bridge.send("Chain B", abi.encodePacked(message));
  }
  
  <receiveVaultCreation(bytes memory data)> {
    (address _collateral, uint256 nonce) = abi.decode(data, ...);
    require(!executedNonces[nonce], "already executed");
    executedNonces[nonce] = true;
    
    // Use CURRENT factory parameters, not message-encoded values
    (uint256 ltv, uint256 threshold) = factory.getDefaultParameters();
    factory.deployVault(_collateral, ..., ltv, threshold);
  }
  ```
- **Detection Heuristics:** Audit bridge message encoding; check for hardcoded parameters; verify cross-chain sync

---

### Vulnerability MON-X-011: Bridge Griefing via Payout Baiting (NEW)

- **Pattern ID:** MON-X-011
- **Severity:** MEDIUM (6.2/10)
- **Rationale:** Attacker can intentionally cause bridge messages to fail on receiving chain, trapping funds mid-transit
- **Preconditions:** Bridge has retry queue; receiver contract has strict validation; attacker can craft messages to fail validation
- **Concrete Call Sequence:**
  1. User initiates redemption: "Burn 100 stables on Chain B, send 100 USDC to user on Chain A"
  2. User burns stables on Chain B; bridge message queued
  3. Attacker front-runs on Chain A: withdraws collateral, vault is now insolvent
  4. Bridge message arrives: tries to mint 100 USDC collateral to user, but vault lacks collateral
  5. Minting fails (insufficient balance), message retries forever (stuck in queue)
  6. User's 100 stables burned on Chain B, but never receive USDC on Chain A (griefed)
  7. Attacker has extracted USDC without repayment
- **Vulnerable Code (Pseudo):**
  ```
  <receiveRedemption(
    address user,
    uint256 amount
  )> {
    require(collateral.balanceOf(address(this)) >= amount, "insufficient funds");  // ❌ Revert if funds low
    collateral.transfer(user, amount);
  }
  ```
- **Broken Invariants:** INV-X-016 (bridge messages never get stuck), INV-X-017 (redemption is atomic across chains)
- **Exploit Economics:** Attacker can grief arbitrary users by draining collateral; with 1M TVL, grief entire pool
- **Fix Suggestion:**
  ```
  <receiveRedemption(address user, uint256 amount)> {
    if (collateral.balanceOf(address(this)) >= amount) {
      collateral.transfer(user, amount);
    } else {
      // Safe fallback: mark as pending, don't revert
      pendingRedemptions[user] += amount;
      emit RedemptionPending(user, amount);
    }
  }
  
  <claimPendingRedemption(address user)> {
    uint256 amount = pendingRedemptions[user];
    require(collateral.balanceOf(address(this)) >= amount, "still insufficient");
    pendingRedemptions[user] = 0;
    collateral.transfer(user, amount);
  }
  ```
- **Detection Heuristics:** Audit bridge receive functions for strict validation; check for revert-on-insufficient-funds patterns; verify fallback mechanisms

---

## BORROWER MODE & L2 DESYNC (NEW v0.3 SECTION)

### Vulnerability MON-X-012: Borrower Mode Switch Race Across Chains (NEW)

- **Pattern ID:** MON-X-012
- **Severity:** HIGH (8.1/10)
- **Rationale:** If user can switch borrower mode on one chain while liquidation is pending on another, mode protection can be bypassed
- **Preconditions:** Cross-chain vaults track borrower mode locally; bridge messages delayed; liquidation and mode switch race
- **Concrete Call Sequence:**
  1. User on Chain A: REDEMPTION_FREE mode (protected from liquidation)
  2. Liquidator on Chain A calls `liquidatePartial(user, 100)`, blocked by mode
  3. User on Chain B initiates mode switch: "Change user to STANDARD mode"
  4. Bridge message sent, but delayed
  5. Liquidator waits, then calls liquidate again on Chain A
  6. Before bridge message arrives on Chain A, liquidation succeeds (mode still REDEMPTION_FREE)
  7. User's collateral seized, but mode switch message also arrives
  8. Both liquidation AND mode switch execute, mode now STANDARD but collateral already seized
  9. Attacker benefits from liquidation despite mode protection
- **Vulnerable Code (Pseudo):**
  ```
  <setBorrowerMode(address user, BorrowerMode newMode)> {
    borrowerMode[user] = newMode;  // Local update
    bridge.send("other chains", abi.encode(user, newMode));  // Async message
  }
  
  <liquidatePartial(address user, uint256 debtToRepay)> {
    require(borrowerMode[user] != REDEMPTION_FREE, "mode-protected");  // Local check
    // ... liquidation proceeds
  }
  ```
- **Broken Invariants:** INV-X-018 (borrower mode synchronized across chains), INV-X-019 (liquidation respects mode across all chains)
- **Exploit Economics:** Attacker can liquidate cross-chain-protected positions; if mode protects 20% of TVL, attacker can steal 20% via race
- **Fix Suggestion:**
  ```
  <setBorrowerMode(address user, BorrowerMode newMode)> {
    pendingBorrowerMode[user] = newMode;
    modeChangeTime[user] = block.timestamp;
    bridge.send("other chains", abi.encode(user, newMode, block.timestamp));
  }
  
  <liquidatePartial(address user, uint256 debtToRepay)> {
    BorrowerMode currentMode = getBorrowerMode(user);  // Includes pending checks
    require(currentMode != REDEMPTION_FREE, "mode-protected");
    // ... liquidation proceeds
  }
  ```
- **Detection Heuristics:** Audit cross-chain state consistency; check for mode synchronization; verify liquidation checks across all chains

---

### Vulnerability MON-X-013: L2 Block Delay → HF Misalignment (NEW)

- **Pattern ID:** MON-X-013
- **Severity:** MEDIUM (6.4/10)
- **Rationale:** If L2 block times are longer than L1 (e.g., Optimism 2-sec vs Ethereum 12-sec), health factor calculations may lag oracle updates
- **Preconditions:** Vault deployed on L2; oracle prices updated on L1 with delay; liquidation triggered with stale L2 state
- **Concrete Call Sequence:**
  1. L1 oracle updates: ETH = 1800 (price crash)
  2. Relayer submits price update to L2 oracle (batches updates, takes 1 L1 block = ~12 seconds)
  3. During 12-second window on L2 (~6 blocks), user appears safe (HF using old 2000 price)
  4. L2 liquidator waits for oracle update; by then, user position may have worsened further
  5. OR: L2 liquidator sees stale HF, liquidates user, but by the time tx settles on L1, oracle price has moved again
  6. Liquidation amount calculated with stale price; user over-liquidated
- **Vulnerable Code (Pseudo):**
  ```
  <computeHealthFactor(address user)> {
    (uint256 price, uint256 timestamp) = oracle.getPrice();
    // ❌ Staleness window applies to L1 time, not L2 block time
    require(block.timestamp - timestamp <= STALENESS_WINDOW, "stale");
    
    uint256 hf = (assetShares[user] * price * assetIndex * liquidationLtv) / (debtShares[user] * debtIndex);
    return hf;
  }
  ```
- **Broken Invariants:** INV-X-020 (HF staleness accounts for L2 block time), INV-X-021 (liquidation prices validated per L2 context)
- **Exploit Economics:** Attacker can exploit 12-second (6+ block) window to liquidate or avoid liquidation; with 1M TVL at 5% HF margin = $50k manipulation window
- **Fix Suggestion:**
  ```
  <computeHealthFactor(address user)> {
    (uint256 price, uint256 timestamp) = oracle.getPrice();
    
    // Adjust staleness check for L2 context (shorter block times)
    uint256 maxStaleness = block.chainid == OPTIMISM ? 6 minutes : 1 days;  // Shorter window on L2
    require(block.timestamp - timestamp <= maxStaleness, "stale");
    
    uint256 hf = (assetShares[user] * price * assetIndex * liquidationLtv) / (debtShares[user] * debtIndex);
    return hf;
  }
  ```
- **Detection Heuristics:** Check oracle staleness windows on L2 deployments; verify block-time adjustments; audit L2-specific liquidation logic

---

## FOUNDRY TEST SKELETONS (CROSSCUT v0.3)

### Skeleton 1: Oracle Multi-Feed & Staleness
```solidity
contract MonolithOracleTest is Test {
  Vault vault;
  
  function testPerFeedStalenessPrevention() public {
    oracle.updateFeed(0, 2000e18, block.timestamp);
    oracle.updateFeed(1, 2010e18, block.timestamp);
    oracle.updateFeed(2, 2020e18, block.timestamp);
    oracle.updateFeed(3, 1500e18, block.timestamp - 2 hours);  // Stale
    
    vm.expectRevert("insufficient recent feeds");
    oracle.getMedianPrice();
  }
  
  function testTWAPSpotSpreadValidation() public {
    uint256 twap = oracle.getTWAPPrice();
    uint256 spot = oracle.getSpotPrice();
    
    uint256 spread = Math.abs(twap - spot) * 100 / twap;
    assertTrue(spread <= 200);  // Max 2% spread
  }
}
```

### Skeleton 2: Bridge & Cross-Chain
```solidity
contract MonolithBridgeTest is Test {
  Vault vaultChainA;
  Vault vaultChainB;
  
  function testBridgeReplayProtection() public {
    bytes32 messageId = keccak256("test-message");
    
    vm.prank(bridge);
    vaultChainB.receiveDepositMessage(user, 100e18, 80e18, messageId);
    
    // Replay attempt should fail
    vm.expectRevert("already processed");
    vm.prank(bridge);
    vaultChainB.receiveDepositMessage(user, 100e18, 80e18, messageId);
  }
  
  function testBorrowerModeRaceAcrossChains() public {
    // Mode-protected on Chain A
    vaultChainA.setBorrowerMode(user, REDEMPTION_FREE);
    vaultChainA.deposit(100e18, 80e18);
    
    oracle.setPrice(0.95e18);  // Underwater
    
    // Liquidation blocked due to mode on Chain A
    vm.expectRevert("mode-protected");
    liquidator.liquidatePartial(user, 40e18);
    
    // Bridge message to switch mode on other chain
    // Should synchronize before liquidation allowed
  }
}
```

### Skeleton 3: Reentrancy Protection
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

---

## LATEST UPDATE SUMMARY (v0.2 → v0.3)

**Added 5 new vulnerability families:**
- MON-X-008: Implementation Upgrade Without Governance
- MON-X-009: Bridge Receive Replay → Double-Mint
- MON-X-010: Delayed Bridge Message → Factory Desync
- MON-X-011: Bridge Griefing via Payout Baiting
- MON-X-012: Borrower Mode Switch Race Across Chains
- MON-X-013: L2 Block Delay → HF Misalignment

**Added 8 new invariants:**
- INV-X-012 through INV-X-021 (Implementation security, bridge replay, cross-chain sync, L2 timing)

**Expanded sections:**
- Proxy & Initialization Security (NEW): Implementation takeover, initialize locks
- Cross-Chain Failures (NEW): Bridge replay, delayed messages, griefing, parameter desync
- Borrower Mode & L2 Desync (NEW): Mode-switch races, L2 block time effects
- Oracle Staleness (ENHANCED): Per-feed validation, Chainlink/Pyth multi-feed patterns

**Added Foundry test skeletons:**
- Skeleton 2: Bridge & Cross-Chain (2 test cases)
- Skeleton 3: Reentrancy Protection (2 test cases, enhanced from v0.2)

**Added numerical examples:**
- Bridge replay double-mint quantification
- Cross-chain parameter desync arbitrage
- L2 block delay manipulation windows
- Borrower mode race exploitation scenarios

**Added Slither/Semgrep detection rules:**
- Identify missing per-feed staleness checks
- Detect replay-unprotected bridge message handlers
- Flag unprotected initialize() calls on implementations
- Verify reentrancy guards on all external-call-bearing functions
- Check borrower mode synchronization across chains

Version: 0.3

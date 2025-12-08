# MONOLITH CDP STABLECOIN ENGINE — CORE AUDIT PRIMER

**Protocol Class:** Overcollateralized Stablecoin Minting (MakerDAO/Fraxlend/Liquity family)  
**Scope:** Vault architecture, debt accounting, share conversions, factory patterns, interest accrual, fees, roles  
**Audit Focus:** Implementation-driven, invariant-aware, attacker-first threat modeling

---

## ARCHITECTURE FINGERPRINT

Monolith operates as a **CDP (Collateralized Debt Position) engine** with the following canonical components:

### Core Layer Topology
- **VaultFactory**: Deploys isolated vault + stablecoin pairs with independent governance
- **Vault**: Per-vault collateral management, debt issuance, liquidation state
- **Stablecoin (ERC20)**: Minted against vaults, redeemable at parity
- **Oracle**: Collateral pricing with staleness windows and fallback chains
- **RateController**: Autonomous interest rate adjustment based on peg deviation
- **Liquidation Module**: Sequenced partial/full liquidation with auction/swap routing

### State Tracking Duality
Monolith uses a **share-based accounting model** (ERC-4626 inspired but asymmetric):

**DebtShares System:**
- User holds `debtShares[user]` in storage
- Global `totalDebtShares` tracks cumulative issuance
- Interest accrual inflates the conversion ratio: `debtIndex` (similar to Aave's `variableBorrowIndex`)
- Debt calculation: `debtOwed = debtShares[user] * debtIndex / PRECISION`

**AssetShares System:**
- Collateral backing uses `assetShares[user]` for fractional ownership
- Global `totalAssetShares` represents total collateral units
- Collateral value: `assetValue = assetShares[user] * assetIndex / PRECISION`
- Enables dynamic collateral rebalancing without withdrawal/redeposit

### Factory Deployment Pattern
```
VaultFactory.deployVault(
  collateralToken,
  stablecoinName,
  ltv,
  liquidationThreshold,
  borrowFee,
  liquidationBonus
) → (vaultAddress, stablecoinAddress)
```

Each deployment initializes:
- Isolated vault with independent debt ceiling
- Fresh stablecoin contract with burn/mint permissions
- Rate controller bound to vault
- Oracle feed validator list

---

## STABLECOIN MINT/BURN MECHANICS

### Minting Flow (User Deposits Collateral → Receives Debt)

**Function Signature (Placeholder):**
```
<deposit(uint256 collateralAmount, uint256 debtToMint)>
  requires: collateralAmount > 0
  requires: debtToMint > 0
  requires: msg.sender is non-zero, not vault/factory
```

**Execution Sequence:**
1. Transfer collateral from user to vault: `collateralToken.transferFrom(msg.sender, vault, collateralAmount)`
2. Record asset shares: `assetShares[msg.sender] += collateralAmount / currentAssetIndex`
3. Accrue interest on existing debt (if any)
4. Calculate new debt shares: `debtShares[msg.sender] += debtToMint / currentDebtIndex`
5. Increment `totalDebtShares`
6. Mint stablecoin to user: `stablecoin.mint(msg.sender, debtToMint)`
7. Check health factor: `require(computeHealthFactor(msg.sender) >= LTV_THRESHOLD)`

**State Mutations:**
- `assetShares[user] += ∆` (collateral tracking)
- `debtShares[user] += ∆` (debt obligation)
- `totalDebtShares += ∆`
- `stablecoin.totalSupply() += debtToMint`

---

### Burning Flow (User Repays Debt → Collateral Stays)

**Function Signature (Placeholder):**
```
<repay(uint256 debtAmount)>
  requires: debtAmount > 0
  requires: user has stablecoin balance ≥ debtAmount
```

**Execution Sequence:**
1. Transfer stablecoin from user to vault: `stablecoin.transferFrom(msg.sender, vault, debtAmount)`
2. Burn stablecoin: `stablecoin.burn(vault, debtAmount)`
3. Accrue interest (recalculate `debtIndex`)
4. Convert debt amount to shares: `sharesToReduce = debtAmount / currentDebtIndex`
5. Decrement user's debt shares: `debtShares[msg.sender] -= sharesToReduce`
6. Decrement `totalDebtShares`
7. Emit `Repaid(user, debtAmount)`

**Key Invariant Checks:**
- Repay does NOT affect collateral position (assetShares unchanged)
- Health factor may improve post-repay (lower debt numerator)
- User can repay even if underwater (liquidation-eligible)

---

### Withdrawal (Collateral Extraction Without Debt Repayment)

**Function Signature (Placeholder):**
```
<withdraw(uint256 assetAmount)>
  requires: assetAmount > 0
  requires: assetShares[user] sufficient
```

**Execution Sequence:**
1. Convert asset amount to shares: `sharesToReduce = assetAmount / currentAssetIndex`
2. Require: `assetShares[msg.sender] >= sharesToReduce`
3. Decrement user's asset shares: `assetShares[msg.sender] -= sharesToReduce`
4. Decrement `totalAssetShares`
5. Transfer collateral to user: `collateralToken.transfer(msg.sender, assetAmount)`
6. **CRITICAL CHECK:** Verify health factor remains ≥ liquidation threshold
7. Emit `Withdrawn(user, assetAmount)`

**Broken Invariant Risk:**
- If HF check bypassed: user can reduce collateral below liquidation while debt remains
- Subsequent interest accrual may trap position in insolvency

---

## VAULT STORAGE LAYOUT & INITIALIZATION

### Critical State Variables

```solidity
// Vault.sol
mapping(address => uint256) public assetShares;      // User collateral ownership units
mapping(address => uint256) public debtShares;       // User debt obligation units
uint256 public totalAssetShares;                     // Sum of all assetShares
uint256 public totalDebtShares;                      // Sum of all debtShares
uint256 public debtIndex;                            // Accrual multiplier (18 decimals + 9)
uint256 public assetIndex;                           // Collateral rebalance multiplier
uint256 public lastAccrualBlock;                     // Interest checkpoint
address public collateralToken;                      // ERC20 input asset
address public stablecoin;                           // Minted liability
address public oracle;                               // Price feed
address public rateController;                       // Interest rate manager
bool public initialized;                             // Guard against re-initialization
```

### Initialization Attack Surface

**Initializer Function (Placeholder):**
```
<initialize(
  address _collateral,
  address _stablecoin,
  address _oracle,
  address _rateController,
  uint256 _ltv,
  uint256 _liquidationThreshold,
  uint256 _borrowFee
)>
```

**Vulnerability MON-C-001: Uninitialized Proxy Takeover**
- **Pattern ID:** MON-C-001
- **Severity:** CRITICAL (9.8/10)
- **Rationale:** If vault deployed as UUPS/transparent proxy without initializer lock, attacker can initialize with malicious oracle/controller
- **Preconditions:** Vault is proxy; initializer lacks access control; deployer ≠ admin during deployment window
- **Concrete Call Sequence:**
  1. Attacker watches for vault deployment tx
  2. Frontrun or race condition: Attacker calls `initialize()` with `oracle = attacker_oracle`, `rateController = attacker_controller`
  3. Vault now queries attacker-controlled oracle → always returns inflated collateral price
  4. Users deposit collateral thinking it's worth more than actual
  5. Attacker can steal via liquidation or parameter manipulation
- **Vulnerable Code (Pseudo):**
  ```
  <initialize(address _oracle, address _rateController, ...)> {
    require(!initialized, "already init");  // ❌ Missing require(msg.sender == factory)
    oracle = _oracle;
    rateController = _rateController;
    initialized = true;
  }
  ```
- **Broken Invariants:** INV-C-001 (oracle is trusted), INV-C-002 (controller is authorized)
- **Exploit Economics:** Attacker gains unbounded oracle manipulation + rate control at zero cost
- **Foundry Repro:**
  ```solidity
  function testUninitializedProxyTakeover() public {
    // Deploy vault as proxy
    Vault vaultProxy = new Vault();
    // Attacker calls initialize before factory
    address attackerOracle = address(new MockOracle());
    vaultProxy.initialize(attackerOracle, address(0), 0, 0, 0);
    // Vault now trusts attacker oracle
    assertEq(vaultProxy.oracle(), attackerOracle);
  }
  ```
- **Fix Suggestion:**
  ```
  <initialize(...)> {
    require(msg.sender == factory, "only factory");
    require(!initialized, "already");
    // ... rest of init
  }
  ```
- **Detection Heuristics:** Check proxy contracts for initialize() calls lacking factory/admin check; grep for `initialized` flag without msg.sender guard

---

## DEBTSHARES & ASSETSHARES SYSTEMS

### Interest Index Accrual (Fraxlend Model)

The vault accumulates interest via an **index multiplier** mechanism:

**State Variables:**
- `debtIndex`: Tracks cumulative interest (18 decimals + 9 additional)
- `lastAccrualBlock`: Last block where accrual occurred
- `interestRate`: Annual rate (set by RateController)

**Accrual Formula:**
```
debtIndex_new = debtIndex_old * (1 + interestRate * (block.number - lastAccrualBlock) / BLOCKS_PER_YEAR) / 1e18
```

**Interest Accrual Function (Placeholder):**
```
<accrueInterest()>
  reads: debtIndex, lastAccrualBlock, interestRate
  mutates: debtIndex, lastAccrualBlock
```

**Execution:**
1. Calculate elapsed blocks: `elapsedBlocks = block.number - lastAccrualBlock`
2. If `elapsedBlocks == 0`, return early (same-block guard)
3. Query interest rate: `rate = rateController.getRate()`
4. Apply formula: `debtIndex *= (1 + rate * elapsedBlocks / BLOCKS_PER_YEAR)`
5. Update checkpoint: `lastAccrualBlock = block.number`

---

### Share Conversion Mechanics

#### Debt Share Conversion

**User's actual debt obligation:**
```
debtOwed(user) = debtShares[user] * debtIndex / PRECISION
where PRECISION = 1e27 (27 decimal fixed-point)
```

**Minting shares from debt amount:**
```
sharesToMint = debtAmount * PRECISION / debtIndex
```

**Vulnerability MON-C-002: Rounding Bias in convertToDebt()**
- **Pattern ID:** MON-C-002
- **Severity:** MEDIUM (6.5/10)
- **Rationale:** Truncation rounding in `sharesToMint` calculation allows attacker to accumulate dust debt
- **Preconditions:** Interest accrual active; vault has high debtIndex (from long runtime); attacker executes many small borrows
- **Concrete Call Sequence:**
  1. Vault runs for 1 year, debtIndex = 1.12e27 (12% interest)
  2. Attacker calls `deposit(100e18, 89285714285714284)` (89.28 stablecoins)
  3. sharesToMint = 89.28e18 * 1e27 / 1.12e27 = 79.71e18 shares (truncated)
  4. Attacker's debtShares = 79.71e18
  5. Attacker's actual debt = 79.71e18 * 1.12e27 / 1e27 = 89.27...e18 (⚠️ 0.01e18 dust remains unaccounted)
  6. If attacker repeats 1M times with 0.01e18 dust per tx → 10,000 stablecoins of untracked debt
  7. Attacker never repays dust; vault's accounting diverges from reality
- **Vulnerable Code (Pseudo):**
  ```
  <deposit(uint256 collateral, uint256 debtAmount)> {
    <accrueInterest()>;
    uint256 newShares = debtAmount * PRECISION / debtIndex;  // ❌ Truncates
    debtShares[msg.sender] += newShares;
    totalDebtShares += newShares;
    stablecoin.mint(msg.sender, debtAmount);  // ✓ Correct amount minted
  }
  ```
- **Broken Invariants:** INV-C-003 (totalDebtShares * debtIndex ≈ minted stablecoin)
- **Exploit Economics:** ~0.01 stablecoin per transaction × 1M txs = 10k stolen; gas cost ~500 gwei/tx × 1M = 500 ETH losses to attacker (~$2M), but steal > gas implies profitability at higher scales
- **Foundry Repro:**
  ```solidity
  function testRoundingBiasAccumulation() public {
    vault.deposit(100e18, 89285714285714284);
    uint256 debtOwed = vault.debtShares(user) * vault.debtIndex() / 1e27;
    assertLt(debtOwed, 89285714285714284);  // Undertracked
  }
  ```
- **Fix Suggestion:**
  ```
  <deposit(uint256 debtAmount)> {
    uint256 newShares = debtAmount * PRECISION / debtIndex;
    uint256 actualDebt = newShares * debtIndex / PRECISION;
    require(actualDebt >= debtAmount - 1, "rounding loss");  // Allow 1 wei tolerance
    // OR use OpenZeppelin's Math.ceilDiv()
    uint256 newShares = Math.ceilDiv(debtAmount * PRECISION, debtIndex);
  }
  ```
- **Detection Heuristics:** Scan for share-to-amount conversions without rounding guards; calculate delta between minted stablecoin and actual shares * index

---

#### Asset Share Conversion

**User's collateral balance:**
```
assetBalance(user) = assetShares[user] * assetIndex / PRECISION
```

**Deposit collateral → mint shares:**
```
sharesToMint = assetAmount * PRECISION / assetIndex
```

---

### Vulnerability MON-C-003: Flash Loan + Share Inflation

- **Pattern ID:** MON-C-003
- **Severity:** HIGH (8.1/10)
- **Rationale:** If assetIndex is dynamic and affected by collateral balance (e.g., LP token rebases), attacker can inflate index via flash loan then extract value
- **Preconditions:** Collateral is rebase token (e.g., aToken, stkAAVE); assetIndex is computed from collateral.balanceOf(vault); vault lacks reentrancy guard on deposit
- **Concrete Call Sequence:**
  1. Vault holds 1000 aTokens (aUSDC), assetIndex = 1e27
  2. Attacker initiates flash loan for 1M aTokens from Aave
  3. Attacker `deposit(1M tokens, 0 debt)` into vault
  4. Vault now holds 1.001M tokens; assetIndex recalculated = 1e27 * 1.001 = 1.001e27
  5. Attacker repays flash loan (1M tokens transferred out)
  6. Vault now holds 1000 tokens again
  7. BUT attacker's assetShares were minted at index 1.001e27 (when balance was 1.001M)
  8. Post-withdrawal: attacker's assetBalance = assetShares[attacker] * 1e27 / 1e27 = 1001 tokens (gained 1 token from thin air)
  9. Attacker withdraws 1001, repeats with fresh flash loan cycle
- **Vulnerable Code (Pseudo):**
  ```
  <deposit(uint256 collateralAmount, uint256 debt)> {
    // ❌ assetIndex computed AFTER external transfer but DURING same tx
    collateralToken.transferFrom(msg.sender, address(this), collateralAmount);
    uint256 currentIndex = collateralToken.balanceOf(address(this)) * 1e27 / totalAssetShares;
    assetShares[msg.sender] += collateralAmount * 1e27 / currentIndex;
    totalAssetShares += collateralAmount * 1e27 / currentIndex;
  }
  
  <withdraw(uint256 assetAmount)> {
    uint256 currentIndex = collateralToken.balanceOf(address(this)) * 1e27 / totalAssetShares;
    assetShares[msg.sender] -= assetAmount * 1e27 / currentIndex;
    collateralToken.transfer(msg.sender, assetAmount);  // ❌ No check for balance sufficiency
  }
  ```
- **Broken Invariants:** INV-C-004 (assetIndex stable across blocks), INV-C-005 (collateral.balanceOf(vault) ≥ sum of withdrawable assets)
- **Exploit Economics:** Gain ~0.1% per cycle × 10 cycles = 1% vault inflation; if vault holds $100M → $1M stolen
- **Foundry Repro:**
  ```solidity
  function testFlashLoanIndexInflation() public {
    // Assume collateral is rebase token
    uint256 initialBalance = collateral.balanceOf(address(vault));
    vm.prank(flashLoanProvider);
    collateral.transfer(address(vault), 1000e18);
    
    vm.prank(attacker);
    vault.deposit(1000e18, 0);
    
    vm.prank(flashLoanProvider);
    collateral.transferFrom(address(vault), address(flashLoanProvider), 1000e18);
    
    uint256 finalBalance = collateral.balanceOf(address(vault));
    assertEq(finalBalance, initialBalance);  // Collateral restored
    
    uint256 stealAmount = vault.assetShares(attacker) * vault.assetIndex() / 1e27;
    assertGt(stealAmount, 1000e18);  // Attacker has more than deposited!
  }
  ```
- **Fix Suggestion:**
  ```
  <deposit(uint256 collateralAmount, uint256 debt)> {
    require(nonReentrant(), "guard");
    collateralToken.transferFrom(msg.sender, address(this), collateralAmount);
    // Snapshot balance before any user shares are minted
    uint256 balanceBefore = collateralToken.balanceOf(address(this)) - collateralAmount;
    uint256 currentIndex = (balanceBefore + collateralAmount) * 1e27 / (totalAssetShares + collateralAmount * 1e27 / oldIndex);
    // ... share minting with stable index
  }
  ```
- **Detection Heuristics:** Check if assetIndex computation depends on live collateral balance; flag rebase token collateral without reentrancy guards; audit index calculation order

---

## INTEREST ACCRUAL & ROUNDING TRAPS

### Vulnerability MON-C-004: Same-Block Interest Rate Change Exploitation

- **Pattern ID:** MON-C-004
- **Severity:** MEDIUM (6.2/10)
- **Rationale:** If RateController allows same-block rate changes and vault doesn't snapshot rates, attacker can borrow at old rate, then immediately update rate + accrue
- **Preconditions:** RateController has no rate change delay; multiple accrual calls in same block; attacker controls RateController or governance
- **Concrete Call Sequence:**
  1. Current rate = 5% per year, debtIndex = 1e27
  2. Attacker calls `rateController.setRate(1000%)` (1000% annual)
  3. Attacker calls `deposit(collateral, debtAmount)` (borrows at 5%)
  4. Attacker calls `accrueInterest()` with 1000% rate
  5. debtIndex jumps to 1e27 * (1 + 1000% * 1 / BLOCKS_PER_YEAR) ≈ 1.0317e27 after 1 block
  6. Attacker's debt obligation increases 3.17% instantly
  7. BUT: if interest rates are supposed to be gradual, attacker abuses governance to extract value from other borrowers
- **Vulnerable Code (Pseudo):**
  ```
  <accrueInterest()> {
    uint256 rate = rateController.getRate();  // ❌ No staleness check, can change same-block
    uint256 elapsedBlocks = block.number - lastAccrualBlock;
    debtIndex *= (1 + rate * elapsedBlocks / BLOCKS_PER_YEAR);
    lastAccrualBlock = block.number;
  }
  ```
- **Broken Invariants:** INV-C-006 (interest rate changes are gradual), INV-C-007 (user can estimate borrow cost)
- **Exploit Economics:** Minimal per-tx, but enables MEV attacks on liquidation thresholds
- **Foundry Repro:**
  ```solidity
  function testSameBlockRateChange() public {
    vault.setRate(50);  // 5%
    vault.deposit(1000e18, 100e18);
    uint256 debtBefore = vault.debtShares(attacker) * vault.debtIndex() / 1e27;
    
    vault.setRate(10000);  // 1000%
    vault.accrueInterest();
    uint256 debtAfter = vault.debtShares(attacker) * vault.debtIndex() / 1e27;
    
    assertGt(debtAfter, debtBefore * 1.03);  // >3% jump
  }
  ```
- **Fix Suggestion:**
  ```
  <setRate(uint256 newRate)> {
    rateChangeTime = block.timestamp;
    pendingRate = newRate;
  }
  
  <accrueInterest()> {
    if (block.timestamp - rateChangeTime >= RATE_CHANGE_DELAY) {
      interestRate = pendingRate;
    }
    // Accrue using interestRate (locked-in, not live)
  }
  ```
- **Detection Heuristics:** Grep for RateController.getRate() calls without staleness checks; audit governance delay mechanisms

---

### Vulnerability MON-C-005: Zero-Block Accrual Skip → Debt Underflow

- **Pattern ID:** MON-C-005
- **Severity:** LOW (4.1/10)
- **Rationale:** If multiple operations in same block skip accrual (due to `lastAccrualBlock == block.number` guard), debt tracking can diverge slightly
- **Preconditions:** Two deposit/withdraw calls in single block; second call doesn't re-accrue
- **Concrete Call Sequence:**
  1. Block N: User A calls `deposit(100e18, 10e18)` → accrues, debtIndex = 1e27
  2. Block N: User B calls `deposit(100e18, 10e18)` → skips accrual (same block), debtIndex = 1e27 (same)
  3. Block N+1: User A calls `accrueInterest()` → debtIndex = 1.000005e27 (1 block of interest)
  4. User B's debt: 10e18 shares × 1.000005e27 / 1e27 = 10.00005e18 (should have been lower if accrued at block N)
  5. Over millions of txs, this compounds to measurable divergence
- **Vulnerable Code (Pseudo):**
  ```
  <accrueInterest()> {
    if (lastAccrualBlock == block.number) return;  // ❌ Silently skip
    // ... accrual logic
  }
  ```
- **Broken Invariants:** INV-C-008 (interest accrual monotonic), INV-C-009 (all users see same debtIndex within block)
- **Exploit Economics:** Negligible per-user; not exploitable for direct theft
- **Foundry Repro:**
  ```solidity
  function testZeroBlockAccrualSkip() public {
    vault.deposit(100e18, 10e18);
    uint256 indexAfter1 = vault.debtIndex();
    vault.deposit(100e18, 10e18);  // Same block
    uint256 indexAfter2 = vault.debtIndex();
    assertEq(indexAfter1, indexAfter2);  // Index unchanged in same block
  }
  ```
- **Fix Suggestion:**
  ```
  <deposit(uint256 collateral, uint256 debt)> {
    <accrueInterest()>;  // Always accrue first
    // ... rest of logic
  }
  ```
- **Detection Heuristics:** Identify all paths that call accrueInterest(); verify none are conditional on block.number check alone

---

## FEE FLOW MISROUTING

### Vulnerability MON-C-006: Borrow Fee Double-Charging

- **Pattern ID:** MON-C-006
- **Severity:** HIGH (8.0/10)
- **Rationale:** Borrow fee (%) applied to principal amount AND reinvested into vault, causing compounding debt without user consent
- **Preconditions:** Vault has `borrowFee` parameter; fee is deducted from user's minted stablecoin but added back to totalDebtShares
- **Concrete Call Sequence:**
  1. User calls `deposit(1000 collateral, 100 stablecoin debt)`
  2. Vault applies 1% borrow fee = 1 stablecoin fee
  3. User minted: 99 stablecoin (after fee deduction)
  4. BUT vault's debtShares increased for full 100 debt (fee not subtracted from debt tracking)
  5. Over time, interest accrues on the 100 (including the hidden 1% fee)
  6. User's actual debt obligation: 100 + (100 × interest rate) = higher than expected
  7. User only borrowed 99 stablecoins but owes debt for 100
- **Vulnerable Code (Pseudo):**
  ```
  <deposit(uint256 collateral, uint256 debtAmount)> {
    <accrueInterest()>;
    uint256 fee = debtAmount * borrowFeePercent / 1e4;
    uint256 userAmount = debtAmount - fee;
    
    debtShares[msg.sender] += debtAmount * PRECISION / debtIndex;  // ❌ Full amount
    totalDebtShares += debtAmount * PRECISION / debtIndex;
    
    feeAccumulator += fee;  // Fee tracked separately
    stablecoin.mint(msg.sender, userAmount);  // ✓ Only user amount
  }
  ```
- **Broken Invariants:** INV-C-010 (debtShares * debtIndex == minted stablecoins + accumulated fees)
- **Exploit Economics:** If vault issues 1M stablecoins, 1% fee = 10k stolen; scales linearly with issuance
- **Foundry Repro:**
  ```solidity
  function testBorrowFeeDoubleCharge() public {
    uint256 borrowAmount = 100e18;
    vault.deposit(1000e18, borrowAmount);
    
    uint256 userMinted = stablecoin.balanceOf(user);
    uint256 expectedWithFee = borrowAmount * 99 / 100;  // 1% fee
    assertEq(userMinted, expectedWithFee);
    
    uint256 debtOwed = vault.debtShares(user) * vault.debtIndex() / 1e27;
    assertGt(debtOwed, borrowAmount);  // User owes MORE than they borrowed!
  }
  ```
- **Fix Suggestion:**
  ```
  <deposit(uint256 collateral, uint256 debtAmount)> {
    <accrueInterest()>;
    uint256 fee = debtAmount * borrowFeePercent / 1e4;
    uint256 netDebt = debtAmount - fee;  // Reduce debt obligation by fee
    
    debtShares[msg.sender] += netDebt * PRECISION / debtIndex;
    totalDebtShares += netDebt * PRECISION / debtIndex;
    
    feeAccumulator += fee;
    stablecoin.mint(msg.sender, netDebt);
  }
  ```
- **Detection Heuristics:** Search for fee calculations applied to debtShares but not to minted stablecoin amount; compare minted stables to shares * index

---

### Vulnerability MON-C-007: Fee Receiver Uninitialized

- **Pattern ID:** MON-C-007
- **Severity:** CRITICAL (9.5/10)
- **Rationale:** If feeReceiver is not set during initialization, accumulated fees are locked or sent to zero address
- **Preconditions:** Vault initializes without feeReceiver parameter; fees are accumulated but never withdrawn
- **Concrete Call Sequence:**
  1. Factory deploys vault without setting `feeReceiver`
  2. feeReceiver = address(0)
  3. Vault accumulates 10,000 stablecoins in fees over 1 year
  4. Governance calls `withdrawFees()` and sends to address(0) → fees permanently lost
  5. OR: If feeReceiver is later set to attacker address, attacker claims all historical fees
- **Vulnerable Code (Pseudo):**
  ```
  <initialize(address _collateral, ...)> {
    // ❌ Missing: require(_feeReceiver != address(0));
    feeReceiver = _feeReceiver;  // Could be address(0)
  }
  
  <withdrawFees()> {
    uint256 fees = feeAccumulator;
    feeAccumulator = 0;
    stablecoin.transfer(feeReceiver, fees);  // ❌ If feeReceiver is address(0), burned
  }
  ```
- **Broken Invariants:** INV-C-011 (feeReceiver is valid non-zero address)
- **Exploit Economics:** Entire fee pool (e.g., 1% of 1B stables = 10M) is lost or stolen
- **Foundry Repro:**
  ```solidity
  function testUnintializedFeeReceiver() public {
    Vault vault = factory.deployVault(collateral, stablecoin, address(0), address(0), 0);
    vault.initialize(collateral, stablecoin, oracle, controller, 1e4, 8000, 100);
    
    vault.deposit(100e18, 10e18);  // Accumulate 0.1e18 fee
    
    assertEq(vault.feeReceiver(), address(0));  // Unset!
    vault.withdrawFees();  // Fees burn
    assertEq(vault.feeAccumulator(), 0);
  }
  ```
- **Fix Suggestion:**
  ```
  <initialize(address _collateral, address _feeReceiver, ...)> {
    require(_feeReceiver != address(0), "invalid receiver");
    feeReceiver = _feeReceiver;
    // ...
  }
  ```
- **Detection Heuristics:** Audit initialization functions for address(0) checks; search for transfers to unconstrained feeReceiver

---

## PERMISSION & ROLE ATTACKS

### Vulnerability MON-C-008: Oracle Update Without Access Control

- **Pattern ID:** MON-C-008
- **Severity:** CRITICAL (9.6/10)
- **Rationale:** If oracle setter lacks proper role checks, attacker can update oracle to malicious contract
- **Preconditions:** `setOracle()` function lacks onlyOwner/onlyFactory modifier; attacker has transaction access
- **Concrete Call Sequence:**
  1. Attacker deploys MockOracle that always returns 1000x inflated price
  2. Attacker calls `vault.setOracle(mockOracle)`
  3. All collateral valuations are 1000x higher
  4. Attacker deposits low-value collateral, borrows massive debt
  5. Liquidation engine sees inflated values, fails to liquidate
  6. Attacker defaults; vault is insolvent
- **Vulnerable Code (Pseudo):**
  ```
  <setOracle(address _oracle)> {
    oracle = _oracle;  // ❌ No access control
  }
  ```
- **Broken Invariants:** INV-C-012 (oracle is immutable or controlled by trusted party)
- **Exploit Economics:** Unbounded; entire vault collateral can be stolen
- **Foundry Repro:**
  ```solidity
  function testUncontrolledOracleChange() public {
    MockOracle evil = new MockOracle(1000e18);
    vm.prank(attacker);
    vault.setOracle(address(evil));  // ❌ Succeeds
    assertEq(vault.oracle(), address(evil));
  }
  ```
- **Fix Suggestion:**
  ```
  <setOracle(address _oracle)> {
    require(msg.sender == factory || msg.sender == owner, "unauthorized");
    oracle = _oracle;
  }
  ```
- **Detection Heuristics:** Search for setter functions lacking onlyOwner/onlyFactory; grep for `=` assignments without guards

---

### Vulnerability MON-C-009: Rate Controller Takeover

- **Pattern ID:** MON-C-009
- **Severity:** CRITICAL (9.7/10)
- **Rationale:** Attacker-controlled rate controller can set rates to 0 or 10000% to drain vault
- **Preconditions:** RateController setter unguarded; attacker can update controller
- **Concrete Call Sequence:**
  1. Attacker calls `vault.setRateController(attackerController)`
  2. Attacker's controller returns `getRate() = 0`
  3. Existing borrowers' debt no longer accrues interest
  4. Attacker deposits collateral and borrows at 0% interest
  5. Meanwhile, legitimate borrowers see no debt growth
  6. Attacker repays after borrowing peak, dumps collateral
  7. Vault's debt-to-collateral ratio is inverted (negative real interest)
- **Vulnerable Code (Pseudo):**
  ```
  <setRateController(address _controller)> {
    rateController = _controller;  // ❌ Unguarded
  }
  ```
- **Broken Invariants:** INV-C-013 (rateController immutable or trusted)
- **Exploit Economics:** Entire interest pool (potentially millions in expected accrual) is lost
- **Foundry Repro:**
  ```solidity
  function testRateControllerTakeover() public {
    MockRateController evil = new MockRateController(0);  // 0% interest
    vm.prank(attacker);
    vault.setRateController(address(evil));
    
    vault.deposit(1000e18, 100e18);
    vm.roll(block.number + 1000);  // Simulate 1000 blocks
    
    uint256 debtAfter = vault.debtShares(user) * vault.debtIndex() / 1e27;
    assertEq(debtAfter, 100e18);  // Zero interest!
  }
  ```
- **Fix Suggestion:**
  ```
  <setRateController(address _controller)> {
    require(msg.sender == owner || msg.sender == factory, "unauthorized");
    rateController = _controller;
  }
  ```
- **Detection Heuristics:** Cross-reference all setter functions with onlyOwner modifiers; audit factory role delegation

---

## FACTORY DEPLOYMENT SECURITY

### Vulnerability MON-C-010: Predictable Vault Address Collision

- **Pattern ID:** MON-C-010
- **Severity:** MEDIUM (6.8/10)
- **Rationale:** If factory uses deterministic deployment (CREATE2 with user params), attacker can pre-deploy vault with same params and redirect users
- **Preconditions:** Factory uses CREATE2 without nonce randomization; vault address derivable from collateral + stablecoin params
- **Concrete Call Sequence:**
  1. Factory deployment pattern: `salt = keccak256(abi.encode(collateral, decimals, symbol))`
  2. Attacker observes pending vault deployment in mempool
  3. Attacker pre-deploys vault with same params to address X
  4. User thinks they're depositing to official vault, but deposited to attacker's pre-staged vault
  5. Attacker's vault has malicious oracle/rate controller
  6. Attacker steals deposited collateral
- **Vulnerable Code (Pseudo):**
  ```
  <deployVault(address _collateral, string _symbol, ...)> {
    bytes32 salt = keccak256(abi.encode(_collateral, _symbol, _decimals));
    Vault vault = new Vault{salt: salt}(other params);  // ❌ Deterministic
  }
  ```
- **Broken Invariants:** INV-C-014 (vault address uniqueness), INV-C-015 (vault address non-guessable)
- **Exploit Economics:** Attacker steals deposits to fake vault until contract verified
- **Foundry Repro:**
  ```solidity
  function testPredictableVaultAddress() public {
    bytes32 salt = keccak256(abi.encode(collateral, "STABLE", 18));
    address predictedAddr = factory.computeVaultAddress(salt);
    
    // Attacker pre-deploys to predictedAddr
    // ...
    
    address deployedAddr = factory.deployVault(collateral, "STABLE", ...);
    assertEq(deployedAddr, predictedAddr);  // Matched!
  }
  ```
- **Fix Suggestion:**
  ```
  <deployVault(address _collateral, string _symbol, ...)> {
    bytes32 salt = keccak256(abi.encode(_collateral, _symbol, block.timestamp, msg.sender));
    // Include timestamp + caller to randomize
  }
  ```
- **Detection Heuristics:** Inspect CREATE2 salt construction; verify non-deterministic components

---

### Vulnerability MON-C-011: Factory Admin Upgrade Without Governance

- **Pattern ID:** MON-C-011
- **Severity:** CRITICAL (9.4/10)
- **Rationale:** If factory is upgradeable and lacks timelock, admin can unilaterally change vault implementation
- **Preconditions:** Factory is UUPS/transparent proxy; admin account not secured by multisig; no timelock
- **Concrete Call Sequence:**
  1. Factory admin account (single signer) is compromised
  2. Attacker calls `factory.upgradeTo(maliciousFactory)`
  3. Malicious factory's `deployVault()` deploys vaults with backdoored implementations
  4. All NEW vaults become attacker-controlled
  5. Existing vaults unaffected, but new deposits go to backdoored contracts
- **Vulnerable Code (Pseudo):**
  ```
  <upgradeToAndCall(address newImpl, bytes calldata data)> {
    require(msg.sender == admin, "unauthorized");  // ❌ Single EOA check
    _authorizeUpgrade(newImpl);
    // ... upgrade logic
  }
  ```
- **Broken Invariants:** INV-C-016 (factory implementation immutable or governance-gated)
- **Exploit Economics:** All future vault liquidity can be siphoned
- **Foundry Repro:**
  ```solidity
  function testAdminUpgradeWithoutGovernance() public {
    MaliciousFactory evil = new MaliciousFactory();
    vm.prank(factory.admin());
    factory.upgradeToAndCall(address(evil), "");
    
    // All new vaults now backdoored
    (address newVault, ) = factory.deployVault(...);
    assertTrue(evil.isVaultBydoored(newVault));
  }
  ```
- **Fix Suggestion:**
  ```
  <upgradeToAndCall(address newImpl, bytes calldata data)> {
    require(msg.sender == governance.timelock, "must go through governance");
    // Require 2-day delay minimum
    // ...
  }
  ```
- **Detection Heuristics:** Audit factory upgradeability; verify multisig + timelock on proxy upgrades

---

## INVARIANT CATALOG (CORE MODULE)

| ID | Invariant | Violation Impact |
|---|---|---|
| INV-C-001 | Oracle is trusted, non-upgradeable without governance | Collateral mispricing, insolvency |
| INV-C-002 | RateController is authorized, immutable without delay | Interest manipulation, debt accrual exploit |
| INV-C-003 | totalDebtShares × debtIndex ≈ minted stablecoins + accumulated fees (within 1 wei) | Debt undertracking, insolvency |
| INV-C-004 | assetIndex stable within block (no reentrancy) | Flash loan share inflation, collateral theft |
| INV-C-005 | collateral.balanceOf(vault) ≥ sum(assetShares) × assetIndex / PRECISION | Undercollateralization on withdrawal |
| INV-C-006 | Interest rate changes are gradual (no same-block jumps >1% per block) | MEV liquidation frontrunning |
| INV-C-007 | All users see identical debtIndex per block | Interest fairness violation |
| INV-C-008 | debtIndex monotonically increases | Debt forgiveness if index decreases |
| INV-C-009 | assetIndex monotonically increases (if collateral yield-bearing) | Phantom collateral, insolvency |
| INV-C-010 | Borrow fees reflected in debtShares, not minted stablecoin | Double-charging on interest accrual |
| INV-C-011 | feeReceiver is non-zero, immutable without governance | Fee lock-up or loss |
| INV-C-012 | Oracle is immutable or admin-upgradeable via governance only | Oracle manipulation |
| INV-C-013 | RateController is immutable or admin-upgradeable via governance only | Rate manipulation |
| INV-C-014 | Vault addresses are globally unique | Vault collision / impersonation |
| INV-C-015 | Vault addresses are non-guessable before deployment | Pre-deployment vault spoofing |
| INV-C-016 | Factory implementation is immutable or governance-gated | Factory backdoor, all future vaults compromised |
| INV-C-017 | debtShares[user] + totalDebtShares never overflow | Debt wrapping, liquidation evasion |
| INV-C-018 | assetShares[user] + totalAssetShares never overflow | Collateral wrapping, phantom deposits |
| INV-C-019 | Interest accrual is atomic per block (no partial index updates) | Mid-block state inconsistency |
| INV-C-020 | Collateral token does not reenter during deposit/withdraw | Reentrancy, index inflation |

---

## FOUNDRY TEST SKELETONS (CORE)

### Skeleton 1: Initialization & Role Isolation
```solidity
contract MonolithCoreInitTest is Test {
  Vault vault;
  address factory;
  
  function setUp() public {
    factory = address(new VaultFactory());
  }
  
  function testFactoryOnlyCanInitialize() public {
    Vault impl = new Vault();
    // Attempt to initialize as non-factory
    vm.prank(address(0xdead));
    vm.expectRevert("unauthorized");
    impl.initialize(address(collateral), address(stablecoin), address(oracle), 
                    address(controller), 1e4, 8000, 100);
  }
  
  function testDeployVaultIsolation() public {
    (address v1, ) = VaultFactory(factory).deployVault(collateralA, "STAB-A", 1e4, 8000, 100);
    (address v2, ) = VaultFactory(factory).deployVault(collateralB, "STAB-B", 1e4, 8000, 100);
    assertNotEq(v1, v2);
  }
}
```

### Skeleton 2: Interest Accrual Edge Cases
```solidity
contract MonolithInterestAccrualTest is Test {
  Vault vault;
  
  function testZeroBlockNoAccrual() public {
    vault.deposit(100e18, 10e18);
    uint256 idx1 = vault.debtIndex();
    vault.deposit(100e18, 10e18);  // Same block
    uint256 idx2 = vault.debtIndex();
    assertEq(idx1, idx2);
  }
  
  function testRoundingBiasAccumulation() public {
    vm.roll(block.number + 52560000);  // 1 year at 13-sec blocks
    // High debtIndex environment
    vault.deposit(100e18, 89285714285714284);
    uint256 debt = vault.debtShares(address(this)) * vault.debtIndex() / 1e27;
    assertLt(debt, 89285714285714284);  // Dust loss
  }
}
```

### Skeleton 3: Multi-User State Consistency
```solidity
contract MonolithStateConsistencyTest is Test {
  Vault vault;
  address user1 = address(0x111);
  address user2 = address(0x222);
  
  function testDebtSumConsistency() public {
    uint256 debt1 = 100e18;
    uint256 debt2 = 50e18;
    
    vm.prank(user1);
    vault.deposit(collateral, debt1);
    vm.prank(user2);
    vault.deposit(collateral, debt2);
    
    uint256 total = vault.totalDebtShares() * vault.debtIndex() / 1e27;
    uint256 sum = debt1 + debt2;  // Ignoring fees for simplicity
    assertEq(total, sum);
  }
}
```

### Skeleton 4: Fee Accumulation
```solidity
contract MonolithFeeAccumulationTest is Test {
  Vault vault;
  
  function testBorrowFeeTracking() public {
    uint256 borrowAmount = 100e18;
    vault.deposit(1000e18, borrowAmount);
    
    uint256 expectedFee = borrowAmount * vault.borrowFeePercent() / 1e4;
    assertEq(vault.feeAccumulator(), expectedFee);
  }
  
  function testFeeWithdrawalToValidReceiver() public {
    vault.deposit(1000e18, 100e18);
    uint256 fees = vault.feeAccumulator();
    
    address receiver = vault.feeReceiver();
    assertNotEq(receiver, address(0));
    
    vault.withdrawFees();
    assertEq(stablecoin.balanceOf(receiver), fees);
  }
}
```

---

## SUMMARY: CORE MODULE ATTACK SURFACE

**Total Vulnerabilities Catalogued:** 11 (MON-C-001 through MON-C-011)  
**Total Invariants Identified:** 20 (INV-C-001 through INV-C-020)  
**Test Skeletons Provided:** 4

**Critical (9.0+):** 4 vulnerabilities (uninitialized proxy, oracle change, rate controller, factory upgrade)  
**High (7.0–8.9):** 3 vulnerabilities (flash loan inflation, borrow fee double-charge, controller takeover)  
**Medium (4.0–6.9):** 4 vulnerabilities (rounding bias, same-block rate, fee receiver, vault address)

**Key Defensive Practices:**
- Always accrue interest before state mutations
- Guard all initializers and setters with role checks
- Snapshot asset indices before external calls
- Implement timelock governance for critical upgrades
- Round UP debt shares (use ceilDiv for protection)

---

✓ **Module Complete.**

# MONOLITH CDP STABLECOIN ENGINE — CORE AUDIT PRIMER v0.3

**Protocol Class:** Overcollateralized Stablecoin Minting (MakerDAO/Fraxlend/Liquity family)  
**Scope:** Vault architecture, debt accounting, share conversions, factory patterns, interest accrual, fees, yield vault integration, borrower modes  
**Audit Focus:** Implementation-driven, invariant-aware, attacker-first threat modeling  
**Version:** 0.3 (Self-Evolved, v0.2→v0.3 Gap Integration)

---

## ARCHITECTURE FINGERPRINT

Monolith operates as a **CDP (Collateralized Debt Position) engine** with the following canonical components:

### Core Layer Topology
- **VaultFactory**: Deploys isolated vault + stablecoin pairs with independent governance
- **Vault**: Per-vault collateral management, debt issuance, liquidation state, yield accrual
- **Stablecoin (ERC20)**: Minted against vaults, redeemable at parity, fee-aware
- **Oracle**: Collateral pricing with staleness windows and fallback chains
- **RateController**: Autonomous interest rate adjustment based on peg deviation
- **YieldController** (NEW): Manages vault yield accrual if collateral is yield-bearing (ERC4626)
- **Liquidation Module**: Sequenced partial/full liquidation with auction/swap routing
- **BorrowerMode Manager** (NEW): Tracks interest-free and redemption-free mode flags per user

### State Tracking Duality
Monolith uses a **share-based accounting model** (ERC-4626 inspired but asymmetric):

**DebtShares System:**
- User holds `debtShares[user]` in storage
- Global `totalDebtShares` tracks cumulative issuance
- Interest accrual inflates the conversion ratio: `debtIndex` (similar to Aave's `variableBorrowIndex`)
- Debt calculation: `debtOwed = debtShares[user] * debtIndex / PRECISION`
- Borrower mode flag modulates interest accrual (interest-free mode bypasses rate accrual)

**AssetShares System:**
- Collateral backing uses `assetShares[user]` for fractional ownership
- Global `totalAssetShares` represents total collateral units
- Collateral value: `assetValue = assetShares[user] * assetIndex / PRECISION`
- Enables dynamic collateral rebalancing without withdrawal/redeposit
- Yield accrual on ERC4626 tokens inflates `assetIndex` (yieldIndex)

**Yield Share System** (NEW):
- If collateral is ERC4626 vault token: `vaultYieldShares[user]` tracks accrued yield
- Yield calculation: `yieldAccrued = assetShares[user] * (currentYieldIndex - userYieldIndexSnapshot) / PRECISION`
- Fees deducted from yield: `accruedFees += yieldAccrued * feePercent / 10000`
- Risk: yield can be front-run or drained pre-rebase

**Borrower Mode System** (NEW):
- `borrowerMode[user]` ∈ {STANDARD, INTEREST_FREE, REDEMPTION_FREE, HYBRID}
- INTEREST_FREE: debtIndex NOT incremented for this user (free borrows)
- REDEMPTION_FREE: blocking external burn() on user's stablecoin during liquidation
- Risk: mode switch races allow free redemption or unpaid interest

### Factory Deployment Pattern
```
VaultFactory.deployVault(
  collateralToken,
  stablecoinName,
  ltv,
  liquidationThreshold,
  borrowFee,
  liquidationBonus,
  yieldStrategy  // NEW: if collateral is ERC4626
) → (vaultAddress, stablecoinAddress)
```

Each deployment initializes:
- Isolated vault with independent debt ceiling
- Fresh stablecoin contract with burn/mint permissions
- Rate controller bound to vault
- Yield controller (if collateral is yield-bearing) 
- Borrower mode defaults (all users start as STANDARD)
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
3. If collateral is ERC4626: snapshot yield index: `userYieldIndexSnapshot[msg.sender] = currentYieldIndex`
4. Accrue interest on existing debt (if any)
5. Check borrower mode: if INTEREST_FREE, set flag to skip debtIndex increment on next accrual
6. Calculate new debt shares: `debtShares[msg.sender] += debtToMint / currentDebtIndex`
7. Apply borrow fee: `fee = debtToMint * borrowFeePercent / 10000`
8. Adjust debt shares by fee (see §Fee Flow Misrouting): `debtShares[msg.sender] -= fee / currentDebtIndex`
9. Increment `totalDebtShares`
10. Mint stablecoin to user (after fee): `stablecoin.mint(msg.sender, debtToMint - fee)`
11. Accrue fee to feeAccumulator: `feeAccumulator += fee`
12. Check health factor: `require(computeHealthFactor(msg.sender) >= LTV_THRESHOLD)`

**State Mutations:**
- `assetShares[user] += ∆` (collateral tracking)
- `debtShares[user] += ∆` (debt obligation, adjusted for fees)
- `userYieldIndexSnapshot[user] = currentYieldIndex` (NEW: yield tracking)
- `totalDebtShares += ∆`
- `stablecoin.totalSupply() += debtToMint - fee`
- `feeAccumulator += fee`

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
4. Check borrower mode: if INTEREST_FREE, accrue pending interest NOW before reducing shares
5. Convert debt amount to shares: `sharesToReduce = debtAmount / currentDebtIndex`
6. Decrement user's debt shares: `debtShares[msg.sender] -= sharesToReduce`
7. Decrement `totalDebtShares`
8. Emit `Repaid(user, debtAmount)`

**Key Invariant Checks:**
- Repay does NOT affect collateral position (assetShares unchanged)
- Health factor may improve post-repay (lower debt numerator)
- User can repay even if underwater (liquidation-eligible)
- If user is in INTEREST_FREE mode, repay triggers "catch-up" accrual (sets user back to STANDARD mode)

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
5. If collateral is ERC4626: accrue yield and deduct accrued fees from withdrawal: (see §Yield Vault Integration)
6. Transfer collateral to user: `collateralToken.transfer(msg.sender, assetAmount)`
7. **CRITICAL CHECK:** Verify health factor remains ≥ liquidation threshold
8. Emit `Withdrawn(user, assetAmount)`

**Broken Invariant Risk:**
- If HF check bypassed: user can reduce collateral below liquidation while debt remains
- Subsequent interest accrual may trap position in insolvency
- Yield fee deduction can be front-run (pre-rebase dilution attack)

---

## VAULT STORAGE LAYOUT & INITIALIZATION

### Critical State Variables

```solidity
// Vault.sol
mapping(address => uint256) public assetShares;              // User collateral ownership units
mapping(address => uint256) public debtShares;               // User debt obligation units
mapping(address => uint256) public userYieldIndexSnapshot;   // NEW: yield index at deposit
mapping(address => BorrowerMode) public borrowerMode;        // NEW: interest-free / redemption-free flags
uint256 public totalAssetShares;                             // Sum of all assetShares
uint256 public totalDebtShares;                              // Sum of all debtShares
uint256 public debtIndex;                                    // Accrual multiplier (18 decimals + 9)
uint256 public assetIndex;                                   // Collateral rebalance multiplier
uint256 public yieldIndex;                                   // NEW: cumulative yield multiplier (ERC4626)
uint256 public lastAccrualBlock;                             // Interest checkpoint
uint256 public lastYieldAccrualBlock;                        // NEW: yield accrual checkpoint
address public collateralToken;                              // ERC20 or ERC4626 input asset
address public stablecoin;                                   // Minted liability
address public oracle;                                       // Price feed
address public rateController;                               // Interest rate manager
address public yieldController;                              // NEW: yield accrual manager (if ERC4626)
uint256 public accruedFees;                                  // Fee accumulator
address public feeReceiver;                                  // NEW: fee withdrawal address
uint256 public feePercent;                                   // NEW: yield fee rate (e.g., 10% = 1000 bps)
bool public initialized;                                     // Guard against re-initialization
bool public isYieldVault;                                    // NEW: flag if collateral is ERC4626
```

### Initialization Attack Surface

**Initializer Function (Placeholder):**
```
<initialize(
  address _collateral,
  address _stablecoin,
  address _oracle,
  address _rateController,
  address _yieldController,  // NEW
  address _feeReceiver,      // NEW
  uint256 _ltv,
  uint256 _liquidationThreshold,
  uint256 _borrowFee,
  uint256 _yieldFeePercent   // NEW
)>
```

### Vulnerability MON-C-001: Uninitialized Proxy Takeover

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

### Vulnerability MON-C-002: Rounding Bias in convertToDebt()

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

## YIELD VAULT INTEGRATION (NEW v0.3 SECTION)

### ERC4626 Yield-Bearing Collateral Architecture

If collateral is an ERC4626 vault token (e.g., Lido stETH, Aave aUSDC, Yearn yDAI):

**State Tracking:**
- `isYieldVault`: Boolean flag set at initialization
- `yieldIndex`: Cumulative yield multiplier (initialized to 1e27)
- `lastYieldAccrualBlock`: Checkpoint for yield accrual
- `userYieldIndexSnapshot[user]`: Per-user yield index at deposit/last claim
- `vaultYieldShares[user]`: User's accrued yield (in underlying token units)
- `accruedFees`: Fees deducted from yield before distribution

**Yield Accrual Formula:**
```
yieldAccrued = assetShares[user] * (currentYieldIndex - userYieldIndexSnapshot[user]) / PRECISION
accruedFees = yieldAccrued * feePercent / 10000
userYieldShares[user] += yieldAccrued - accruedFees
```

### Vulnerability MON-C-006: Pre-Rebase Front-Run → Share Dilution (NEW)

- **Pattern ID:** MON-C-006
- **Severity:** HIGH (8.2/10)
- **Rationale:** If ERC4626 vault rebases (e.g., new yield accrues), attacker can deposit immediately BEFORE rebase to capture diluted shares, then exit AFTER rebase for profit
- **Preconditions:** Collateral rebases daily (e.g., stETH, Lido); rebase time is predictable; attacker monitors mempool for rebase txs
- **Concrete Call Sequence:**
  1. Lido stETH vault: 1000 stETH, totalSupply = 1000 shares, yield = 1 stETH pending
  2. Attacker deposits 100 USDC worth collateral: gets 100 shares (before rebase)
  3. Rebase occurs: Lido distributes 1 stETH to vault
  4. Vault now has 1001 stETH, but totalSupply still 1100 shares (dilution!)
  5. Attacker's 100 shares now worth: 100 / 1100 * 1001 ≈ 91 stETH (LOSS of 9 stETH)
  6. BUT attacker front-runs: deposits 100 just before rebase, claims yield immediately after
  7. Yield snapshot: userYieldIndexSnapshot = 1e27; yieldIndex = 1.001e27 (post-rebase)
  8. Attacker's yield = 100 shares * (1.001e27 - 1e27) / 1e27 = 0.1 stETH (captured rebase)
  9. Attacker's net: deposited 100, captured 0.1 yield, exits profitably
  10. Other users diluted (their shares worth less because attacker captured rebase)
- **Vulnerable Code (Pseudo):**
  ```
  <accrueYield()> {
    uint256 currentBalance = collateralToken.balanceOf(address(this));
    uint256 expectedBalance = totalAssetShares * assetIndex / PRECISION;
    uint256 yieldGenerated = currentBalance - expectedBalance;  // ❌ Detects rebase
    yieldIndex *= (1 + yieldGenerated / expectedBalance);
  }
  
  <deposit(uint256 collateralAmount, uint256 debt)> {
    // ❌ No yield accrual before snapshot
    collateral.transferFrom(msg.sender, address(this), collateralAmount);
    assetShares[msg.sender] += collateralAmount / assetIndex;
    userYieldIndexSnapshot[msg.sender] = yieldIndex;  // Captures full rebase immediately
  }
  ```
- **Broken Invariants:** INV-C-017 (yield captured proportionally to deposit duration), INV-C-018 (no rebase front-running)
- **Exploit Economics:** With 1000 ETH vault rebasing daily at 5% annual (0.0137% daily), attacker can capture 0.0137% × 1000 = 0.137 ETH per tx; scales with vault size
- **Foundry Repro:**
  ```solidity
  function testPreRebaseFrontRun() public {
    // Lido rebase: 1000 stETH → 1001 stETH
    vault.deposit(100e18, 0);  // Deposit before rebase, get 100 shares
    
    // Rebase occurs
    lido.distributeYield(1e18);  // Add 1 stETH yield
    
    // Attacker's yield should be proportional to duration held, NOT 1 full ETH
    uint256 attackerYield = vault.vaultYieldShares(attacker);
    assertLt(attackerYield, 1e18);  // Should be fraction, not full rebase
  }
  ```
- **Fix Suggestion:**
  ```
  <deposit(uint256 collateralAmount, uint256 debt)> {
    <accrueYield()>;  // Always accrue yield BEFORE snapshot
    collateral.transferFrom(msg.sender, address(this), collateralAmount);
    assetShares[msg.sender] += collateralAmount / assetIndex;
    userYieldIndexSnapshot[msg.sender] = yieldIndex;  // Now captures only future yield
  }
  
  <accrueYield()> {
    uint256 currentBalance = collateralToken.balanceOf(address(this));
    uint256 expectedBalance = totalAssetShares * assetIndex / PRECISION;
    if (currentBalance > expectedBalance) {
      uint256 yieldGenerated = currentBalance - expectedBalance;
      // Distribute to fee receiver
      uint256 fee = yieldGenerated * feePercent / 10000;
      accruedFees += fee;
      yieldIndex *= (1 + (yieldGenerated - fee) / expectedBalance);
    }
  }
  ```
- **Detection Heuristics:** Check ERC4626 vaults for rebase; audit deposit/yield accrual ordering; simulate front-run scenarios

---

### Vulnerability MON-C-007: Yield Fee Accrual Race → Uncollected Fees (NEW)

- **Pattern ID:** MON-C-007
- **Severity:** MEDIUM (6.3/10)
- **Rationale:** If yield fees are calculated asynchronously (deferred accrual), attacker can withdraw accrued yield before fees are deducted
- **Preconditions:** Yield accrual and fee deduction are separate txs; feeReceiver is non-zero but fee withdrawal is manual
- **Concrete Call Sequence:**
  1. User deposits 100 collateral (stETH), earns 1 stETH daily yield
  2. Day 1: Yield accrues: vaultYieldShares[user] = 1 stETH
  3. Day 2: Attacker calls `claimYield()` before `collectFees()` is called
  4. Attacker receives full 1 stETH yield (fees not deducted yet)
  5. feeAccumulator = 1 stETH × 10% = 0.1 stETH (pending)
  6. Later, feeReceiver collects fees from vault: collateralToken.transfer(feeReceiver, accruedFees)
  7. BUT collateral balance was already reduced by attacker's withdrawal
  8. If vault has insufficient collateral, fee withdrawal fails or steals from other users
- **Vulnerable Code (Pseudo):**
  ```
  <claimYield(address user)> {
    uint256 yield = vaultYieldShares[user];
    vaultYieldShares[user] = 0;
    collateral.transfer(user, yield);  // ❌ No fee deduction
  }
  
  <collectFees()> {
    require(msg.sender == feeReceiver, "unauthorized");
    uint256 fees = accruedFees;
    accruedFees = 0;
    collateral.transfer(feeReceiver, fees);  // May fail if balance insufficient
  }
  ```
- **Broken Invariants:** INV-C-019 (yield claimed = vaultYieldShares - applicable fees), INV-C-020 (feeAccumulator never exceeds available collateral)
- **Exploit Economics:** If vault earns 1% yield monthly on $100M = $1M, and fee = 10%, attacker can front-run and claim full $1M before $100k fee is deducted
- **Foundry Repro:**
  ```solidity
  function testYieldFeeRace() public {
    vault.deposit(100e18, 0);
    // Yield accrues
    lido.distributeYield(1e18);
    vault.accrueYield();
    
    uint256 yieldBefore = vault.vaultYieldShares(user);
    
    vm.prank(user);
    vault.claimYield();
    
    uint256 yieldClaimed = collateral.balanceOf(user);
    uint256 expectedFee = yieldBefore * vault.feePercent() / 10000;
    
    assertEq(yieldClaimed, yieldBefore);  // No fee deducted!
    assertGt(vault.accruedFees(), expectedFee);  // Fees still pending
  }
  ```
- **Fix Suggestion:**
  ```
  <claimYield(address user)> {
    uint256 yield = vaultYieldShares[user];
    vaultYieldShares[user] = 0;
    
    uint256 fee = yield * feePercent / 10000;
    uint256 userAmount = yield - fee;
    
    accruedFees += fee;  // Deduct before transfer
    collateral.transfer(user, userAmount);
  }
  
  <collectFees()> {
    require(msg.sender == feeReceiver, "unauthorized");
    uint256 fees = accruedFees;
    accruedFees = 0;
    require(collateral.balanceOf(address(this)) >= fees, "insufficient balance");
    collateral.transfer(feeReceiver, fees);
  }
  ```
- **Detection Heuristics:** Audit yield claim vs. fee accrual ordering; check feeAccumulator bounds; verify atomic fee deduction

---

## FEE FLOW MISROUTING

### Vulnerability MON-C-008: Borrow Fee Double-Charging (UPDATED v0.3)

- **Pattern ID:** MON-C-008
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
- **Broken Invariants:** INV-C-021 (debtShares * debtIndex == minted stablecoins + accumulated fees)
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

### Vulnerability MON-C-009: Fee Receiver Uninitialized (NEW v0.3)

- **Pattern ID:** MON-C-009
- **Severity:** HIGH (7.6/10)
- **Rationale:** If feeReceiver is address(0) or not set, accrued fees are locked forever (address(0) cannot claim)
- **Preconditions:** Factory deploys vault without feeReceiver argument; vault initializer does not validate feeReceiver ≠ address(0)
- **Concrete Call Sequence:**
  1. Factory deploys vault with feeReceiver = address(0) (default)
  2. Users deposit, accrue fees: accruedFees = 100 stables
  3. Protocol DAO attempts to claim fees: `feeReceiver.claimFees()` → reverts (address(0) cannot receive)
  4. Attacker waits for vault to accumulate high fees, then calls `emergencyWithdraw()` if present
  5. Attacker extracts accumulated fees (if no access control on emergency function)
- **Vulnerable Code (Pseudo):**
  ```
  <initialize(address _feeReceiver, ...)> {
    require(_feeReceiver != address(0), "zero receiver");  // ❌ Missing guard
    feeReceiver = _feeReceiver;
  }
  
  <collectFees()> {
    require(msg.sender == feeReceiver, "unauthorized");  // ❌ If feeReceiver = 0, always fails
    collateral.transfer(feeReceiver, accruedFees);
  }
  ```
- **Broken Invariants:** INV-C-022 (feeReceiver is non-zero, immutable without governance)
- **Exploit Economics:** If vault earns $1M in fees and feeReceiver is unset, $1M is locked; attacker with access to emergency functions can steal
- **Foundry Repro:**
  ```solidity
  function testFeeReceiverUninitialized() public {
    vault.deposit(100e18, 80e18);
    
    uint256 feesAccrued = vault.accruedFees();
    assertTrue(feesAccrued > 0);
    
    vm.expectRevert("zero receiver");
    vault.collectFees();  // Fails because feeReceiver = 0
  }
  ```
- **Fix Suggestion:**
  ```
  <initialize(address _feeReceiver, ...)> {
    require(_feeReceiver != address(0), "zero receiver");
    feeReceiver = _feeReceiver;
  }
  
  <collectFees()> {
    require(msg.sender == feeReceiver, "unauthorized");
    require(feeReceiver != address(0), "receiver unset");
    collateral.transfer(feeReceiver, accruedFees);
  }
  ```
- **Detection Heuristics:** Check vault initialization for feeReceiver validation; verify no zero-address paths; audit fee collection

---

### Vulnerability MON-C-010: Deployer Skimming via Isolated Pair (NEW v0.3)

- **Pattern ID:** MON-C-010
- **Severity:** MEDIUM (6.8/10)
- **Rationale:** If factory allows deployer to set initial parameters without upper bounds, deployer can create undercollateralized vault pairs or extract fees
- **Preconditions:** Factory deployer account not secured by multisig; LTV/liquidationThreshold can be set to extreme values
- **Concrete Call Sequence:**
  1. Deployer creates vault pair: collateral = USDC, debtToken = new Stablecoin
  2. Sets LTV = 95%, liquidationThreshold = 90% (extreme, no buffer)
  3. Sets borrowFee = 50% (high fee extraction)
  4. Early users deposit USDC, borrow stablecoins
  5. Deployer front-runs: deposits tiny amount, borrows stablecoin, creates large debt position
  6. Deployer immediately liquidates own position to extract liquidation bonus + fees
  7. Or: deployer sets RateController to 1000% annual, collects fees from high interest accrual
- **Vulnerable Code (Pseudo):**
  ```
  <deployVault(
    address _collateral,
    string _name,
    uint256 _ltv,
    uint256 _liquidationThreshold,
    uint256 _borrowFee
  )> {
    // ❌ No validation on parameters
    Vault vault = new Vault();
    vault.initialize(_collateral, ..., _ltv, _liquidationThreshold, _borrowFee);
    return vault;
  }
  ```
- **Broken Invariants:** INV-C-023 (LTV ≤ liquidationThreshold), INV-C-024 (borrowFee ≤ 10%), INV-C-025 (deployer cannot skim)
- **Exploit Economics:** Deployer can extract 50% of all borrowed amounts as fees; with $100M borrowed = $50M steal
- **Foundry Repro:**
  ```solidity
  function testDeployerSkimmingViaFee() public {
    vm.prank(deployer);
    (address vault, ) = factory.deployVault(collateral, "STAB", 9500, 9000, 5000);  // 50% fee!
    
    vault.setLtv(9500);  // 95% LTV, extreme
    
    // Users deposit
    vault.deposit(100e18, 90e18);  // 90% LTV, risky
    
    uint256 feesCollected = vault.accruedFees();
    assertGt(feesCollected, 4.5e18);  // 50% of 90 = 45, but rounds up
  }
  ```
- **Fix Suggestion:**
  ```
  <deployVault(..., uint256 _ltv, uint256 _liquidationThreshold, uint256 _borrowFee)> {
    require(_ltv >= 5000 && _ltv <= 8000, "invalid LTV");  // Bounds: 50-80%
    require(_liquidationThreshold >= _ltv, "threshold < LTV");
    require(_borrowFee <= 1000, "fee > 10%");  // Max 10% borrow fee
    Vault vault = new Vault();
    vault.initialize(...);
  }
  ```
- **Detection Heuristics:** Audit factory deployment parameter validation; check for unbounded LTV/fee setters

---

## BORROWER MODE SYSTEM (NEW v0.3 SECTION)

### Interest-Free Mode
- If `borrowerMode[user] == INTEREST_FREE`, user's debt does NOT accrue interest
- `debtIndex` increments normally for other users
- User's debt shares fixed; actual debt obligation = shares × current index (but skipped accrual for this user)
- Risk: Free borrows can accumulate, diluting other borrowers' interest
- Attack: Attacker borrows unlimited debt in interest-free mode, vault becomes unsustainable

### Redemption-Free Mode
- If `borrowerMode[user] == REDEMPTION_FREE`, user's stablecoin cannot be redeemed/burned externally
- Blocks liquidations via external redemption (user stays solvent artificially)
- Risk: Mode switch race allows free redemption before enforcement

### Vulnerability MON-C-011: Borrower Mode Switch Race → Free Redemption (NEW)

- **Pattern ID:** MON-C-011
- **Severity:** HIGH (8.3/10)
- **Rationale:** If borrower mode can be switched mid-block, user can redeem in REDEMPTION_FREE mode, then switch back to STANDARD, violating invariants
- **Preconditions:** Borrower mode is mutable; no delay on mode switches; liquidation checks mode flag post-switch
- **Concrete Call Sequence:**
  1. User in REDEMPTION_FREE mode: borrows 100 stables, mode = REDEMPTION_FREE
  2. Liquidator tries to liquidate user's position (invalid due to mode)
  3. Attacker (user's accomplice) calls `setBorrowerMode(user, STANDARD)` (same block)
  4. Liquidator now sees mode = STANDARD, calls liquidate (now valid)
  5. BUT user's shares were reduced with REDEMPTION_FREE protection (no burn)
  6. User redeems stables externally before liquidation settles
  7. Vault loses collateral + stables (both assets leak)
- **Vulnerable Code (Pseudo):**
  ```
  <setBorrowerMode(address user, BorrowerMode newMode)> {
    require(msg.sender == user || msg.sender == governance, "unauthorized");
    borrowerMode[user] = newMode;  // ❌ Immediate, no timelock
  }
  
  <liquidatePartial(address user, uint256 debtToRepay)> {
    require(computeHealthFactor(user) < 1e18, "safe");
    require(borrowerMode[user] != REDEMPTION_FREE, "mode protected");  // ❌ Checks mode at liquidation time
    // ... liquidation proceeds
  }
  ```
- **Broken Invariants:** INV-C-026 (borrower mode changes require timelock), INV-C-027 (liquidation invariant to mode switches)
- **Exploit Economics:** Attacker can avoid liquidations indefinitely by mode-switching; vault becomes zombie (no liquidations)
- **Foundry Repro:**
  ```solidity
  function testBorrowerModeSwitchRace() public {
    vault.deposit(100e18, 80e18);
    vault.setBorrowerMode(user, REDEMPTION_FREE);  // User protected
    
    oracle.setPrice(0.95e18);  // User underwater
    
    // Attacker switches mode mid-block
    vm.prank(attacker);
    vault.setBorrowerMode(user, STANDARD);
    
    // Liquidator now sees STANDARD mode
    uint256 hf = vault.computeHealthFactor(user);
    assertTrue(hf < 1e18);  // Liquidatable
    
    liquidator.liquidatePartial(user, 40e18);  // Succeeds
    
    // BUT user can redeem stables before settlement
  }
  ```
- **Fix Suggestion:**
  ```
  <setBorrowerMode(address user, BorrowerMode newMode)> {
    require(msg.sender == user || msg.sender == governance, "unauthorized");
    pendingBorrowerMode[user] = newMode;
    modeChangeTime[user] = block.timestamp;
  }
  
  <getBorrowerMode(address user)> returns (BorrowerMode) {
    if (block.timestamp - modeChangeTime[user] >= MODE_CHANGE_DELAY) {
      return pendingBorrowerMode[user];
    }
    return borrowerMode[user];  // Current mode (locked)
  }
  ```
- **Detection Heuristics:** Audit borrower mode setters for delays; check liquidation logic for race conditions; verify mode snapshot at liquidation start

---

## AUTONOMOUS RATECONTROLLER EXPLOITS (NEW v0.3 SECTION)

### Peg Deviation → Rate Spike Attack

If RateController adjusts rates based on peg deviation (stablecoin price vs. $1):

**Attack Template:**
1. Monitor stablecoin price on exchange
2. If price < $0.99 (depeg), RateController raises rates to incentivize repayment
3. Attacker has borrowed at low rate; sudden spike + liquidation spam
4. Attacker's debt obligation increases 10%+ in one block
5. Attacker liquidates own position to extract liquidation bonus

**Mitigations:**
- Rate changes should be gradual (not >1% per block)
- Rounding should not favor exploiters in liquidation bonus calculations
- Accrual must happen BEFORE liquidation checks

### Spam Borrows → LTV Degradation

**Attack Template:**
1. Attacker deposits minimal collateral (e.g., 1 token)
2. Borrows tiny amounts many times (e.g., 0.0001 stables per tx)
3. Each borrow triggers fee accrual + rate spike
4. LTV of other users degrades (interest compounds faster)
5. Attacker liquidates underwater users for bonus extraction

**Mitigations:**
- Minimum borrow amounts enforced
- Fee per-tx caps to prevent spam
- Liquidation bonus limited per-user per-block

---

## FACTORY PARAMETER MANAGEMENT (NEW v0.3 SECTION)

### Vulnerability MON-C-012: Factory Governance Without Timelock (NEW)

- **Pattern ID:** MON-C-012
- **Severity:** CRITICAL (9.1/10)
- **Rationale:** If factory owner can unilaterally change oracle/controller without timelock, attacker can steal all vault liquidity
- **Preconditions:** Factory has mutable oracle/controller; no governance delay; owner account compromised
- **Concrete Call Sequence:**
  1. Attacker compromises factory owner (private key leak, rug-pull team)
  2. Attacker calls `setDefaultOracle(attacker_oracle)`, `setDefaultController(attacker_controller)`
  3. All NEW vault deployments use attacker-controlled oracles
  4. Attacker's oracle reports collateral price = $0 for existing vaults
  5. All users become instantly liquidatable
  6. Attacker liquidates all positions, seizes all collateral
- **Vulnerable Code (Pseudo):**
  ```
  <setDefaultOracle(address newOracle)> {
    require(msg.sender == owner, "unauthorized");  // ❌ Only owner check, no delay
    defaultOracle = newOracle;
  }
  ```
- **Broken Invariants:** INV-C-028 (oracle/controller require governance + timelock)
- **Exploit Economics:** Steal entire factory TVL (potentially $1B+)
- **Fix Suggestion:**
  ```
  <setDefaultOracle(address newOracle)> {
    require(msg.sender == governance.timelock, "must go through governance");
    pendingOracle = newOracle;
    oracleUpdateTime = block.timestamp + ORACLE_UPDATE_DELAY;  // e.g., 2 days
  }
  
  <finalizeOracleUpdate()> {
    require(block.timestamp >= oracleUpdateTime, "delay not elapsed");
    defaultOracle = pendingOracle;
    pendingOracle = address(0);
  }
  ```
- **Detection Heuristics:** Audit all factory oracle/controller setters; verify timelock + governance gate

---

## INVARIANT CATALOG (CORE MODULE v0.3)

| ID | Invariant | Violation Impact | Added in v0.3 |
|---|---|---|---|
| INV-C-001 | Oracle is trusted, non-upgradeable without governance | Collateral mispricing, insolvency | No |
| INV-C-002 | RateController is authorized, immutable without delay | Interest manipulation, debt accrual exploit | No |
| INV-C-003 | totalDebtShares × debtIndex ≈ minted stablecoins + accumulated fees (within 1 wei) | Debt undertracking, insolvency | No |
| INV-C-004 | assetIndex stable within block (no reentrancy) | Flash loan share inflation, collateral theft | No |
| INV-C-005 | collateral.balanceOf(vault) ≥ sum(assetShares) × assetIndex / PRECISION | Undercollateralization on withdrawal | No |
| INV-C-006 | Interest rate changes are gradual (no same-block jumps >1% per block) | MEV liquidation frontrunning | No |
| INV-C-007 | All users see identical debtIndex per block | Interest fairness violation | No |
| INV-C-008 | debtIndex monotonically increases | Debt forgiveness if index decreases | No |
| INV-C-009 | assetIndex monotonically increases (if collateral yield-bearing) | Phantom collateral, insolvency | No |
| INV-C-010 | Borrow fees reflected in debtShares, not minted stablecoin | Double-charging on interest accrual | No |
| INV-C-011 | feeReceiver is non-zero, immutable without governance | Fee lock-up or loss | No |
| INV-C-012 | Fee withdrawal is atomic, no reentrancy | Attacker drains all fees | No |
| INV-C-013 | Vault must be deployed via factory | Unauthorized vault deployments | No |
| INV-C-014 | Oracle/controller require governance + timelock | Unilateral parameter manipulation | No |
| INV-C-015 | Factory implementation immutable or governance-gated | Factory backdoor, all future vaults compromised | No |
| INV-C-016 | debtShares[user] + totalDebtShares never overflow | Debt wrapping, liquidation evasion | No |
| INV-C-017 | Yield captured proportionally to deposit duration | Pre-rebase front-running dilution | **NEW** |
| INV-C-018 | No rebase front-running (yield accrual before snapshot) | Share dilution, early rebase capture | **NEW** |
| INV-C-019 | Yield claimed = vaultYieldShares - applicable fees | Fee evasion, vault insolvency | **NEW** |
| INV-C-020 | feeAccumulator never exceeds available collateral | Fee collection failure, fund lock-up | **NEW** |
| INV-C-021 | Borrow fees deducted from debt shares AND minted amount | Double-charging avoided | **NEW** |
| INV-C-022 | feeReceiver is non-zero at initialization | Fees not locked forever | **NEW** |
| INV-C-023 | LTV ≤ liquidationThreshold ≤ 100% | Invalid vault parameters | **NEW** |
| INV-C-024 | borrowFee ≤ 10% of debt | Deployer fee skimming prevented | **NEW** |
| INV-C-025 | Deployer cannot unilaterally skim early liquidation bonus | Vault fairness | **NEW** |
| INV-C-026 | Borrower mode changes require timelock | Mode switch race prevented | **NEW** |
| INV-C-027 | Liquidation invariant to borrower mode switches | Liquidation guarantees | **NEW** |
| INV-C-028 | Oracle/controller require governance + timelock at factory level | Factory-wide parameter manipulation blocked | **NEW** |

---

## FOUNDRY TEST SKELETONS (CORE v0.3)

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
    vm.prank(address(0xdead));
    vm.expectRevert("unauthorized");
    impl.initialize(address(collateral), address(stablecoin), address(oracle), 
                    address(controller), address(0), 1e4, 8000, 100, 0, 0);
  }
  
  function testDeployVaultIsolation() public {
    (address v1, ) = VaultFactory(factory).deployVault(collateralA, "STAB-A", 1e4, 8000, 100);
    (address v2, ) = VaultFactory(factory).deployVault(collateralB, "STAB-B", 1e4, 8000, 100);
    assertNotEq(v1, v2);
  }
}
```

### Skeleton 2: Yield Vault Integration
```solidity
contract MonolithYieldVaultTest is Test {
  Vault vault;
  MockERC4626 yieldCollateral;
  
  function testPreRebaseFrontRunPrevention() public {
    yieldCollateral = new MockERC4626(collateral);
    vault.deposit(100e18, 0);
    
    // Accrue yield BEFORE snapshot
    vault.accrueYield();
    uint256 indexBeforeRebase = vault.yieldIndex();
    
    // Rebase: +1 token
    yieldCollateral.distribute(1e18);
    
    // Deposit after rebase uses new index
    vault.deposit(100e18, 0);
    uint256 indexAfterRebase = vault.yieldIndex();
    
    assertGt(indexAfterRebase, indexBeforeRebase);
  }
  
  function testYieldFeeDeduction() public {
    vault.setYieldFeePercent(1000);  // 10%
    vault.deposit(100e18, 0);
    
    yieldCollateral.distribute(10e18);
    vault.accrueYield();
    
    uint256 expectedFee = 10e18 * 1000 / 10000;
    assertEq(vault.accruedFees(), expectedFee);
  }
}
```

### Skeleton 3: Borrower Mode
```solidity
contract MonolithBorrowerModeTest is Test {
  Vault vault;
  
  function testInterestFreeModeAccrualSkip() public {
    vault.setBorrowerMode(user, INTEREST_FREE);
    vault.deposit(100e18, 50e18);
    
    vm.roll(block.number + 100000);
    
    // Accrue, but user in interest-free mode
    vault.accrueInterest();
    
    uint256 debt = vault.debtShares(user) * vault.debtIndex() / 1e27;
    assertEq(debt, 50e18);  // No interest accrued for this user
  }
  
  function testRedemptionFreeModeLiquidationBlock() public {
    vault.setBorrowerMode(user, REDEMPTION_FREE);
    vault.deposit(100e18, 80e18);
    
    oracle.setPrice(0.95e18);  // Underwater
    
    vm.expectRevert("redemption-free mode");
    liquidator.liquidatePartial(user, 40e18);
  }
}
```

---

## ATTACK VECTOR PRIORITIZATION (v0.3)

**Immediate Risk (CRITICAL/HIGH):**
1. MON-C-001: Uninitialized Proxy Takeover (9.8/10)
2. MON-C-012: Factory Governance Without Timelock (9.1/10)
3. MON-C-011: Borrower Mode Switch Race (8.3/10)
4. MON-C-003: Flash Loan + Share Inflation (8.1/10)
5. MON-C-008: Borrow Fee Double-Charging (8.0/10)
6. MON-C-006: Pre-Rebase Front-Run (8.2/10)

**Medium-Term Risk (MEDIUM):**
7. MON-C-007: Yield Fee Accrual Race (6.3/10)
8. MON-C-010: Deployer Skimming (6.8/10)
9. MON-C-004: Same-Block Rate Change (6.2/10)
10. MON-C-002: Rounding Bias (6.5/10)

---

## LATEST UPDATE SUMMARY (v0.2 → v0.3)

**Added 6 new vulnerability families:**
- MON-C-006: Pre-Rebase Front-Run Share Dilution (ERC4626)
- MON-C-007: Yield Fee Accrual Race
- MON-C-009: Fee Receiver Uninitialized
- MON-C-010: Deployer Skimming via Isolated Pair
- MON-C-011: Borrower Mode Switch Race
- MON-C-012: Factory Governance Without Timelock

**Added 12 new invariants:**
- INV-C-017 through INV-C-028 (Yield, Fee, Borrower Mode, Factory governance)

**Expanded sections:**
- Yield Vault Integration (NEW): ERC4626 mechanics, yieldIndex, fee accrual, pre-rebase attacks
- Borrower Mode System (NEW): Interest-free mode, redemption-free mode, mode-switch races
- Autonomous RateController Exploits (NEW): Peg deviation attacks, spam borrow strategies
- Factory Parameter Management (NEW): Governance delays, parameter validation

**Added Foundry test skeletons:**
- Skeleton 2: Yield Vault Integration (3 test cases)
- Skeleton 3: Borrower Mode (2 test cases)

**Added numerical examples:**
- Pre-rebase yield capture quantification
- Fee deduction calculations
- Borrower mode interest accrual scenarios

Version: 0.3

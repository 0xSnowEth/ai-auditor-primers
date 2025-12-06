# EUKUBO Cross-Cutting Concerns Auditing Primer
## Oracles, Upgradeability, State Convergence, TWAMM, and Defenses

---

## TABLE OF CONTENTS
1. Oracle Models & TWAMM Integration
2. Upgradeability & Extension Layout
3. Cross-Module State Desync
4. Strict Reentrancy Model
5. Cross-Cutting Attack Catalog
6. Invariants & Checkpoints
7. Test Cases & Foundry Skeletons

---

## 1. ORACLE MODELS & TWAMM INTEGRATION

### 1.1 Oracle Architecture in EUKUBO

EUKUBO likely uses **on-chain price feeds** rather than external oracles, given its AMM nature. Price sources include:
- **Current tick price**: `price = 1.0001^(slot0.tick)`
- **TWAP (Time-Weighted Average Price)**: Historical average over a window
- **TWAMM (Time-Weighted Automated Market Maker)**: Extension that smooths swaps over time

**Oracle Hierarchy**:
```
1. Spot price (slot0.tick) → used for swaps, most accurate but volatile
2. TWAP → used for liquidation, resistant to flash loan manipulation
3. TWAMM extension → schedules orders over time, creates synthetic TWAP
```

### 1.2 Stale Read Vulnerabilities

An attacker can exploit the gap between when a price is calculated and when it's used:

```
Time T1: liquidator reads TWAP (value = 100)
Time T2: attacker executes flash loan swap, pushes spot price to 50
Time T3: liquidator calls liquidate() using TWAP value from T1
         → collateral value is overstated
         → position isn't liquidated (or is, but unfairly priced)
```

**Vulnerability**: If TWAP is cached instead of recalculated, it remains stale across multiple blocks.

### 1.3 TWAMM Price Desync

TWAMM allows order scheduling. If the TWAMM extension is out-of-sync with the core:

```
Core state: accumulated price = 1000
TWAMM state: accumulated price = 995 (stale)

When liquidation queries TWAMM price:
  TWAP = (accumulated_price_now - accumulated_price_t_ago) / time_delta
  
If accumulated_price is stale, TWAP is wrong.
```

**Attack**: Attacker can:
1. Schedule a long-tail TWAMM order (moves accumulated price over time)
2. Before TWAMM executes, trigger liquidation with stale accumulated price
3. Liquidation uses wrong price → wrong collateral valuation

### 1.4 Multi-Source Oracle Divergence

If EUKUBO uses multiple price sources:
```
Source A (Uniswap V3): price = 100
Source B (Curve): price = 95
Source C (Chainlink): price = 102

Protocol uses median or weighted average:
median(100, 95, 102) = 100

Attacker exploits one source (e.g., flash loans on Curve) to diverge it:
Source A: 100, Source B: 50 (attacked), Source C: 102
median(100, 50, 102) = 100 (still correct)

But if weighted average is used:
avg = (100 + 50 + 102) / 3 = 84 (wrong!)
```

### 1.5 Manipulation Cost Formula

For an attacker to manipulate TWAP by Δprice over time window T:

```
Manipulation Cost = (liquidity * Δprice) * T / price_normalization

If T is short (e.g., 1 block):
  Cost is high → manipulation is expensive
  
If T is long (e.g., 1 hour):
  Cost is lower if attacker can sustain the position
```

**Defense**: Use TWAP with long enough window (16+ blocks on Ethereum) to make manipulation economically infeasible.

### 1.6 TWAMM Extension Pushing Stale Deltas into Core

If TWAMM and core are not tightly coupled:

```
TWAMM schedules: swap 100 tokens A for B over 60 seconds
TWAMM accumulates deltas: +100 A, -90 B (partial execution)

If core's slot0 is updated BEFORE TWAMM submits final delta:
  Core sees price move based on partial swap
  Users perform swaps at intermediate price
  When TWAMM finally settles, price jumps again → unexpected slippage
```

**Vulnerability**: TWAMM can push **stale** deltas (from previous blocks) into the core, causing price discontinuities.

---

## 2. UPGRADEABILITY & EXTENSION LAYOUT

### 2.1 Extension Layout Assumptions

Extensions are registered with a callpoint bitmask, but the core assumes they:
- Have a specific function signature (e.g., `onSwap(uint256 amount, bytes calldata data)`)
- Store state independently (not in core's storage)
- Don't modify core's state directly (only via core's public/privileged functions)

**Vulnerability**: If an extension uses `delegatecall` instead of `call`:

```solidity
// In core:
(bool ok, ) = extension.delegatecall(abi.encodeWithSignature("onSwap(uint256)", amount));

// Extension now has core's context (storage, msg.sender, address(this))
// Extension can directly:
// 1. Read core's state (expected)
// 2. Modify core's state (unexpected, dangerous)
// 3. Perform actions as if it's the core (reentrancy risk)
```

### 2.2 Bit Cleaning Assumptions

If an extension is designed to run multiple times per block, each call must **clean bits** before writing:

```solidity
assembly {
    // VULNERABLE: stale bits from previous call
    let newTick := shiftedValue  // assumes high bits are 0
    sstore(slot0.slot, newTick)
    
    // CORRECT: explicitly mask out old bits
    let oldSlot0 := sload(slot0.slot)
    let clearedSlot0 := and(oldSlot0, CLEAR_MASK)  // zero out tick bits
    let newSlot0 := or(clearedSlot0, (newTick << 200))
    sstore(slot0.slot, newSlot0)
}
```

If bit cleaning is skipped, previous values leak into new state.

### 2.3 Shared Storage Slots & Silent Corruption Risk

If core and extensions share storage (via layout inheritance or explicit overlaps):

```solidity
// Core layout
contract EUKUBOCore {
    uint256 slot0;  // slot 0
    mapping(...) tickMap;  // slot 1
}

// Extension layout (DANGEROUS)
contract ExtensionBad is EUKUBOCore {
    uint256 myState;  // ALSO slot 0 ??? Collision!
}
```

If `myState` and `slot0` collide, writes to `myState` corrupt `slot0` silently.

**Protection**: Use explicit slot definitions (e.g., `bytes32 constant SLOT_0 = keccak256("eukubo.core.slot0");`) and avoid layout inheritance.

### 2.4 How One Extension Can Corrupt Core Accounting

An extension with delegatecall or direct storage access can:

```solidity
// Extension (malicious)
function onSwap(uint256 amount, bytes calldata data) external {
    // Direct storage corruption
    assembly {
        sstore(coreSlot0Address, corruptedValue)
    }
    
    // Or via delegatecall:
    // coreSlot0 = corruptedValue;
}
```

This breaks all subsequent operations that rely on the corrupted state.

### 2.5 Self-Destruct or Rogue Extension Replacement

An attacker can:
1. Register a benign extension (audited and approved)
2. Self-destruct the extension contract
3. Redeploy a malicious version at the same address (via CREATE2)
4. The core still considers the new address valid (maps to the same `extensionCallpoints`)

**Mitigation**: Use `extcodesize` check or require code hash verification before calling extensions.

---

## 3. CROSS-MODULE STATE DESYNC

### 3.1 Core → Extension → Core Call Stack Depth

When core calls extension, which calls back into core:

```
Depth 0: Core.swap() reads slot0
Depth 1: Core calls Extension.onSwap()
Depth 2: Extension calls Core._updateDebt()
Depth 3: Core calls Extension.onDebtUpdate() (allowed by callpoint)
         Extension reads slot0 (stale, read at Depth 0)
Depth 4: Extension returns, Core returns, Extension returns, Core returns
```

By the time the initial `Core.swap()` continues, slot0 may have changed 3 times over, and Extension (at Depth 3) used a stale snapshot.

### 3.2 TWAMM Extension Scheduling & Core Sync

TWAMM schedules swaps over time. Core must sync with TWAMM:

```
TX 1 (block N): Core swap, accum_price += delta
TX 2 (block N+1): TWAMM settles scheduled order, accum_price += additional_delta

If core doesn't read TWAMM's accumulated deltas, it misses price updates.
```

**Vulnerability**: If core and TWAMM accumulate prices independently:
```
Core's accumulated_price(block N) = 1000
TWAMM's accumulated_price(block N) = 1000

Core's accumulated_price(block N+1) = 1005 (from core swaps)
TWAMM's accumulated_price(block N+1) = 1010 (from core swaps + TWAMM swaps)

Liquidation using core's TWAP: wrong, because it's missing TWAMM's contribution
```

### 3.3 TempDebt Surviving Extension Reentry

If `flashState.tmpDebt` is not atomically cleared:

```
TX: flashBorrow(amount)
  flashState.tmpDebt = amount
  call Extension.onFlashBorrow()
    Extension calls Core.swap()
      Core calls Extension.onSwap()
        Extension reads flashState.tmpDebt (still = amount)
        Extension assumes flash is still active
        Extension performs flash-dependent logic
      Core returns
    Extension returns
  require(flashState.tmpDebt == 0);  // MAY PASS even if not repaid!
```

If the extension doesn't explicitly call `flashRepay()`, `tmpDebt` is never decremented, but if the extension's logic modified it (unlikely), it could be 0 even without proper repayment.

### 3.4 TickMap Mutated in Extension But Not Committed in Core

If an extension directly modifies `tickMap` (via delegatecall or storage access):

```solidity
// Extension (malicious, via delegatecall):
tickMap[someIndex] = newBitmask;  // updates tickMap

// Core's swap loop still relies on old tickMap cached in memory:
uint256 cachedTickMap = tickMap[someIndex];  // read BEFORE extension call
// ... extension executes, modifies tickMap ...
// Core uses cachedTickMap for subsequent operations (stale)
```

If core caches tickMap before calling extension, the cache is stale after the extension returns.

### 3.5 Callpoint Mismatch Across Modules

Different modules might expect different callpoint values:

```
Core expects: LIQUIDATE = 32
Extension A expects: LIQUIDATE = 16 (different!)

Core checks: require(extensionCallpoints[ext] & (1 << 32) != 0);
Extension A checks: require(callpoint & (1 << 16) != 0);

Both checks can pass if mask is set to 48 (binary 110000), but they interpret it differently.
```

---

## 4. STRICT REENTRANCY MODEL

### 4.1 Allowed Reentrancy Points

EUKUBO should explicitly define which operations allow reentrancy:

```
ALLOWED:
- Core.state() [read-only, no state changes]
- Extension.onSwap() [can call Core.state()]

FORBIDDEN:
- Core.swap() [should not call another swap]
- Core.flashBorrow() [should not call another flashBorrow]
- Core.liquidate() [should not call another liquidate]
```

### 4.2 Forbidden Sequences

Certain sequences of operations should never occur in the same call stack:

```
FORBIDDEN:
1. swap() → swap()
2. flashBorrow() → flashBorrow()
3. liquidate() → liquidate() [of same or related position]
4. addLiquidity() → swap() → removeLiquidity() [order matters]
```

### 4.3 Extension-Induced Unexpected Recursion

An extension can trigger recursion that core doesn't expect:

```
Core.swap() → Extension.onSwap() → ??? [extension calls something unexpected]
  → Extension itself calls Core.swap() (if extension has privileged access)
  → Inner swap modifies slot0
  → Outer swap uses stale slot0

OR:

Core.liquidate() → Extension.onLiquidate() → Extension.swapCollateral()
  → This swap can trigger another liquidation (cascade)
```

### 4.4 State Snapshot Invariants Before/After Extension Call

Before calling an extension, core should snapshot state:

```solidity
// Before extension call:
(uint24 tickBefore, uint96 liqBefore, uint96 feesBefore) = decodeSlot0();

// Call extension
_callExtension(...);

// After extension call:
(uint24 tickAfter, uint96 liqAfter, uint96 feesAfter) = decodeSlot0();

// Validate invariant:
require(tickAfter >= tickBefore || tickAfter <= tickBefore);  // monotonic? depends on operation
require(liqAfter >= 0);  // liquidity never negative
```

If extension violates state invariants, revert.

---

## 5. CROSS-CUTTING ATTACK CATALOG

### ATTACK #1: Cross-Module Solvency Drift via Extension State Mutation

**Severity**: CRITICAL  
**Category**: Extension + Solvency

**Description**:
An extension modifies both core and TWAMM state in a way that desynchronizes solvency calculations.

**Vulnerability**:
```solidity
function liquidate(uint256 posId) external {
    uint256 collateralValueCore = getCollateralValue(posId);  // uses core price
    uint256 collateralValueTWAMM = getCollateralValueTWAMM(posId);  // uses TWAMM price
    
    // ⚠️ If extension modifies TWAMM's accumulated price during liquidation:
    _callExtension(extensionLiquidation, LIQUIDATE, data);
    
    // collateralValueCore and collateralValueTWAMM are now stale
    require(collateralValueCore < debtValue, "SOLVENT");
}
```

**Attack**:
1. Attacker monitors two solvency checks: one using core price, one using TWAMM
2. Attacker's position: solvency_core = +5 (solvent), solvency_twamm = -5 (insolvent)
3. Attacker calls liquidate(ownPosition) with a liquidation extension
4. Extension (attacker-controlled) modifies TWAMM's accumulated_price (upward)
5. Liquidation check uses stale collateral value (from before TWAMM update)
6. Liquidation executes and seizes collateral
7. But after liquidation, real solvency shows attacker's position was actually solvent (via TWAMM price)
8. Attacker profited from self-liquidation

**Test Case**:
```foundry
function testCrossModuleSolvencyDriftExtension() public {
    // Setup: position with divergent solvency signals
    uint256 posId = core.openPosition(attacker, 1000e18, 950e18);
    
    // Core price: 1.0, solvency = +50
    core.setTickPrice(0);
    
    // TWAMM price: 0.95, solvency = -50
    twamm.setAccumulatedPrice(0.95e18);
    
    // Register malicious extension
    address malExt = address(new SolvencyDesyncExtension(address(core), address(twamm)));
    core.registerExtension(malExt, CALLPOINT_LIQUIDATE);
    
    // Liquidate with extension
    // Extension modifies TWAMM during liquidation
    core.liquidate(posId, malExt);
    
    // After liquidation:
    // Position should be liquidated, but attacker profited
    (uint96 debtShares, , ) = core.positions(posId);
    assertEq(debtShares, 0);  // liquidated
    
    // Attacker's balance increased (profit from attack)
    uint256 balAfter = token.balanceOf(attacker);
    assertGt(balAfter, initialBalance);
}
```

---

### ATTACK #2: Extension Misuse to Bypass Reentrancy Guard

**Severity**: CRITICAL  
**Category**: Reentrancy

**Description**:
An attacker uses an extension with multiple callpoints to bypass a reentrancy guard that only protects a specific entry point.

**Vulnerability**:
```solidity
uint8 locked = 0;  // reentrancy guard

function swap(...) external {
    require(locked == 0, "REENTRANT");
    locked = 1;
    
    _callExtension(extensionSwap, SWAP, data);
    // ⚠️ Extension has multiple callpoints: SWAP | LIQUIDATE
    // Extension can call liquidate(), which is NOT guarded
    
    locked = 0;
}

function liquidate(...) external {
    // No reentrancy guard!
    _callExtension(extensionLiquidation, LIQUIDATE, data);
}
```

**Attack**:
1. Attacker calls `swap()`; `locked = 1`
2. Extension (attacker's) is invoked with SWAP callpoint
3. Extension calls `liquidate()` (because extension has LIQUIDATE callpoint too)
4. `liquidate()` executes without reentrancy guard
5. `liquidate()` calls extension's `onLiquidate()`
6. Extension triggers another `swap()` (if extension has access)
7. Inner `swap()` checks `locked == 1` (would fail), BUT extension might call swap via core's public interface with a callback that doesn't check `locked`

**Test Case**:
```foundry
function testExtensionReentrancyBypassMultiCallpoint() public {
    // Setup
    uint256 posId = core.openPosition(user, 1000e18, 900e18);
    
    // Malicious extension with multiple callpoints
    address malExt = address(new MultiCallpointExtension(address(core)));
    core.registerExtension(malExt, CALLPOINT_SWAP | CALLPOINT_LIQUIDATE);
    
    // Call swap, which invokes extension
    // Extension exploits multiple callpoints to call liquidate
    vm.prank(attacker);
    core.swap(100e18, abi.encode(malExt));
    
    // If reentrancy guard is bypassed, position is liquidated unexpectedly
    (uint96 debtShares, , ) = core.positions(posId);
    assertGt(debtShares, 0);  // guard worked, position NOT liquidated
}
```

---

### ATTACK #3: TWAMM Desync Attack via Accumulated Price Manipulation

**Severity**: HIGH  
**Category**: Oracle / TWAMM

**Description**:
An attacker manipulates TWAMM's accumulated price to cause liquidations based on stale prices.

**Vulnerability**:
```solidity
// In TWAMM extension:
uint256 accumulatedPrice;  // snapshot at block start

function settleScheduledOrders() external {
    uint256 priceNow = getCurrentPrice();
    uint256 timeElapsed = block.timestamp - lastSettlementTime;
    
    // ⚠️ accumulatedPrice is updated, but not synchronized with core's slot0
    accumulatedPrice += priceNow * timeElapsed / WINDOW;
    lastSettlementTime = block.timestamp;
}

// In core:
function getTWAPPrice() external view returns (uint256) {
    return twamm.accumulatedPrice() / WINDOW;  // reads stale accumulated price
}
```

**Attack**:
1. Attacker calls `settleScheduledOrders()` on TWAMM multiple times
2. Each settlement increments `accumulatedPrice` (artificially inflating it)
3. Core liquidation reads TWAP, which is now overstated
4. Liquidation doesn't trigger (collateral value seems higher than it is)
5. Attacker's position remains open, underliquidated

**Test Case**:
```foundry
function testTWAMM_DeSyncAttack() public {
    // Setup: position near liquidation threshold using TWAP
    uint256 posId = core.openPosition(user, 1000e18, 950e18);
    
    // Initial TWAP: 1.0
    uint256 twapBefore = twamm.getTWAPPrice();
    assertEq(twapBefore, 1e18);
    
    // Attacker directly calls TWAMM settlement multiple times
    // (simulating artificial price increase)
    vm.prank(attacker);
    for (uint i = 0; i < 10; i++) {
        twamm.settleScheduledOrders();
    }
    
    // TWAP is now inflated
    uint256 twapAfter = twamm.getTWAPPrice();
    assertGt(twapAfter, twapBefore);
    
    // Liquidation uses inflated TWAP, doesn't trigger
    bool canLiq = core.canLiquidateUsingTWAP(posId);
    assertFalse(canLiq);  // should be TRUE but isn't
}
```

---

### ATTACK #4: Pseudo-Oracle Updates via Extension Timing

**Severity**: MEDIUM  
**Category**: Oracle Manipulation

**Description**:
An attacker times extension calls to update oracle prices in a favorable order, creating arbitrage opportunities.

**Vulnerability**:
```solidity
// Core reads price from extension's cached value:
function getPrice() external view returns (uint256) {
    return extensionOracleCache.price;  // cache updated by extension
}

// Attacker controls extension:
function updatePrice(uint256 newPrice) external {
    extensionOracleCache.price = newPrice;
}
```

**Attack**:
1. Attacker calls `updatePrice(lowPrice)` → extension cache = lowPrice
2. Attacker performs liquidations (using lowPrice, seizing cheap collateral)
3. Attacker calls `updatePrice(highPrice)` → extension cache = highPrice
4. Attacker performs swaps (using highPrice, selling seized collateral at profit)
5. Net result: Attacker arbitraged the price, profiting from the cache update order

**Test Case**:
```foundry
function testPseudoOracleUpdate_ExtensionTiming() public {
    // Setup: oracle extension
    address oracleExt = address(new MockOracleExtension(address(core)));
    
    // Initial price: 100
    MockOracleExtension(oracleExt).updatePrice(100e18);
    
    // Attacker's position: collateral = 100, debt = 95
    uint256 posId = core.openPosition(attacker, 100e18, 95e18);
    
    // Attacker calls extension to lower price
    vm.prank(attacker);
    MockOracleExtension(oracleExt).updatePrice(50e18);  // price halved
    
    // Liquidation uses lowPrice, seizes cheap collateral
    vm.prank(liquidator);
    core.liquidate(posId);  // collateral seized at 50e18 price
    
    // Attacker then raises price
    vm.prank(attacker);
    MockOracleExtension(oracleExt).updatePrice(100e18);  // price restored
    
    // Attacker swaps seized collateral at high price
    // (would need to acquire collateral first, but profit is evident)
    
    // Verify: attacker profited from oracle timing
}
```

---

### ATTACK #5: External Hook-Induced State Corruption

**Severity**: HIGH  
**Category**: Composability

**Description**:
If core allows external contracts to hook into operations, those contracts can corrupt state.

**Vulnerability**:
```solidity
interface ILiquidationHook {
    function onLiquidate(uint256 posId, uint256 debtRepaid) external;
}

function liquidate(uint256 posId) external {
    uint256 debt = getDebtValue(posId);
    _repayDebtAndSeizeCollateral(posId, debt);
    
    // ⚠️ Call external hook without state consistency check
    ILiquidationHook(hook).onLiquidate(posId, debt);
}
```

**Attack**:
1. Attacker deploys a malicious hook contract
2. Attacker's position is liquidated
3. Hook's `onLiquidate()` is called
4. Hook (attacker's) performs unexpected operations:
   - Modifies position state (if delegatecall)
   - Transfers funds to attacker
   - Triggers reentrancy
5. State is corrupted before liquidation completes

**Test Case**:
```foundry
function testExternalHookStateCorruption() public {
    // Setup: malicious hook
    address malHook = address(new MaliciousLiquidationHook(address(core)));
    core.setLiquidationHook(malHook);
    
    // Position is liquidated
    uint256 posId = core.openPosition(user, 1000e18, 900e18);
    
    vm.prank(liquidator);
    core.liquidate(posId);
    
    // Hook corrupted state (e.g., restored position's debt)
    (uint96 debtShares, , ) = core.positions(posId);
    assertEq(debtShares, 0);  // should be liquidated
}
```

---

## 6. INVARIANTS & CHECKPOINTS

### Cross-Cutting Invariants Registry

| ID | Invariant | Formula | Checkpoint |
|----|-----------|---------|------------|
| INV_XCUT_001 | Extension callpoint validity | ext ∈ registered ⇒ callpoint ∈ bitmask | Before ext call |
| INV_XCUT_002 | Core-TWAMM accumulated price alignment | coreAccum ~= twammAccum ± tolerance | After settlement |
| INV_XCUT_003 | Oracle price bounds | minPrice ≤ oraclePrice ≤ maxPrice | Liquidation entry |
| INV_XCUT_004 | TWAP staleness limit | now - lastTWAPUpdate ≤ MAX_STALENESS | Liquidation entry |
| INV_XCUT_005 | Extension code hash match | codeHashBefore == codeHashAfter (no self-destruct) | Extension callback |
| INV_XCUT_006 | Storage slot isolation | ext slots ≠ core slots | Ext deployment |
| INV_XCUT_007 | Reentrancy guard atomic | locked transitions 0→1→0 atomically | Guarded function |
| INV_XCUT_008 | State snapshot consistency | snapshot(before_ext) ≈ snapshot(after_ext) [bounds] | Ext completion |
| INV_XCUT_009 | Bitpacked state cleaned | All high bits cleared before pack | Bit write |
| INV_XCUT_010 | TickMap committed after crossing | TickMap update persists across ext calls | Post-crossing |
| INV_XCUT_011 | TempDebt ephemeral | tmpDebt == 0 after flashBorrow callback | Flash end |
| INV_XCUT_012 | Callpoint isolation | Calling ext via callpoint A doesn't trigger callpoint B | Ext invocation |
| INV_XCUT_013 | Price consistency | core_price ≈ twamp_price ± max_deviation | Liquidation calc |
| INV_XCUT_014 | Extension context clarity | msg.sender == core (call) or msg.sender == caller (delegatecall) | Ext execution |
| INV_XCUT_015 | Core-slot0 tick post-update | slot0.tick == computedTick after swap | Swap completion |

### State Checkpoints

**At Liquidation Entry**:
```solidity
// Snapshot before any ext calls
uint256 checkpointSolvency = getSolvency(posId);
uint256 checkpointPrice = getTWAPPrice();
uint256 checkpointDebt = getDebtValue(posId);

// Verify invariants:
require(checkpointSolvency < 0, "SOLVENT");  // should be insolvent
require(checkpointPrice >= MIN_PRICE && checkpointPrice <= MAX_PRICE, "PRICE_OUT_BOUNDS");
require(now - lastPriceUpdate <= MAX_PRICE_STALENESS, "PRICE_STALE");
```

**At Extension Completion**:
```solidity
// After ext returns:
uint256 postExtSolvency = getSolvency(posId);
uint256 postExtPrice = getTWAPPrice();

// Validate constraints (may be different, but within bounds):
require(abs(postExtPrice - checkpointPrice) <= MAX_PRICE_DELTA, "PRICE_DIVERGENCE");
require(postExtDebt == checkpointDebt || postExtDebt == 0, "DEBT_MISMATCH");  // debt either unchanged or cleared
```

---

## 7. TEST CASES & FOUNDRY SKELETONS

### Test Folder Structure

```
tests/crosscut/
├── test_oracle_models.sol
├── test_twamm_desync.sol
├── test_extension_layout.sol
├── test_reentrancy_boundaries.sol
├── test_cross_module_desync.sol
├── test_extension_attacks.sol
└── test_state_checkpoints.sol
```

### Test #1: TWAMM Desync Reproduction

```solidity
pragma solidity ^0.8.0;

import "foundry/Test.sol";
import "../src/EUKUBOCore.sol";
import "../src/extensions/TWAMMExtension.sol";

contract TestTWAMM_Desync is Test {
    EUKUBOCore core;
    TWAMMExtension twamm;
    
    function setUp() public {
        core = new EUKUBOCore();
        twamm = new TWAMMExtension(address(core));
        core.registerExtension(address(twamm), CALLPOINT_SWAP | CALLPOINT_SETTLEMENT);
    }
    
    function testTWAMM_AccumulatedPriceDiverges() public {
        // Schedule long-tail TWAMM order
        uint256 scheduleAmount = 1000e18;
        twamm.scheduleSwap(scheduleAmount, 1 hours);  // order over 1 hour
        
        // Core executes immediate swap
        uint256 immediateAmount = 100e18;
        uint256 corePrice = core.getCurrentPrice();
        
        // Accumulated prices initially sync
        uint256 coreAccum = core.getAccumulatedPrice();
        uint256 twammAccum = twamm.getAccumulatedPrice();
        assertEq(coreAccum, twammAccum);
        
        // Fast-forward 30 minutes (half of TWAMM execution)
        vm.warp(block.timestamp + 30 minutes);
        
        // Settle TWAMM once (only partial execution)
        twamm.settleScheduledOrders();
        
        // Prices diverge
        coreAccum = core.getAccumulatedPrice();
        twammAccum = twamm.getAccumulatedPrice();
        
        // If core doesn't update from TWAMM, they're different
        if (coreAccum != twammAccum) {
            // Desync detected!
            assertGt(abs(int256(coreAccum - twammAccum)), 0);
        }
    }
    
    function testTWAMM_LiquidationUsingStalePrice() public {
        // Setup position
        uint256 posId = core.openPosition(borrower, 1000e18, 950e18);
        
        // Liquidation reads TWAP
        uint256 twapPrice = twamm.getTWAPPrice();
        uint256 collateralValue = 1000e18 * twapPrice / 1e18;
        
        // Liquidation check
        bool canLiq = (collateralValue < 950e18);  // insolvent?
        
        // Schedule TWAMM order that moves price down (over time)
        twamm.scheduleSwap(10000e18, 1 days);  // large order
        
        // Fast-forward and settle TWAMM multiple times (artificial price increase)
        for (uint i = 0; i < 24; i++) {
            vm.warp(block.timestamp + 1 hours);
            twamm.settleScheduledOrders();
        }
        
        // TWAP is now different
        uint256 twapPriceAfter = twamm.getTWAPPrice();
        
        // If TWAP increased, but core liquidation didn't re-check, position isn't liquidated
        if (twapPriceAfter > twapPrice) {
            // Liquidation is stale
            bool canLiqAfter = core.canLiquidateUsingTWAP(posId);
            // canLiqAfter may be false even though real insolvency persists
        }
    }
}
```

### Test #2: Bitpacking Invariant Violation via Extension

```solidity
contract TestBitpackingInvariant_Extension is Test {
    EUKUBOCore core;
    
    function setUp() public {
        core = new EUKUBOCore();
    }
    
    function testBitpacking_HighBitsLeak() public {
        // Set clean slot0
        uint256 slot0 = encodeSlot0(int24(100), uint96(1e18), uint96(1e6));
        core.setSlot0(slot0);
        
        // Register delegatecall extension (DANGEROUS)
        address malExt = address(new DelegateCallExtension(address(core)));
        core.registerExtension(malExt, CALLPOINT_SWAP);
        
        // Swap with malicious extension
        core.swap(1000e18, abi.encode(malExt));
        
        // Extension (via delegatecall) wrote stale bits to slot0
        uint256 slot0After = core.getSlot0();
        (int24 tick, uint96 liq, uint96 fees) = decodeSlot0(slot0After);
        
        // Verify bitpacking invariant: no high-bit leakage
        uint256 extraBits = slot0After >> 256;  // anything above 256 bits is corruption
        assertEq(extraBits, 0);
        
        // Tick, liq, fees should still be valid
        assert(tick >= -887272 && tick <= 887272);
        assert(liq >= 0);
        assert(fees >= 0);
    }
}
```

### Test #3: Extension Callpoint Mismatch Test

```solidity
contract TestExtensionCallpointMismatch is Test {
    EUKUBOCore core;
    
    function setUp() public {
        core = new EUKUBOCore();
    }
    
    function testCallpointMismatchPrevention() public {
        // Register extension with limited callpoints
        address ext = address(new LimitedExtension());
        uint256 allowedCallpoints = CALLPOINT_SWAP;  // only SWAP allowed
        core.registerExtension(ext, allowedCallpoints);
        
        // Attempt to call extension via forbidden callpoint
        vm.expectRevert("CALLPOINT_FORBIDDEN");
        core._callExtensionIfAllowed(ext, CALLPOINT_LIQUIDATE, "");
        
        // Allowed callpoint should work
        core._callExtensionIfAllowed(ext, CALLPOINT_SWAP, "");
        // (no revert)
    }
}
```

### Test #4: Reentrancy Boundary via State Snapshot

```solidity
contract TestReentrancyBoundary_StateSnapshot is Test {
    EUKUBOCore core;
    
    function setUp() public {
        core = new EUKUBOCore();
    }
    
    function testStateSnapshot_PreAndPostExtension() public {
        // Setup: two positions
        uint256 pos1 = core.openPosition(user1, 500e18, 400e18);
        uint256 pos2 = core.openPosition(user2, 500e18, 400e18);
        
        // Snapshot before swap
        (uint24 tickBefore, uint96 liqBefore, ) = core.decodeSlot0();
        uint256 debt1Before = core.getDebtValue(pos1);
        uint256 debt2Before = core.getDebtValue(pos2);
        
        // Extension performs nested operations
        address nestingExt = address(new ReentrancyExtension(address(core)));
        core.registerExtension(nestingExt, CALLPOINT_SWAP);
        
        // Swap with nesting extension
        core.swap(100e18, abi.encode(nestingExt));
        
        // Snapshot after swap
        (uint24 tickAfter, uint96 liqAfter, ) = core.decodeSlot0();
        uint256 debt1After = core.getDebtValue(pos1);
        uint256 debt2After = core.getDebtValue(pos2);
        
        // Validate invariant: debt didn't change unexpectedly
        // (pos1 and pos2 shouldn't be affected by a swap between them)
        assertEq(debt1Before, debt1After);  // pos1 debt unchanged
        assertEq(debt2Before, debt2After);  // pos2 debt unchanged
        
        // Tick and liquidity changed appropriately
        assert(tickAfter >= tickBefore);  // price moved forward (or stayed)
        assert(liqAfter >= 0);  // liquidity valid
    }
}
```

---

## GLOSSARY & QUICK REFERENCE

| Term | Definition |
|------|-----------|
| TWAP | Time-Weighted Average Price; average price over a window |
| TWAMM | Time-Weighted Automated Market Maker; schedules swaps over time |
| Accumulated Price | Sum of prices × time; used to compute TWAP |
| Call vs. Delegatecall | call: ext's context; delegatecall: ext has core's storage |
| Callpoint | Permission bitmask; controls which functions ext can invoke |
| State Desync | Core and extension state diverge; inconsistent reads |
| Reentrancy | Function calls itself (directly or indirectly) before completing |
| Bit Cleaning | Explicitly zeroing out bits before packing new values |
| Stale Read | Using data from a prior state, now updated |
| Oracle Manipulation | Pushing false prices into oracle (flash loan, large swaps) |

---

✓ Module Complete.

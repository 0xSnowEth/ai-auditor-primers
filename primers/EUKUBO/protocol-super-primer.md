# EUKUBO Super-Primer: Complete Auditing Reference
## Singleton-Core AMM with Modular Extensions, Debt Accounting, and Cross-Module State Management

---

## TABLE OF CONTENTS
1. Architecture Fingerprint
2. Tick & Liquidity Math
3. Accounting & Debt Mechanics
4. Extension System & Callpoint Validation
5. Assembly-Level State Access
6. Oracle Models & TWAMM Integration
7. Upgradeability & Extension Layout
8. Cross-Module State Desync
9. Strict Reentrancy Model
10. Complete Attack Catalog (Core)
11. Complete Attack Catalog (Liquidation)
12. Complete Attack Catalog (Cross-Cutting)
13. Complete Invariants Registry
14. Test Suite & Foundry Skeletons

---

## 1. ARCHITECTURE FINGERPRINT

### 1.1 Singleton Core Model

EUKUBO uses a **singleton-core pattern**:
- **Single core contract** owns all state (slot0, tickMap, positionMap, flashState)
- **Delegates privileged operations** to registered extension contracts
- **Maintains strict reentrancy barriers** through callpoint validation
- **Enforces atomic state transitions** via assembly-heavy accounting

Core contract layout:
```solidity
contract EUKUBOCore {
    // slot0: packedTick, sqrtPrice, liquidity, feeGrowth
    uint256 slot0;
    
    // tickMap[i] = bitmap of ticks i*256..(i+1)*256
    mapping(int16 => uint256) tickMap;
    
    // positions[posId] = {liquidity, tickLower, tickUpper, ...}
    mapping(uint256 => PositionState) positions;
    
    // flashState = {tmpDebt, inFlash, tmpCaller}
    struct FlashAccountantState {
        uint256 tmpDebt;
        bool inFlashCallback;
        address tmpCaller;
    }
    FlashAccountantState flashState;
    
    // extensionRegistry[extensionAddr] = bitmask of allowed callpoints
    mapping(address => uint256) extensionCallpoints;
}
```

### 1.2 Assembly-Heavy State Access

Assembly optimizes critical paths but introduces risks:
```solidity
assembly {
    let packedSlot := sload(slot0.slot)
    let tick := shr(200, packedSlot)  // unsafe if bits misaligned
    let liquidity := and(packedSlot, 0xFFFFFFFFFFFFFFFFFFFFFFFF)
}
```
**Risk**: Assembly reads bypass type checking; stale data corrupts silently.

### 1.3 Bitpacking & Bit-Cleaning Assumptions

| Field | Bits | Mask | Notes |
|-------|------|------|-------|
| tick | 24 | 0xFF0000 | Signed int24; must be cleaned before repack |
| liquidity | 96 | 0xFFFFFFFFFFFFFFFFFFFFFFFF | Must validate >= 0 |
| feeGrowth | 96 | 0xFFFFFFFFFFFFFFFFFFFFFFFF | Monotonic |
| locked | 8 | 0xFF | Reentrancy guard; must be atomic |

Bit-cleaning failure pattern:
```solidity
// VULNERABLE: stale bits leak
uint256 newSlot0 = (tick << 200) | (liq << 96) | fees;

// CORRECT: explicit masking
uint256 newSlot0 = (tick & 0xFFFFFF) << 200 | (liq & LIQUIDITY_MASK) << 96 | ...;
```

### 1.4 Extension System with Callpoint Validation

Extensions register with a **callpoint bitmask**:
```solidity
enum CallPoint {
    SWAP = 1,
    ADD_LIQ = 2,
    REMOVE_LIQ = 4,
    FLASH = 8,
    TWAMM_SCHEDULE = 16,
    LIQUIDATE = 32
}

function _validateExtensionCallpoint(address ext, uint8 cp) internal view {
    uint256 allowed = extensionCallpoints[ext];
    require(allowed & (1 << cp) != 0, "CALLPOINT_FORBIDDEN");
}
```

### 1.5 Core → Extension → Core Recursion Model

```
[Core.swap()] 
  → [_call(extension, data)]  // validate callpoint
     → [Extension.onSwap()] 
        → [Core.state()] (READ-ONLY, allowed)
        → [Core._balanceUpdate()] (guarded by callpoint)
           → [Extension.onBalanceChange()] ⚠️ DANGEROUS
```

### 1.6 Custom FlashAccountant for Ephemeral Debt

```solidity
struct FlashAccountantState {
    uint256 tmpDebt;        // must be 0 after flash ends
    bool inFlashCallback;   // reentrancy guard
    address tmpCaller;      // who called flash
}

function flashBorrow(uint256 amount, bytes calldata data) external {
    require(!flashState.inFlashCallback, "RECURSIVE_FLASH");
    flashState.inFlashCallback = true;
    flashState.tmpDebt = amount;
    flashState.tmpCaller = msg.sender;
    
    _transfer(msg.sender, amount);
    IFlashBorrower(msg.sender).onFlashBorrow(amount, data);
    
    require(flashState.tmpDebt == 0, "FLASH_DEBT_NOT_REPAID");
    flashState.inFlashCallback = false;
}
```

### 1.7 Storage Slot Maps

| Variable | Slot | Purpose | Details |
|----------|------|---------|---------|
| slot0 | 0 | Core state | tick (bits 200-223), liq (bits 0-95), fees (bits 96-191) |
| tickMap | keccak256(abi.encode(1, tick >> 8)) | Tick bitmap | One bit per tick |
| positionMap | keccak256(abi.encode(2, owner, id)) | Position accounting | liquidity, tickLower, tickUpper, feeOwed |
| flashState | 3 | Ephemeral debt | tmpDebt, inFlashCallback, tmpCaller |
| extensionRegistry | keccak256(abi.encode(4, extAddr)) | Extension permissions | Bitmask of callpoints |

---

## 2. TICK & LIQUIDITY MATH

### 2.1 Tick Representation & Overflow Conditions

Ticks use **int24** (range \(-887272\) to \(887272\)):
```solidity
int24 constant MIN_TICK = -887272;
int24 constant MAX_TICK = 887272;
// price = 1.0001^tick
```

Overflow attack:
```solidity
int24 tick = 887272;
int24 newTick = tick + 1;  // wraps to -887272 in int24!

// In assembly (no overflow check):
uint256 newTick := add(tick, 1)  // 887273 without int24 cast
```

### 2.2 Liquidity Deltas Under Extreme Swaps

```solidity
uint96 cumLiquidity = 0;
for each tick crossed {
    uint96 tickLiquidity = tickState[tick].liquidityNet;
    if (tickLiquidity > LIQUIDITY_MAX - cumLiquidity) {
        revert("LIQUIDITY_OVERFLOW");
    }
    cumLiquidity += tickLiquidity;
    slot0.liquidity = cumLiquidity;  // ⚠️ no overflow check in assembly
}
```

### 2.3 Delta Rounding Attack Templates

```solidity
uint256 amountOut = (sqrtPriceX96After - sqrtPriceBefore) * liquidity / sqrtPriceX96After;

// Attacker exploits rounding-down to:
// 1. Retain excess dust in pool (accrue to next swap)
// 2. Cause liquidation to underflow (rounds to 0)
// 3. Manipulate fee accrual (rounding-up compounds over time)
```

### 2.4 Tick Crossing Invariants

After each tick crossing:
1. Read tick's liquidityNet
2. Update cumulative liquidity
3. Emit event
4. Update slot0.tick

**Invariant**: In-memory liquidity must match slot0.liquidity after crossing.

### 2.5 Solvency Invariants for Liquidity Updates

```
Solvency = (Total Collateral Value) - (Total Debt)

During liquidity update:
New Solvency = Old Solvency + (delta liquidity * price) - (fee accrual)
```

### 2.6 Liquidity += Delta vs. Liquidity = Liquidity + Delta

Assembly pattern (SAFE if atomic):
```solidity
assembly {
    let oldLiq := sload(slot0.slot)
    let newLiq := add(oldLiq, delta)
    sstore(slot0.slot, newLiq)
}
```

Solidity pattern (UNSAFE, allows read-modify-write):
```solidity
uint96 liq = slot0.liquidity;
liq = liq + delta;
slot0 = _packSlot0(..., liq);  // ext call between read and write
```

---

## 3. ACCOUNTING & DEBT MECHANICS

### 3.1 Debt Mis-accounting

EUKUBO uses **per-position debt shares**:
```solidity
struct Position {
    uint96 liquidity;
    uint96 debtShares;      // position's share of totalDebt
    int256 feesOwed;
}

uint96 totalDebtShares;
uint256 totalDebt;

function getDebtValue(uint256 posId) public view returns (uint256) {
    return (positions[posId].debtShares * totalDebt) / totalDebtShares;
}
```

### 3.2 Debt Share Inflation via Rounding

```solidity
function borrowAgainstCollateral(uint256 posId, uint256 amount) external {
    require(isSolvent(posId, amount), "INSOLVENCY");
    
    uint96 sharesToMint = (amount * totalDebtShares) / totalDebt;
    // ⚠️ Rounding: if amount * totalDebtShares < totalDebt, rounds to 0
    
    positions[posId].debtShares += sharesToMint;
    totalDebt += amount;
    _transfer(borrower, amount);
}
```

### 3.3 FlashAccountant Temp-Debt Lifecycle

```
1. flashBorrow: tmpDebt = amount, inFlash = true, tmpCaller = caller
2. onFlashBorrow: tmpDebt -= repaidAmount(s)
3. After callback: require(tmpDebt == 0)
4. inFlash = false
```

**Vulnerability**: Gap between tmpDebt == 0 check and inFlash = false allows extension reentrancy.

### 3.4 Extension-Induced Debt Desync

Extension can call `_updateDebt()` multiple times, desynchronizing tmpDebt:
```solidity
function onFlashBorrow(uint256 amt, bytes calldata data) {
    IEUKUBOCore(core).updateDebt(amt);  // not flashRepay!
    IEUKUBOCore(core).updateDebt(amt);  // called twice!
    // totalDebt += 2*amt, but tmpDebt still = amt
}
```

---

## 4. EXTENSION SYSTEM & CALLPOINT VALIDATION

### 4.1 Unvalidated Callpoints

If extension is registered with callpoint `0xFF`:
```solidity
registerExtension(maliciousExt, 0xFFFFFFFFFFFFFFFFFFFFFFFF);
// maliciousExt can now call any core function
```

### 4.2 Callpoint Mismatch (Wrong Extension Invoked)

```solidity
// Extension A: onSwap restricts to token A -> token B
// Extension B: onSwap allows ANY token pair

// If both have SWAP callpoint enabled:
// → Core might call wrong extension's onSwap
// → Or extension A masquerades as B's signature
```

### 4.3 Extension → Core State Drift

Extension reads slot0, then another extension runs, slot0 changes, original extension's computation is stale.

### 4.4 Assembly Copy/Memcopy Bug Surfaces

```solidity
assembly {
    let ptr := 0x00
    let size := 0x40
    memmove(ptr, slotAddr, size)  // ⚠️ invalid slotAddr corrupts memory
}
```

### 4.5 Incorrect Context Propagation (msg.sender, _caller, _origin)

```solidity
function _callExtension(address ext, uint8 cp, bytes calldata data) internal {
    // ⚠️ Missing context: who is ext acting for?
    (bool ok, bytes memory result) = ext.delegatecall(data);
}
```

If delegatecall: ext gains core's state. If call: ext doesn't know original caller.

---

## 5. ASSEMBLY-LEVEL STATE ACCESS

### 5.1 Unsafe sload / sstore Patterns

```solidity
assembly {
    let value := sload(0)  // direct slot load, no bounds check
    let price := sload(priceSlot)  // stale if slot modified by another tx
    sstore(slot0, newValue)  // no consistency check
}
```

### 5.2 Bitshift Misalignment

VULNERABLE:
```solidity
assembly {
    let tick := shr(200, sload(slot0Addr))  // assumes bits at [200:223]
}
```

CORRECT:
```solidity
assembly {
    let raw := sload(slot0Addr)
    let tickMask := 0xFFFFFF
    let tick := shr(200, and(raw, shl(200, tickMask)))
}
```

### 5.3 Reentrancy in Assembly Context

```solidity
function swap(...) external {
    assembly {
        let slot0Val := sload(slot0.slot)
        sstore(slot0.slot, newSlot0Val)
    }
    
    _callExtension(...);  // ⚠️ Extension can call back into swap
    
    // At this point, slot0 might be stale
}
```

---

## 6. ORACLE MODELS & TWAMM INTEGRATION

### 6.1 Oracle Architecture in EUKUBO

Price sources (hierarchy):
1. **Spot price**: \(\text{price} = 1.0001^{\text{slot0.tick}}\) — volatile, used for swaps
2. **TWAP**: Historical average over window — resistant to flash loans
3. **TWAMM extension**: Schedules orders over time, creates synthetic TWAP

### 6.2 Stale Read Vulnerabilities

```
Time T1: liquidator reads TWAP (value = 100)
Time T2: attacker executes flash swap, pushes price to 50
Time T3: liquidator calls liquidate() using TWAP from T1
         → collateral value overstated
         → position isn't liquidated
```

If TWAP is cached, remains stale across blocks.

### 6.3 TWAMM Price Desync

```
Core: accumulated_price = 1000
TWAMM: accumulated_price = 995 (stale)

TWAP = (accumulated_price_now - accumulated_price_t_ago) / time_delta

If accumulated_price is stale, TWAP is wrong.
```

Attacker can:
1. Schedule long-tail TWAMM order
2. Before TWAMM executes, trigger liquidation with stale accumulated price
3. Liquidation uses wrong price

### 6.4 Multi-Source Oracle Divergence

```
Source A: price = 100
Source B: price = 95
Source C: price = 102

median(100, 95, 102) = 100

Attacker flash-attacks Source B:
median(100, 50, 102) = 100 (correct)

But if weighted average:
avg = (100 + 50 + 102) / 3 = 84 (wrong!)
```

### 6.5 Manipulation Cost Formula

```
Manipulation Cost = (liquidity * Δprice) * T / price_normalization

Short T (1 block): high cost
Long T (1 hour): lower cost if attacker sustains position
```

### 6.6 TWAMM Extension Pushing Stale Deltas into Core

```
TWAMM schedules: 100 A for B over 60 seconds
TWAMM accumulates: +100 A, -90 B (partial execution)

If core's slot0 updates BEFORE TWAMM settles:
  Core sees price move based on partial swap
  When TWAMM finally settles, price jumps again
  → Unexpected slippage
```

---

## 7. UPGRADEABILITY & EXTENSION LAYOUT

### 7.1 Extension Layout Assumptions

Extensions are assumed to:
- Have specific function signature (e.g., `onSwap(uint256, bytes calldata)`)
- Store state independently (not in core's storage)
- Not modify core state directly (only via core's functions)

**Vulnerability**: If extension uses `delegatecall`:
```solidity
(bool ok, ) = extension.delegatecall(abi.encodeWithSignature("onSwap(uint256)", amount));
// Extension now has core's context: can read/modify core's state, perform actions as core
```

### 7.2 Bit Cleaning Assumptions

```solidity
// VULNERABLE: stale bits from previous call
assembly {
    let newTick := shiftedValue
    sstore(slot0.slot, newTick)
}

// CORRECT: explicitly mask out old bits
assembly {
    let oldSlot0 := sload(slot0.slot)
    let clearedSlot0 := and(oldSlot0, CLEAR_MASK)
    let newSlot0 := or(clearedSlot0, (newTick << 200))
    sstore(slot0.slot, newSlot0)
}
```

### 7.3 Shared Storage Slots & Silent Corruption Risk

```solidity
contract EUKUBOCore {
    uint256 slot0;  // slot 0
    mapping(...) tickMap;  // slot 1
}

contract ExtensionBad is EUKUBOCore {
    uint256 myState;  // ALSO slot 0 ??? Collision!
}
```

**Protection**: Use explicit slot definitions, avoid layout inheritance.

### 7.4 How One Extension Can Corrupt Core Accounting

```solidity
function onSwap(uint256 amount, bytes calldata data) external {
    assembly {
        sstore(coreSlot0Address, corruptedValue)
    }
}
```

### 7.5 Self-Destruct or Rogue Extension Replacement

```
1. Register benign extension (audited)
2. Self-destruct extension contract
3. Redeploy malicious version at same address (via CREATE2)
4. Core still considers address valid
```

**Mitigation**: Use `extcodesize` check or require code hash verification.

---

## 8. CROSS-MODULE STATE DESYNC

### 8.1 Core → Extension → Core Call Stack Depth

```
Depth 0: Core.swap() reads slot0
Depth 1: Core calls Extension.onSwap()
Depth 2: Extension calls Core._updateDebt()
Depth 3: Core calls Extension.onDebtUpdate()
         Extension reads slot0 (stale, from Depth 0)
```

### 8.2 TWAMM Extension Scheduling & Core Sync

```
TX 1 (block N): Core swap, accum_price += delta
TX 2 (block N+1): TWAMM settles, accum_price += additional_delta

If core doesn't read TWAMM's deltas, misses price updates.
```

**Vulnerability**: Core and TWAMM accumulate independently:
```
Core(N+1) = 1005 (from core swaps)
TWAMM(N+1) = 1010 (from core + TWAMM swaps)

Liquidation using core's TWAP: wrong
```

### 8.3 TempDebt Surviving Extension Reentry

```
TX: flashBorrow(amount)
  flashState.tmpDebt = amount
  Extension.onFlashBorrow()
    Core.swap()
      Extension.onSwap()
        reads flashState.tmpDebt (still = amount)
        assumes flash still active
  require(flashState.tmpDebt == 0)  // may pass without repayment!
```

### 8.4 TickMap Mutated in Extension But Not Committed in Core

```solidity
// Extension (via delegatecall) modifies tickMap
tickMap[someIndex] = newBitmask;

// Core's swap loop uses cached tickMap (read before extension)
uint256 cachedTickMap = tickMap[someIndex];  // STALE after extension
```

### 8.5 Callpoint Mismatch Across Modules

```
Core expects: LIQUIDATE = 32
Extension A expects: LIQUIDATE = 16 (different!)

Core checks: extensionCallpoints[ext] & (1 << 32)
Extension A checks: callpoint & (1 << 16)

Both pass if mask = 48 (binary 110000) but interpret differently
```

---

## 9. STRICT REENTRANCY MODEL

### 9.1 Allowed Reentrancy Points

```
ALLOWED:
- Core.state() [read-only]
- Extension.onSwap() [can call Core.state()]

FORBIDDEN:
- Core.swap() → another swap()
- Core.flashBorrow() → nested flashBorrow()
- Core.liquidate() → another liquidate()
```

### 9.2 Forbidden Sequences

```
1. swap() → swap()
2. flashBorrow() → flashBorrow()
3. liquidate() → liquidate() [same or related position]
4. addLiquidity() → swap() → removeLiquidity() [order matters]
```

### 9.3 Extension-Induced Unexpected Recursion

```
Core.swap() → Extension.onSwap() → Extension.swap() [if ext has access]
  → Inner swap modifies slot0
  → Outer swap uses stale slot0

OR:

Core.liquidate() → Extension.onLiquidate() → Extension.swapCollateral()
  → Swap triggers another liquidation (cascade)
```

### 9.4 State Snapshot Invariants Before/After Extension Call

```solidity
(uint24 tickBefore, uint96 liqBefore, ) = decodeSlot0();
_callExtension(...);
(uint24 tickAfter, uint96 liqAfter, ) = decodeSlot0();

require(liqAfter >= 0);
```

---

## 10. COMPLETE ATTACK CATALOG (CORE)

### CORE_ATTACK_001: Delta Rounding Liquidation Bypass

**Name**: Delta Rounding Liquidation Bypass  
**Pattern ID**: CORE_ATTACK_001  
**Severity**: CRITICAL  
**Category**: Accounting  

**Vulnerability**:
```solidity
function canLiquidate(uint256 posId) public view returns (bool) {
    uint256 debtValue = (pos.debtShares * totalDebt) / totalDebtShares;
    return debtValue > collateralValue;  // rounding-down in division
}
```

**Preconditions**:
- Position at solvency edge
- debtShares and totalDebtShares ratio creates rounding artifact
- collateralValue equals rounded debtValue

**Call Sequence**:
1. Attacker: open position with debtShares = 10^18
2. Protocol: totalDebtShares = 3 × 10^18, totalDebt = 3 × 10^18 - 1
3. Attacker: getDebtValue() → (10^18 × (3 × 10^18 - 1)) / (3 × 10^18) = 10^18 - 1/3 → rounds to 10^18 - 1
4. Attacker: collateral = 10^18
5. Liquidator: canLiquidate check fails (10^18 - 1 > 10^18 is FALSE)

**Broken Invariants**:
- INV_LIQ_001: isSolvent(posId) == false ⇒ canLiquidate(posId) == true [BROKEN]
- INV_LIQ_002: debtShares > 0 ⇒ debtValue > 0 [BROKEN: debtValue = 0]

**Exploit Economics**:
Attacker maintains overleveraged position indefinitely; collateral subject to price swings but position cannot be liquidated.

**Repro Test**:
```foundry
function testDeltaRoundingLiquidationBypass() public {
    position1.debtShares = 1e18;
    position2.debtShares = 1e18;
    position3.debtShares = 1e18;
    core.totalDebtShares = 3e18;
    core.totalDebt = 3e18 - 1;
    
    uint256 collateral3 = 1e18;
    uint256 debtValue = core.getDebtValue(position3Id);
    assertLt(debtValue, collateral3);  // rounds to less than collateral
    
    bool canLiq = core.canLiquidate(position3Id);
    assertFalse(canLiq);  // should be TRUE
}
```

**Fix Suggestions**:
1. Use ceiling division: `(debtValue + totalDebtShares - 1) / totalDebtShares`
2. Track rounding errors separately; apply conservatively to liquidation checks
3. Use higher precision (uint256 × uint256 / uint256 → uint512 intermediate)

**Detection Heuristics**:
- Monitor positions where: `getDebtValue(posId) << collateralValue` but solvency check fails
- Alert if position's debt share ratio is 1/N where N is large prime
- Flag liquidations that fail with 1-wei precision loss

---

### CORE_ATTACK_002: Debt Mis-accounting via FlashAccountant Cleanup Failure

**Name**: FlashAccountant Cleanup Gap  
**Pattern ID**: CORE_ATTACK_002  
**Severity**: CRITICAL  
**Category**: Flash Accounting  

**Vulnerability**:
```solidity
function flashBorrow(uint256 amount, bytes calldata data) external {
    flashState.inFlashCallback = true;
    flashState.tmpDebt = amount;
    _transfer(msg.sender, amount);
    
    IFlashBorrower(msg.sender).onFlashBorrow(amount, data);
    
    require(flashState.tmpDebt == 0, "FLASH_DEBT_NOT_REPAID");
    flashState.inFlashCallback = false;  // ⚠️ GAP
}
```

**Preconditions**:
- Extension has access to `_decrementTmpDebt()` or similar function
- Extension is called during `onFlashBorrow` callback
- Extension can manipulate tmpDebt directly

**Call Sequence**:
1. Attacker: call `flashBorrow(1000)`
2. Core: set `tmpDebt = 1000`, `inFlashCallback = true`
3. Core: transfer 1000 to attacker
4. Core: call `onFlashBorrow` (attacker's contract)
5. Attacker: in callback, call extension with privileged access
6. Extension: decrement `tmpDebt` to 0
7. Attacker: return from `onFlashBorrow`
8. Core: check `tmpDebt == 0` → PASSES
9. Core: set `inFlashCallback = false`
10. Attacker: keeps 1000 units

**Broken Invariants**:
- INV_CORE_010: After flashBorrow: tmpDebt == 0 [BROKEN: 0 but not repaid]
- INV_CORE_011: inFlashCallback prevents nested flash [BROKEN: extension called within callback]

**Exploit Economics**:
Attacker acquires unsecured funds equal to flash borrow amount; no collateral required.

**Repro Test**:
```foundry
function testFlashAccountantCleanupFailure() public {
    uint256 borrowAmount = 1000e18;
    
    address badExtension = address(new BadFlashExtension(address(core)));
    core.registerExtension(badExtension, CALLPOINT_FLASH);
    
    uint256 balBefore = token.balanceOf(attacker);
    
    vm.prank(attacker);
    core.flashBorrow(borrowAmount, abi.encode(badExtension));
    
    uint256 balAfter = token.balanceOf(attacker);
    assertEq(balAfter, balBefore + borrowAmount);  // kept funds
    assertEq(core.totalDebt, 0);  // no debt recorded
}
```

**Fix Suggestions**:
1. Disallow `tmpDebt` modification during callback; use separate cleanup mechanism
2. Require explicit `flashRepay()` call; check balance delta instead of tmpDebt flag
3. Implement pull-based repayment: after callback, core pulls repayment from attacker
4. Use reentrancy guard that encompasses entire flash lifecycle

**Detection Heuristics**:
- Monitor extensions registered with CALLPOINT_FLASH
- Alert if tmpDebt changes outside of `flashBorrow` or `flashRepay` functions
- Track fund flows: borrow without corresponding debt increase

---

### CORE_ATTACK_003: Extension-Induced Solvency Drift

**Name**: Extension-Induced Solvency Drift  
**Pattern ID**: CORE_ATTACK_003  
**Severity**: CRITICAL  
**Category**: Extension State Desync  

**Vulnerability**:
```solidity
function liquidate(uint256 posId) external onlyExtension(LIQUIDATE) {
    uint256 debtToRepay = getDebtValue(posId);
    
    _callExtension(extensionLiquidation, LIQUIDATE, abi.encode(posId, debtToRepay));
    // ⚠️ Extension can modify totalDebt, totalDebtShares
    
    _repayDebtAndSeizeCollateral(posId, debtToRepay);
    // debtToRepay is now stale
}
```

**Preconditions**:
- Attacker controls extension with LIQUIDATE callpoint
- Extension can call `_updateDebt()` or modify global debt state
- Two positions exist: victim and attacker's own

**Call Sequence**:
1. Victim position becomes liquidatable
2. Liquidator calls `liquidate(victimPos)`
3. Core calculates `debtToRepay = 100` (based on current totalDebt = 1000)
4. Core calls extension with debt = 100
5. Extension (attacker) decreases `totalDebt` to 500
6. Core repays 100; but totalDebt is now 500
7. Debt-share ratio corrupted: attacker's position benefits

**Broken Invariants**:
- INV_CORE_020: solvency >= 0 under all deltas [BROKEN: extension modified totalDebt]
- INV_LIQ_003: Liquidation must reduce debt [BROKEN: repayment is misaligned with totalDebt]

**Exploit Economics**:
Attacker's position gains solvency improvement without contributing assets.

**Repro Test**:
```foundry
function testExtensionInducedSolvencyDrift() public {
    uint256 victimPos = core.openPosition(victimCollateral);
    uint256 attackerPos = core.openPosition(attackerCollateral);
    
    uint256 solvencyBefore = core.getSolvency(attackerPos);
    
    address malExt = address(new MaliciousLiquidationExt(address(core)));
    core.registerExtension(malExt, CALLPOINT_LIQUIDATE);
    
    vm.prank(liquidator);
    core.liquidate(victimPos, malExt);
    
    uint256 solvencyAfter = core.getSolvency(attackerPos);
    assertGt(solvencyAfter, solvencyBefore);  // unearned improvement
}
```

**Fix Suggestions**:
1. Snapshot totalDebt and totalDebtShares at liquidation start; validate no change post-extension
2. Implement pull-based repayment: calculate debt post-extension, after all state mutations
3. Disallow extension calls that modify global debt parameters during liquidation
4. Use checks-effects-interactions pattern: validate state after all external calls

**Detection Heuristics**:
- Monitor liquidations where `debtToRepay` differs from final repayment
- Alert if totalDebt decreases during liquidation extension call
- Track solvency changes across extension boundaries

---

### CORE_ATTACK_004: Tick Crossing Liquidity Overflow

**Name**: Tick Crossing Liquidity Overflow  
**Pattern ID**: CORE_ATTACK_004  
**Severity**: HIGH  
**Category**: Tick & Liquidity Math  

**Vulnerability**:
```solidity
function _swapLoop() internal {
    uint96 cumLiquidity = slot0.liquidity;
    
    while (remainingAmount > 0) {
        nextTick = _findNextTick();
        int96 liquidityDelta = tickState[nextTick].liquidityNet;
        
        cumLiquidity += liquidityDelta;  // ⚠️ no overflow check
        slot0.liquidity = cumLiquidity;
        
        uint256 amountOut = _calculateOutput(remainingAmount, cumLiquidity);
        remainingAmount -= amountOut;
    }
}
```

**Preconditions**:
- Attacker can create positions with large liquidityNet at multiple ticks
- Swap crosses many ticks in single transaction
- Cumulative sum exceeds uint96 max

**Call Sequence**:
1. Attacker adds liquidity at ticks: 0 (2^95), 10 (2^95), 20 (2^95), ...
2. Each tick has liquidityNet = 2^95
3. Attacker initiates swap from tick 0 to tick 30
4. Swap crosses: 0, 10, 20, 30
5. cumLiquidity: 2^95 → 2^96 (OVERFLOW) → 0 (wraps)
6. Swap now uses tiny liquidity value
7. Attacker outputs far less tokens than expected swap rate

**Broken Invariants**:
- INV_CORE_001: liquidity >= 0 [BROKEN: wraps to small value]
- INV_CORE_002: cumLiquidity must be valid throughout [BROKEN: overflow]

**Exploit Economics**:
Attacker exploits liquidity underpricing to extract more tokens than fair swap rate allows.

**Repro Test**:
```foundry
function testTickCrossingLiquidityOverflow() public {
    int24 startTick = 0;
    int24 endTick = 1000;
    
    for (int24 i = startTick; i <= endTick; i += 10) {
        core.setTickLiquidity(i, uint96(2**95));
    }
    
    uint256 amountIn = 1000e18;
    uint256 amountOutComputed = core.estimateSwap(amountIn);
    
    uint256 balBefore = token.balanceOf(address(this));
    core.swap(amountIn, abi.encode(...));
    uint256 balAfter = token.balanceOf(address(this));
    
    uint256 actualAmountOut = balAfter - balBefore;
    assertLt(actualAmountOut, amountOutComputed / 2);
}
```

**Fix Suggestions**:
1. Check cumLiquidity + delta against uint96 max before update
2. Use safe math library (Solidity 0.8 built-in checks for overflow)
3. Validate cumLiquidity is in valid range after each tick crossing
4. Cap maximum cumLiquidity value explicitly

**Detection Heuristics**:
- Monitor swaps crossing many ticks; alert if liquidity decreases during crossing
- Check tick's liquidityNet for unreasonably large values
- Flag positions with liquidityNet = type(uint96).max or near boundary

---

### CORE_ATTACK_005: Bitpacking Corruption via Stale Slot0 Read

**Name**: Bitpacking Corruption via Stale Reads  
**Pattern ID**: CORE_ATTACK_005  
**Severity**: CRITICAL  
**Category**: Assembly State Access  

**Vulnerability**:
```solidity
function swap(...) external {
    uint256 slot0Snapshot = slot0;  // ⚠️ read without snapshot semantics
    
    _callExtension(extensionA, SWAP, data);  // extension mutates slot0
    
    slot0 = _updatePriceInSlot0(slot0Snapshot, newPrice);  // write stale snapshot
}
```

**Preconditions**:
- Extension has delegatecall or direct write access to core state
- Extension is called within swap
- Core writes back stale slot0 snapshot

**Call Sequence**:
1. Core: `slot0Snapshot = slot0` → `{tick: 100, liq: 1000, fee: 50}`
2. Core: `_callExtension()`
3. Extension: modifies slot0 directly → `{tick: 101, liq: 1100, fee: 60}`
4. Core: `slot0 = _updatePrice(slot0Snapshot, ...)` → writes back stale values
5. Result: slot0 = `{tick: 100, liq: 1000, fee: 50}` (rolled back)

**Broken Invariants**:
- INV_CORE_014: Slot0 atomicity [BROKEN: stale bits revert changes]
- INV_CORE_015: Bitpacking consistency [BROKEN: corrupted state]

**Exploit Economics**:
Attacker resets tick and liquidity to stale values; subsequent swaps use wrong price.

**Repro Test**:
```foundry
function testBitpackingCorruptionStaleRead() public {
    core.setSlot0(encodeSlot0(100, 1000, 50));
    
    address malExt = address(new CorruptingExtension(address(core)));
    core.registerExtension(malExt, CALLPOINT_SWAP);
    
    vm.prank(attacker);
    core.swap(1000e18, abi.encode(malExt));
    
    (int24 tick, uint96 liq, ) = decodeSlot0(core.slot0);
    
    assertEq(tick, 100);  // stale, should be 105
    assertEq(liq, 1000);  // stale, should be 1050
}
```

**Fix Suggestions**:
1. Don't cache entire slot0; cache individual fields
2. Use assembly-level atomic updates (single sstore after all calculations)
3. Validate slot0 consistency immediately after extension call
4. Disallow delegatecall; use call with explicit parameter passing

**Detection Heuristics**:
- Monitor slot0 reads and writes; alert if write happens after external call
- Track tick values: if tick ever decreases (should be monotonic within swap), flag
- Check bit alignment: verify no high-bit corruption in packed fields

---

### CORE_ATTACK_006: Callpoint Mismatch via Extension Upgrade

**Name**: Callpoint Mismatch via Extension Self-Destruct Redeploy  
**Pattern ID**: CORE_ATTACK_006  
**Severity**: HIGH  
**Category**: Extension System  

**Vulnerability**:
```solidity
function registerExtension(address ext, uint256 mask) external onlyOwner {
    extensionCallpoints[ext] = mask;  // keyed by address, not code hash
}

// Attacker:
// 1. Deploy ExtensionV1 (benign)
// 2. Owner registers V1 with SWAP callpoint
// 3. Attacker self-destructs V1
// 4. Attacker redeploys ExtensionV2 (malicious) at same address (via CREATE2)
// 5. extensionCallpoints[V2] still = SWAP
// 6. Next swap calls V2's onSwap (malicious)
```

**Preconditions**:
- Attacker can create CREATE2 factories to control deployment address
- V1 and V2 are functionally different but V2 is at same address
- Owner doesn't verify code hash before calling

**Call Sequence**:
1. Deploy V1: safe swap logic
2. Owner: `registerExtension(V1, CALLPOINT_SWAP)`
3. Attacker: `V1.selfDestruct()`
4. Attacker: deploy V2 at same address via CREATE2 with salt = precomputed
5. User: call `swap()` with V2
6. Core: checks `extensionCallpoints[V2]` → still = CALLPOINT_SWAP
7. Core: calls V2's `onSwap()` (malicious)

**Broken Invariants**:
- INV_XCUT_005: Extension code hash match [BROKEN: code changed, address same]
- INV_XCUT_001: Extension callpoint validity [BROKEN: wrong function at address]

**Exploit Economics**:
Attacker drains pool via malicious extension at trusted address.

**Repro Test**:
```foundry
function testCallpointMismatchExtensionUpgrade() public {
    SafeExtensionV1 extV1 = new SafeExtensionV1();
    core.registerExtension(address(extV1), CALLPOINT_SWAP);
    
    address extAddr = address(extV1);
    
    uint256 balBefore = core.poolBalance();
    core.swap(100e18, abi.encode(extAddr));
    uint256 balAfter = core.poolBalance();
    assertGe(balAfter, balBefore);  // safe
    
    extV1.selfDestruct();
    
    MaliciousExtensionV2 extV2 = new MaliciousExtensionV2{salt: keccak256("salt")}();
    assertEq(address(extV2), extAddr);  // same address!
    
    balBefore = core.poolBalance();
    core.swap(100e18, abi.encode(address(extV2)));
    balAfter = core.poolBalance();
    assertLt(balAfter, balBefore);  // drained!
}
```

**Fix Suggestions**:
1. Store code hash alongside callpoint: `mapping(address => bytes32) extensionCodeHash`
2. Verify code hash before extension call: require current code hash == stored hash
3. Use code size check: `require(extcodesize(ext) > 0, "NO_CODE")`
4. Implement extension deactivation on code change detection
5. Use timelocks and multi-sig for extension registration/updates

**Detection Heuristics**:
- Monitor extension self-destructs; flag redeployments to same address
- Alert if extension's function signature changes while callpoint is unchanged
- Track code hashes; detect when address's code changes mid-protocol-operation

---

## 11. COMPLETE ATTACK CATALOG (LIQUIDATION)

### LIQ_ATTACK_001: Stale Tick → Underpriced Liquidation

**Name**: Stale Tick Liquidation Bypass  
**Pattern ID**: LIQ_ATTACK_001  
**Severity**: CRITICAL  
**Category**: Oracle / State Staleness  

**Vulnerability**:
```solidity
function swap(uint256 amountIn, bytes calldata data) external {
    uint256 amountOut = _executeSwap(amountIn);  // price moves, slot0.tick not yet updated
    
    _callExtension(extensionSwap, SWAP, data);  // ⚠️ gap: extension sees stale tick
    
    slot0.tick = computeNewTick(...);  // NOW updated
}

function liquidate(uint256 posId) external {
    uint256 collateralValue = position.collateral * priceFromTick(slot0.tick);
    if (collateralValue < position.debt) {
        _repayDebtAndSeizeCollateral(posId);  // uses stale price
    }
}
```

**Preconditions**:
- Position near liquidation threshold
- Large swap moves price dramatically
- Liquidation called during gap (before slot0 update)
- Extension has access to liquidation functions

**Call Sequence**:
1. Position: collateral = 1000, debt = 900, tick = 100 (price = 100), solvency = +100
2. Attacker: orchestrate swap moving tick to 90 (price = 90)
3. During swap, before slot0 update: liquidation is triggered
4. Liquidation: reads stale tick = 100
5. Liquidation: collateral_value = 1000 × 100 = 100000
6. Liquidation: solvency = 100000 - 900 = positive, doesn't liquidate
7. After swap completes: real price = 90, real solvency = 90000 - 900 = negative
8. Position remains open, insolvent

**Broken Invariants**:
- INV_LIQ_001: isSolvent == false ⇒ canLiquidate == true [BROKEN: stale price]
- INV_XCUT_015: core-slot0 tick must equal post-extension tick [BROKEN: gap exists]

**Exploit Economics**:
Attacker maintains underwater position; liquidators cannot action despite insolvency.

**Repro Test**:
```foundry
function testStaleTick_LiquidationBypass() public {
    uint256 posId = core.openPosition(user, 1000e18, 900e18);
    
    core.setTickPrice(0);
    assertGt(core.getCollateralValue(posId), core.getDebtValue(posId));
    
    (int24 tickBefore, , ) = core.decodeSlot0();
    
    core.swap(100000e18, abi.encode(...));  // moves tick
    
    uint256 actualCollateral = core.getCollateralValue(posId);
    uint256 actualDebt = core.getDebtValue(posId);
    
    if (actualCollateral < actualDebt) {
        core.liquidate(posId);
        assertEq(core.positions(posId).debtShares, 0);
    }
}
```

**Fix Suggestions**:
1. Update slot0.tick atomically with swap execution (before extension call)
2. Use TWAP instead of spot price for liquidation checks
3. Implement price staleness check: revert if tick hasn't been updated in N blocks
4. Add liquidation delay: require tick to be stable for M blocks before liquidation

**Detection Heuristics**:
- Monitor gap between swap execution and slot0 update
- Alert if liquidation is called within same transaction as swap
- Track tick values: detect if liquidation uses old tick after swap

---

### LIQ_ATTACK_002: Debt-Share Inflation via Rounding

**Name**: Debt-Share Inflation Rounding Attack  
**Pattern ID**: LIQ_ATTACK_002  
**Severity**: HIGH  
**Category**: Debt Accounting  

**Vulnerability**:
```solidity
function borrowAgainstCollateral(uint256 posId, uint256 amount) external {
    require(isSolvent(posId, amount), "INSOLVENCY");
    
    uint96 sharesToMint = (amount * totalDebtShares) / totalDebt;
    // ⚠️ if amount * totalDebtShares < totalDebt, rounds to 0
    
    positions[posId].debtShares += sharesToMint;
    totalDebt += amount;
    _transfer(borrower, amount);
}
```

**Preconditions**:
- Attacker can borrow in small increments
- totalDebt / totalDebtShares ratio is high (e.g., 10:1)
- Tiny borrow amounts round shares down to 0

**Call Sequence**:
1. Setup: totalDebt = 10e18, totalDebtShares = 1e18 (10:1 ratio)
2. Attacker: borrow(1) wei
3. Shares = (1 × 1e18) / 10e18 = 0.1 → rounds to 0
4. Attacker gains 1 wei of debt-free funds
5. Repeat 1e18 times → attacker borrows 1e18 wei with zero debt shares

**Broken Invariants**:
- INV_LIQ_002: debtShares > 0 ⇔ debtValue > 0 [BROKEN: debtShares = 0, amount > 0]
- INV_CORE_003: Debt shares consistency [BROKEN: shares ≠ debt]

**Exploit Economics**:
Attacker acquires substantial unsecured debt; position is unborrowed and unliquidatable.

**Repro Test**:
```foundry
function testDebtShareInflationRounding() public {
    core.setTotalDebt(10e18);
    core.setTotalDebtShares(1e18);
    
    uint256 borrowAmount = 1;
    uint256 expectedShares = (borrowAmount * 1e18) / 10e18;
    assertEq(expectedShares, 0);
    
    uint256 debtBefore = core.totalDebt();
    
    vm.prank(attacker);
    core.borrowAgainstCollateral(attackerPosId, borrowAmount);
    
    uint256 debtAfter = core.totalDebt();
    assertEq(debtAfter, debtBefore + borrowAmount);
    
    (uint96 debtShares, , ) = core.positions(attackerPosId);
    assertEq(debtShares, 0);  // zero shares!
    
    uint256 debtValue = core.getDebtValue(attackerPosId);
    assertEq(debtValue, 0);  // unliquidatable
}
```

**Fix Suggestions**:
1. Use ceiling division: `(amount * totalDebtShares + totalDebt - 1) / totalDebt`
2. Track rounding errors; apply accumulated rounding to borrower's debt
3. Enforce minimum borrow amount: require `sharesToMint >= MIN_SHARES`
4. Use higher precision intermediate calculations (e.g., uint256 × uint256 / uint256 via uint512)

**Detection Heuristics**:
- Alert if position has positive totalDebt but zero debtShares
- Monitor borrow amounts relative to totalDebt/totalDebtShares ratio
- Flag positions where debtValue rounds to 0

---

### LIQ_ATTACK_003: TempDebt Double-Count Exploit

**Name**: TempDebt Double-Count Liquidation Exploit  
**Pattern ID**: LIQ_ATTACK_003  
**Severity**: CRITICAL  
**Category**: Flash + Liquidation  

**Vulnerability**:
```solidity
function liquidate(uint256 posId) external {
    uint256 debt = getDebtValue(posId);
    if (flashState.inFlashCallback && flashState.tmpCaller == pos.owner) {
        debt += flashState.tmpDebt;  // ⚠️ double-count
    }
    
    _repayDebtAndSeizeCollateral(posId, debt);
}
```

**Preconditions**:
- Attacker's position is solvent without tmpDebt
- Attacker can trigger flash loan
- Liquidation is called during flash callback
- tmpDebt is counted in liquidation but not backed by real debt increase

**Call Sequence**:
1. Attacker position: debt = 100, collateral = 150, solvency = +50
2. Attacker: call `flashBorrow(50)`
3. Core: set tmpDebt = 50, inFlashCallback = true
4. Core: call `onFlashBorrow` (attacker's contract)
5. Attacker: in callback, trigger `liquidate(myPos)`
6. Liquidation: debt = 100 + 50 = 150, collateral = 150, solvency = 0
7. Liquidation: executes, seizes collateral for 150
8. Attacker: returns from `onFlashBorrow`
9. Core: tmpDebt is cleared (part of flash cleanup)
10. Attacker: keeps seized collateral (150) + flash funds (50) = 200 from 150 initial

**Broken Invariants**:
- INV_LIQ_007: Flash debt cleared after liquidation [BROKEN: tmpDebt counted, then cleared]
- INV_CORE_010: flashDebtTemp == 0 after call [BROKEN: was counted as debt]

**Exploit Economics**:
Attacker extracts collateral value greater than initial investment via tmpDebt double-count.

**Repro Test**:
```foundry
function testTempDebtDoubleCountExploit() public {
    uint256 posId = core.openPosition(attacker, 150e18, 100e18);
    
    assertGt(core.getCollateralValue(posId), core.getDebtValue(posId));
    
    uint256 flashAmount = 50e18;
    
    vm.prank(attacker);
    core.flashBorrow(flashAmount, abi.encode(
        address(liquidationCallback),
        posId
    ));
    
    (uint96 debtShares, , ) = core.positions(posId);
    assertEq(debtShares, 0);  // liquidated
    
    // attacker profited from the exploit
    uint256 seizedAmount = 150e18;
    // Attacker repaid: 100 (real debt) + 50 (flash) = 150 (covered by collateral)
    // Collateral was 150, so attacker is even? But liquidation should impose loss.
}
```

**Fix Suggestions**:
1. Do NOT count tmpDebt in liquidation; only use real debt
2. Implement flash-liquidation prohibition: revert if `inFlashCallback == true`
3. Clear tmpDebt immediately after callback, before any extension calls
4. Use separate liquidation path for flash-backed positions

**Detection Heuristics**:
- Monitor liquidations called with `inFlashCallback == true`
- Alert if tmpDebt is non-zero during liquidation
- Track debt composition: flag if tmpDebt ever included in solvency calculation

---

### LIQ_ATTACK_004: Invalid Solvency State Due to Extension Cleanup Failure

**Name**: Extension Cleanup Failure Induces Invalid Solvency  
**Pattern ID**: LIQ_ATTACK_004  
**Severity**: CRITICAL  
**Category**: Extension + Liquidation  

**Vulnerability**:
```solidity
function liquidate(uint256 posId) external {
    uint256 debtToRepay = getDebtValue(posId);
    
    _callExtension(extensionLiquidation, LIQUIDATE, abi.encode(posId, debtToRepay));
    // ⚠️ Extension can modify totalDebt, totalDebtShares
    
    _repayDebtAndSeizeCollateral(posId, debtToRepay);  // stale debtToRepay
}
```

**Preconditions**:
- Attacker controls extension with LIQUIDATE callpoint
- Extension can invoke `_updateDebt()` or modify debt globals
- Multiple positions exist; liquidation of one affects another

**Call Sequence**:
1. Two positions: victim (100 debt, 50 collateral) and attacker (100 debt, 200 collateral)
2. totalDebt = 200, totalDebtShares = 200
3. Liquidator: call `liquidate(victimPos)`
4. Core: calculate `debtToRepay = 100`
5. Core: call extension
6. Extension: decrease totalDebt to 100 (via _updateDebt or direct write)
7. Core: repay 100, seize 50 collateral
8. Debt-share ratio: now 100 debt / 200 shares (was 200/200)
9. Attacker's position: debt value = 100 × (100/200) = 50 (down from 100)
10. Attacker gained solvency without legitimate action

**Broken Invariants**:
- INV_LIQ_003: Liquidation must reduce debt [BROKEN: debt repaid doesn't match totalDebt change]
- INV_CORE_020: solvency >= 0 under all deltas [BROKEN: extension modified totalDebt]

**Exploit Economics**:
Attacker's debt is implicitly forgiven via extension-induced state mutation.

**Repro Test**:
```foundry
function testInvalidSolvencyExtensionCleanupFailure() public {
    uint256 victimPos = core.openPosition(victim, 100e18, 100e18);
    uint256 attackerPos = core.openPosition(attacker, 200e18, 100e18);
    
    uint256 totalDebtBefore = core.totalDebt();
    
    address malExt = address(new MaliciousLiquidationExt(address(core)));
    core.registerExtension(malExt, CALLPOINT_LIQUIDATE);
    
    uint256 debtA = core.getDebtValue(victimPos);
    
    vm.prank(liquidator);
    core.liquidate(victimPos, malExt);
    
    uint256 totalDebtAfter = core.totalDebt();
    
    if (totalDebtAfter < totalDebtBefore) {
        uint256 debtAttacker = core.getDebtValue(attackerPos);
        assertGt(debtAttacker, 100e18);  // attacker's debt inflated (in share terms)
    }
}
```

**Fix Suggestions**:
1. Snapshot totalDebt and totalDebtShares at liquidation start
2. Validate no change in debt globals after extension call; if changed, revert
3. Use pull-based repayment: calculate final debt amount after all ext calls
4. Prohibit debt-modifying calls during liquidation extension

**Detection Heuristics**:
- Monitor totalDebt changes during liquidation
- Alert if debtToRepay differs from actual debt reduction post-liquidation
- Track solvency changes across liquidations; flag unexpected improvements

---

### LIQ_ATTACK_005: Tick Boundary Liquidation

**Name**: Tick Boundary Liquidation Profit Extraction  
**Pattern ID**: LIQ_ATTACK_005  
**Severity**: MEDIUM  
**Category**: Tick Crossing + Liquidation  

**Vulnerability**:
Tick crossing causes discrete liquidity changes. Liquidator can time liquidation to capture liquidity jump:
```solidity
liquidationProfit = seizedCollateral - debtRepaid - liquidationCost

// If liquidation happens just after tick crosses:
// seizedCollateral might include liquidity jump bonus
```

**Preconditions**:
- Position liquidatable at or near tick boundary
- Large liquidity concentrated at boundary tick
- Liquidator can monitor mempool and front-run tick crossing

**Call Sequence**:
1. Price approaching tick 100 (boundary)
2. Initialize tick 100 with large liquidityNet = 1e18
3. Swap moves price across tick 100
4. Liquidation triggers during or after crossing
5. Liquidator captures extra value from liquidity jump

**Broken Invariants**:
- INV_LIQ_006: Liquidation discount applied fairly [BROKEN: MEV-driven profit]

**Exploit Economics**:
Liquidator extracts disproportionate value at tick boundaries.

**Repro Test**:
```foundry
function testTickBoundaryLiquidation() public {
    uint256 posId = core.openPosition(user, 1000e18, 900e18);
    
    core.setCurrentTick(99);
    core.setTickLiquidity(100, 1e18);
    
    assertTrue(core.isSolvent(posId));
    
    core.swap(10000e18, abi.encode(...));  // crosses tick 100
    
    core.liquidate(posId);
    
    uint256 liquidationReward = core.getLiquidationReward(posId);
    assertGt(liquidationReward, expectedReward);  // excess at boundary
}
```

**Fix Suggestions**:
1. Smooth liquidation rewards across tick boundary (time-lock or gradual accrual)
2. Implement MEV-resistant liquidation: randomize liquidation reward or use sealed-bid auctions
3. Monitor tick liquidity concentrations; flag large liquidityNet at boundaries

**Detection Heuristics**:
- Alert if liquidation reward >> expected based on debt
- Monitor tick boundary crossings; correlate with liquidation profitability
- Flag positions where liquidation occurs within 1 block of tick crossing

---

### LIQ_ATTACK_006: Delta-Rounding Liquidation Attack

**Name**: Delta-Rounding Liquidation Impossibility  
**Pattern ID**: LIQ_ATTACK_006  
**Severity**: CRITICAL  
**Category**: Accounting  

**Vulnerability**:
```solidity
function liquidate(uint256 posId) external {
    uint256 debtToRepay = (positions[posId].debtShares * totalDebt) / totalDebtShares;
    
    require(debtToRepay > 0, "NO_DEBT");  // ⚠️ can round to 0
    _repayDebtAndSeizeCollateral(posId, debtToRepay);
}
```

**Preconditions**:
- Position has tiny debtShares (e.g., 1 wei)
- totalDebt / totalDebtShares ratio is small (e.g., 2/3)
- debtToRepay rounds down to 0

**Call Sequence**:
1. Position: debtShares = 1
2. Global: totalDebt = 2, totalDebtShares = 3
3. Liquidation: debtToRepay = (1 × 2) / 3 = 0 (rounds down)
4. Liquidation: require(0 > 0) → reverts
5. Position remains unliquidated despite insolvency

**Broken Invariants**:
- INV_LIQ_001: isSolvent == false ⇒ canLiquidate == true [BROKEN: liquidation reverts]
- INV_LIQ_004: Liquidation resets shares [BROKEN: liquidation doesn't execute]

**Exploit Economics**:
Attacker maintains insolvent position indefinitely; liquidators cannot force closure.

**Repro Test**:
```foundry
function testDeltaRoundingLiquidationAttack() public {
    core.setTotalDebt(2e18);
    core.setTotalDebtShares(3e18);
    
    uint256 posId = core.openPosition(user, 10e18, 2e18);
    core.setPositionDebtShares(posId, 1);
    
    uint256 debtValue = core.getDebtValue(posId);
    assertEq(debtValue, 0);  // rounds to 0!
    
    vm.expectRevert("NO_DEBT");
    core.liquidate(posId);
}
```

**Fix Suggestions**:
1. Use ceiling division: `(debtShares * totalDebt + totalDebtShares - 1) / totalDebtShares`
2. Enforce minimum debtShares: require `sharesToMint >= MIN_DEBT_SHARES` on borrow
3. Implement debt-dust collector: periodically consolidate sub-wei debts
4. Allow liquidation with 1-wei threshold enforcement

**Detection Heuristics**:
- Alert if liquidation reverts with "NO_DEBT" but position is insolvent
- Monitor positions where debtValue rounds to 0 but debtShares > 0
- Flag debtShares of 1-3 wei as suspicious (likely rounding artifacts)

---

## 12. COMPLETE ATTACK CATALOG (CROSS-CUTTING)

### XCUT_ATTACK_001: Cross-Module Solvency Drift via Extension State Mutation

**Name**: Cross-Module Solvency Drift  
**Pattern ID**: XCUT_ATTACK_001  
**Severity**: CRITICAL  
**Category**: Extension + Solvency  

**Vulnerability**:
```solidity
function liquidate(uint256 posId) external {
    uint256 collateralValueCore = getCollateralValue(posId);  // uses core price
    uint256 collateralValueTWAMM = getCollateralValueTWAMM(posId);  // uses TWAMM price
    
    _callExtension(extensionLiquidation, LIQUIDATE, data);
    // ⚠️ Extension modifies TWAMM's accumulated_price
    
    require(collateralValueCore < debtValue, "SOLVENT");
}
```

**Preconditions**:
- Core and TWAMM maintain separate price state
- Position solvency differs by price source
- Extension has access to TWAMM state

**Call Sequence**:
1. Position: solvency_core = +5 (solvent), solvency_twamm = -5 (insolvent)
2. Liquidator: call `liquidate(posId)`
3. Core: check solvency_core → +5, doesn't liquidate
4. OR, liquidation is triggered via TWAMM check
5. Extension: modifies TWAMM's accumulated_price (upward)
6. Liquidation: executes based on stale collateralValue
7. After liquidation: real solvency shows position was solvent (via updated TWAMM)
8. Attacker profited from self-liquidation

**Broken Invariants**:
- INV_XCUT_013: Price consistency [BROKEN: core and TWAMM diverge]

**Exploit Economics**:
Attacker self-liquidates at favorable price; seizes own collateral at discount.

**Repro Test**:
```foundry
function testCrossModuleSolvencyDriftExtension() public {
    uint256 posId = core.openPosition(attacker, 1000e18, 950e18);
    
    core.setTickPrice(0);  // core price: 1.0
    twamm.setAccumulatedPrice(0.95e18);  // TWAMM price: 0.95
    
    address malExt = address(new SolvencyDesyncExtension(address(core), address(twamm)));
    core.registerExtension(malExt, CALLPOINT_LIQUIDATE);
    
    core.liquidate(posId, malExt);
    
    (uint96 debtShares, , ) = core.positions(posId);
    assertEq(debtShares, 0);
    
    uint256 balAfter = token.balanceOf(attacker);
    assertGt(balAfter, initialBalance);
}
```

**Fix Suggestions**:
1. Snapshot core price and TWAMM price at liquidation start
2. Validate no price changes post-extension call
3. Use single, canonical price source for liquidation
4. Implement price divergence limits: revert if core/TWAMM diverge > threshold

**Detection Heuristics**:
- Monitor liquidations where core price ≠ TWAMM price
- Alert if liquidation proceeds despite price divergence
- Track solvency changes across extension boundaries during liquidation

---

### XCUT_ATTACK_002: Extension Misuse to Bypass Reentrancy Guard

**Name**: Multi-Callpoint Reentrancy Bypass  
**Pattern ID**: XCUT_ATTACK_002  
**Severity**: CRITICAL  
**Category**: Reentrancy  

**Vulnerability**:
```solidity
uint8 locked = 0;

function swap(...) external {
    require(locked == 0, "REENTRANT");
    locked = 1;
    
    _callExtension(extensionSwap, SWAP, data);
    // ⚠️ Extension has multiple callpoints: SWAP | LIQUIDATE
    // Extension can call liquidate(), which has NO reentrancy guard
    
    locked = 0;
}

function liquidate(...) external {
    // No reentrancy guard!
    _callExtension(extensionLiquidation, LIQUIDATE, data);
}
```

**Preconditions**:
- Extension has multiple callpoints
- Core has per-function reentrancy guards
- Some functions (e.g., liquidate) lack guards
- Extension can invoke unguarded function

**Call Sequence**:
1. Attacker: call `swap()`; `locked = 1`
2. Core: invoke extension with SWAP callpoint
3. Extension: call `liquidate()` (has LIQUIDATE callpoint)
4. `liquidate()`: no guard check, proceeds
5. `liquidate()`: invoke extension with LIQUIDATE callpoint
6. Extension: call `swap()` again via core callback
7. Inner `swap()`: check `locked == 1` (would fail)
8. But if extension bypasses check via different code path, reentrancy succeeds

**Broken Invariants**:
- INV_XCUT_007: Reentrancy guard atomic [BROKEN: locked state bypassed]

**Exploit Economics**:
Attacker performs unexpected nested operations; liquidates own position or manipulates state.

**Repro Test**:
```foundry
function testExtensionReentrancyBypassMultiCallpoint() public {
    uint256 posId = core.openPosition(user, 1000e18, 900e18);
    
    address malExt = address(new MultiCallpointExtension(address(core)));
    core.registerExtension(malExt, CALLPOINT_SWAP | CALLPOINT_LIQUIDATE);
    
    vm.prank(attacker);
    core.swap(100e18, abi.encode(malExt));
    
    (uint96 debtShares, , ) = core.positions(posId);
    assertGt(debtShares, 0);  // position NOT liquidated (guard worked)
}
```

**Fix Suggestions**:
1. Use global reentrancy guard (single locked flag) for all entry points
2. Implement check-locked pattern before ANY external call:
   ```solidity
   require(locked == 0, "REENTRANT");
   locked = 1;
   // ... work ...
   locked = 0;
   ```
3. Validate callpoint hierarchy: forbid extension from invoking lower-priority functions
4. Implement call-depth tracking to detect unexpected nesting

**Detection Heuristics**:
- Monitor call stack depth; alert if depth > expected max
- Track function reentries; flag if same function called >1 time per TX
- Monitor extensions with multiple callpoints; validate they don't cross invoke

---

### XCUT_ATTACK_003: TWAMM Desync Attack via Accumulated Price Manipulation

**Name**: TWAMM Accumulated Price Desync  
**Pattern ID**: XCUT_ATTACK_003  
**Severity**: HIGH  
**Category**: Oracle / TWAMM  

**Vulnerability**:
```solidity
// In TWAMM extension:
uint256 accumulatedPrice;

function settleScheduledOrders() external {
    uint256 priceNow = getCurrentPrice();
    uint256 timeElapsed = block.timestamp - lastSettlementTime;
    
    accumulatedPrice += priceNow * timeElapsed / WINDOW;
    // ⚠️ not synchronized with core's slot0
    lastSettlementTime = block.timestamp;
}

// In core:
function getTWAPPrice() external view returns (uint256) {
    return twamm.accumulatedPrice() / WINDOW;
}
```

**Preconditions**:
- TWAMM extension is called multiple times without corresponding core updates
- Attacker can trigger TWAMM settlement repeatedly
- Liquidation relies on TWAP price

**Call Sequence**:
1. Position: liquidatable if price < X
2. Current TWAP price: 1.0 (position is solvent)
3. Attacker: schedule large TWAMM order (moves price down over time)
4. Attacker: call `settleScheduledOrders()` multiple times in rapid succession
5. TWAM's accumulated_price increases (artificially)
6. TWAP becomes overstated: 1.0 → 1.05 → 1.10 (wrong!)
7. Liquidation check: uses inflated TWAP, position appears solvent
8. Position remains unliquidated

**Broken Invariants**:
- INV_XCUT_002: Core-TWAMM accumulated price alignment [BROKEN: TWAMM is ahead]
- INV_XCUT_013: Price consistency [BROKEN: core ≠ TWAMM]

**Exploit Economics**:
Attacker keeps position open via TWAP manipulation; avoids liquidation.

**Repro Test**:
```foundry
function testTWAMM_DeSyncAttack() public {
    uint256 posId = core.openPosition(user, 1000e18, 950e18);
    
    uint256 twapBefore = twamm.getTWAPPrice();
    assertEq(twapBefore, 1e18);
    
    vm.prank(attacker);
    for (uint i = 0; i < 10; i++) {
        twamm.settleScheduledOrders();
    }
    
    uint256 twapAfter = twamm.getTWAPPrice();
    assertGt(twapAfter, twapBefore);
    
    bool canLiq = core.canLiquidateUsingTWAP(posId);
    assertFalse(canLiq);
}
```

**Fix Suggestions**:
1. Synchronize TWAMM and core accumulated prices: core commits to TWAMM's value after settlement
2. Implement staleness check: revert if TWAP hasn't been updated in N blocks
3. Use single, canonical accumulated price (in core, TWAMM reads from core)
4. Validate TWAP is monotonically increasing; alert on decreases (impossible)

**Detection Heuristics**:
- Monitor TWAP price increases; correlate with TWAMM settlement calls
- Alert if TWAP diverges from observable spot prices by >threshold
- Track accumulated_price: verify monotonic increase, alert on jumps

---

### XCUT_ATTACK_004: Pseudo-Oracle Updates via Extension Timing

**Name**: Extension-Timed Oracle Manipulation  
**Pattern ID**: XCUT_ATTACK_004  
**Severity**: MEDIUM  
**Category**: Oracle Manipulation  

**Vulnerability**:
```solidity
function getPrice() external view returns (uint256) {
    return extensionOracleCache.price;  // cache updated by extension
}

// Attacker controls extension:
function updatePrice(uint256 newPrice) external {
    extensionOracleCache.price = newPrice;
}
```

**Preconditions**:
- Oracle price is cached (not computed per-block)
- Attacker can call extension to update cache
- Liquidation and swaps use cached price
- Extension can be called multiple times per block (no rate limiting)

**Call Sequence**:
1. Initial price: 100
2. Attacker: call `updatePrice(50)` → oracle cache = 50
3. Liquidation uses lowPrice; seizes cheap collateral
4. Attacker: call `updatePrice(100)` → oracle cache = 100
5. Attacker: swap seized collateral at high price
6. Net result: arbitrage via price manipulation

**Broken Invariants**:
- INV_XCUT_003: Oracle price bounds [BROKEN: attacker can set arbitrary price]
- INV_XCUT_004: TWAP staleness limit [BROKEN: cache not timestamped]

**Exploit Economics**:
Attacker arbitrages between low liquidation price and high swap price.

**Repro Test**:
```foundry
function testPseudoOracleUpdate_ExtensionTiming() public {
    address oracleExt = address(new MockOracleExtension(address(core)));
    
    MockOracleExtension(oracleExt).updatePrice(100e18);
    
    uint256 posId = core.openPosition(attacker, 100e18, 95e18);
    
    vm.prank(attacker);
    MockOracleExtension(oracleExt).updatePrice(50e18);
    
    vm.prank(liquidator);
    core.liquidate(posId);
    
    vm.prank(attacker);
    MockOracleExtension(oracleExt).updatePrice(100e18);
}
```

**Fix Suggestions**:
1. Use block.timestamp-stamped oracle updates; reject stale updates
2. Implement rate limiting: only allow price updates once per block
3. Use multi-source price feeds; require consensus
4. Implement price delta checks: revert if price changes >threshold per block

**Detection Heuristics**:
- Monitor oracle price updates; alert if multiple updates in same block
- Track price volatility; flag unrealistic jumps
- Correlate oracle updates with liquidations; detect intentional timing

---

### XCUT_ATTACK_005: External Hook-Induced State Corruption

**Name**: Hook-Induced State Corruption  
**Pattern ID**: XCUT_ATTACK_005  
**Severity**: HIGH  
**Category**: Composability  

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

**Preconditions**:
- Core allows external hook callbacks
- Hook is attacker-controlled (or compromised)
- Hook can perform unexpected operations
- No reentrancy guard around liquidation

**Call Sequence**:
1. Liquidation is triggered
2. Core calculates debt, initiates repayment
3. Hook's `onLiquidate()` is called
4. Hook (attacker): performs unexpected operations:
   - Modifies position state (if delegatecall used)
   - Restores liquidated position's debt
   - Transfers funds to attacker
5. State is corrupted; liquidation is incomplete

**Broken Invariants**:
- INV_LIQ_004: Liquidation resets shares [BROKEN: hook restores shares]
- INV_XCUT_014: Extension context clarity [BROKEN: hook's context unclear]

**Exploit Economics**:
Attacker's position is liquidated but position state is restored; collateral is seized but debt remains.

**Repro Test**:
```foundry
function testExternalHookStateCorruption() public {
    address malHook = address(new MaliciousLiquidationHook(address(core)));
    core.setLiquidationHook(malHook);
    
    uint256 posId = core.openPosition(user, 1000e18, 900e18);
    
    vm.prank(liquidator);
    core.liquidate(posId);
    
    (uint96 debtShares, , ) = core.positions(posId);
    assertEq(debtShares, 0);
}
```

**Fix Suggestions**:
1. Disallow external hooks; implement all liquidation logic in core
2. If hooks are needed: implement strict interface with no state mutation permission
3. Use reentrancy guard: lock core state during hook call
4. Snapshot position state before liquidation; validate state post-liquidation
5. Implement hook whitelisting; require governance approval

**Detection Heuristics**:
- Monitor hook calls; alert if hook modifies position state
- Track liquidation completeness: verify position is fully liquidated post-liquidation
- Monitor state rollbacks during hooks; flag any reversions

---

## 13. COMPLETE INVARIANTS REGISTRY

### CORE INVARIANTS

| ID | Invariant | Formula / Constraint | Enforcement | Category |
|----|-----------|---------------------|-------------|----------|
| INV_CORE_001 | Liquidity non-negative | liquidity ≥ 0 | Check after updates | Accounting |
| INV_CORE_002 | Tick in bounds | MIN_TICK ≤ tick ≤ MAX_TICK | Check on crossing | Tick Math |
| INV_CORE_003 | Debt shares consistency | totalDebtShares ≥ 0 | Atomic update | Debt |
| INV_CORE_004 | Ticks must remain sorted | tickMap bits monotonic | Bitmap invariant | Tick Math |
| INV_CORE_005 | Position liquidity bounded | position.liquidity ≤ totalLiquidity | Global tracking | Liquidity |
| INV_CORE_010 | Flash debt ephemeral | After flashBorrow: tmpDebt == 0 | End-of-tx check | Flash |
| INV_CORE_011 | Flash reentrancy guard | inFlashCallback prevents nested flash | Atomic bool | Flash |
| INV_CORE_013 | Extension callpoint valid | ext callpoint ∈ allowed | Validation on call | Extension |
| INV_CORE_014 | Slot0 atomicity | No intermediate states readable | Assembly atomic | State |
| INV_CORE_015 | Bitpacking consistency | No stale bits in packed slots | Pre-write clear | State |
| INV_CORE_020 | Pool solvency | totalCollateral ≥ totalDebt | Liquidation check | Solvency |

### LIQUIDATION INVARIANTS

| ID | Invariant | Formula / Constraint | Enforcement | Category |
|----|-----------|---------------------|-------------|----------|
| INV_LIQ_001 | Liquidation triggers insolvency | isSolvent(posId) == false ⇒ canLiquidate(posId) == true | Guard | Liquidation |
| INV_LIQ_002 | Debt shares consistency | debtShares > 0 ⇔ debtValue > 0 | Avoid zero-debt | Debt |
| INV_LIQ_003 | Liquidation reduces debt | totalDebt(after) < totalDebt(before) | Post-liquidation check | Liquidation |
| INV_LIQ_004 | Liquidation resets shares | positions[posId].debtShares == 0 after | Clean liquidation | Liquidation |
| INV_LIQ_005 | Collateral seized fairly | seizedAmount ≈ debtRepaid + discount | Repayment validation | Liquidation |
| INV_LIQ_006 | Liquidation discount bounded | 0 ≤ liquidationDiscount ≤ MAX_DISCOUNT | Bounded incentive | Liquidation |
| INV_LIQ_007 | Flash debt cleared after liquidation | After liquidate in flash: tmpDebt == 0 | Ephemeral debt constraint | Flash |
| INV_LIQ_008 | Solvency improvement | solvency(after) ≥ solvency(before) | Liquidations improve health | Solvency |
| INV_LIQ_009 | No cascade from liquidation | Liquidation of posA ≠> posB liquidation (if posB solvency unaffected) | Isolation | Liquidation |
| INV_LIQ_010 | Tick consistency | Liquidation uses same tick as swap during liquidation | No stale price | Oracle |

### CROSS-CUTTING INVARIANTS

| ID | Invariant | Formula / Constraint | Enforcement | Category |
|----|-----------|---------------------|-------------|----------|
| INV_XCUT_001 | Extension callpoint validity | ext ∈ registered ⇒ callpoint ∈ bitmask | Before ext call | Extension |
| INV_XCUT_002 | Core-TWAMM accumulated price alignment | coreAccum ~= twammAccum ± tolerance | After settlement | Oracle |
| INV_XCUT_003 | Oracle price bounds | minPrice ≤ oraclePrice ≤ maxPrice | Liquidation entry | Oracle |
| INV_XCUT_004 | TWAP staleness limit | now - lastTWAPUpdate ≤ MAX_STALENESS | Liquidation entry | Oracle |
| INV_XCUT_005 | Extension code hash match | codeHashBefore == codeHashAfter | Extension callback | Extension |
| INV_XCUT_006 | Storage slot isolation | ext slots ≠ core slots | Ext deployment | State |
| INV_XCUT_007 | Reentrancy guard atomic | locked transitions 0→1→0 atomically | Guarded function | Reentrancy |
| INV_XCUT_008 | State snapshot consistency | snapshot(before_ext) ≈ snapshot(after_ext) [bounds] | Ext completion | State |
| INV_XCUT_009 | Bitpacked state cleaned | All high bits cleared before pack | Bit write | State |
| INV_XCUT_010 | TickMap committed after crossing | TickMap update persists across ext calls | Post-crossing | Tick Math |
| INV_XCUT_011 | TempDebt ephemeral | tmpDebt == 0 after flashBorrow callback | Flash end | Flash |
| INV_XCUT_012 | Callpoint isolation | Calling ext via callpoint A ≠> callpoint B invoked | Ext invocation | Extension |
| INV_XCUT_013 | Price consistency | core_price ≈ twamp_price ± max_deviation | Liquidation calc | Oracle |
| INV_XCUT_014 | Extension context clarity | msg.sender == core (call) OR msg.sender == caller (delegatecall) | Ext execution | Extension |
| INV_XCUT_015 | Core-slot0 tick post-update | slot0.tick == computedTick after swap | Swap completion | Tick Math |

---

## 14. TEST SUITE & FOUNDRY SKELETONS

### Test Folder Structure

```
tests/
├── core/
│   ├── test_core_invariants.sol
│   ├── test_tick_math.sol
│   ├── test_debt_accounting.sol
│   ├── test_flash_accounting.sol
│   ├── test_extension_callpoint.sol
│   └── test_assembly_safety.sol
├── liquidation/
│   ├── test_health_factor.sol
│   ├── test_debt_solvency.sol
│   ├── test_liquidation_mechanics.sol
│   ├── test_flash_liquidation.sol
│   ├── test_liquidation_attacks.sol
│   └── test_liquidation_invariants.sol
├── crosscut/
│   ├── test_oracle_models.sol
│   ├── test_twamm_desync.sol
│   ├── test_extension_layout.sol
│   ├── test_reentrancy_boundaries.sol
│   ├── test_cross_module_desync.sol
│   ├── test_extension_attacks.sol
│   └── test_state_checkpoints.sol
└── fuzz/
    ├── test_liquidity_fuzz.sol
    ├── test_tick_crossing_fuzz.sol
    ├── test_debt_share_fuzz.sol
    └── test_oracle_fuzz.sol
```

### CORE_TEST_001: Tick Overflow Fuzz

```solidity
pragma solidity ^0.8.0;
import "foundry/Test.sol";
import "../src/EUKUBOCore.sol";

contract TestTickOverflowFuzz is Test {
    EUKUBOCore core;
    
    function setUp() public {
        core = new EUKUBOCore();
        core.initialize();
    }
    
    function testTickOverflowFuzz(int24 tick1, int24 tick2) public {
        tick1 = int24(bound(int256(tick1), -887272, 887272));
        tick2 = int24(bound(int256(tick2), -887272, 887272));
        
        core.setCurrentTick(tick1);
        int24 nextTick = _findNextTick(tick1, tick2);
        
        assert(nextTick >= -887272 && nextTick <= 887272);
    }
    
    function testLiquidityDeltaUnderflowFuzz(uint96 liq, uint96 delta) public {
        liq = uint96(bound(uint256(liq), 1, type(uint96).max));
        delta = uint96(bound(uint256(delta), liq + 1, type(uint96).max));
        
        vm.expectRevert();
        core.subtractLiquidity(liq, delta);
    }
}
```

### CORE_TEST_002: FlashAccountant Temp-Debt Misuse

```solidity
contract TestFlashAccountantTempDebt is Test {
    EUKUBOCore core;
    MockToken token;
    MaliciousFlashBorrower malBorrower;
    
    function setUp() public {
        core = new EUKUBOCore();
        token = new MockToken();
        malBorrower = new MaliciousFlashBorrower(address(core), address(token));
        core.initialize(address(token));
        token.mint(address(core), 1e24);
    }
    
    function testFlashTempDebtMustClearAfterCallback() public {
        uint256 borrowAmount = 1000e18;
        core.flashBorrow(borrowAmount, abi.encode(0));
        assert(core.flashState().tmpDebt == 0);
    }
    
    function testFlashTempDebtNotClearedReverts() public {
        uint256 borrowAmount = 1000e18;
        vm.expectRevert("FLASH_DEBT_NOT_REPAID");
        core.flashBorrow(borrowAmount, abi.encode(address(malBorrower)));
    }
    
    function testFlashStateRaceCondition() public {
        vm.expectRevert("RECURSIVE_FLASH");
        malBorrower.nestedFlash(1000e18);
    }
}
```

### CORE_TEST_003: Extension Desync Reproduction

```solidity
contract TestExtensionDesync is Test {
    EUKUBOCore core;
    DesyncingExtension badExt;
    
    function setUp() public {
        core = new EUKUBOCore();
        badExt = new DesyncingExtension(address(core));
        core.registerExtension(address(badExt), CALLPOINT_SWAP);
    }
    
    function testExtensionStateDesyncDuringCallback() public {
        (uint24 tickBefore, uint96 liqBefore, ) = core.slot0();
        
        core.swap(100e18, abi.encode(address(badExt)));
        
        (uint24 tickAfter, uint96 liqAfter, ) = core.slot0();
        
        assert(tickAfter > tickBefore);
        assert(liqAfter >= 0);
    }
}
```

### CORE_TEST_004: Bitpacked-State Corruption Reproduction

```solidity
contract TestBitpackingCorruption is Test {
    EUKUBOCore core;
    CorruptingExtension malExt;
    
    function setUp() public {
        core = new EUKUBOCore();
        malExt = new CorruptingExtension(address(core));
        core.registerExtension(address(malExt), CALLPOINT_SWAP);
    }
    
    function testBitpackingStaleReadWriteBack() public {
        uint256 slot0 = encodeSlot0(int24(100), uint96(1e18), uint96(1e6));
        core.setSlot0(slot0);
        
        core.swap(1000e18, abi.encode(address(malExt)));
        
        (int24 tick, uint96 liq, uint96 fees) = core.decodeSlot0();
        
        assert(tick >= -887272 && tick <= 887272);
        assert(liq > 0 && liq <= type(uint96).max);
    }
}
```

### CORE_TEST_005: Debt Rounding Exploit in Liquidation

```solidity
contract TestLiquidationRoundingExploit is Test {
    EUKUBOCore core;
    
    function setUp() public {
        core = new EUKUBOCore();
        core.initialize();
    }
    
    function testLiquidationRoundingCanMakeUnliquidatable() public {
        uint256 posId = core.openPosition(borrower, 1000e18, 1e18);
        
        core.setDebtShares(posId, 1e18);
        core.setTotalDebtShares(3e18);
        core.setTotalDebt(3e18 - 1);
        
        uint256 collateralValue = 1e18;
        uint256 debtValue = core.getDebtValue(posId);
        
        assert(debtValue < collateralValue);
        assert(!core.canLiquidate(posId));
    }
}
```

### CORE_TEST_006: Extension Upgrade Callpoint Mismatch

```solidity
contract TestExtensionUpgradeCallpointMismatch is Test {
    EUKUBOCore core;
    
    function setUp() public {
        core = new EUKUBOCore();
    }
    
    function testExtensionUpgradeViaSelfDestructRedeploy() public {
        SafeExtensionV1 extV1 = new SafeExtensionV1();
        core.registerExtension(address(extV1), CALLPOINT_SWAP);
        
        address extAddr = address(extV1);
        
        uint256 balBefore = core.poolBalance();
        core.swap(100e18, abi.encode(extAddr));
        uint256 balAfter = core.poolBalance();
        assert(balAfter >= balBefore);
        
        extV1.selfDestruct();
        
        MaliciousExtensionV2 extV2 = new MaliciousExtensionV2{salt: keccak256("salt")}();
        assert(address(extV2) == extAddr);
        
        balBefore = core.poolBalance();
        core.swap(100e18, abi.encode(address(extV2)));
        balAfter = core.poolBalance();
        
        assert(balAfter < balBefore);
    }
}
```

### LIQ_TEST_001: Stale Tick Liquidation Bypass

```solidity
contract TestStaleTick_LiquidationBypass is Test {
    EUKUBOCore core;
    MockToken collateral;
    
    function setUp() public {
        core = new EUKUBOCore();
        collateral = new MockToken();
        core.initialize(address(collateral));
    }
    
    function testLiquidation_StaleTickAllowsEvasion() public {
        uint256 posId = core.openPosition(borrower, 1000e18, 950e18);
        
        core.setTickPrice(0);
        assertTrue(core.isSolvent(posId));
        
        (int24 tickBefore, , ) = core.decodeSlot0();
        
        core.swap(5000e18, abi.encode(liquidationExtension, posId));
        
        (uint96 debtShares, , ) = core.positions(posId);
        assertGt(debtShares, 0);
    }
}
```

### LIQ_TEST_002: Debt Inflation & Liquidation

```solidity
contract TestDebtInflation_Liquidation is Test {
    EUKUBOCore core;
    
    function setUp() public {
        core = new EUKUBOCore();
        core.initialize();
    }
    
    function testDebtInflation_UnliquidatablePosition() public {
        core.setTotalDebt(10e18);
        core.setTotalDebtShares(3e18);
        
        uint256 posId = core.openPosition(attacker, 100e18, 0);
        
        uint256 borrowAmount = 1;
        core.borrowAgainstCollateral(posId, borrowAmount);
        
        uint256 debtValue = core.getDebtValue(posId);
        assertEq(debtValue, 0);
        
        core.setPriceMultiplier(0.5e18);
        
        vm.expectRevert();
        core.liquidate(posId);
    }
}
```

### LIQ_TEST_003: Flash-Liquidation Reentrancy Boundary

```solidity
contract TestFlashLiquidation_Reentrancy is Test {
    EUKUBOCore core;
    
    function setUp() public {
        core = new EUKUBOCore();
        core.initialize();
    }
    
    function testFlashLiquidation_ReentrancyBoundary() public {
        uint256 posA = core.openPosition(userA, 500e18, 400e18);
        uint256 posB = core.openPosition(userB, 500e18, 400e18);
        
        uint256 flashAmount = 200e18;
        
        vm.prank(attacker);
        core.flashBorrow(flashAmount, abi.encode(
            address(liquidationCallback),
            posA
        ));
        
        (uint96 debtSharesA, , ) = core.positions(posA);
        assertGt(debtSharesA, 0);
    }
}
```

### XCUT_TEST_001: TWAMM Desync Reproduction

```solidity
contract TestTWAMM_Desync is Test {
    EUKUBOCore core;
    TWAMMExtension twamm;
    
    function setUp() public {
        core = new EUKUBOCore();
        twamm = new TWAMMExtension(address(core));
        core.registerExtension(address(twamm), CALLPOINT_SWAP | CALLPOINT_SETTLEMENT);
    }
    
    function testTWAMM_AccumulatedPriceDiverges() public {
        uint256 scheduleAmount = 1000e18;
        twamm.scheduleSwap(scheduleAmount, 1 hours);
        
        uint256 corePrice = core.getCurrentPrice();
        
        uint256 coreAccum = core.getAccumulatedPrice();
        uint256 twammAccum = twamm.getAccumulatedPrice();
        assertEq(coreAccum, twammAccum);
        
        vm.warp(block.timestamp + 30 minutes);
        twamm.settleScheduledOrders();
        
        coreAccum = core.getAccumulatedPrice();
        twammAccum = twamm.getAccumulatedPrice();
        
        if (coreAccum != twammAccum) {
            assertGt(abs(int256(coreAccum - twammAccum)), 0);
        }
    }
}
```

### XCUT_TEST_002: Bitpacking Invariant Test

```solidity
contract TestBitpackingInvariant_Extension is Test {
    EUKUBOCore core;
    
    function setUp() public {
        core = new EUKUBOCore();
    }
    
    function testBitpacking_HighBitsLeak() public {
        uint256 slot0 = encodeSlot0(int24(100), uint96(1e18), uint96(1e6));
        core.setSlot0(slot0);
        
        address malExt = address(new DelegateCallExtension(address(core)));
        core.registerExtension(malExt, CALLPOINT_SWAP);
        
        core.swap(1000e18, abi.encode(malExt));
        
        uint256 slot0After = core.getSlot0();
        (int24 tick, uint96 liq, uint96 fees) = decodeSlot0(slot0After);
        
        uint256 extraBits = slot0After >> 256;
        assertEq(extraBits, 0);
        
        assert(tick >= -887272 && tick <= 887272);
        assert(liq >= 0);
        assert(fees >= 0);
    }
}
```

### XCUT_TEST_003: Extension Callpoint Mismatch Test

```solidity
contract TestExtensionCallpointMismatch is Test {
    EUKUBOCore core;
    
    function setUp() public {
        core = new EUKUBOCore();
    }
    
    function testCallpointMismatchPrevention() public {
        address ext = address(new LimitedExtension());
        uint256 allowedCallpoints = CALLPOINT_SWAP;
        core.registerExtension(ext, allowedCallpoints);
        
        vm.expectRevert("CALLPOINT_FORBIDDEN");
        core._callExtensionIfAllowed(ext, CALLPOINT_LIQUIDATE, "");
        
        core._callExtensionIfAllowed(ext, CALLPOINT_SWAP, "");
    }
}
```


---

## ATTACK REFERENCE MATRIX

| Attack ID | Pattern Name | Severity | Category | Broken Invariants | Test | Module |
|-----------|--------------|----------|----------|-------------------|------|--------|
| CORE_001 | Delta Rounding Liquidation Bypass | CRITICAL | Accounting | INV_LIQ_001, INV_LIQ_002 | CORE_TEST_005 | Core |
| CORE_002 | FlashAccountant Cleanup Failure | CRITICAL | Flash | INV_CORE_010, INV_CORE_011 | CORE_TEST_002 | Core |
| CORE_003 | Extension-Induced Solvency Drift | CRITICAL | Extension | INV_CORE_020, INV_LIQ_003 | CORE_TEST_003 | Core |
| CORE_004 | Tick Crossing Liquidity Overflow | HIGH | Tick Math | INV_CORE_001, INV_CORE_002 | CORE_TEST_001 | Core |
| CORE_005 | Bitpacking Corruption via Stale Reads | CRITICAL | Assembly | INV_CORE_014, INV_CORE_015 | CORE_TEST_004 | Core |
| CORE_006 | Callpoint Mismatch via Extension Upgrade | HIGH | Extension | INV_XCUT_005, INV_XCUT_001 | CORE_TEST_006 | Core |
| LIQ_001 | Stale Tick Liquidation Bypass | CRITICAL | Oracle | INV_LIQ_001, INV_XCUT_015 | LIQ_TEST_001 | Liquidation |
| LIQ_002 | Debt-Share Inflation via Rounding | HIGH | Debt | INV_LIQ_002, INV_CORE_003 | LIQ_TEST_002 | Liquidation |
| LIQ_003 | TempDebt Double-Count Exploit | CRITICAL | Flash | INV_LIQ_007, INV_CORE_010 | LIQ_TEST_003 | Liquidation |
| LIQ_004 | Invalid Solvency Extension Cleanup | CRITICAL | Extension | INV_LIQ_003, INV_CORE_020 | LIQ_TEST_003 | Liquidation |
| LIQ_005 | Tick Boundary Liquidation | MEDIUM | Tick | INV_LIQ_006 | LIQ_TEST_001 | Liquidation |
| LIQ_006 | Delta-Rounding Liquidation Impossible | CRITICAL | Accounting | INV_LIQ_001, INV_LIQ_004 | LIQ_TEST_002 | Liquidation |
| XCUT_001 | Cross-Module Solvency Drift | CRITICAL | Extension | INV_XCUT_013 | XCUT_TEST_001 | Crosscut |
| XCUT_002 | Multi-Callpoint Reentrancy Bypass | CRITICAL | Reentrancy | INV_XCUT_007 | XCUT_TEST_004 | Crosscut |
| XCUT_003 | TWAMM Accumulated Price Desync | HIGH | Oracle | INV_XCUT_002, INV_XCUT_013 | XCUT_TEST_001 | Crosscut |
| XCUT_004 | Pseudo-Oracle Updates via Timing | MEDIUM | Oracle | INV_XCUT_003, INV_XCUT_004 | XCUT_TEST_001 | Crosscut |
| XCUT_005 | External Hook-Induced Corruption | HIGH | Composability | INV_LIQ_004, INV_XCUT_014 | XCUT_TEST_003 | Crosscut |

---

## QUICK REFERENCE: VULNERABILITY BY CATEGORY

### By Severity
**CRITICAL (11)**:
- CORE_001, CORE_002, CORE_003, CORE_005
- LIQ_001, LIQ_003, LIQ_004, LIQ_006
- XCUT_001, XCUT_002, XCUT_003

**HIGH (5)**:
- CORE_004, CORE_006
- LIQ_002
- XCUT_004, XCUT_005

**MEDIUM (1)**:
- LIQ_005

### By Category
**Accounting (4)**: CORE_001, LIQ_002, LIQ_006, CORE_002  
**Flash (4)**: CORE_002, LIQ_003, CORE_010, INV_CORE_011  
**Extension (5)**: CORE_003, CORE_006, LIQ_004, XCUT_001, XCUT_005  
**Oracle (4)**: LIQ_001, XCUT_003, XCUT_004, INV_XCUT_003  
**Reentrancy (1)**: XCUT_002  
**Tick Math (2)**: CORE_004, LIQ_005  
**Assembly (1)**: CORE_005  
**State (4)**: CORE_014, CORE_015, XCUT_008, XCUT_009  


## DETECTION HEURISTICS SUMMARY

### Monitoring Points
1. **Liquidation Entry**: Validate price freshness, solvency calculation consistency, extension state pre-check
2. **Extension Calls**: Monitor callpoint validity, code hash consistency, state mutations
3. **Flash Operations**: Track tmpDebt lifecycle, verify cleanup, monitor reentrancy guard
4. **Tick Crossing**: Alert on liquidity overflow, validate bit alignment, track tickMap mutations
5. **Oracle Access**: Monitor TWAP staleness, validate core-TWAMM alignment, track price jumps
6. **Reentrancy**: Track call depth, validate state snapshots, monitor locked flag transitions

### Red Flags
- Liquidation fails with "NO_DEBT" but position is insolvent
- Position has debtShares > 0 but debtValue == 0 (rounds to 0)
- Solvency improves during liquidation without legitimate action
- Slot0.tick decreases after swap (should be monotonic)
- TWAP diverges from spot price by >threshold
- Extension called with different callpoint than registered
- tmpDebt non-zero after flashBorrow callback
- Storage layout collision between core and extension


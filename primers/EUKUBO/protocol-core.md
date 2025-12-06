# EUKUBO Core Auditing Primer
## Singleton-Core AMM Security Architecture

---

## TABLE OF CONTENTS
1. Architecture Fingerprint
2. Tick & Liquidity Math
3. Accounting & Debt Mechanics
4. Extension System & Callpoint Validation
5. Assembly-Level State Access
6. Core Attack Catalog
7. Core Invariants & Formulas
8. Test Cases & Foundry Skeletons

---

## 1. ARCHITECTURE FINGERPRINT

### 1.1 Singleton Core Model

EUKUBO is built on a **singleton-core pattern** where a single core contract:
- **Owns all state** (slot0, tickMap, positionMap, flashState)
- **Delegates privileged operations** to registered extension contracts
- **Maintains strict reentrancy barriers** through callpoint validation
- **Enforces atomic state transitions** via assembly-heavy accounting

The core contract signature pattern:

```solidity
// Pseudo-layout
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

To optimize gas, EUKUBO uses assembly for critical paths:

```solidity
assembly {
    // Direct slot0 read bypasses Solidity type checking
    let packedSlot := sload(slot0.slot)
    
    // Bitpacking extractions (unsafe if not carefully masked)
    let tick := shr(200, packedSlot) // assumes tick at bits [200:256]
    let liquidity := and(packedSlot, 0xFFFFFFFFFFFFFFFFFFFFFFFF) // bits [0:96]
}
```

**Critical Risk**: Assembly reads **do not auto-unpack bitmasks**. If bit boundaries are miscalculated or stale data is read before a write, corruption spreads silently.

### 1.3 Bitpacking & Bit-Cleaning Assumptions

EUKUBO packs multiple values into single storage slots for efficiency:

| Field | Bits | Mask | Notes |
|-------|------|------|-------|
| `tick` | 24 | `0xFF0000` | Signed int24; must be cleaned before repack |
| `liquidity` | 96 | `0xFFFFFFFFFFFFFFFFFFFFFFFF` | Must validate >= 0 |
| `feeGrowth` | 96 | `0xFFFFFFFFFFFFFFFFFFFFFFFF` | Grows monotonically |
| `locked` | 8 | `0xFF` | Reentrancy guard; must be atomic |

**Bit-Cleaning Failure Pattern**:
```solidity
// VULNERABLE: Stale bits from prior value leak
uint256 newSlot0 = (tick << 200) | (liq << 96) | fees;
// If tick was not masked: (oldBits << 200) corrupts new value

// CORRECT: Explicit clearing
uint256 newSlot0 = (tick & 0xFFFFFF) << 200 | (liq & LIQUIDITY_MASK) << 96 | ...;
```

### 1.4 Extension System with Callpoint Validation

Extensions register with a **callpoint bitmask** to limit entry vectors:

```solidity
enum CallPoint {
    SWAP = 1,
    ADD_LIQ = 2,
    REMOVE_LIQ = 4,
    FLASH = 8,
    TWAMM_SCHEDULE = 16,
    LIQUIDATE = 32
}

// In core, before calling extension:
function _validateExtensionCallpoint(address ext, uint8 cp) internal view {
    uint256 allowed = extensionCallpoints[ext];
    require(allowed & (1 << cp) != 0, "CALLPOINT_FORBIDDEN");
}
```

**Problem**: If an extension is upgraded (self-destruct + redeploy) or a callpoint bitmask is corrupted, **wrong functions execute silently**.

### 1.5 Core → Extension → Core Recursion Model

EUKUBO allows controlled extensions to call back into core:

```
[Core.swap()] 
  → [_call(extension, data)]  // validate callpoint
     → [Extension.onSwap()] 
        → [Core.state()] (READ-ONLY, allowed)
        → [Core._balanceUpdate()] (guarded by callpoint)
           → [Extension.onBalanceChange()] ⚠️ DANGEROUS
              → [Core.state()] again (stale if not snapshot'd)
```

The **call stack depth** and **state snapshot consistency** are auditor concerns. A stale read of slot0 after an extension call could use an outdated tick.

### 1.6 Custom FlashAccountant for Ephemeral Debt

Instead of a separate contract, EUKUBO embeds flash accounting in the core:

```solidity
struct FlashAccountantState {
    uint256 tmpDebt;        // Temporary debt, must be 0 after flash ends
    bool inFlashCallback;   // Reentrancy guard
    address tmpCaller;      // Who called flash; used to validate repayment callback
}

function flashBorrow(uint256 amount, bytes calldata data) external {
    require(!flashState.inFlashCallback, "RECURSIVE_FLASH");
    flashState.inFlashCallback = true;
    flashState.tmpDebt = amount;
    flashState.tmpCaller = msg.sender;
    
    _transfer(msg.sender, amount); // unsecured
    
    IFlashBorrower(msg.sender).onFlashBorrow(amount, data);
    
    require(flashState.tmpDebt == 0, "FLASH_DEBT_NOT_REPAID");
    flashState.inFlashCallback = false;
}

function flashRepay(uint256 amount) external {
    require(flashState.inFlashCallback, "NOT_IN_FLASH");
    require(msg.sender == flashState.tmpCaller, "WRONG_REPAYER");
    flashState.tmpDebt -= amount; // underflow risk if caller is malicious
}
```

**Critical Issue**: If `tmpDebt` is not atomically cleared or if `tmpCaller` is spoofed, the flash loan escapes.

### 1.7 Storage Slot Maps

| Variable | Slot | Purpose | Bitpacking Details |
|----------|------|---------|-------------------|
| `slot0` | 0 | Core state snapshot | tick (bits 200-223), liq (bits 0-95), fees (bits 96-191) |
| `tickMap` | keccak256(abi.encode(1, tick >> 8)) | Bitmap to find initialized ticks | One bit per tick; see Tick Crossing |
| `positionMap` | keccak256(abi.encode(2, owner, id)) | Per-position accounting | liquidity, tickLower, tickUpper, feeOwed |
| `flashState` | 3 | Ephemeral flash debt | tmpDebt, inFlashCallback, tmpCaller |
| `extensionRegistry` | keccak256(abi.encode(4, extAddr)) | Extension permissions | Bitmask of allowed callpoints |

---

## 2. TICK & LIQUIDITY MATH

### 2.1 Tick Representation & Overflow Conditions

Ticks in EUKUBO use **int24** (not int256), allowing \(2^{23} - 1 \approx 8.4M\) distinct ticks.

```solidity
// Tick boundaries
int24 constant MIN_TICK = -887272;  // ~0.0001 in price space
int24 constant MAX_TICK = 887272;   // ~10000 in price space

// Tick-to-price formula (pseudo):
// price = 1.0001^tick
```

**Overflow Attack #1: Tick Saturation**
```solidity
// If tick arithmetic overflows int24 silently due to assembly:
int24 tick = 887272;
int24 newTick = tick + 1;  // int24(887273) == -887272 in two's complement!

// In assembly (no overflow check):
uint256 newTick := add(tick, 1)  // Results in 887273 without int24 cast
```

**Overflow Attack #2: Liquidity Delta Underflow**
```solidity
uint96 liquidity = 1;
uint96 delta = 2;

// If using unchecked arithmetic:
uint96 newLiq = liquidity - delta;  // wraps to MAX_UINT96 - 1 (silently!)

// Correct pattern:
require(liquidity >= delta, "LIQ_UNDERFLOW");
```

### 2.2 Liquidity Deltas Under Extreme Swaps

During a single large swap, liquidity can change in ticks as the price crosses boundaries:

```solidity
// Pseudo-code for swap loop
uint96 cumLiquidity = 0;
for each tick crossed {
    uint96 tickLiquidity = tickState[tick].liquidityNet;
    if (tickLiquidity > LIQUIDITY_MAX - cumLiquidity) {
        // Overflow! Attacker triggers tick saturation
        revert("LIQUIDITY_OVERFLOW");
    }
    cumLiquidity += tickLiquidity;
    slot0.liquidity = cumLiquidity;  // stored without overflow check
}
```

**Attack**: If assembly writes to slot0 without checking cumLiquidity, the stored value wraps silently.

### 2.3 Delta Rounding Attack Templates

When converting real-number price deltas to integer amounts, rounding is a vector:

```solidity
// Amount out calculation for swap
uint256 amountOut = (sqrtPriceX96After - sqrtPriceBefore) * liquidity / sqrtPriceX96After;

// Attacker exploits rounding-down to cause:
// 1. Retain excess dust in pool (accrue to attacker's next swap)
// 2. Cause liquidation to underflow (liquidation amount rounds to 0)
// 3. Manipulate fee accrual (rounding-up fees compounds over time)
```

**Concrete Example: Liquidation Rounding**
```solidity
uint256 debtToRepay = position.debt;
uint256 collateralAmount = (debtToRepay * price) / SCALE;

// Attacker crafts position.debt such that:
// (debtToRepay * price) % SCALE is very small
// → collateralAmount rounds down heavily
// → Liquidation executes but collateral seized < debt repaid
```

### 2.4 Tick Crossing Invariants

When a swap moves the pool price across a tick boundary, the core MUST:
1. Read the tick's `liquidityNet` from storage
2. Update cumulative liquidity
3. Emit event
4. Update slot0.tick

**Invariant**: After each tick crossing, the in-memory liquidity and slot0.liquidity **must match**.

```solidity
// VULNERABLE pattern:
uint96 liqStart = slot0.liquidity;
_crossTick(nextTick);  // reads tickState, updates liqStart in-memory
slot0 = PackedSlot(..., liqStart);  // writes updated value

// If _crossTick reenter via extension:
//   → reads stale slot0.liquidity (snapshot from before _crossTick)
//   → writes stale value back
//   → subsequent swaps use corrupted liquidity
```

### 2.5 Solvency Invariants for Liquidity Updates

For a lending pool backing EUKUBO (if integrated), **solvency** is:

```
Solvency = (Total Collateral Value) - (Total Debt)

During a liquidity update:
New Solvency = Old Solvency + (delta liquidity * price) - (fee accrual)
```

An attacker can trigger a liquidity change that violates solvency:

```solidity
// Attack: craft swap that crosses many ticks, inflating liquidity
// → Position holder borrows more (solvency check fails but is stale)
// → Pool becomes under-collateralized
```

### 2.6 Liquidity += Delta vs. Liquidity = Liquidity + Delta

In assembly, the distinction matters:

```solidity
// Pattern 1: SAFE (if atomic)
assembly {
    let oldLiq := sload(slot0.slot)
    let newLiq := add(oldLiq, delta)
    sstore(slot0.slot, newLiq)
}

// Pattern 2: UNSAFE (allows read-modify-write between reads)
uint96 liq = slot0.liquidity;
liq = liq + delta;
slot0 = _packSlot0(..., liq);
```

If an extension call or another transaction writes to slot0 between the read and write in Pattern 2, the delta is lost or compounded incorrectly.

---

## 3. ACCOUNTING & DEBT MECHANICS

### 3.1 Debt Mis-accounting

Debt can be tracked per-position or globally. EUKUBO likely uses **per-position debt shares**:

```solidity
struct Position {
    uint96 liquidity;
    uint96 debtShares;  // position's share of total pool debt
    int256 feesOwed;    // accumulated fees
}

// Global tracking:
uint96 totalDebtShares;
uint256 totalDebt;  // actual stablecoin outstanding
```

**Vulnerability: Debt Share Inflation via Rounding**
```solidity
// When borrower deposits collateral:
uint96 sharesToMint = (collateralValue * totalDebtShares) / totalDebt;

// Attacker crafts collateralValue such that:
// (collateralValue * totalDebtShares) % totalDebt == 0
// → sharesToMint rounds to 0, but attacker gains collateral

// Or conversely, craft to round UP:
// → sharesToMint > actualDebtAdded
// → Attacker's share becomes oversized
```

### 3.2 FlashAccountant Temp-Debt Lifecycle

The flashState.tmpDebt is meant to be ephemeral:

```
1. Flash borrow called: tmpDebt = amount, inFlash = true, tmpCaller = caller
2. Borrower receives funds
3. Borrower calls onFlashBorrow hook
4. Borrower must repay: tmpDebt -= repayAmount
5. After callback: require(tmpDebt == 0)
6. inFlash = false
```

**Vulnerability: Cleanup → Rollback Gap**

If between step 5 and 6 an extension is called that reads `flashState`, it sees `inFlash = true` but `tmpDebt = 0`. The extension could:
- Trigger another flashBorrow (if reentrancy is possible)
- Perform actions assuming flash is still active
- Later, the outer flashBorrow's check fails or passes incorrectly

```solidity
// VULNERABLE sequence:
function flashBorrow(uint256 amt) {
    require(!inFlash, "no reentrance");
    inFlash = true;
    tmpDebt = amt;
    _transfer(caller, amt);
    IFlashBorrower(caller).onFlash(...);
    
    // ⚠️ If onFlash calls extension, extension reads:
    // inFlash = true, tmpDebt = amt (still set)
    // But if extension calls back into core (allowed by callpoint):
    //   → might perform flash-only operations
    
    require(tmpDebt == 0, "not repaid");  // passes or fails based on race
    inFlash = false;
}
```

### 3.3 Extension-Induced Debt Desync

If an extension has a bug or is malicious, it can:
1. Call core._updateDebt(amount) multiple times
2. Each call increments totalDebt, but tmpDebt is not updated
3. After flash ends, tmpDebt != actualRepayment

```solidity
// In extension (malicious):
function onFlashBorrow(uint256 amt, bytes calldata data) {
    IEUKUBOCore(core).updateDebt(amt);  // not flashRepay!
    IEUKUBOCore(core).updateDebt(amt);  // called twice!
    // Now totalDebt += 2*amt, but tmpDebt still = amt
}

// Core's flashBorrow check:
require(tmpDebt == 0, "not repaid");  // FAILS, correctly
// But if core naively checks only balance:
require(balanceOf(core) >= originalBalance + fees);  // PASSES (attacker repaid balance)
// → Debt is now 2*amt in core state, but market thinks it's amt
```

---

## 4. EXTENSION SYSTEM & CALLPOINT VALIDATION

### 4.1 Unvalidated Callpoints

If an extension is registered with callpoint bitmask `0xFF` (all bits), it can invoke any core function:

```solidity
// In core:
function registerExtension(address ext, uint256 callpointMask) external onlyOwner {
    extensionCallpoints[ext] = callpointMask;  // ⚠️ No validation of mask
}

// Attacker (or compromised owner):
registerExtension(maliciousExt, 0xFFFFFFFFFFFFFFFFFFFFFFFF);

// maliciousExt can now call:
// - swap() (SWAP callpoint)
// - addLiquidity() (ADD_LIQ)
// - liquidate() (LIQUIDATE)
// - flashBorrow() (FLASH)
// All in a single transaction, breaking isolation assumptions
```

### 4.2 Callpoint Mismatch (Wrong Extension Invoked)

If two extensions both have SWAP callpoint enabled, and they use the same function signature but different logic:

```solidity
// Extension A: "SwapA"
function onSwap(uint256 amountIn, bytes calldata data) external {
    // Only allows swaps of token A -> token B
}

// Extension B: "SwapB"
function onSwap(uint256 amountIn, bytes calldata data) external {
    // Allows ANY token pair
}

// In core, callpoint lookup uses extensionCallpoints[msg.sender]
// But if both A and B are registered with same callpoint:
// → Core might call the wrong extension's onSwap
// → Or extension A might masquerade as B's signature
```

### 4.3 Extension → Core State Drift

An extension can read slot0, trigger logic based on it, but if another extension runs concurrently (in another transaction), slot0 changes:

```solidity
// Tx 1: Extension A
- Reads slot0 (tick = 100, liq = 1000)
- Computes swap output
- Calls Core.swap()
  → Tick moves to 105, liq changes
  → Extension A's computation was based on stale state

// Tx 2: Extension B (executed before Tx 1 is included)
- Modifies pool state
```

In a **non-atomic system**, this is expected. But if Extension A assumes atomicity and checks a post-condition that's now false, it can revert, leaving partial state updates.

### 4.4 Assembly Copy/Memcopy Bug Surfaces

If an extension uses assembly to copy state snapshots:

```solidity
// In extension, assembly copy:
assembly {
    let ptr := 0x00
    let size := 0x40  // copy 64 bytes
    memmove(ptr, slotAddr, size)  // ⚠️ assumes slotAddr is valid
}
```

If `slotAddr` points to unitialized or reserved memory, the copy corrupts subsequent operations.

### 4.5 Incorrect Context Propagation (msg.sender, _caller, _origin)

Extensions receive context from core. If core doesn't pass the original caller:

```solidity
// Core:
function swap(...) external {
    _callExtension(extensionA, SWAP, abi.encode(...));
}

// _callExtension:
function _callExtension(address ext, uint8 cp, bytes calldata data) internal {
    // ⚠️ Missing context: who is ext acting for?
    // ext's msg.sender = address(this) (core)
    // ext doesn't know original user
    (bool ok, bytes memory result) = ext.delegatecall(data);
}

// If delegatecall is used, ext gains core's state access.
// If low-level call is used, ext doesn't know caller.
// Both are risky!
```

---

## 5. ASSEMBLY-LEVEL STATE ACCESS

### 5.1 Unsafe sload / sstore Patterns

```solidity
assembly {
    // Direct slot load without bounds checking
    let value := sload(0)
    
    // Stale read if slot is modified by another tx
    let price := sload(priceSlot)
    
    // Write without consistency check
    sstore(slot0, newValue)
    // No validation that newValue is consistent with rest of slot0
}
```

### 5.2 Bitshift Misalignment

```solidity
// VULNERABLE: Assumes bits are at a specific location
assembly {
    let tick := shr(200, sload(slot0Addr))  // extract bits 200-223
    // But if previous write shifted bits differently, corruption
}

// CORRECT: Mask first, then shift
assembly {
    let raw := sload(slot0Addr)
    let tickMask := 0xFFFFFF
    let tick := shr(200, and(raw, shl(200, tickMask)))
}
```

### 5.3 Reentrancy in Assembly Context

When assembly is used inside a function that calls an extension:

```solidity
function swap(...) external {
    assembly {
        let slot0Val := sload(slot0.slot)
        // ... modify slot0Val in-memory ...
        sstore(slot0.slot, newSlot0Val)
    }
    
    _callExtension(...);  // ⚠️ Extension can call back into swap
    
    // At this point, slot0 might be stale!
    // Next assembly block reads corrupted data
}
```

---

## 6. CORE ATTACK CATALOG

### ATTACK #1: Delta Rounding Liquidation Bypass

**Severity**: CRITICAL  
**Category**: Accounting

**Description**:
An attacker borrows near the liquidation threshold, then exploits rounding in the liquidation function to avoid liquidation.

**Vulnerability**:
```solidity
function canLiquidate(uint256 posId) public view returns (bool) {
    Position storage pos = positions[posId];
    uint256 collateralValue = getCollateralValue(pos);
    uint256 debtValue = (pos.debtShares * totalDebt) / totalDebtShares;
    
    // VULNERABLE: rounding-down in division
    return debtValue > collateralValue;
}
```

**Attack**:
1. Attacker borrows: `debtShares = 10^18, totalDebtShares = 3 * 10^18`
2. Price moves such that `totalDebt = 3 * 10^18 - 1` (rounding artifact)
3. Attacker's debtValue = `(10^18 * (3 * 10^18 - 1)) / (3 * 10^18)` = `10^18 - 1/3` → rounds down to `10^18 - 1`
4. Collateral value = `10^18` (exactly)
5. `canLiquidate` check: `10^18 - 1 > 10^18` = FALSE
6. Position is insolvent but not liquidatable

**Test Case**:
```foundry
function testDeltaRoundingLiquidationBypass() public {
    // Setup: 3 equal positions, each borrowing 1/3 of pool
    position1.debtShares = 1e18;
    position2.debtShares = 1e18;
    position3.debtShares = 1e18;
    core.totalDebtShares = 3e18;
    core.totalDebt = 3e18;
    
    // Price moves down slightly
    // Attacker positions portfolio: collateral barely covers debt
    uint256 collateral3 = 1e18;  // exact value
    
    // Adjust totalDebt to introduce rounding artifact
    // _depositToPool in external contract decreases totalDebt by 1
    core.totalDebt = 3e18 - 1;
    
    // Now attacker's debt = (1e18 * (3e18 - 1)) / 3e18 = ~9.999...e17
    // Rounds down to 9.999...e17 < 1e18 (collateral)
    
    bool canLiq = core.canLiquidate(position3Id);
    assertFalse(canLiq);  // Should be TRUE but rounds FALSE
    assertGt(core.getDebtValue(position3Id), collateral3);
}
```

---

### ATTACK #2: Debt Mis-accounting via FlashAccountant Cleanup Failure

**Severity**: CRITICAL  
**Category**: Flash Accounting

**Description**:
Attacker exploits the FlashAccountant cleanup gap to escape flash loan repayment.

**Vulnerability**:
```solidity
function flashBorrow(uint256 amount, bytes calldata data) external {
    require(!flashState.inFlashCallback, "RECURSIVE_FLASH");
    flashState.inFlashCallback = true;
    flashState.tmpDebt = amount;
    flashState.tmpCaller = msg.sender;
    
    _transfer(msg.sender, amount);
    IFlashBorrower(msg.sender).onFlashBorrow(amount, data);
    
    // ⚠️ GAP: If tmpDebt is decremented by another path (not flashRepay),
    // the check passes even if funds aren't repaid
    require(flashState.tmpDebt == 0, "FLASH_DEBT_NOT_REPAID");
    flashState.inFlashCallback = false;
}
```

**Attack**:
1. Attacker calls `flashBorrow(1000)`, `tmpDebt = 1000`
2. In `onFlashBorrow`, attacker calls an extension that has access to `_decrementTmpDebt` (if such a function exists)
3. Extension calls `_decrementTmpDebt(1000)`; now `tmpDebt = 0`
4. `onFlashBorrow` returns
5. Core checks `tmpDebt == 0`, passes
6. Attacker keeps the borrowed funds

**Test Case**:
```foundry
function testFlashAccountantCleanupFailure() public {
    uint256 borrowAmount = 1000e18;
    
    // Mock extension with privileged access
    address badExtension = address(new BadFlashExtension(address(core)));
    core.registerExtension(badExtension, CALLPOINT_FLASH);
    
    // Attacker flashBorrows
    uint256 balBefore = token.balanceOf(attacker);
    
    vm.prank(attacker);
    core.flashBorrow(borrowAmount, abi.encode(badExtension));
    
    // Attacker never repaid, but check passed
    // Fund balance increased without corresponding debt
    uint256 balAfter = token.balanceOf(attacker);
    assertEq(balAfter, balBefore + borrowAmount);
    
    // Core's totalDebt unchanged (no debt recorded)
    assertEq(core.totalDebt, 0);
}
```

---

### ATTACK #3: Extension-Induced Solvency Drift

**Severity**: CRITICAL  
**Category**: Extension State Desync

**Description**:
An extension performs operations that desync core's solvency invariant.

**Vulnerability**:
```solidity
function liquidate(uint256 posId) external onlyExtension(LIQUIDATE) {
    Position storage pos = positions[posId];
    uint256 debt = getDebt(posId);
    
    // ⚠️ If extension modifies state during this calculation:
    // debt might be stale
    _repayDebt(debt);
    _claimCollateral(pos, debt);
}

// Extension (malicious) during liquidation:
function onLiquidate(uint256 posId) {
    // Attacker's position
    Position storage myPos = core.position(attacId);
    myPos.liquidity += 1e18;  // artificially inflate liquidity
    
    // Now liquidation's debt calculation is based on inflated state
}
```

**Attack**:
1. Two positions: victim (borrower) and attacker's own position
2. Victim is liquidatable
3. Core calls liquidation extension
4. Extension reads state, then modifies attacker's position
5. Liquidation's solvency check is now stale (reads old slot0)
6. Attacker's position benefits from the liquidation proceeds

**Test Case**:
```foundry
function testExtensionInducedSolvencyDrift() public {
    // Setup: victim position insolvent, attacker position solvent
    uint256 victimPos = core.openPosition(victimCollateral);
    uint256 attackerPos = core.openPosition(attackerCollateral);
    
    // Attacker-controlled extension
    address malExt = address(new MaliciousLiquidationExt(address(core)));
    core.registerExtension(malExt, CALLPOINT_LIQUIDATE);
    
    // Trigger liquidation of victim
    uint256 solvencyBefore = core.getSolvency(attackerPos);
    
    vm.prank(liquidator);
    core.liquidate(victimPos, malExt);
    
    uint256 solvencyAfter = core.getSolvency(attackerPos);
    // Attacker's solvency improved without legitimate action
    assertGt(solvencyAfter, solvencyBefore);
}
```

---

### ATTACK #4: Tick Crossing Liquidity Overflow

**Severity**: HIGH  
**Category**: Tick & Liquidity Math

**Description**:
Attacker crafts a swap that crosses multiple ticks, causing cumulative liquidity to overflow and wrap silently.

**Vulnerability**:
```solidity
function _swapLoop() internal {
    uint96 cumLiquidity = slot0.liquidity;
    
    while (remainingAmount > 0) {
        nextTick = _findNextTick();
        int96 liquidityDelta = tickState[nextTick].liquidityNet;
        
        // ⚠️ No overflow check
        cumLiquidity += liquidityDelta;  // can wrap in assembly
        slot0.liquidity = cumLiquidity;
        
        // Use slot0.liquidity for swap calculation
        uint256 amountOut = _calculateOutput(remainingAmount, cumLiquidity);
        remainingAmount -= amountOut;
    }
}
```

**Attack**:
1. Attacker crafts liquidity provision such that many ticks have `liquidityNet > 0`
2. Orchestrates a swap that crosses all ticks
3. Cumulative liquidity: `1 + 2 + 4 + ... (oversized adds)` → wraps to small value
4. Swap now uses tiny liquidity value, outputting far less than expected
5. Attacker pockets the difference or uses it in a follow-up transaction

**Test Case**:
```foundry
function testTickCrossingLiquidityOverflow() public {
    // Setup: multiple ticks with large liquidityNet
    int24 startTick = 0;
    int24 endTick = 1000;
    
    for (int24 i = startTick; i <= endTick; i += 10) {
        core.setTickLiquidity(i, uint96(2**95)); // very large
    }
    
    // Perform a swap crossing all ticks
    uint256 amountIn = 1000e18;
    uint256 amountOutComputed = core.estimateSwap(amountIn);
    
    uint256 balBefore = token.balanceOf(address(this));
    core.swap(amountIn, abi.encode(...));
    uint256 balAfter = token.balanceOf(address(this));
    
    uint256 actualAmountOut = balAfter - balBefore;
    // With overflow, actualAmountOut << amountOutComputed
    assertLt(actualAmountOut, amountOutComputed / 2);
}
```

---

### ATTACK #5: Bitpacking Corruption via Stale Slot0 Read

**Severity**: CRITICAL  
**Category**: Assembly State Access

**Description**:
An attacker triggers a state read → extension call → state mutation, then a write of the stale read value, corrupting packed bits.

**Vulnerability**:
```solidity
function swap(...) external {
    uint256 slot0Snapshot = slot0;  // ⚠️ Read without snapshot semantics
    
    // ... swap logic ...
    _callExtension(extensionA, SWAP, data);  // extension mutates slot0
    
    // Write back stale snapshot
    slot0 = _updatePriceInSlot0(slot0Snapshot, newPrice);
}
```

**Attack**:
1. Attacker initiates swap
2. Core reads slot0: `slot0 = {tick: 100, liq: 1000, fee: 50}`
3. Swap calls extension
4. Extension (attacker-controlled) modifies core state directly (if extension has delegatecall or direct write permission)
5. slot0 now: `{tick: 101, liq: 1100, fee: 60}`
6. Swap writes back stale snapshot: `{tick: 100, liq: 1000, fee: 50}`
7. Silent corruption: tick rolled back, liquidity reset

**Test Case**:
```foundry
function testBitpackingCorruptionStaleRead() public {
    // Setup: core with bit-packed slot0
    core.setSlot0(encodeSlot0(100, 1000, 50));
    
    // Attacker-controlled extension
    address malExt = address(new CorruptingExtension(address(core)));
    core.registerExtension(malExt, CALLPOINT_SWAP);
    
    // Trigger swap
    uint256 amountIn = 100e18;
    
    vm.prank(attacker);
    core.swap(amountIn, abi.encode(malExt));
    
    // After swap, expected: tick = 105, liq = 1050
    (uint24 tick, uint96 liq, ) = decodeSlot0(core.slot0);
    
    // But bitpacking corruption rolled it back
    assertEq(tick, 100);  // stale
    assertEq(liq, 1000);  // stale
}
```

---

### ATTACK #6: Callpoint Mismatch via Extension Upgrade

**Severity**: HIGH  
**Category**: Extension System

**Description**:
An attacker self-destructs an extension and redeploys a new one at the same address, changing the function it implements but retaining the callpoint bitmask.

**Vulnerability**:
```solidity
function registerExtension(address ext, uint256 mask) external onlyOwner {
    extensionCallpoints[ext] = mask;  // keyed by address, not code hash
}

// Attacker-controller extension (v1):
contract ExtensionV1 {
    function onSwap(uint256 amt, bytes calldata data) external {
        // Safe swap logic
    }
}

// Attacker's new extension (v2), deployed after v1 self-destructs:
contract ExtensionV2 {
    function onSwap(uint256 amt, bytes calldata data) external {
        // Malicious logic: drains pool
    }
}
```

**Attack**:
1. Owner registers ExtensionV1 with mask = SWAP
2. ExtensionV1 is trusted, integrates safely
3. Attacker-controller self-destructs ExtensionV1
4. Attacker deploys ExtensionV2 to same address (using CREATE2)
5. extensionCallpoints[ExtensionV2] still maps to SWAP (same address)
6. Next swap calls ExtensionV2's onSwap (malicious)

**Test Case**:
```foundry
function testCallpointMismatchExtensionUpgrade() public {
    // Deploy v1
    address ext = deployExtensionV1();
    core.registerExtension(ext, CALLPOINT_SWAP);
    
    // Verify v1 is safe
    uint256 balBefore = token.balanceOf(address(core));
    core.swap(100e18, abi.encode(ext));
    uint256 balAfter = token.balanceOf(address(core));
    // Balance change is normal
    
    // Attacker self-destructs v1
    IDestructible(ext).selfDestruct();
    
    // Attacker redeploys v2 to same address
    address ext2 = redeployExtensionV2AtSameAddress();
    assertEq(ext2, ext);  // same address!
    
    // extensionCallpoints[ext2] still = CALLPOINT_SWAP
    // But now ext2 is malicious
    
    balBefore = token.balanceOf(address(core));
    core.swap(100e18, abi.encode(ext2));
    balAfter = token.balanceOf(address(core));
    
    // Malicious behavior occurs
    assertLt(balAfter, balBefore);  // pool balance decreased unexpectedly
}
```

---

## 7. CORE INVARIANTS & FORMULAS

### Core Invariants Registry

| ID | Invariant | Formula | Enforcement |
|----|-----------|---------|-------------|
| INV_CORE_001 | Liquidity non-negative | liquidity ≥ 0 | Check after updates |
| INV_CORE_002 | Tick in bounds | MIN_TICK ≤ tick ≤ MAX_TICK | Check on crossing |
| INV_CORE_003 | Debt shares consistency | totalDebtShares ≥ 0 | Atomic update |
| INV_CORE_004 | Tick map sorted | tickMap bits monotonic | Bitmap invariant |
| INV_CORE_005 | Position liquidity bounded | position.liquidity ≤ totalLiquidity | Global tracking |
| INV_CORE_010 | Flash debt ephemeral | After flashBorrow: tmpDebt == 0 | End-of-tx check |
| INV_CORE_011 | Flash reentrancy guard | inFlashCallback prevents nested flash | Atomic bool |
| INV_CORE_013 | Extension callpoint valid | ext callpoint ∈ registered callpoints | Validation on call |
| INV_CORE_014 | Slot0 atomicity | No intermediate states readable | Assembly atomic |
| INV_CORE_015 | Bitpacking consistency | No stale bits in packed slots | Pre-write clear |
| INV_CORE_020 | Pool solvency | totalCollateral ≥ totalDebt | Liquidation check |

### Derivation of Critical Invariants

**INV_CORE_001: Liquidity Non-negativity**
```
Liquidity Δ from tick crossing = Σ(liquidityNet per crossed tick)

If cumLiquidity < 0 at any point:
  → Swap outputs are negative (impossible)
  → Liquidations underflow

Constraint: cumLiquidity(t) >= 0 ∀ t in [0, totalSwaps]
```

**INV_CORE_010: Flash Debt Ephemeral**
```
tmpDebt lifecycle:
  1. Init: tmpDebt = 0
  2. flashBorrow: tmpDebt = amount
  3. onFlashBorrow: tmpDebt -= repaidAmount(s)
  4. End: tmpDebt must == 0

If tmpDebt != 0 at end:
  → Attacker escaped with borrowed funds
  → Core's debt accounting breaks

Constraint: ∀ tx, tmpDebt(tx.end) == 0
```

**INV_CORE_014: Slot0 Atomicity**
```
slot0 = {tick (bits 200-223), liquidity (bits 0-95), fees (bits 96-191)}

If extension reads slot0 during another extension's write:
  → Tick and liquidity may be out-of-sync
  → Swap uses wrong price/liq combination

Constraint: All reads and writes to slot0 must be atomic
            (no intermediate states visible to extensions)
```

---

## 8. TEST CASES & FOUNDRY SKELETONS

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
├── attacks/
│   ├── test_delta_rounding.sol
│   ├── test_flash_escape.sol
│   ├── test_extension_desync.sol
│   ├── test_tick_overflow.sol
│   ├── test_bitpacking_corruption.sol
│   └── test_callpoint_mismatch.sol
└── fuzz/
    ├── test_liquidity_fuzz.sol
    ├── test_tick_crossing_fuzz.sol
    └── test_debt_share_fuzz.sol
```

### Test #1: Tick Overflow Fuzz

```solidity
// SPDX-License-Identifier: MIT
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
        // Constrain to valid tick range (after overflow)
        tick1 = int24(bound(int256(tick1), -887272, 887272));
        tick2 = int24(bound(int256(tick2), -887272, 887272));
        
        // Attempt to cross both ticks
        core.setCurrentTick(tick1);
        
        // Crossing from tick1 to tick2 should not overflow
        int24 nextTick = _findNextTick(tick1, tick2);
        
        // Verify invariant: tick remains in bounds
        assert(nextTick >= -887272 && nextTick <= 887272);
    }
    
    function testLiquidityDeltaUnderfowFuzz(uint96 liq, uint96 delta) public {
        // Constrain: delta > liq (underflow scenario)
        liq = uint96(bound(uint256(liq), 1, type(uint96).max));
        delta = uint96(bound(uint256(delta), liq + 1, type(uint96).max));
        
        // Attempt to subtract: should revert
        vm.expectRevert();
        core.subtractLiquidity(liq, delta);
    }
}
```

### Test #2: FlashAccountant Temp-Debt Misuse

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
        
        // Normal flash: tmpDebt clears
        core.flashBorrow(borrowAmount, abi.encode(0));
        assert(core.flashState().tmpDebt == 0);
    }
    
    function testFlashTempDebtNotClearedReverts() public {
        uint256 borrowAmount = 1000e18;
        
        // Malicious borrower that doesn't repay
        vm.expectRevert("FLASH_DEBT_NOT_REPAID");
        core.flashBorrow(borrowAmount, abi.encode(address(malBorrower)));
    }
    
    function testFlashStateRaceCondition() public {
        // Attempt nested flash: should revert on inFlashCallback flag
        vm.expectRevert("RECURSIVE_FLASH");
        malBorrower.nestedFlash(1000e18);
    }
}
```

### Test #3: Extension Desync Reproduction

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
        
        // badExt will modify slot0 during swap callback
        core.swap(100e18, abi.encode(address(badExt)));
        
        (uint24 tickAfter, uint96 liqAfter, ) = core.slot0();
        
        // Verify: slot0 state is consistent, not corrupted
        // by extension's side effects
        assert(tickAfter > tickBefore);  // price moved forward
        assert(liqAfter >= 0);  // liquidity is valid
    }
}
```

### Test #4: Bitpacked-State Corruption Reproduction

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
        // Encode a valid slot0 state
        uint256 slot0 = encodeSlot0(int24(100), uint96(1e18), uint96(1e6));
        core.setSlot0(slot0);
        
        // Trigger swap with corrupting extension
        // Extension modifies slot0 mid-transaction
        core.swap(1000e18, abi.encode(address(malExt)));
        
        (int24 tick, uint96 liq, uint96 fees) = core.decodeSlot0();
        
        // With corruption, bits are scrambled or stale
        // Verify invariant: tick and liq are consistent
        assert(tick >= -887272 && tick <= 887272);
        assert(liq > 0 && liq <= type(uint96).max);
    }
}
```

### Test #5: Debt Rounding Exploit in Liquidation

```solidity
contract TestLiquidationRoundingExploit is Test {
    EUKUBOCore core;
    MockCollateral collateral;
    MockDebt debtToken;
    
    function setUp() public {
        core = new EUKUBOCore();
        collateral = new MockCollateral();
        debtToken = new MockDebt();
        core.initialize(address(collateral), address(debtToken));
    }
    
    function testLiquidationRoundingCanMakeUnliquidatable() public {
        // Open position: borrower
        uint256 posId = core.openPosition(borrower, 1000e18, 1e18);
        
        // Set up state such that liquidation rounds down
        // debtValue = (debtShares * totalDebt) / totalDebtShares
        core.setDebtShares(posId, 1e18);
        core.setTotalDebtShares(3e18);
        core.setTotalDebt(3e18 - 1);  // introduce rounding
        
        uint256 collateralValue = 1e18;
        
        // Calculate liquidation value
        uint256 debtValue = core.getDebtValue(posId);
        
        // Due to rounding, debtValue < collateralValue
        // even though position is insolvent
        assert(debtValue < collateralValue);
        
        // Verify: liquidation should not be possible
        assert(!core.canLiquidate(posId));
    }
}
```

### Test #6: Extension Upgrade Callpoint Mismatch

```solidity
contract TestExtensionUpgradeCallpointMismatch is Test {
    EUKUBOCore core;
    
    function setUp() public {
        core = new EUKUBOCore();
    }
    
    function testExtensionUpgradeViaSelfDestructRedeploy() public {
        // Deploy safe extension v1
        SafeExtensionV1 extV1 = new SafeExtensionV1();
        core.registerExtension(address(extV1), CALLPOINT_SWAP);
        
        address extAddr = address(extV1);
        
        // Verify v1 is safe
        uint256 balBefore = core.poolBalance();
        core.swap(100e18, abi.encode(extAddr));
        uint256 balAfter = core.poolBalance();
        assert(balAfter >= balBefore);  // no loss
        
        // Attacker self-destructs v1
        extV1.selfDestruct();
        
        // Attacker redeploys malicious v2 at same address (via CREATE2)
        MaliciousExtensionV2 extV2 = new MaliciousExtensionV2{salt: keccak256("salt")}();
        // In real scenario, attacker uses CREATE2 factories to match address
        
        // extV2 callpoint = CALLPOINT_SWAP (unchanged, same address)
        // But now logic is malicious
        
        // Next swap uses malicious extension
        // Expected: balance loss or exploit
    }
}
```

---

## GLOSSARY & QUICK REFERENCE

| Term | Definition |
|------|-----------|
| slot0 | Packed core state: tick, liquidity, fee growth |
| tmpDebt | Temporary debt in flash loan; must clear |
| tickMap | Bitmap of initialized ticks for gas-efficient searching |
| callpoint | Permission bitmask for extension; SWAP, FLASH, etc. |
| Tick crossing | Swap moves price across a tick boundary |
| Delta rounding | Exploiting integer division rounding in calculations |
| Solvency | Total collateral - total debt; must be >= 0 |
| Extension | Modular contract with delegated logic; has access via callpoint |
| Bitpacking | Combining multiple values into one storage slot |

---

✓ Module Complete.

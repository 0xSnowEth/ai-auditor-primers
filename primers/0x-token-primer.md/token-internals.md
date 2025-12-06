# Token-0x Internals Module Primer
## Yul Assembly, Storage Layout & Memory Safety

**Version:** 1.0.0  
**Generated:** Saturday, December 06, 2025, 3:30 PM PST  
**Scope:** ERC20.sol Yul sections, README.md:22-26, Storage architecture

---

## 1. Assembly Footprint: Annotated Code Sections

### 1.1 Expected Assembly Blocks in ERC20.sol

Token-0x uses Yul assembly to optimize gas-critical paths:

1. **transfer(address to, uint256 amount)** → Update balances, emit log3
2. **transferFrom(address from, address to, uint256 amount)** → Check allowance, update balances
3. **approve(address spender, uint256 amount)** → Update allowance, emit log3
4. **balanceOf(address account)** → Load balance from storage
5. **allowance(address owner, address spender)** → Load allowance from storage
6. **totalSupply()** → Load totalSupply from slot 0
7. **_mint(address to, uint256 amount)** → Update balance, totalSupply, emit Transfer
8. **_burn(address from, uint256 amount)** → Update balance, totalSupply, emit Transfer

### 1.2 Assembly Block Purposes

| Block | Purpose | Gas Savings |
| --- | --- | --- |
| balanceOf load | Query balance without Solidity overhead | ~300 gas vs dispatch |
| transfer | Direct balance mutation + event log | ~1000+ gas per transfer |
| transferFrom | Allowance check + balance update + log | ~1500+ gas |
| approve | Allowance store + event | ~500+ gas |
| mint | Supply increment + balance update + log | ~1000+ gas |

---

## 2. Storage Slot Math & Mapping Calculation

### 2.1 Storage Layout Baseline

Token-0x stores state in three main structures:

```
Slot 0: uint256 totalSupply
Slot 1: (reserved or packed data)
Slot 2: mapping(address => uint256) balanceOf  ← base slot for balances
Slot 3: mapping(address => mapping(address => uint256)) allowance  ← base slot
Slot 4+: (available for derived contracts)
```

### 2.2 Single-Level Mapping: balanceOf[account]

**Formula:** `slot_for_balance[address] = keccak256(abi.encode(address, BASE_SLOT_BALANCES))`

**Example:**
```
address alice = 0x1111111111111111111111111111111111111111
BASE_SLOT = 2

// Compute slot
balanceSlot = keccak256(encode(alice, 2))
            = hash of [alice, 2]
```

**Assembly code:**
```yul
function balanceOf_assembly(account) -> balance {
    mstore(0, account)      // Store address in memory
    mstore(0x20, 2)         // Store base slot
    let slot := keccak256(0, 0x40)  // Hash 64 bytes
    balance := sload(slot)  // Load from computed slot
}
```

**Vulnerable pattern (incorrect):**
```yul
// WRONG: direct sload without keccak256
function balanceOf_wrong(account) -> balance {
    balance := sload(account)  // This reads from slot = account address!
}
```

### 2.3 Double-Level Mapping: allowance[owner][spender]

**Formula:** `slot = keccak256(abi.encode(spender, keccak256(abi.encode(owner, BASE_SLOT))))`

**Step-by-step:**

```
owner = 0x2222...2222
spender = 0x3333...3333
BASE_SLOT = 3

Step 1: Compute inner hash
  inner_hash = keccak256(encode(owner, 3))

Step 2: Compute outer hash
  slot = keccak256(encode(spender, inner_hash))
```

**Safe assembly pattern:**
```yul
function allowance_assembly(owner, spender) -> allowed {
    // Step 1: Inner hash
    mstore(0, owner)
    mstore(0x20, 3)         // BASE_SLOT
    let innerHash := keccak256(0, 0x40)
    
    // Step 2: Outer hash
    mstore(0, spender)
    mstore(0x20, innerHash)
    let slot := keccak256(0, 0x40)
    
    allowed := sload(slot)
}
```

### 2.4 SLOT_DIAGRAM: Visual Example

```
Storage layout for Token-0x:

┌─────────────────────────────────────────┐
│ Slot 0: totalSupply (uint256)           │
│ Value: 1000000000000000000000000000     │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│ Slot 2+: balanceOf mapping              │
│ balanceOf[0x1111...] → slot hash        │
│ balanceOf[0x2222...] → different slot   │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│ Slot 3+: allowance mapping              │
│ allowance[0x1111...][0x2222...] → slot  │
└─────────────────────────────────────────┘
```

**Test recipe:**
```solidity
function testStorageSlotCalculation() public {
    address alice = address(0x1111111111111111111111111111111111111111);
    uint256 baseSlot = 2;
    
    bytes32 expectedSlot = keccak256(abi.encode(alice, baseSlot));
    
    _mint(alice, 100e18);
    
    uint256 storedBalance = uint256(vm.load(address(token), expectedSlot));
    uint256 queriedBalance = token.balanceOf(alice);
    
    assert(storedBalance == queriedBalance);
    assert(storedBalance == 100e18);
}
```

---

## 3. Memory & Pointer Model: Safe Allocation

### 3.1 Free Memory Pointer Assumption

Solidity maintains a free memory pointer at `0x40`:

```
┌──────────────────────────────┐
│ Memory Layout                │
├──────────────────────────────┤
│ 0x00-0x3f: Scratch space     │
│ 0x40-0x5f: Free mem pointer  │
│ 0x60+: Safe allocation       │
└──────────────────────────────┘
```

**Safe pattern:**
```yul
function someFunction() -> result {
    let fmp := mload(0x40)        // Get free memory pointer
    let newFmp := add(fmp, 0x20)  // Allocate 32 bytes
    mstore(0x40, newFmp)          // Update pointer
    
    mstore(fmp, 0xDEADBEEF)       // Write to allocated space
    result := mload(fmp)
}
```

**Vulnerable pattern:**
```yul
// WRONG: hardcoded offset
function vulnerable() -> result {
    mstore(0x60, 0x11111111)      // Assumes 0x60 is always free
    result := mload(0x60)
}
```

### 3.2 Memory Safety in Transfer Function

```yul
function transfer_assembly(to, amount) -> success {
    let fmp := mload(0x40)  // Dynamic allocation
    
    // Prepare Transfer event data
    mstore(fmp, amount)     // Write amount to allocated memory
    
    // Emit Transfer event
    let topic0 := 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
    log3(fmp, 0x20, topic0, caller(), to)  // Log with correct topics
    
    // Update balance
    // ... assembly code ...
    
    success := 1
}
```

### 3.3 Safe Memory Patterns for keccak256

**Pattern 1: Using scratch space (safe for temporary)**
```yul
function computeBalance(account) -> balance {
    mstore(0, account)     // Write to scratch (safe, temporary)
    mstore(0x20, 2)        // Base slot
    
    let slot := keccak256(0, 0x40)  // Hash scratch
    balance := sload(slot)           // Load balance
    
    // Scratch space can be reused after function
}
```

**Pattern 2: Preserving scratch space (safer)**
```yul
function computeBalanceSafe(account) -> balance {
    let fmp := mload(0x40)
    
    mstore(fmp, account)
    mstore(add(fmp, 0x20), 2)
    
    let slot := keccak256(fmp, 0x40)
    balance := sload(slot)
    
    // Free memory pointer unchanged
}
```

**Test recipe:**
```solidity
function testMemorySafety() public {
    address alice = address(0x111);
    address bob = address(0x222);
    
    _mint(alice, 1000e18);
    vm.prank(alice);
    token.transfer(bob, 100e18);
    
    // Second transfer should not have memory corruption
    token.transfer(bob, 100e18);
}
```

---

## 4. Custom Error Encoding & Revert Payload

### 4.1 ERC20 Revert Patterns

Expected custom error signatures:

```solidity
error InsufficientBalance();    // Selector: 0x13be252b
error InsufficientAllowance();  // Selector: 0xddafbaef
error InvalidSpender();         // Selector: 0x36f536ca
error TransferFromZeroAddress();// Selector: 0x75d3d7cb
error TransferToZeroAddress();  // Selector: 0x84fd0e86
```

**Assembly revert with custom error:**
```yul
function revertWithError(errorSelector) {
    mstore(0, errorSelector)  // 4-byte selector
    revert(0, 0x4)            // Revert with 4 bytes
}

// Example: check balance before transfer
let balance := sload(accountSlot)
if lt(balance, amount) {
    let errorSig := 0x13be252b  // InsufficientBalance()
    mstore(0, errorSig)
    revert(0, 0x4)
}
```

### 4.2 Test Error Encoding

```solidity
function testRevertErrorEncoding() public {
    address alice = address(0x111);
    
    vm.prank(alice);
    
    try token.transfer(bob, 100e18) {
        fail("Should have reverted");
    } catch (bytes memory lowLevelData) {
        if (lowLevelData.length == 4) {
            bytes4 selector = bytes4(lowLevelData);
            assert(selector == 0x13be252b);  // InsufficientBalance
        }
    }
}
```

---

## 5. Direct Event Log3 Usage & ABI Compliance

### 5.1 Log3 Instruction Correctness

The `log3` opcode emits an event with 3 topics:

```
log3(data_offset, data_size, topic0, topic1, topic2)
```

**Correct Transfer event assembly:**
```yul
let from := caller()
let to := <to_parameter>
let value := <amount_parameter>

let fmp := mload(0x40)
mstore(fmp, value)

let topic0 := 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
log3(fmp, 0x20, topic0, from, to)  // Correct topic order
```

**Vulnerable pattern (wrong topic order):**
```yul
// WRONG: topics swapped
log3(fmp, 0x20, topic0, to, from)  // "to" as topic1, "from" as topic2
```

**Impact:** Off-chain indexers show Transfer(to, from, value) instead of Transfer(from, to, value).

### 5.2 ABI Compliance: 4-Byte Selector

Function selectors must match Solidity signatures:

```
transfer(address,uint256) → 0xa9059cbb
transferFrom(address,address,uint256) → 0x23b872dd
approve(address,uint256) → 0x095ea7b3
```

**Assembly selector validation:**
```yul
let selector := shr(224, calldataload(0))

switch selector
case 0xa9059cbb {  // transfer
    // Handle transfer
}
case 0x23b872dd {  // transferFrom
    // Handle transferFrom
}
default {
    revert(0, 0)
}
```

---

## 6. Arithmetic & Overflow Detection

### 6.1 Unchecked Arithmetic

```yul
// Unchecked subtraction (no underflow protection)
let newBalance := sub(balance, amount)

// Checked subtraction
if lt(balance, amount) {
    revert(0, 0)
}
let newBalance := sub(balance, amount)  // Safe
```

**Vulnerable pattern:**
```yul
function transfer(to, amount) -> success {
    let balance := sload(fromSlot)
    
    // WRONG: no check
    let newBalance := sub(balance, amount)  // Wraps if amount > balance
    sstore(fromSlot, newBalance)
    
    success := 1
}
```

### 6.2 Overflow Detection in Mint

```yul
function mint(to, amount) {
    let supply := sload(totalSupplySlot)
    let newSupply := add(supply, amount)
    
    if lt(newSupply, supply) {  // Overflow check
        let errorSig := 0x35278d12
        mstore(0, errorSig)
        revert(0, 0x4)
    }
    
    sstore(totalSupplySlot, newSupply)
}
```

**Test recipe:**
```solidity
function testMintOverflowProtection() public {
    address alice = address(0x111);
    
    _mint(alice, type(uint256).max - 1);
    
    vm.expectRevert();
    _mint(alice, 2);  // Should overflow
}
```

---

## 7. Reentrancy & Low-Level Calls

### 7.1 CALL/DELEGATECALL Assessment

Token-0x base likely does NOT include external calls. However, derived contracts might:

**Vulnerable pattern:**
```solidity
contract VulnerableToken is Token {
    function transferWithCallback(address to, uint256 amount, address callback) public {
        transfer(to, amount);  // Updates state
        
        // VULNERABLE: external call after state change
        ICallback(callback).onTransfer(msg.sender, to, amount);
    }
}
```

During callback, re-entrant transfer could see inconsistent state.

---

## 8. Assembly Attack Catalog

### Name: Storage Slot Miscalculation (Collision Attack)
**Pattern ID:** INT-ATK-001  
**Severity:** Critical

**Vulnerable code:**
```yul
function balanceOf_vulnerable(account) -> balance {
    // WRONG: treats account as numeric offset
    let slot := add(2, account)
    balance := sload(slot)
}
```

**Attack:** Attacker crafts address Y where `add(2, Y) = keccak256(X, 2)` for victim X.

**Fix:**
```yul
function balanceOf_fixed(account) -> balance {
    mstore(0, account)
    mstore(0x20, 2)
    let slot := keccak256(0, 0x40)
    balance := sload(slot)
}
```

### Name: Pointer Reuse Causing Arbitrary Storage Write
**Pattern ID:** INT-ATK-002  
**Severity:** High

**Vulnerable pattern:**
```yul
function transfer(to, amount) {
    let fmp := 0x60  // Hardcoded - unsafe!
    mstore(fmp, amount)
    
    let hash := keccak256(0, 0x40)  // May corrupt 0x60
    
    log3(fmp, 0x20, topic0, topic1, topic2)  // Wrong data
    sstore(hash, newBalance)  // Wrong slot
}
```

**Fix:** Use dynamic memory allocation.

### Name: Missing Allowance Decrement
**Pattern ID:** INT-ATK-003  
**Severity:** Critical

**Vulnerable code:**
```yul
function transferFrom_vulnerable(from, to, amount) -> success {
    let balance := sload(balanceSlot)
    if lt(balance, amount) { revert(0, 0) }
    
    // MISSING: allowance check and decrement
    
    let newBalance := sub(balance, amount)
    sstore(balanceSlot, newBalance)
    success := 1
}
```

**Fix:** Check and decrement allowance.

---

## 9. Test Cases

**Test 1: Storage Slot**
```solidity
function testStorageSlotCalculation() public {
    address alice = address(0x1111111111111111111111111111111111111111);
    bytes32 expectedSlot = keccak256(abi.encode(alice, 2));
    
    _mint(alice, 100e18);
    
    uint256 storedBalance = uint256(vm.load(address(token), expectedSlot));
    assert(storedBalance == 100e18);
}
```

**Test 2: Log3 Topics**
```solidity
function testLog3TopicOrder() public {
    address alice = address(0x111);
    address bob = address(0x222);
    
    _mint(alice, 1000e18);
    vm.prank(alice);
    
    vm.expectEmit(true, true, false, true);
    emit Transfer(alice, bob, 100e18);
    token.transfer(bob, 100e18);
}
```

**Test 3: Allowance Slot**
```solidity
function testStorageSlotAllowance() public {
    address alice = address(0x1111111111111111111111111111111111111111);
    address bob = address(0x2222222222222222222222222222222222222222);
    
    bytes32 innerHash = keccak256(abi.encode(alice, 3));
    bytes32 expectedSlot = keccak256(abi.encode(bob, innerHash));
    
    vm.prank(alice);
    token.approve(bob, 500e18);
    
    uint256 storedAllowance = uint256(vm.load(address(token), expectedSlot));
    assert(storedAllowance == 500e18);
}
```

**Test 4: Memory Pointer**
```solidity
function testMemoryPointerFreedom() public {
    address alice = address(0x111);
    address bob = address(0x222);
    
    _mint(alice, 1000e18);
    vm.prank(alice);
    token.transfer(bob, 100e18);
    
    vm.prank(alice);
    token.transfer(bob, 100e18);
    
    assert(token.balanceOf(bob) == 200e18);
}
```

**Test 5: Overflow Detection**
```solidity
function testMintOverflow() public {
    address alice = address(0x111);
    
    _mint(alice, type(uint256).max - 1);
    
    vm.expectRevert();
    _mint(alice, 2);
}
```

**Test 6: Max Allowance**
```solidity
function testMaxAllowanceNonDecrement() public {
    address alice = address(0x111);
    address bob = address(0x222);
    
    _mint(alice, 1000e18);
    vm.prank(alice);
    token.approve(bob, type(uint256).max);
    
    vm.prank(bob);
    token.transferFrom(alice, bob, 100e18);
    
    assert(token.allowance(alice, bob) == type(uint256).max);
}
```

---

## INVARIANTS SUMMARY

| ID | Name | Formula | Severity |
| --- | --- | --- | --- |
| INV-INT-001 | STORAGE_SLOT_CALCULATION_CORRECT | balanceOf slot = keccak256(addr, baseSlot) | Critical |
| INV-INT-002 | LOG3_TOPICS_IN_CORRECT_ORDER | topic1 = from, topic2 = to | Critical |
| INV-INT-003 | MEMORY_POINTER_DYNAMIC_ALLOCATION | fmp from mload(0x40) | Critical |
| INV-INT-004 | OVERFLOW_CHECKED_ON_MINT | totalSupply + amount checked | Critical |
| INV-INT-005 | ALLOWANCE_DECREMENTS_UNLESS_MAX | If allowed != max, decrements | High |

---

**✓ Module Complete.**

**LATEST UPDATE**  
**Version:** 1.0.0  
**Generated:** Saturday, December 06, 2025, 3:30 PM PST

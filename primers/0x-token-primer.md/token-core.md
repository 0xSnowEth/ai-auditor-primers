# Token-0x Core Module Primer
## Public API, Derived Contracts & Behavioral Equivalence

**Version:** 1.0.0  
**Generated:** Saturday, December 06, 2025, 3:30 PM PST  
**Scope:** ERC20.sol:7-51, Token.t.sol:1-5, README.md:10-26

---

## 1. Architecture Fingerprint: Public API Surface

### 1.1 ERC20 Function Signature Audit

Token-0x implements the standard ERC20 interface through Solidity public functions layered atop Yul assembly internals. The contract exposes:

```solidity
// Core transfer functions
function transfer(address to, uint256 amount) public returns (bool)
function transferFrom(address from, address to, uint256 amount) public returns (bool)
function approve(address spender, uint256 amount) public returns (bool)

// Balance & allowance queries
function balanceOf(address account) public view returns (uint256)
function allowance(address owner, address spender) public view returns (uint256)
function totalSupply() public view returns (uint256)
```

**Code Reference:** ERC20.sol:7-51 defines the external interface. Each function declaration must be verified to accept exact ERC20 parameter types (address, uint256) with no extra parameters that would alter the ABI-encoded selector. The transfer selector is `0xa9059cbb`, transferFrom is `0x23b872dd`, approve is `0x095ea7b3`.

### 1.2 Derived Contract Minting Hooks

Token-0x is designed as an abstract base for derived contracts to implement minting. The base contract itself does NOT include a public `mint()` function; derived contracts must add internal `_mint()` calls.

**Safe derived contract pattern:**
```solidity
contract MyToken is Token {
    address public owner;
    
    constructor(address _owner) {
        owner = _owner;
    }
    
    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "Only owner");
        _mint(to, amount);  // Calls internal _mint from base
    }
}
```

### 1.3 Event Signature Conformance

Token-0x must emit ERC20-standard events:

```solidity
event Transfer(address indexed from, address indexed to, uint256 value);
// Selector: keccak256("Transfer(address,address,uint256)") = 0xddf252ad...

event Approval(address indexed owner, address indexed spender, uint256 value);
// Selector: keccak256("Approval(address,address,uint256)") = 0x8c5be1e5...
```

---

## 2. Behavioral Equivalence & State Transitions

### 2.1 Transfer Post-State Invariant

A successful `transfer(to, amount)` must produce:

**State before:**
- `balanceOf[msg.sender]` = B_from
- `balanceOf[to]` = B_to
- `totalSupply` = T

**State after successful transfer:**
- `balanceOf[msg.sender]` = B_from - amount
- `balanceOf[to]` = B_to + amount
- `totalSupply` = T (unchanged)
- One Transfer event with `(from=msg.sender, to, amount)`

**Test Recipe (Foundry):**
```solidity
function testTransferStateChange() public {
    address alice = address(0x111);
    address bob = address(0x222);
    uint256 transferAmount = 100e18;
    
    _mint(alice, 1000e18);
    vm.startPrank(alice);
    
    uint256 aliceBalBefore = token.balanceOf(alice);
    uint256 bobBalBefore = token.balanceOf(bob);
    uint256 supplyBefore = token.totalSupply();
    
    bool success = token.transfer(bob, transferAmount);
    
    require(success, "Transfer should return true");
    require(token.balanceOf(alice) == aliceBalBefore - transferAmount, "Alice balance mismatch");
    require(token.balanceOf(bob) == bobBalBefore + transferAmount, "Bob balance mismatch");
    require(token.totalSupply() == supplyBefore, "Total supply should be unchanged");
}
```

### 2.2 TransferFrom with Allowance

A successful `transferFrom(from, to, amount)` from `msg.sender` (the spender) must:

**State changes:**
- `balanceOf[from]` decreases by amount
- `balanceOf[to]` increases by amount
- `allowance[from][msg.sender]` decreases by amount (unless infinite: 2^256-1)
- One Transfer event

**Test Recipe (Foundry):**
```solidity
function testTransferFromWithFiniteAllowance() public {
    address alice = address(0x111);
    address bob = address(0x222);
    uint256 allowedAmount = 500e18;
    uint256 transferAmount = 100e18;
    
    _mint(alice, 1000e18);
    vm.prank(alice);
    token.approve(bob, allowedAmount);
    
    uint256 allowanceBefore = token.allowance(alice, bob);
    vm.prank(bob);
    token.transferFrom(alice, bob, transferAmount);
    
    require(token.allowance(alice, bob) == allowanceBefore - transferAmount, "Allowance not decremented");
    require(token.balanceOf(bob) == transferAmount, "Bob balance incorrect");
}
```

### 2.3 Approve Overwrite & Race Condition

The ERC20 `approve(spender, amount)` function overwrites the previous allowance:

**Test Recipe:**
```solidity
function testApproveRaceCondition() public {
    address alice = address(0x111);
    address bob = address(0x222);
    
    _mint(alice, 1000e18);
    
    vm.prank(alice);
    token.approve(bob, 100e18);
    
    vm.prank(alice);
    token.approve(bob, 0);  // Revoke
    
    // Race: Bob could have front-run and spent tokens
    vm.prank(bob);
    try token.transferFrom(alice, bob, 100e18) {
        // May succeed or fail depending on race timing
    } catch {}
}
```

---

## 3. Event Correctness & Log Encoding

### 3.1 Transfer Event Topic & Data Layout

The ERC20 Transfer event is emitted with:
```
log3(
    data_ptr,        // Pointer to value (uint256 = 32 bytes)
    0x20,            // Length of data = 32 bytes
    topic0,          // keccak256("Transfer(address,address,uint256)")
    topic1,          // from (indexed)
    topic2           // to (indexed)
)
```

**Expected topic values:**
- Topic 0: `0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef`
- Topic 1: from address (zero-padded to 32 bytes)
- Topic 2: to address

**Vulnerability – Log3 Misuse:** If topics are in wrong order, indexers fail to detect transfers correctly.

**Test recipe:**
```solidity
function testTransferEventData() public {
    address alice = address(0x111);
    address bob = address(0x222);
    uint256 amount = 100e18;
    
    _mint(alice, 1000e18);
    vm.prank(alice);
    
    vm.expectEmit(true, true, false, true);
    emit Transfer(alice, bob, amount);
    token.transfer(bob, amount);
}
```

---

## 4. Mint/Burn Semantics & Derived Constructor Patterns

### 4.1 Internal Mint Function

Token-0x exposes an internal function for derived contracts:

```solidity
function _mint(address to, uint256 amount) internal virtual
```

**State changes:**
- `balanceOf[to]` increases by amount
- `totalSupply` increases by amount
- One Transfer event emitted with `from = address(0)`, `to`, `amount`

### 4.2 Initializer Pattern Risk (Proxy Contracts)

If derived contract uses external initializer:

```solidity
contract MyToken is Token {
    bool private initialized;
    address public minter;
    
    function initialize(address _minter) external {
        require(!initialized, "Already initialized");
        initialized = true;
        minter = _minter;
    }
}
```

**Attack vector:** Attacker calls `initialize(attacker)` on uninitialized implementation before intended owner.

**Test recipe:**
```solidity
function testInitializerRace() public {
    MyToken implementation = new MyToken();
    
    vm.prank(attacker);
    implementation.initialize(attacker);
    
    require(implementation.minter() == attacker, "Vulnerability: attacker is minter");
}
```

---

## 5. Edge Cases & Attack Scenarios

### 5.1 Zero Address Transfer Attack

**Scenario:** Attacker calls `transfer(address(0), 100)`.

**Vulnerability if not prevented:**
```solidity
function transfer(address to, uint256 amount) public returns (bool) {
    // NO check: require(to != address(0), ...)
    balanceOf[msg.sender] -= amount;
    balanceOf[to] += amount;  // to == address(0) is accepted
    return true;
}
```

**Test recipe:**
```solidity
function testZeroAddressTransfer() public {
    address alice = address(0x111);
    
    _mint(alice, 1000e18);
    vm.prank(alice);
    
    bool success = token.transfer(address(0), 100e18);
    
    // Should fail if properly guarded
    require(!success || token.balanceOf(address(0)) == 100e18, "Zero address transfer uncontrolled");
}
```

### 5.2 Max Uint Allowance Race

**Scenario:** Alice approves Bob for `type(uint256).max`, then Bob transfers repeatedly.

**Expected behavior:** Allowance should NOT decrement if it was max.

**Test recipe:**
```solidity
function testInfiniteAllowanceNonDecrement() public {
    address alice = address(0x111);
    address bob = address(0x222);
    
    _mint(alice, 1000e18);
    vm.prank(alice);
    token.approve(bob, type(uint256).max);
    
    vm.prank(bob);
    token.transferFrom(alice, bob, 100e18);
    
    require(token.allowance(alice, bob) == type(uint256).max, "Max allowance should not decrement");
}
```

### 5.3 Approve Overwrite without Event

**Scenario:** Alice approves Bob for 100, then approves Bob for 200.

**Expected events:**
1. Approval(alice, bob, 100)
2. Approval(alice, bob, 200)

**Test recipe:**
```solidity
function testApproveEmitsEvent() public {
    address alice = address(0x111);
    address bob = address(0x222);
    
    vm.prank(alice);
    vm.expectEmit(true, true, false, true);
    emit Approval(alice, bob, 100e18);
    token.approve(bob, 100e18);
    
    vm.prank(alice);
    vm.expectEmit(true, true, false, true);
    emit Approval(alice, bob, 200e18);
    token.approve(bob, 200e18);
}
```

---

## 6. Core Invariants

### INV-CORE-001: TOTAL_SUPPLY_MATCHES_SUM_BALANCES
**Formula:** `totalSupply == ∑(balanceOf[addr] for all addr)`

**Test:**
```solidity
function invariant_totalSupplyMatchesSumBalances() public {
    uint256 sum = 0;
    for (uint256 i = 0; i < allAccounts.length; i++) {
        sum += token.balanceOf(allAccounts[i]);
    }
    assert(token.totalSupply() == sum);
}
```

### INV-CORE-002: TRANSFER_EVENT_EMITTED_FOR_STATE_CHANGE
**Formula:** If balance changes, Transfer event must exist in logs.

### INV-CORE-003: ALLOWANCE_ONLY_DECREMENTS_ON_TRANSFERFROM
**Formula:** If allowance[from][spender] < type(uint256).max, it decrements by amount on transferFrom.

### INV-CORE-004: APPROVAL_EVENT_FOLLOWS_APPROVE_CALL
**Formula:** Every approve() call results in exactly one Approval event.

### INV-CORE-005: BALANCE_NEVER_EXCEEDS_TOTALUPPLY
**Formula:** For all A: balanceOf[A] <= totalSupply

---

## 7. Attack Catalog: API-Level Vulnerabilities

### Name: Unauthorized Mint via Unprotected _mint Exposure
**Pattern ID:** CORE-ATK-001  
**Severity:** Critical

**Preconditions:**
- Derived contract exposes `_mint()` as public without access control
- Attacker discovers the selector and calls it

**Vulnerable code:**
```solidity
contract BadToken is Token {
    function mint(address to, uint256 amount) public {
        _mint(to, amount);  // No access control!
    }
}
```

**Exploit:**
1. Attacker calls `badToken.mint(attacker, type(uint256).max)`
2. Minting succeeds without authorization
3. Attacker receives inflated token supply

**Fix:**
```solidity
function mint(address to, uint256 amount) external {
    require(msg.sender == owner, "Only owner can mint");
    _mint(to, amount);
}
```

**Test:**
```solidity
function testUnauthorizedMintVulnerability() public {
    BadToken badToken = new BadToken();
    address attacker = address(0xABCD);
    
    uint256 supplyBefore = badToken.totalSupply();
    
    vm.prank(attacker);
    badToken.mint(attacker, 1000000e18);
    
    require(badToken.totalSupply() == supplyBefore + 1000000e18, "Vulnerability confirmed");
}
```

### Name: Approve-Transfer Race Condition (TOCTOU)
**Pattern ID:** CORE-ATK-002  
**Severity:** Medium

**Preconditions:**
- Alice approves Bob for 100 tokens
- Alice revokes with approve(bob, 0)
- Bob observes first approval in mempool and races second approval

**Vulnerable pattern:**
```solidity
function approve(address spender, uint256 amount) public returns (bool) {
    allowance[msg.sender][spender] = amount;  // Overwrites without atomic revocation
    emit Approval(msg.sender, spender, amount);
    return true;
}
```

**Mitigation:** Use increaseAllowance/decreaseAllowance or permit (EIP-2612).

### Name: Event Signature Mismatch via Malformed Log3
**Pattern ID:** CORE-ATK-003  
**Severity:** High

**Preconditions:**
- Token assembly uses log3 with incorrect topic ordering
- Off-chain indexers break

**Vulnerable assembly:**
```yul
// WRONG: topics swapped
log3(dataPtr, 0x20, topic0, topic2, topic1)  // "to" as topic1, "from" as topic2
```

**Impact:** Wallet shows inverted sender/recipient; indexers fail to track transfers.

**Test:**
```solidity
function testTransferEventTopics() public {
    address alice = address(0x111);
    address bob = address(0x222);
    
    _mint(alice, 1000e18);
    vm.prank(alice);
    
    vm.expectEmit(true, true, false, true);
    emit Transfer(alice, bob, 100e18);  // Correct order
    token.transfer(bob, 100e18);
}
```

---

## 8. Test Cases Summary

**Test 1: Basic Transfer**
```solidity
function testTransferBasic() public {
    address alice = address(0x111);
    address bob = address(0x222);
    
    _mint(alice, 1000e18);
    vm.prank(alice);
    token.transfer(bob, 100e18);
    
    assert(token.balanceOf(alice) == 900e18);
    assert(token.balanceOf(bob) == 100e18);
}
```

**Test 2: TransferFrom with Allowance**
```solidity
function testTransferFromWithAllowance() public {
    address alice = address(0x111);
    address bob = address(0x222);
    
    _mint(alice, 1000e18);
    vm.prank(alice);
    token.approve(bob, 200e18);
    
    vm.prank(bob);
    token.transferFrom(alice, bob, 100e18);
    
    assert(token.balanceOf(bob) == 100e18);
    assert(token.allowance(alice, bob) == 100e18);
}
```

**Test 3: Approve Overwrite**
```solidity
function testApproveOverwrite() public {
    address alice = address(0x111);
    address bob = address(0x222);
    
    vm.prank(alice);
    token.approve(bob, 100e18);
    assert(token.allowance(alice, bob) == 100e18);
    
    vm.prank(alice);
    token.approve(bob, 50e18);
    assert(token.allowance(alice, bob) == 50e18);
}
```

**Test 4: Infinite Allowance**
```solidity
function testInfiniteAllowance() public {
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

**Test 5: Event Emission**
```solidity
function testTransferEmitsEvent() public {
    address alice = address(0x111);
    address bob = address(0x222);
    
    _mint(alice, 1000e18);
    vm.prank(alice);
    
    vm.expectEmit(true, true, false, true);
    emit Transfer(alice, bob, 100e18);
    token.transfer(bob, 100e18);
}
```

**Test 6: Zero Address Prevention**
```solidity
function testZeroAddressTransferReverts() public {
    address alice = address(0x111);
    
    _mint(alice, 1000e18);
    vm.prank(alice);
    
    vm.expectRevert();
    token.transfer(address(0), 100e18);
}
```

---

## INVARIANTS SUMMARY

| ID | Name | Formula | Severity |
| --- | --- | --- | --- |
| INV-CORE-001 | TOTAL_SUPPLY_MATCHES_SUM_BALANCES | totalSupply == ∑balanceOf[addr] | Critical |
| INV-CORE-002 | TRANSFER_EVENT_EMITTED_FOR_STATE_CHANGE | If balance changes, event exists | Critical |
| INV-CORE-003 | ALLOWANCE_ONLY_DECREMENTS_ON_TRANSFERFROM | allowance decrements correctly or stays max | High |
| INV-CORE-004 | APPROVAL_EVENT_FOLLOWS_APPROVE_CALL | One Approval event per approve call | High |
| INV-CORE-005 | BALANCE_NEVER_EXCEEDS_TOTALUPPLY | balanceOf[A] <= totalSupply for all A | Critical |

---

**✓ Module Complete.**

**LATEST UPDATE**  
**Version:** 1.0.0  
**Generated:** Saturday, December 06, 2025, 3:30 PM PST

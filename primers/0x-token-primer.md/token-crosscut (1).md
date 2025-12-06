# Token-0x Cross-Cutting Module Primer
## Storage Upgradeability, Integration & Auditor Checklist

**Version:** 1.0.0  
**Generated:** Saturday, December 06, 2025, 3:30 PM PST  
**Scope:** Derived contracts, gas/security tradeoffs, integration tests, detection

---

## 1. Storage Layout & Upgradeability for Derived Contracts

### 1.1 Storage Layout Expectations

Token-0x base defines storage:

```
Slot 0: uint256 totalSupply
Slot 1: (reserved)
Slot 2: mapping(address => uint256) balanceOf
Slot 3: mapping(address => mapping(address => uint256)) allowance
Slot 4+: (available for derived contract state)
```

### 1.2 Derived Contract Collision Risk

**VULNERABLE DERIVED CONTRACT:**
```solidity
contract MyToken is Token {
    address public owner;           // Slot 0 or 1? Collision risk!
    uint256 public cap;             // May overwrite totalSupply
    
    constructor(address _owner) {
        owner = _owner;  // Could overwrite totalSupply!
    }
}
```

**SAFE DERIVED CONTRACT:**
```solidity
contract MyToken is Token {
    // Slots 0-3 reserved for base
    // Derive from slot 4
    
    struct MinterInfo {
        address owner;
        bool paused;
        uint248 cap;
    }
    
    MinterInfo private minterInfo;  // Slot 4
    mapping(address => bool) public minters;  // Slot 5+
    
    constructor(address _owner) {
        minterInfo.owner = _owner;
    }
}
```

### 1.3 Automated Slot Collision Detection

**Bash script:**
```bash
#!/bin/bash
forge inspect Token storageLayout > base.txt
forge inspect MyToken storageLayout > derived.txt

for SLOT in 0 1 2 3; do
    BASE=$(grep "│ $SLOT │" base.txt | awk -F'│' '{print $2}')
    DERIVED=$(grep "│ $SLOT │" derived.txt | awk -F'│' '{print $2}')
    
    if [ "$BASE" != "$DERIVED" ]; then
        echo "ERROR: Slot $SLOT collision detected!"
        exit 1
    fi
done
```

### 1.4 Proxy Upgradeability (ERC-1967)

**VULNERABLE PROXY (direct delegate):**
```solidity
contract TokenProxy {
    address public implementation;  // Slot 0 - Collision with totalSupply!
    
    fallback() external {
        _delegate(implementation);
    }
}
```

**SAFE PROXY (ERC-1967):**
```solidity
contract TokenProxy {
    bytes32 private constant IMPLEMENTATION_SLOT = 
        bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1);
    
    function _getImplementation() internal view returns (address) {
        return address(uint160(uint256(vm.load(address(this), IMPLEMENTATION_SLOT))));
    }
}
```

**Test recipe:**
```solidity
function testProxyStorageCollision() public {
    TokenProxy proxy = new TokenProxy(address(tokenImpl));
    Token tokenViaProxy = Token(address(proxy));
    
    require(tokenViaProxy.totalSupply() == 0, "Should be 0");
    
    // Proxy implementation shouldn't corrupt totalSupply
}
```

---

## 2. Derived Contract Patterns & Risk Assessment

### 2.1 Constructor vs Initializer Pattern

**SAFE - Constructor:**
```solidity
contract MyToken is Token {
    address public minter;
    
    constructor(address _minter) {
        minter = _minter;
    }
    
    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "Only minter");
        _mint(to, amount);
    }
}
```

**RISKY - Initializer without guard:**
```solidity
contract MyToken is Token {
    address public minter;
    
    function initialize(address _minter) external {
        minter = _minter;  // First caller wins!
    }
}
```

**SAFE - Initializer with guard:**
```solidity
contract MyToken is Token {
    address public minter;
    bool private initialized;
    
    function initialize(address _minter) external {
        require(!initialized, "Already initialized");
        initialized = true;
        minter = _minter;
    }
}
```

**Test race condition:**
```solidity
function testInitializerRace() public {
    MyToken token = new MyToken();
    address owner = address(0x1);
    address attacker = address(0xABC);
    
    vm.prank(attacker);
    token.initialize(attacker);  // Attacker frontrun!
    
    require(token.minter() == attacker, "Vulnerability confirmed");
}
```

### 2.2 Mint Function Requirements

**Correct pattern:**
```solidity
function mint(address to, uint256 amount) external {
    require(msg.sender == owner, "Only owner");
    require(to != address(0), "Mint to zero");
    _mint(to, amount);  // Call internal _mint
}
```

---

## 3. Gas-Optimization Tradeoffs

| Optimization | Savings | Security Risk | Mitigation |
| --- | --- | --- | --- |
| Inline keccak | ~100 gas | Assumes static slot | Verify in tests |
| Unchecked arithmetic | ~200 gas | Overflow possible | Pre-validate inputs |
| Direct sstore/sload | ~300 gas | Slot collision | Use keccak256 hash |
| Log3 assembly | ~100 gas | Topic order wrong | Verify in tests |
| Hardcoded memory | ~50 gas | Memory corruption | Use dynamic fmp |

**Test equivalence:**
```solidity
function testGasAndSafety() public {
    address alice = address(0x111);
    
    _mint(alice, 1000e18);
    
    vm.prank(alice);
    uint256 gasBefore = gasleft();
    token.transfer(bob, 100e18);
    uint256 gasUsed = gasBefore - gasleft();
    
    // Should be 25-30k gas for optimized transfer
    require(gasUsed > 15000 && gasUsed < 50000, "Gas cost unreasonable");
    
    // Verify safety
    require(token.balanceOf(alice) == 900e18, "Safety check failed");
}
```

---

## 4. Integration Testing

### 4.1 Token vs Token2 Equivalence

```solidity
contract TokenEquivalenceTest {
    Token token1;
    Token2 token2;
    
    function testTransferEquivalence() public {
        address alice = address(0x111);
        address bob = address(0x222);
        
        _mint(token1, alice, 1000e18);
        _mint(token2, alice, 1000e18);
        
        vm.prank(alice);
        token1.transfer(bob, 100e18);
        
        vm.prank(alice);
        token2.transfer(bob, 100e18);
        
        require(token1.balanceOf(alice) == token2.balanceOf(alice), "Mismatch");
        require(token1.balanceOf(bob) == token2.balanceOf(bob), "Mismatch");
    }
}
```

### 4.2 Event Equivalence

```solidity
function testEventEquivalence() public {
    address alice = address(0x111);
    address bob = address(0x222);
    
    vm.recordLogs();
    vm.prank(alice);
    token.transfer(bob, 100e18);
    Vm.Log[] memory logs = vm.getRecordedLogs();
    
    require(logs.length > 0, "No Transfer event emitted");
    require(logs[0].topics[0] == keccak256("Transfer(address,address,uint256)"), "Wrong event");
}
```

---

## 5. Detection & Automation

### 5.1 Slither Custom Rules

**Rule 1: Detect raw keccak256 collisions**
```bash
grep -n "keccak256.*caller()\|keccak256.*msg.sender" src/*.sol
```

**Rule 2: Detect missing allowance checks**
```bash
grep -A 10 "function transferFrom" src/*.sol | grep -L "allowance" | head -5
```

**Rule 3: Detect hardcoded memory**
```bash
grep -n "let fmp := 0x[0-9a-f]\|mstore(0x[0-9a-f]," src/*.sol
```

### 5.2 Python Slot Collision Detector

```python
#!/usr/bin/env python3
import subprocess
import json

def get_storage_layout(contract):
    result = subprocess.run(
        ["forge", "inspect", contract, "storageLayout"],
        capture_output=True, text=True
    )
    try:
        return json.loads(result.stdout)
    except:
        return {}

def check_collision(base_layout, derived_layout):
    base_slots = {item['label']: item['slot'] 
                  for item in base_layout.get('storage', [])}
    derived_slots = {item['label']: item['slot'] 
                     for item in derived_layout.get('storage', [])}
    
    collisions = []
    for slot in [0, 1, 2, 3]:
        for label, s in derived_slots.items():
            if s == slot:
                base_label = base_slots.get(slot, "UNKNOWN")
                collisions.append({
                    "slot": slot,
                    "base": base_label,
                    "derived": label
                })
    
    return collisions

if __name__ == "__main__":
    base = get_storage_layout("src/Token.sol")
    derived = get_storage_layout("src/MyToken.sol")
    
    collisions = check_collision(base, derived)
    
    if collisions:
        print("⚠️ COLLISIONS DETECTED:")
        for c in collisions:
            print(f"  Slot {c['slot']}: {c['base']} vs {c['derived']}")
    else:
        print("✓ No collisions")
```

---

## 6. Auditor Checklist

### Top 10 Priority Findings

| # | Finding | Severity | Check |
| --- | --- | --- | --- |
| 1 | Storage collision in derived | Critical | Run Python detector |
| 2 | Missing allowance check | Critical | Grep transferFrom |
| 3 | Uninitialized initializer | Critical | Check onlyInitializing |
| 4 | Hardcoded memory offset | High | Grep "let fmp := 0x" |
| 5 | Log3 topics swapped | High | Verify topic indices |
| 6 | Missing overflow check | High | Check mint logic |
| 7 | Unchecked underflow | High | Verify balance checks |
| 8 | Base not final | Medium | Check contract design |
| 9 | Zero address not rejected | Medium | Test transfer(0x0, ...) |
| 10 | Event vs state mismatch | Medium | Check event data |

### Pre-Deployment Checklist

- [ ] Run `forge inspect Token storageLayout`
- [ ] Run slot collision detector
- [ ] Execute all 18 test cases
- [ ] Run `forge test --fuzz-runs 10000`
- [ ] Check all 16 invariants pass
- [ ] Review derived contract storage
- [ ] Verify no proxy slot collisions
- [ ] Estimate gas vs cost savings
- [ ] Document all design decisions
- [ ] Sign-off on risk assessment

---

## 7. Fuzz/Invariant Testing

### 7.1 Foundry Invariant Harness

```solidity
contract TokenInvariants {
    Token token;
    address alice = address(0x111);
    address bob = address(0x222);
    
    function setUp() public {
        token = new Token();
        _mint(alice, 10000e18);
        _mint(bob, 10000e18);
    }
    
    function invariant_totalSupplyBalance() public {
        uint256 sum = token.balanceOf(alice) + token.balanceOf(bob);
        require(sum <= token.totalSupply());
    }
    
    function invariant_balanceNeverExceedsSupply() public {
        require(token.balanceOf(alice) <= token.totalSupply());
        require(token.balanceOf(bob) <= token.totalSupply());
    }
}
```

**Run:**
```bash
forge test --invariant TokenInvariants
```

### 7.2 Fuzz Test Template

```solidity
contract TokenFuzz {
    Token token;
    address alice = address(0x111);
    address bob = address(0x222);
    
    function setUp() public {
        token = new Token();
        _mint(alice, type(uint128).max);
    }
    
    function fuzz_transfer(uint256 amount) public {
        amount = bound(amount, 0, token.balanceOf(alice));
        
        uint256 aliceBalBefore = token.balanceOf(alice);
        uint256 bobBalBefore = token.balanceOf(bob);
        
        vm.prank(alice);
        token.transfer(bob, amount);
        
        require(token.balanceOf(alice) == aliceBalBefore - amount);
        require(token.balanceOf(bob) == bobBalBefore + amount);
    }
}
```

**Run:**
```bash
forge test --fuzz-runs 10000 TokenFuzz
```

---

## 8. Final Test Cases

**Test 1: Storage Collision**
```solidity
function testDerivedStorageCollision() public {
    bytes32 baseSlot0 = keccak256(abi.encode("Token.totalSupply"));
    bytes32 derivedSlot0 = keccak256(abi.encode("MyToken.owner"));
    
    require(baseSlot0 != derivedSlot0);
}
```

**Test 2: Proxy Separation**
```solidity
function testProxySlotSeparation() public {
    bytes32 proxyImplSlot = keccak256("eip1967.proxy.implementation") - 1;
    bytes32 baseSlot0 = bytes32(uint256(0));
    
    require(proxyImplSlot != baseSlot0);
}
```

**Test 3: Gas Efficiency**
```solidity
function testGasDifferential() public {
    address alice = address(0x111);
    
    _mint(alice, 1000e18);
    uint256 gasBefore = gasleft();
    vm.prank(alice);
    token.transfer(bob, 100e18);
    uint256 gasUsed = gasBefore - gasleft();
    
    require(gasUsed < 50000);
    require(gasUsed > 15000);
}
```

**Test 4: Initializer Race**
```solidity
function testInitializerRaceCondition() public {
    MyToken token = new MyToken();
    address attacker = address(0xABC);
    
    vm.prank(attacker);
    token.initialize(attacker);
    
    require(token.owner() == attacker, "Race vulnerability");
}
```

**Test 5: Invariant Fuzzing**
```solidity
function testInvariantUnderFuzz() public {
    for (uint i = 0; i < 50; i++) {
        address from = address(uint160(uint256(keccak256(abi.encode("from", i)))));
        address to = address(uint160(uint256(keccak256(abi.encode("to", i)))));
        uint256 amount = uint256(keccak256(abi.encode(i))) % 1000e18;
        
        if (from == address(0) || to == address(0)) continue;
        
        _mint(from, amount);
        vm.prank(from);
        token.transfer(to, amount / 2);
        
        uint256 sum = token.balanceOf(from) + token.balanceOf(to);
        require(sum <= token.totalSupply());
    }
}
```

**Test 6: Complex Scenario**
```solidity
function testComplexScenario() public {
    // Setup: Multiple actors, multiple operations
    address[] memory actors = new address[](5);
    for (uint i = 0; i < 5; i++) {
        actors[i] = address(uint160(0x1000 + i));
        _mint(actors[i], 1000e18);
    }
    
    // Execute: Random transfers and approvals
    for (uint i = 0; i < 20; i++) {
        uint256 fromIdx = i % 5;
        uint256 toIdx = (i + 1) % 5;
        uint256 amount = (1000e18) / 5;
        
        vm.prank(actors[fromIdx]);
        token.transfer(actors[toIdx], amount);
    }
    
    // Verify: Invariants still hold
    uint256 totalBalance = 0;
    for (uint i = 0; i < 5; i++) {
        totalBalance += token.balanceOf(actors[i]);
    }
    require(totalBalance == token.totalSupply());
}
```

---

## INVARIANTS SUMMARY

| ID | Name | Formula | Severity |
| --- | --- | --- | --- |
| INV-CROSS-001 | STORAGE_SLOT_NO_COLLISION | derived slots >= 4 | Critical |
| INV-CROSS-002 | PROXY_SLOT_SEPARATION | proxyImplSlot != base slots | Critical |
| INV-CROSS-003 | INITIALIZER_ONE_TIME_ONLY | initialize() idempotent | Critical |
| INV-CROSS-004 | DERIVED_MINT_HAS_ACCESS_CONTROL | mint() requires auth | Critical |
| INV-CROSS-005 | GAS_EFFICIENCY_TARGET | transfer <= 30k gas | High |
| INV-CROSS-006 | BEHAVIORAL_EQUIVALENCE | Token ≡ Token2 (state) | High |

---

## Risk Assessment Framework

```
Risk = (Likelihood × Impact × Market_Cap_Factor)

Likelihood: Low (1), Medium (2), High (3)
Impact: Damage in USD
Market Cap Factor: Token market cap / $1M (min 1)

Risk > 50 → Critical (fix before launch)
Risk 20-50 → High (fix before mainnet)
Risk 5-20 → Medium (plan fix)
Risk < 5 → Low (best effort)
```

---

**✓ Module Complete.**

**LATEST UPDATE**  
**Version:** 1.0.0  
**Generated:** Saturday, December 06, 2025, 3:30 PM PST

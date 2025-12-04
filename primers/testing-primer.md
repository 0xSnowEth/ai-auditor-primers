UNIVERSAL SMART CONTRACT TESTER FRAMEWORK
Zero-Information System Reconstruction & Vulnerability Discovery
Maximum Density, No Filler
═══════════════════════════════════════════════════════════════════════════════

EXECUTIVE OVERVIEW
This is a protocol-agnostic, density-maximum testing methodology for reconstructing any smart 
contract system from zero information and deriving ALL exploitable vulnerabilities.

CORE PRINCIPLE: Every contract follows predictable structural patterns. By systematically 
decomposing these patterns, the tester can MECHANICALLY discover all execution flows, 
state mutations, and attack vectors WITHOUT domain assumptions.

═══════════════════════════════════════════════════════════════════════════════
SECTION 1: SYSTEM MECHANICS (Automated Reconstruction)
═══════════════════════════════════════════════════════════════════════════════

1.1 CONTRACT ROLE IDENTIFICATION

Execution Roles to Detect:
  - OWNER/ADMIN: Unrestricted high-privilege functions (onlyOwner, onlyAdmin)
  - KEEPER/RELAYER: Restricted execution, typically permissionless or specific-actor-gated
  - PROPOSER/EXECUTOR: Governance-like roles (proposal vs execution)
  - ORACLE: External data providers (signed, timestamped, or other)
  - VAULT/POOL: Value containers and liquidity pools
  - ROUTER/AGGREGATOR: Multi-contract coordinators, execution orchestrators

Detection Method:
  For each function:
    1. Trace ALL modifiers and require() conditions
    2. Extract access control gates (owner, role-based, whitelists)
    3. Map function → role requirement
    4. Mark as: PUBLIC_UNRESTRICTED | GATED_SPECIFIC | GATED_ROLE | PRIVILEGED

High-Privilege Path Mapping:
  - Functions that mutate critical state (pausing, upgrading, draining, minting)
  - Functions that bypass normal validation
  - Functions with emergency overrides
  - Functions with delegatecall or low-level calls

1.2 STATE MACHINE MAPPING

The tester must extract the implicit OR explicit state machine by:

  State Identification:
    grep for: enum, state variables with names like "phase", "stage", "status"
    
    Common states:
      - INITIALIZED / UNINITIALIZED
      - ACTIVE / PAUSED
      - LOCKED / UNLOCKED
      - REQUEST_PENDING / REQUEST_FULFILLED
      - PHASE_ACCEPTANCE / PHASE_REVEAL / PHASE_SETTLEMENT
      - Any phase-dependent behavior

  State Transition Rules:
    For each state transition:
      Pre-conditions: What MUST be true before transition
      Guard conditions: require() statements that gate transition
      Post-conditions: Expected state after transition
      Side-effects: All storage writes, external calls, events emitted

  Forbidden Transitions (VULNERABILITY CHECK):
    Can state be skipped? (SETUP → ACTIVE → skip FINALIZATION?)
    Can state revert to earlier phase? (FINALIZED → ACTIVE?)
    Can multiple states be simultaneously true? (Race condition?)

1.3 CRITICAL STORAGE VARIABLES

Category 1: Value Containers
  - balances[user], shares[user], debt[user], credit[user]
  - positions[id], reserves, totalSupply
  - stakedAmount, lockedAmount

Category 2: Control & Limits
  - maxBalance, minBalance
  - limits[user], dailyLimit
  - collateralRatio, leverageLimit
  - paused, frozen (emergency flags)

Category 3: Counters & Sequencing
  - nonce[user] (replay prevention)
  - requestId, orderId (sequence tracking)
  - epoch, round (temporal sequencing)
  - totalRequests (protocol-wide counter)

Category 4: Access Control Flags
  - isApproved[user], whitelisted[addr]
  - role[user] (role assignments)
  - authorized[contract] (contract authorization)

Category 5: Queue & Position Structures
  - queue[index] (FIFO/LIFO)
  - entries[id] (mapping-based tracking)
  - headPointer, tailPointer (queue management)

Category 6: Time-Sensitive State
  - lastUpdate[key]
  - lockedUntil[user]
  - expiry[request]
  - timestamp (creation/modification times)

Category 7: External Dependencies
  - token, oracle, router (contract pointers)
  - approved[external] (whitelisting)
  - externalState (read-only mirrors)

1.4 PATTERN CLASSIFICATION

Classify contract type mechanically:

FINANCIAL/VAULT:
  Indicators: deposit(), withdraw(), balances[], totalAssets
  Risk Focus: Balance conservation, rounding, reentrancy
  Critical Functions: deposit, withdraw, claim

TOKEN (ERC20-like):
  Indicators: transfer(), mint(), burn(), allowance[]
  Risk Focus: Balance conservation, approval logic, transfer hooks
  Critical Functions: transfer, transferFrom, approve

ROUTER/AGGREGATOR:
  Indicators: External calls to multiple contracts, path selection
  Risk Focus: Order dependence, callback ordering, state desync
  Critical Functions: swap, execute, route

GOVERNANCE:
  Indicators: propose(), vote(), execute(), timelock
  Risk Focus: Voting manipulation, execution gates, proposal bypass
  Critical Functions: propose, vote, execute

BRIDGE/ESCROW:
  Indicators: lock(), unlock(), dual-chain state
  Risk Focus: State desync, unlock conditions, proof validation
  Critical Functions: lock, unlock, settle

ORACLE/PRICE FEED:
  Indicators: update(), getPrice(), signed data
  Risk Focus: Staleness, manipulation, input validation
  Critical Functions: update, getPrice

AMM-like:
  Indicators: swap(), reserves, price calculation
  Risk Focus: Rounding, slippage, reentrancy in swap
  Critical Functions: swap, addLiquidity, removeLiquidity

STAKING/REWARDS:
  Indicators: stake(), claim(), reward accrual
  Risk Focus: Reward calculation, timing attacks, early exit
  Critical Functions: stake, unstake, claim

HYBRID (Router+Vault):
  Multi-function orchestration + value storage
  All patterns combined, interaction risks highest

1.5 BOUNDARY CONDITION DETECTION

For EVERY variable and parameter, test:

Zero Values:
  Can amount be 0?
    - Overflow in rounding
    - Division by zero
    - Silent no-op
  Can index be 0?
    - Off-by-one errors
    - Accessing wrong element
  Can timestamp be 0?
    - Uninitialized checks
    - Time comparison failures
  Can address be 0x0?
    - Lost funds
    - Invalid delegation

Max Values:
  type(uint256).max → overflow edges
  type(int256).min / type(int256).max → negative overflow
  Protocol-specific maxes (maxBalance, maxDebt, etc.)

Uninitialized Variables:
  Storage slots never written before first read
  Default values vs. intended values
  Delegation chains pointing to 0x0

Storage-Slot Collision:
  Overlapping mapping keys
  ERC-1967 proxy slots not reserved
  Delegate call side-effects corrupting storage

═══════════════════════════════════════════════════════════════════════════════
SECTION 2: EXECUTION FLOW TESTING
═══════════════════════════════════════════════════════════════════════════════

2.1 PATH ENUMERATION

For EVERY public/external function:
  1. List all call sequences that reach it
  2. Identify all pre-state conditions
  3. Trace all branches (require, if-else)
  4. Map all post-state mutations
  5. Document all external calls made

Hidden Flows Via Callbacks:
  - ERC777 tokensReceived() called DURING transfer
  - ERC721 onERC721Received() called DURING safeTransferFrom
  - Router/pool callbacks (before/after hooks)
  - Delegate call re-entry points
  - Custom callbacks in protocol

Reentrancy-Enabled Flows:
  Which functions have external calls?
  Are they before or after state mutations?
  Can callbacks trigger the same function again?
  Can callbacks trigger different functions?

Modifier Chains:
  Example: function foo() external onlyOwner noReentrancy nonZero(amount)
  Verify:
    1. onlyOwner → actually restricts
    2. noReentrancy → lock set before external call
    3. nonZero → prevents edge cases
    4. Order matters: do guards run in correct order?

Multi-Call Flows:
  Sequence-dependent state changes
  Cross-function shared state
  Atomic vs. non-atomic operations
  Can atomicity be violated mid-sequence?

Async Flows (Request → Finalize):
  Example: requestWithdraw() → claim()
  Enumerate:
    1. Request state after requestWithdraw()
    2. State during request pending
    3. State when finalized
    4. Can request be cancelled/overwritten?
    5. Can claim() be called multiple times?

2.2 PRE-STATE CONDITIONS

For EVERY function, derive:

Template:
  function example(params) {
      // MUST BE TRUE:
      // - user.balance >= amount
      // - state != PAUSED
      // - caller has role EXECUTOR
      
      // MUST NOT BE TRUE:
      // - position already exists
      // - contract in emergency mode
      
      // ASSUMED (might be wrong):
      // - external token behaves normally
      // - oracle price is fresh
      // - callback won't mutate state
  }

Key Questions:
  What are ALL implicit assumptions?
  Can these assumptions be violated?
  What happens if violated?

2.3 POST-STATE CONDITIONS

For EVERY state-mutating function:

Expected Mutations:
  - User balance decreases by X
  - Pool balance increases by X
  - Nonce increments by 1
  - Event emitted with correct params
  - Invariants still hold

Unintended Mutations (BUG DETECTION):
  - Did ANY other storage write?
  - Was a guard bypassed?
  - Did state violate invariant?
  - Did callback cause side effects?

2.4 REVERT ANALYSIS

Classify EVERY revert cause by type:

VALID GUARD (Expected):
  require(msg.sender == owner) → Revert when violated ✓
  require(amount > 0) → Revert at boundary ✓
  require(index < length) → Revert on invalid index ✓

STATE MACHINE ERROR (Expected):
  Can't execute in current state → Revert ✓

ARITHMETIC ERROR (Expected):
  Division by zero, overflow → Revert ✓

UNEXPECTED REVERT (Bug - investigate):
  Arithmetic overflow in logic → Why not guarded?
  External call reverts cascade → Is fallback provided?
  Silent failure (return false instead of revert) → Token issue?

2.5 FLOW INTERFERENCE TESTING

Multi-Call Ordering Attacks:
  Scenario: User calls A, then B in different txs
  Test: What if B is called before A?
  Can state be desynchronized?
  Can invariant be violated mid-execution?

Callback-Induced Reordering:
  Scenario: ERC777 token has callback in transfer
  Test: What if callback triggers same function?
  Can state be read in inconsistent state?
  Can reentrancy bypass guards?

Cross-Contract Call Poisoning:
  Scenario: Contract A calls Contract B calls Contract A
  Test: Can external state be mutated between A's calls to B?
  Can read-only re-entry exploit state inconsistency?
  Can callback ordering cause desync?

Msg.Sender Manipulation:
  Scenario: Function relies on msg.sender
  Test: Can delegatecall() or _call() spoof sender?
  Can contract-to-contract call be exploited?
  Can context be confused?

═══════════════════════════════════════════════════════════════════════════════
SECTION 3: STATE MUTATION TESTING
═══════════════════════════════════════════════════════════════════════════════

3.1 MAPPING MUTATION COVERAGE

For EVERY mapping: mapping(K => V) data

Key Mutation:
  data[0] = v1;                        // Zero key
  data[type(uint).max] = v2;           // Max key
  data[address(0)] = v3;               // Zero address
  data[bytes32(0)] = v4;               // Zero bytes
  data[nested[key]] = v5;              // Complex keys

Nested Mapping Patterns:
  mapping(addr => mapping(addr => uint)) balances
  Test: Can zero-key in nested mapping cause issues?
    balances[0x0][0x0] = value;
    balances[user][0x0] = value;
  Can nested structure be exploited?

Deletion vs. Reset Behavior:
  data[key] = value;
  delete data[key];
  assert(data[key] == 0);  // True? Or something else?

Collision & Overwrite:
  Can two keys collide in storage?
  Rare, but possible with custom hash or poor slot allocation

3.2 COUNTER & NONCE BEHAVIOR

Increment Correctness:
  counter = 0;
  counter++;  // Is it 1? Always?
  counter++;
  counter++;
  assert(counter == 3);
  
Edge cases:
  counter = type(uint256).max - 1;
  counter++;  // Overflow? Revert? Silent wrap?
  counter++;  // What now?

Nonce Replay Prevention:
  Can nonce be reused?
  Can nonce gap allow replay?
  Can nonce skip forward then backward?
  Is nonce checked before or after mutation?

Rollover Safety:
  If counter is uint64 or smaller:
    What happens at type(uint64).max?
    Can overflow wrap to 0?
    Is wrap detected or allowed?

3.3 WRITE-READ-WRITE ATTACKS

Mutated-Then-Overwritten:
  state = initial;
  state = mutated;        // Mutation
  state = overwrite;      // Overwrite without checking mutated
  Result: Mutated value never used, but side-effects occur

Missing Validation Between Mutations:
  balances[user] -= amount;   // Write 1
  externalCall();             // Can re-enter
  balances[user] += amount;   // Write 2 (but what's balances[user] now?)

Stale-State Propagation:
  price = oracle.getPrice();
  totalValue = balance * price;
  externalCall();             // Modifies oracle state
  result = totalValue;        // Uses stale price

3.4 TIME-DEPENDENT MUTATIONS

Block.Timestamp Drift:
  tx1: require(block.timestamp > deadline) → revert
  tx2: (miner waits 1 second)
  tx2: require(block.timestamp > deadline) → success
  Can deadline bypass be exploited?

Delay Bypasses:
  Scenario: Timelock requires N blocks
  tx1: initiateChange() → block X
  tx2: executeChange() → block X+1 (too early!)
  Does contract check block height correctly?

Minimum-Time Inconsistencies:
  minDelay = 1 day, but stored as seconds
  initiateChange() @ timestamp T
  executeChange() @ timestamp T + 1 second (treated as >= 1 day?)

═══════════════════════════════════════════════════════════════════════════════
SECTION 4: ACCOUNTING & TRACKING LOGIC
═══════════════════════════════════════════════════════════════════════════════

4.1 BALANCE CONSISTENCY

Conservation of Value:
  INVARIANT: sum(all balances) == totalSupply
  
  Tester must verify for EVERY state mutation:
    balances[Alice] += 100;
    balances[Bob] -= 100;
    // sum(balances) still == totalSupply?
  
  But what about:
    mint(50);  // totalSupply += 50?
    // All balances unchanged → Conservation BROKEN

Phantom Balance Creation:
  balances[user] = 0;
  externalCall();  // What if callback modifies balances?
  balances[user] += amount;  // Phantom increase?

External vs. Internal Accounting Mismatch:
  Vault holds ERC20 tokens:
    internalBalance[user] = 100;
    externalToken.balanceOf(vault) = 50;  // MISMATCH
  
  Withdrawal attempt:
    externalToken.transfer(user, internalBalance[user])
    // REVERT (insufficient balance)

Silent Burn/Desync:
  Transfer to deflationary token:
    balances[user] -= 100;
    externalToken.transfer(address(this), 100);
    // External token only received 99 (fee deducted)
    // Internal accounting lost 1 token permanently

4.2 ROUNDING ERRORS

Decimal Differences:
  Token A (18 decimals), Token B (6 decimals)
  amountB = amountA / 10^12;  // Rounding down
  amountA_back = amountB * 10^12;  // Lost decimals
  // amountA > amountA_back

Division Rounding Biases:
  shares = balance / pricePerShare;
  // If balance = 100, pricePerShare = 3:
  // shares = 33 (not 33.33...)
  // Lost fractional shares

Multiply-Then-Divide Errors:
  result = (a * b) / c;
  // vs.
  result = (a / c) * b;
  // First: potential overflow at (a * b)
  // Second: potential underflow due to early division

Truncation in Profit Distribution:
  profitPerUser = totalProfit / N;
  totalDistributed = profitPerUser * N;
  leftover = totalProfit - totalDistributed;
  // leftover > 0? Where does it go? Silent burn or accumulate?

4.3 DEBT/CREDIT SYSTEMS

Negative Debt Edge Cases:
  debt[user] = 100;
  repay(50);
  debt[user] = 50;
  
  repay(100);  // More than owed
  // What happens?
  // A) Revert ✓
  // B) debt[user] = -50 ⚠ (signed int, negative debt!)
  // C) debt[user] = 0 with excess credited elsewhere

Liquidation or Forced Exits:
  collateral[user] = 100;
  debt[user] = 50;
  ratio = 100 / 50 = 2.0 (healthy)
  
  // Price crash:
  collateral[user] = 30;
  ratio = 30 / 50 = 0.6 (liquidatable)
  
  Can user be forcefully liquidated?
  Is there slippage in liquidation sale?
  Can liquidation be griefed?

Incorrect Collateralization:
  Multi-collateral system:
    debt[user] = 100;
    collateral[user][tokenA] = 50;
    collateral[user][tokenB] = 50;
  
  If tokenA price crashes:
    Is user still properly collateralized?
    Does system recognize both collateral types?

Over/Under-Repayment Handling:
  debt[user] = 50;
  repay(40);  // Under-payment
  debt[user] = 10;
  
  repay(100); // Over-payment
  // Is excess refunded? Stuck? Credited?

4.4 TOKEN BEHAVIOR TESTS

Fee-On-Transfer Tokens:
  Transfer of 100 tokens, 1% fee:
    from.balance -= 100;
    to.balance += 99;  // Only 99 received!
  
  If contract doesn't account for fee:
    balancesBefore = contract.balance;
    token.transferFrom(user, contract, 100);
    balancesAfter = contract.balance;
    assert(balancesAfter - balancesBefore == 100);  // FAILS! Only 99

Rebasing Tokens:
  balances[user] = 100;
  token.rebase();  // Multiply all balances by factor
  balances[user] = 110;  // Changed without user action!
  
  If contract caches balance:
    cached = balances[user];  // 100
    token.rebase();
    use(cached);  // Uses stale 100, actual is 110

ERC777 Hooks:
  _transfer() triggers tokensReceived() hook DURING transfer
  token.transfer(contract, 100);
  // Triggers: contract.tokensReceived() callback DURING transfer
  
  If callback is:
    receive() → reenterFunction()
    // Reentrancy!

Deflationary Transfers:
  Every transfer burns 1%:
    sent = 100;
    received = 99;  // 1% burned
  
  If contract doesn't check received amount:
    balance[contract] -= sent;  // -100
    balance[user] += received;  // +99
    // Accounting mismatch!

Missing Return Values:
  Some tokens don't return bool on transfer:
    transfer() → void (instead of bool)
  
  Naive code:
    require(token.transfer(user, amount));  // Returns nothing, treated as FALSE!
    // Transfer succeeds, but require() fails!

═══════════════════════════════════════════════════════════════════════════════
SECTION 5: HOOKS / CALLBACKS / REENTRANCY
═══════════════════════════════════════════════════════════════════════════════

5.1 CALLBACK ENUMERATION

All External Calls:
  1. Direct external calls: addr.function()
  2. Low-level calls: addr.call(), addr.delegatecall(), addr.staticcall()
  3. Token-specific callbacks: transfer hooks, mint hooks
  4. Protocol-specific callbacks: swap callbacks, liquidation callbacks
  5. Delegate call side-effects: storage modifications, caller manipulation

ERC777 Hooks:
  When token.transfer() or token.transferFrom() called:
    BEFORE transfer completes:
      Receiver must implement tokensReceived() callback
    Callback can:
      - Revert the transfer
      - Re-call the contract
      - Trigger other contracts

ERC721/1155 Callbacks:
  When contract receives NFT via safeTransferFrom():
    Contract must implement onERC721Received() or onERC1155Received()
    Callback signature: (operator, from, tokenId, data) -> bytes4
    If contract doesn't return correct selector → transfer reverts
    If callback reverts → entire transfer reverts

Custom Callbacks:
  Router might call: beforeSwap(params) / afterSwap(params)
  Vault might call: onDeposit(amount) / onWithdraw(amount)
  Bridge might call: beforeLock() / afterUnlock()
  Tester must identify ALL callback signatures

5.2 REENTRANCY VECTORS

Direct Reentrancy:
  function withdraw(uint amount) {
      require(balance[msg.sender] >= amount);
      msg.sender.call{value: amount}("");  // EXTERNAL CALL BEFORE state mutation
      balance[msg.sender] -= amount;       // Too late!
  }
  
  Attacker's fallback():
      contract.withdraw(amount);  // Reenter!

Cross-Function Reentrancy:
  function depositAndSwap() {
      deposit(amount);
      uint amountOut = dex.swap(...);  // External call
      shares[msg.sender] += amountOut; // Assumes shares not mutated
  }
  
  function swap() {
      require(balances[msg.sender] >= amountOut);
      balances[msg.sender] -= amountOut;
  }
  
  If swap() called by DEX callback during depositAndSwap(),
  shares are out of sync with balances

Read-Only Reentrancy:
  uint collateral = vault.getBalance(user);  // Read-only call
  collateral.transfer(msg.sender, collateral);
  debt[user] = 0;
  
  During transfer, callback:
    uint currentBalance = vault.getBalance(user);  // Still old value?

Multi-Step Reentrancy:
  tx1: initiateWithdraw() → sets pending
  tx1: (callback triggers)
  tx1: finalizeWithdraw() → but pending already set
  tx1: (callback completes)

Callback-Based State Desync:
  function liquidate(user) {
      reserve -= debt[user];
      collateral.transfer(liquidator, amount);  // External call
      debt[user] = 0;  // Never reached?
  }
  
  During transfer, callback can call liquidate() again

5.3 LOCKING TESTS

CEI Pattern (Checks-Effects-Interactions):
  CORRECT:
    function withdraw(uint amount) external {
        require(balance[msg.sender] >= amount);  // Check
        balance[msg.sender] -= amount;           // Effect
        msg.sender.call{value: amount}("");      // Interaction
    }
  
  INCORRECT:
    function withdraw(uint amount) external {
        msg.sender.call{value: amount}("");      // Interaction FIRST
        require(balance[msg.sender] >= amount);
        balance[msg.sender] -= amount;
    }

Lock Modifier Correctness:
  bool locked = false;
  modifier noReentrancy() {
      require(!locked);
      locked = true;
      _;
      locked = false;
  }
  
  Is lock set BEFORE or AFTER function?
  If AFTER: callback re-enters BEFORE lock is set

Improper State Before External Call:
  function swap(uint amountIn) {
      uint amountOut = calculateOut(amountIn);
      reserve[tokenIn] += amountIn;
      reserve[tokenOut] -= amountOut;
      // NOT updated yet:
      // - shares
      // - price
      // - collateral ratios
      
      externalRouter.swap(...);  // Callback reads stale state
  }

═══════════════════════════════════════════════════════════════════════════════
SECTION 6: ORACLE / EXTERNAL INPUT HANDLING
═══════════════════════════════════════════════════════════════════════════════

6.1 EXTERNAL DATA TRUST MODEL

Signed Data:
  price = oracle.getSignedPrice(signature);
  
  Tester must verify:
    1. Is signature verified?
    2. Is signer trusted?
    3. Can signature be replayed across chains?
    4. Can signature be reordered?

Timestamped Data:
  (price, timestamp) = oracle.getPrice();
  
  Tester must verify:
    1. Is timestamp validated?
    2. How stale can data be?
    3. Can timestamp be manipulated?
    4. What if timestamp < current block.timestamp?

Sequencer Dependencies:
  (price, seqNum) = oracle.getPrice();
  
  Tester must verify:
    1. If sequencer is down, what happens?
    2. Can sequencer reorder transactions?
    3. Is there fallback price?

Array-Based Historical Data:
  prices[i] = priceAtBlock(i);
  
  Tester must verify:
    1. Can array be underflowed? (prices[-1] = garbage)
    2. Can old data be injected?
    3. Is array write-once or rewritable?

6.2 MANIPULATION FEASIBILITY

Underflow of Input Arrays:
  function getAveragePrice() {
      uint sum = 0;
      for (uint i = 0; i < N; i++) {
          sum += prices[currentIndex - i];  // If currentIndex = 0?
      }
      return sum / N;
  }
  
  If currentIndex = 0:
    prices[0 - 1] = prices[max(uint256)] = garbage!

Injection of Arbitrary Data:
  function updatePrice(uint newPrice) {
      prices[block.number] = newPrice;  // Anyone can update!
  }
  
  Attacker:
    updatePrice(type(uint256).max);
    // Triggers overflow, liquidation cascade, etc.

Stale Data Acceptance:
  function getPrice() {
      return priceCache;  // When was this updated?
  }
  
  Tester must check:
    1. Is lastUpdate tracked?
    2. Is there a max staleness requirement?
    3. Can old data be used indefinitely?

Boundary Timestamp Acceptance:
  require(updateTime < block.timestamp);  // Future data? Revert
  require(block.timestamp - updateTime <= maxAge);  // Stale? Revert
  
  Edge case:
    updateTime == block.timestamp (same block)
    updateTime == block.timestamp + 1 (future by 1 sec?)

6.3 ORACLE LIVENESS

Missing Updates:
  lastUpdate = 0;  // Never updated
  block.number = 1000;
  // Use stale or uninitialized data
  
  Tester must check:
    1. What's the default if never updated?
    2. Does contract have fallback?
    3. Can operations proceed without data?

Delayed Updates:
  Update intended for block N, arrives at block N+K
  TWAP calculation includes delayed price
  Liquidation triggered by delayed bad price

Multi-Block Desync:
  tokenA price updated @ block 100
  tokenB price updated @ block 105
  
  Price ratio calculated from different blocks
  Arbitrage opportunity?

Revert Cascade Into Protocol:
  getPrice() → revert("Oracle down")
  
  All operations that depend on price:
    swap() → revert
    liquidate() → revert
    withdraw() → revert
    // Entire protocol frozen!

═══════════════════════════════════════════════════════════════════════════════
SECTION 7: CROSS-CONTRACT & CROSS-MODULE INTERACTIONS
═══════════════════════════════════════════════════════════════════════════════

7.1 MULTI-STEP SEQUENCES

Request → Confirm → Finalize → Settle Pattern:

  Step 1: User initiates
    requestId = initiateRequest(params);
    requestState[requestId] = PENDING
    Balance locked? Partially?

  Step 2: Authority confirms
    confirmRequest(requestId);
    requestState[requestId] = CONFIRMED
    Can request be cancelled now?

  Step 3: Execute
    finalizeRequest(requestId);
    requestState[requestId] = FINALIZED
    Can finalize multiple times?

  Step 4: Settle
    settleRequest(requestId);
    requestState[requestId] = SETTLED
    Transfers occur here

Tester Must Ask:
  Can request be initiated twice?
  Can confirm be skipped?
  Can finalize be called before confirm?
  Can settle be called multiple times?
  What if step 2 fails?

7.2 HIDDEN COUPLING

Storage Reading Between Contracts:
  Contract A:
    balances[user] = 100;
  
  Contract B:
    balance = A.balances[user];
    // What if A.balances not yet updated?

Shared Addressing:
  Same token used by multiple contracts
  If token has shared state:
    totalSupply[token] = 1000;
  
  Multiple contracts depend on this value
  One contract mints without updating totalSupply

Circular Dependencies:
  A calls B
  B calls C
  C calls A
  
  Can state be mutated in cycle?
  Can invariant be violated mid-cycle?

7.3 MESSAGE SENDER MANIPULATION

Sender Spoofing via Delegatecall:
  ContractA delegates to Library:
    (success, ) = library.delegatecall(...);
  
  Library code:
    require(msg.sender == owner);
    // msg.sender is still ContractA, not owner!
    // But ContractA might not check!

Delegatecall Identity Shifting:
  Contract A (Proxy):
    (success, ) = implementation.delegatecall(abi.encodeWithSignature("init()"));
  
  In implementation, msg.sender is now Proxy, not user!

7.4 MULTI-POOL / MULTI-VAULT DESYNC

Inconsistent Cross-Contract Accounting:
  Vault A:
    balances[user] = 100;
  
  Vault B:
    balances[user] = 50;
  
  User's actual balance = 100 + 50 = 150
  But if only one vault is queried → 100 or 50 (wrong total)

Flush/Sweep Race Conditions:
  Scheduled sweep of dust:
    tx1: sweep() → collects 50 from Vault A
    tx2: (same block, different tx)
    tx2: withdraw(40) from Vault A
  
  Vault A now has -10? Or sweep blocked?

Misordered Updates:
  Update price → calculate collateral → liquidate
  vs.
  Update price → liquidate → calculate collateral
  
  If order is wrong, liquidations might be unnecessary or missed

═══════════════════════════════════════════════════════════════════════════════
SECTION 8: PROTOCOL-WIDE INVARIANTS
═══════════════════════════════════════════════════════════════════════════════

INVARIANT I1: No Unexpected Minting
  Only authorized functions should increase totalSupply
  uint initialSupply = token.totalSupply();
  // After random operations:
  uint finalSupply = token.totalSupply();
  assert(finalSupply >= initialSupply);  // Monotonic increase only
  assert(lastMinter == owner || lastMinter == address(0));

INVARIANT I2: No Unexpected Burning
  Balances should never silently disappear
  sumOfAllBalances = sum(balances[addr]) for all addr;
  assert(sumOfAllBalances == totalSupply);

INVARIANT I3: Conservation of Balances
  In closed system: sum(all balances) constant
  uint before = sumBalances();
  externalCall();
  uint after = sumBalances();
  assert(before == after || before + minted == after);

INVARIANT I4: State-Machine Validity
  No forbidden state transitions
  validStates = [INITIALIZED, ACTIVE, PAUSED, ENDED];
  assert(validStates.contains(currentState));
  
  Transition rules:
    INITIALIZED → ACTIVE only via admin
    ACTIVE → PAUSED only via admin
    PAUSED → ACTIVE only via admin
    Any state → ENDED only via timelock or emergency

INVARIANT I5: Callback Stability
  Callback should not break invariants
  callbackDepth = 0;
  function sensitiveOperation() {
      require(callbackDepth == 0);
      callbackDepth++;
      externalCall();
      callbackDepth--;
  }

INVARIANT I6: No Cross-Contract Phantom Value
  If contract holds another contract's tokens:
    internalBalance[token][user] <= externalToken.balanceOf(contract)
  
  for all tokens:
      for all users:
          assert(internalBalance[token][user] <= vault.getBalance(token));

INVARIANT I7: Access Control Correctness
  Only role-holding addresses can perform privileged ops
  bool canExecutePrivileged = hasRole(EXECUTOR_ROLE, msg.sender);
  if (canExecutePrivileged) {
      assert(sensitiveOp() succeeds);
  } else {
      assert(sensitiveOp() reverts);
  }

INVARIANT I8: Event Correctness
  Every state mutation should emit correct event
  Transfer event emitted when balances[user] changes
  Approval event emitted when allowance[user][spender] changes
  Events must have correct parameters

INVARIANT I9: Oracle-Input Validity
  Oracle inputs within expected bounds
  price = oracle.getPrice();
  assert(price > 0 && price < maxPrice);
  assert(timestamp <= block.timestamp);
  assert(block.timestamp - timestamp <= maxAge);

INVARIANT I10: Reentrancy-Safety
  No unexpected state mutations during callbacks
  callStartState = captureState();
  externalCall();  // May callback
  callEndState = captureState();
  // Should be predictable difference only
  assert(reentryDepth == 0 at end);

═══════════════════════════════════════════════════════════════════════════════
SECTION 9: ATTACK TEMPLATES (Real-World Patterns)
═══════════════════════════════════════════════════════════════════════════════

ATTACK TEMPLATE 9.1: DIRECT REENTRANCY (The DAO)

Vulnerable Code:
  function withdraw(uint amount) external {
      require(balances[msg.sender] >= amount);
      msg.sender.call{value: amount}("");     // EXTERNAL CALL FIRST
      balances[msg.sender] -= amount;         // STATE UPDATE SECOND - WRONG!
  }

Why Vulnerable:
  - State mutation happens AFTER external call
  - Attacker controls callback via fallback()
  - Callback can recursively call withdraw() again
  - Balance hasn't been updated yet, so check passes again

Exploit:
  contract ReentrancyAttack {
      Vault vault = Vault(...);
      
      function attack() external payable {
          vault.deposit{value: 1e18}();
          vault.withdraw(1e18);
      }
      
      fallback() external payable {
          if (address(vault).balance > 0) {
              vault.withdraw(1e18);  // Reenter!
          }
      }
  }

Detection:
  Find all call() instructions
  For each: check if state mutation happens AFTER
  Verify mutation uses pre-call state values

Remediation (CEI Pattern):
  function withdraw(uint amount) external {
      require(balances[msg.sender] >= amount);  // Check
      balances[msg.sender] -= amount;           // Effect (FIRST)
      msg.sender.call{value: amount}("");       // Interaction (LAST)
  }

Or (Reentrancy Guard):
  bool private locked;
  modifier noReentrancy() {
      require(!locked);
      locked = true;
      _;
      locked = false;
  }

---

ATTACK TEMPLATE 9.2: CROSS-FUNCTION REENTRANCY

Vulnerable Code:
  function depositAndSwap(uint amountIn) external {
      deposit(amountIn);
      uint amountOut = dex.swap(...);  // External call
      shares[msg.sender] += amountOut; // Assumes shares not mutated
  }
  
  function swap(uint amountOut) external {
      require(balances[msg.sender] >= amountOut);
      balances[msg.sender] -= amountOut;
  }

Why Vulnerable:
  Different functions use shared state
  External call between state mutations across functions
  Callback can invoke another function that mutates same state

Exploit:
  In DEX swap callback:
    function onSwap(uint amountOut) external {
        targetVault.swap(amountOut);
        // Now targetVault.shares is out of sync with balances
    }

Detection:
  1. Identify all functions that share state variables
  2. For each function, find all external calls
  3. Check if other functions that access same state can be invoked

---

ATTACK TEMPLATE 9.3: STATE MACHINE BYPASS

Vulnerable Code:
  enum Phase { SETUP, BIDDING, REVEAL, SETTLEMENT }
  Phase public phase = Phase.SETUP;
  
  function bid(uint amount) external {
      require(phase == Phase.BIDDING);
      bids[msg.sender] = amount;
  }
  
  function settle() external {
      require(phase == Phase.SETTLEMENT);
      // Payout logic
  }
  
  function setPhase(Phase newPhase) external onlyOwner {
      phase = newPhase;  // NO VALIDATION!
  }

Why Vulnerable:
  Owner can set phase directly without validating transition
  Can skip BIDDING, go directly to SETTLEMENT
  Can go backward: SETTLEMENT → BIDDING → SETUP

Exploit:
  setPhase(Phase.BIDDING);
  // Time passes, normal bidding happens
  setPhase(Phase.SETTLEMENT);  // Skip reveal!
  // Now settle without reveal phase

Remediation:
  mapping(Phase => mapping(Phase => bool)) public validTransitions;
  
  function setPhase(Phase newPhase) external onlyOwner {
      require(validTransitions[phase][newPhase], "Invalid transition");
      phase = newPhase;
  }

---

ATTACK TEMPLATE 9.4: ROUNDING ERROR ACCUMULATION

Vulnerable Code:
  function claimRewards() external {
      uint shares = userShares[msg.sender];
      uint totalShares = getTotalShares();
      uint totalRewards = getAccumulatedRewards();
      
      uint userReward = (totalRewards * shares) / totalShares;
      
      rewardsClaimed[msg.sender] += userReward;
      totalRewardsClaimed += userReward;
  }

Why Vulnerable:
  Division truncates remainder
  Repeated claims accumulate rounding errors
  Remainder rewards are lost

Exploit:
  100 rewards, 3 users with 1 share each
  userReward = (100 * 1) / 3 = 33 (truncated)
  Each user claims 33
  Total claimed = 99
  1 reward lost forever

Detection:
  function invariant_rewardConservation() public {
      uint totalClaimed = 0;
      for (uint i = 0; i < userCount; i++) {
          totalClaimed += userRewardsClaimed[users[i]];
      }
      uint totalAccumulated = getTotalRewards();
      assert(totalClaimed <= totalAccumulated);
  }

---

ATTACK TEMPLATE 9.5: FEE-ON-TRANSFER TOKEN DESYNC

Vulnerable Code:
  function deposit(uint amount) external {
      require(token.transferFrom(msg.sender, address(this), amount));
      balances[msg.sender] += amount;  // Wrong! Records requested, not received
  }

Why Vulnerable:
  Some ERC20 tokens charge transfer fee (e.g., 1% for USDT during sanctions)
  Contract records deposited amount, but receives less
  Leads to accounting desync

Exploit:
  User transfers 100 tokens with 1% fee
  Receives: 99 tokens
  Contract records: balances[user] += 100
  Actual in contract: 99 tokens
  
  After many deposits:
    totalBalance (recorded) = 1000
    contract.token.balanceOf(contract) = 990
    Contract is insolvent by 1%

Remediation:
  function deposit(uint amount) external {
      uint balanceBefore = token.balanceOf(address(this));
      require(token.transferFrom(msg.sender, address(this), amount));
      uint balanceAfter = token.balanceOf(address(this));
      uint actualReceived = balanceAfter - balanceBefore;
      balances[msg.sender] += actualReceived;  // Record actual
  }

---

ATTACK TEMPLATE 9.6: STALE ORACLE PRICE

Vulnerable Code:
  function liquidate(address user) external {
      uint collateral = getCollateral(user);
      uint debt = getDebt(user);
      uint price = oracle.getPrice();  // No staleness check!
      
      uint collateralValue = collateral * price / 1e18;
      require(collateralValue < debt);
      // Execute liquidation
  }

Why Vulnerable:
  Oracle price could be arbitrarily old
  Liquidation triggered based on stale price
  Could liquidate healthy position or miss unhealthy one

Exploit:
  Price was $100, recorded in oracle
  Price drops to $50
  Oracle not updated yet
  Attacker liquidates user's $80 collateral, only $50 liability
  Arbitrage profit

Remediation:
  function liquidate(address user) external {
      (uint price, uint timestamp) = oracle.getPrice();
      require(block.timestamp - timestamp <= MAX_PRICE_AGE);
      // Liquidation logic...
  }

---

ATTACK TEMPLATE 9.7: PERMISSIONLESS ORACLE INJECTION

Vulnerable Code:
  mapping(address => uint) public prices;
  
  function updatePrice(uint newPrice) external {
      prices[msg.sender] = newPrice;  // NO ACCESS CONTROL!
  }

Why Vulnerable:
  Any address can update prices
  Malicious user can set arbitrary prices
  Protocol makes decisions based on fake prices

Exploit:
  Attacker updates price:
    contract.updatePrice(type(uint256).max);
  Now all calculations overflow

---

ATTACK TEMPLATE 9.8: SIGNATURE REPLAY WITHOUT NONCE

Vulnerable Code:
  function permit(address user, uint amount, bytes memory signature) external {
      require(verify(user, amount, signature));
      allowance[user] += amount;  // No nonce check!
  }

Why Vulnerable:
  Same signature can be replayed multiple times
  Allowance increased multiple times from single signature
  Cross-chain replay possible

Remediation:
  mapping(address => uint) public nonces;
  
  function permit(address user, uint amount, bytes memory signature) external {
      uint nonce = nonces[user];
      bytes32 message = keccak256(abi.encode(user, amount, nonce));
      require(verify(user, amount, nonce, signature));
      nonces[user]++;
      allowance[user] += amount;
  }

---

ATTACK TEMPLATE 9.9: FLASH LOAN PRICE MANIPULATION

Vulnerable Code:
  function liquidate(address user) external {
      uint price = getPrice();  // From AMM, can be manipulated
      uint collateral = getCollateral(user);
      uint collateralValue = collateral * price / 1e18;
      require(collateralValue < debt);
      // Execute liquidation
  }
  
  function getPrice() internal returns (uint) {
      return dex.getPrice();  // Vulnerable to flash loan
  }

Why Vulnerable:
  Price determined by current pool reserves
  Flash loan can temporarily change reserves
  Triggers liquidation during loan

Exploit:
  Normal: collateral $100, debt $90 → healthy
  Flash loan attack:
    1. Borrow huge amount of collateral token
    2. Sell on DEX → price drops
    3. Trigger liquidation (collateral now cheap)
    4. Repay flash loan
    5. Profit from liquidation discount

Remediation:
  Use TWAP instead of spot price:
    return oracle.getTWAP(address(token), 30 minutes);

═══════════════════════════════════════════════════════════════════════════════
SECTION 10: TESTING IMPLEMENTATION
═══════════════════════════════════════════════════════════════════════════════

10.1 FOUNDRY TEST SUITE SKELETON

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import "../src/TargetContract.sol";

// ============ HANDLER CONTRACT ============
contract Handler is Test {
    TargetContract target;
    uint256 internal constant AMOUNT_BOUND = 10e18;
    
    uint256 callCount = 0;
    address[] actors;
    
    constructor(TargetContract _target) {
        target = _target;
        actors = new address[](5);
        for (uint i = 0; i < 5; i++) {
            actors[i] = address(uint160(0x1000 + i));
        }
    }
    
    function deposit(uint256 amount, uint256 actorIndex) public {
        amount = bound(amount, 0, AMOUNT_BOUND);
        actorIndex = bound(actorIndex, 0, actors.length - 1);
        
        vm.prank(actors[actorIndex]);
        target.deposit(amount);
        callCount++;
    }
    
    function withdraw(uint256 amount, uint256 actorIndex) public {
        amount = bound(amount, 0, AMOUNT_BOUND);
        actorIndex = bound(actorIndex, 0, actors.length - 1);
        
        vm.prank(actors[actorIndex]);
        target.withdraw(amount);
        callCount++;
    }
}

// ============ INVARIANT TEST ============
contract TargetInvariantTest is StdInvariant, Test {
    TargetContract target;
    Handler handler;
    
    function setUp() public {
        target = new TargetContract();
        handler = new Handler(target);
        
        targetContract(address(handler));
        targetSender(address(0x1234));
    }
    
    /// I1: Total balance conservation
    function invariant_balanceConservation() public {
        uint256 sumBalances = 0;
        address[] memory users = handler.actors();
        for (uint256 i = 0; i < users.length; i++) {
            sumBalances += target.balanceOf(users[i]);
        }
        assert(sumBalances == target.totalBalance());
    }
    
    /// I2: Monotonic supply
    function invariant_monotonicSupply() public {
        assert(target.totalSupply() >= INITIAL_SUPPLY);
    }
    
    /// I3: State machine validity
    function invariant_validState() public {
        uint8 state = target.getState();
        assert(state == 0 || state == 1 || state == 2 || state == 3);
    }
}

// ============ UNIT TESTS ============
contract TargetUnitTest is Test {
    TargetContract target;
    
    function setUp() public {
        target = new TargetContract();
    }
    
    function test_noReentrancy() public {
        vm.expectRevert("No reentrancy");
        // Trigger attack
    }
    
    function test_depositZero() public {
        vm.expectRevert("Amount must be > 0");
        target.deposit(0);
    }
    
    function test_invalidStateTransition() public {
        target.pause();
        vm.expectRevert("Invalid state transition");
        target.unpause();
    }
}

10.2 RUNNING TESTS

// Run unit tests
forge test -v

// Run invariant tests
forge test --match-test invariant -v

// Run with specific seed
forge test --fuzz-seed 0x1234 -v

// Run with increased fuzz runs
FOUNDRY_FUZZ_RUNS=10000 forge test -v

10.3 RAPID SYSTEM RECONNAISSANCE (15 minutes)

Step 1: Contract Topology Extraction
  grep -E "^\s*function\s+\w+.*public|external" contract.sol
  grep -E "^\s*(public|private|internal)?\s*(mapping|uint|address|bool|bytes)" contract.sol
  grep -E "^\s*event\s+\w+" contract.sol

Step 2: Role Mapping
  Create table:
    Function Name | Visibility | Modifiers | Role Required | Action Type
    deposit       | external   | none      | PUBLIC        | MUTATE_BALANCE
    withdraw      | external   | nonReent  | PUBLIC        | MUTATE_BALANCE
    setOwner      | external   | onlyOwner | OWNER         | MUTATE_CONTROL

Step 3: State Machine Inference
  List all enum states and state variables related to phases

Step 4: Critical Path Identification
  Mark functions as:
    - Coin-moving: Deposit, Withdraw, Swap, Transfer, Mint, Burn
    - Balance-reading: BalanceOf, TotalSupply, GetDebt
    - Permission-changing: SetOwner, Grant, Revoke
    - State-changing: Pause, Unpause, SetParameter

10.4 MECHANICAL VULNERABILITY DISCOVERY

For each critical function:

Template: Vulnerability Probe for Function foo()

  // STEP 1: Pre-Condition Mapping
  bool canCallWithZero = true;
  bool canCallTwice = false;
  bool canCallBothA_B = true;
  bool canCallB_A = false;
  
  // STEP 2: Boundary Value Testing
  test_foo_zero();           // foo(0)
  test_foo_max();            // foo(type(uint).max)
  test_foo_negative();       // foo(-1) if signed
  test_foo_twice_same();     // foo(x); foo(x)
  test_foo_in_callback();    // foo() called within callback
  
  // STEP 3: State Mutation Verification
  {
      uint stateBefore = contract.getState();
      contract.foo();
      uint stateAfter = contract.getState();
      assert(stateAfter == expectedState);
  }
  
  // STEP 4: Reentrancy Probe
  {
      uint calls = 0;
      contract.foo();  // In callback: calls counter increments
      assert(calls == 1);  // If > 1: REENTRANCY FOUND
  }
  
  // STEP 5: Cross-Function State Desync
  {
      contract.foo();
      externalTarget.call();
      // Verify contract state is consistent
  }

10.5 CHECKLIST FRAMEWORK

Execution Flow Checklist:
  [ ] All public/external functions listed
  [ ] All internal functions traced
  [ ] All modifiers and guards identified
  [ ] All callbacks enumerated (ERC777, ERC721, custom)
  [ ] All external calls mapped
  [ ] All low-level calls identified
  [ ] All delegate calls identified
  [ ] Modifier order verified
  [ ] Guard logic verified
  [ ] All branching paths traced
  [ ] All edge cases covered
  [ ] Revert conditions verified
  [ ] Event emissions verified
  [ ] Return values verified

State Mutation Checklist:
  [ ] All state variables listed and categorized
  [ ] Mutation order verified
  [ ] Write-before-read verified
  [ ] Read-before-write verified
  [ ] Storage slots verified (no collision)
  [ ] Mapping key access verified
  [ ] Nested mapping verified
  [ ] Array indexing verified
  [ ] Deletion behavior verified
  [ ] Reset behavior verified
  [ ] Initialization verified
  [ ] Uninitialized variable risks checked
  [ ] Overflow/underflow checked

Accounting Checklist:
  [ ] Balance conservation verified
  [ ] Phantom balance creation tested
  [ ] Rounding verified (all divisions)
  [ ] Truncation tested
  [ ] Decimal handling tested
  [ ] Token fee-on-transfer tested
  [ ] Token rebasing tested
  [ ] Token burn/mint behavior tested
  [ ] Cross-contract accounting verified
  [ ] Debt/credit logic verified
  [ ] Collateralization logic verified
  [ ] Over/under-repayment handled
  [ ] Liquidation logic verified

Reentrancy Checklist:
  [ ] All external calls identified
  [ ] All callbacks identified
  [ ] CEI pattern verified
  [ ] Lock modifiers verified
  [ ] State before external call verified
  [ ] Direct reentrancy tested
  [ ] Cross-function reentrancy tested
  [ ] Read-only reentrancy tested
  [ ] Nested reentrancy tested
  [ ] Callback ordering tested
  [ ] Multi-call reentrancy tested

Callback Checklist:
  [ ] ERC777 hooks tested
  [ ] ERC721 callbacks tested
  [ ] ERC1155 callbacks tested
  [ ] Custom callbacks tested
  [ ] Callback access to state verified
  [ ] Callback mutation possibilities tested
  [ ] Callback revert handling tested
  [ ] Callback return value handling tested

Oracle Checklist:
  [ ] Oracle data source verified
  [ ] Staleness checks verified
  [ ] Timestamp validation verified
  [ ] Signature verification verified
  [ ] Sequence number verification tested
  [ ] Array underflow tested
  [ ] Array boundary tested
  [ ] Data injection tested
  [ ] Fallback behavior tested
  [ ] Liveness checked
  [ ] Multi-block desync tested
  [ ] Revert cascade tested

Cross-Contract Checklist:
  [ ] All external contract calls identified
  [ ] Contract address assumed values verified
  [ ] External token behavior tested
  [ ] Storage coupling identified
  [ ] Circular dependencies identified
  [ ] Msg.sender manipulation tested
  [ ] Delegatecall risks tested
  [ ] Multi-contract accounting verified

Rounding Checklist:
  [ ] All divisions identified
  [ ] Division order verified
  [ ] Remainder tracking verified
  [ ] Rounding bias identified
  [ ] Decimal conversion tested
  [ ] Profit distribution remainder tested

Storage-Slot Checklist:
  [ ] All storage variables listed
  [ ] Slot allocation verified
  [ ] ERC-1967 proxy slots reserved
  [ ] Gap slots for future variables verified
  [ ] Mapping key collision tested
  [ ] Array out-of-bounds tested

High-MEV Checklist:
  [ ] Reentrancy MEV opportunities identified
  [ ] Oracle MEV opportunities identified
  [ ] Callback MEV opportunities identified
  [ ] Multi-call MEV opportunities identified
  [ ] Ordering dependencies identified
  [ ] Slippage exploitation tested
  [ ] Liquidation MEV tested

═══════════════════════════════════════════════════════════════════════════════
SECTION 11: 4-DAY AUDIT WORKFLOW
═══════════════════════════════════════════════════════════════════════════════

DAY 1: RECONNAISSANCE & STRUCTURE
  [ ] 15 min: Extract contract topology
  [ ] 15 min: Identify roles and permissions
  [ ] 15 min: Map state machine
  [ ] 15 min: List critical functions
  [ ] 30 min: Create vulnerability surface map
  Total: 1.5 hours (start identifying patterns)

DAY 2: VULNERABILITY DISCOVERY
  [ ] 2 hours: Test each critical function boundary
  [ ] 1 hour: Test state mutations
  [ ] 1 hour: Test reentrancy paths
  [ ] 1 hour: Test cross-function interactions
  Total: 5 hours (produce vulnerability list)

DAY 3: INVARIANT & FUZZING
  [ ] 1 hour: Define invariants (I1-I10)
  [ ] 2 hours: Write handlers
  [ ] 2 hours: Run fuzz tests (10k+ sequences)
  [ ] 1 hour: Analyze results
  Total: 6 hours (verify no regressions)

DAY 4: ATTACK SCENARIOS & REPORT
  [ ] 2 hours: Generate exploit scenarios
  [ ] 2 hours: Implement POCs
  [ ] 1 hour: Verify exploitability
  [ ] 1 hour: Write findings report
  Total: 6 hours (produce final report)

═══════════════════════════════════════════════════════════════════════════════
SECTION 12: COMMON PITFALLS & SOLUTIONS
═══════════════════════════════════════════════════════════════════════════════

Pitfall 1: Assuming Function Safety by Name
  Problem: safeTransfer() might not be safe
  Solution: Verify implementation regardless of name
  Check: Look at actual implementation, don't trust naming

Pitfall 2: Missing Callback Vectors
  Problem: Forgot ERC777 tokensReceived() hook
  Solution: Search for ALL transfer() calls, check all receive() functions
  Check: grep -n "transfer" and verify callback handling for each

Pitfall 3: Incomplete State Machine
  Problem: Missed hidden states or transitions
  Solution: Trace ALL state variables, not just named enums
  Check: Create full state diagram with ALL possible values

Pitfall 4: Ignoring Precision/Rounding
  Problem: Division rounding loss in rewards
  Solution: Track ALL division operations, verify remainder handling
  Check: For each division, ask: where do remainders go?

Pitfall 5: Assuming Oracle Honesty
  Problem: Oracle can be manipulated or stale
  Solution: Test oracle failure cases, staleness, replay
  Check: Test getPrice() with zero, max, stale, and manipulated values

═══════════════════════════════════════════════════════════════════════════════
SECTION 13: 30-SECOND VULNERABILITY DETECTOR
═══════════════════════════════════════════════════════════════════════════════

For any suspicious code, ask:

1. Is there an external call?
   → Check for reentrancy (CEI pattern)

2. Is there arithmetic?
   → Check for overflow/underflow

3. Is there state transition?
   → Check for bypass

4. Is there mapping access?
   → Check for key collision/injection

5. Is there delegation?
   → Check for call/delegatecall identity confusion

6. Is there oracle data?
   → Check for staleness/manipulation

7. Is there callback?
   → Check for unexpected state mutation

If ANY of these are true → Vulnerability likely exists

═══════════════════════════════════════════════════════════════════════════════
SECTION 14: HISTORICAL EXPLOITS REFERENCE
═══════════════════════════════════════════════════════════════════════════════

Year | Protocol      | Amount  | Attack                    | Lesson
-----|---------------|---------|---------------------------|------------------------------------
2016 | The DAO       | $50M    | Reentrancy                | CEI pattern critical
2018 | bZx           | $350K   | Flash loan price manip    | Use TWAP
2020 | Harvest       | $34M    | Oracle manipulation       | Multi-source oracles
2021 | Poly Network  | $611M   | Delegatecall overwrite    | Avoid delegatecall
2021 | Wormhole      | $325M   | Missing guard check       | Initialize pattern
2022 | Nomad         | $190M   | Initialization frontrun    | Guard initialization
2022 | Ronin         | $625M   | Private key leak          | Not code-based
2023 | Curve         | $50M+   | Admin compromise          | Multi-sig & timelock

═══════════════════════════════════════════════════════════════════════════════
CONCLUSION
═══════════════════════════════════════════════════════════════════════════════

This framework provides MECHANICAL, EXHAUSTIVE methodology for:

1. Reconstructing any contract from zero information
2. Enumerating all execution flows
3. Testing all state mutations
4. Identifying all reentrancy vectors
5. Validating accounting logic
6. Simulating all attack templates
7. Verifying protocol-wide invariants

Key Principle: No assumptions about code intent. Only assumptions about code mechanics.

Deliverable: For any contract, following this framework produces:
  - Complete flow enumeration
  - Complete vulnerability classification
  - Complete Foundry test suite
  - Complete attack template catalog

If a vulnerability exists, this methodology WILL find it.

> This step ensures hidden vulnerabilities surface through testing, even when pattern recognition misses them.

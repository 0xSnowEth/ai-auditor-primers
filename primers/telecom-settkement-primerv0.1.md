# WERC7575 Master Primer — v1.0

## Overview
This primer provides comprehensive security analysis for WERC7575, an on-chain settlement layer for multi-tier telecom wholesale voice traffic ecosystems connecting DeFi liquidity via multi-asset ERC-7575/4626-style vaults to real-world telecom receivable flows. The protocol implements dual balance accounting (`_balances` / `_rBalances`), batch netting for multi-party settlements, permit-based transfers for off-chain authorization, and async vault flows following ERC-7540-like patterns for uncertain or delayed telecom settlements.

**Latest Update**: Initial comprehensive primer covering WERC7575-specific vulnerability patterns including batch netting underflows, dual balance desynchronization, async request state manipulation, permit replay across vaults, price race conditions in async fulfillment, reentrancy in batch and claim flows, role centralization risks, and cross-contract sequence failures. Includes 10 prioritized attack vectors with full exploit recipes, property tests, invariant specifications, and remediation patches.

---

## A. Executive Fingerprint

### A.1 Core Contracts (roles, not exact names)

All contract names below are conceptual and MUST be mapped to concrete contracts in the WERC7575 repo.  
Every contract name and file path in this section is **NEEDS_MAPPING**.

| Conceptual contract (NEEDS_MAPPING) | Primary responsibility |
| --- | --- |
| `SettlementCore` | Maintains telecom settlement ledgers: `_balances`, `_rBalances`, `allowances`; exposes `batchTransfers()` and single-asset transfers; enforces permit-based transfers. NEEDS_MAPPING |
| `ShareToken` | ERC‑20 / ERC‑20-like share token representing positions in one or more vaults (ERC‑7575-style externalized share token).[1][2] NEEDS_MAPPING |
| `Vault` | ERC‑4626/7575-style vault for one or more assets backing telecom receivables, supporting async `deposit → request → fulfill → claim` flows (ERC‑7540-like).[1][3][2][4] NEEDS_MAPPING |
| `AsyncRequestHub` | Central request router and bookkeeper for asynchronous deposit / redemption requests and their life cycle states (Pending, Claimable, Claimed).[4] NEEDS_MAPPING |
| `BatchRouter` | Orchestrates multi-hop `batchTransfers()` across multiple counterparties, possibly netting routes and applying FX / rate cards. NEEDS_MAPPING |
| `KYCRegistry` | Maintains whitelist / role gating for KYC'd addresses (originators, investors, off-chain telecom counterparties). NEEDS_MAPPING |
| `RoleManager` | On-chain access control for validator / investment manager / KYC admin roles; usually wraps `AccessControl`-style pattern. NEEDS_MAPPING |
| `Oracle/ValidatorGateway` | Accepts price, FX, traffic or revenue attestations from trusted validators; may also sign off-chain messages consumed via `permit`-like flows. NEEDS_MAPPING |
| `UpgradeController` | Proxy / upgrade logic if system is upgradeable. NEEDS_MAPPING |

### A.2 Trusted Parties

All of these are economically privileged actors whose compromise or misbehavior is system-critical.

- **Validators**  
  Provide authoritative off-chain telecom settlement data: traffic volumes, route prices, dispute results. Their outputs influence vault valuations and batch netting outcomes.[5]

- **KYC / Compliance Admins**  
  Configure which on-chain addresses may participate as LPs, telecom wholesalers, or borrowers; may be able to freeze / unfreeze accounts.

- **Investment Managers / Portfolio Managers**  
  Configure vault parameters (fee rates, limits), choose underlying receivables, and may trigger async fulfillment / rollovers for telecom traffic receivables.[5]

- **Protocol Owner / Governance Multisig**  
  Controls upgrades, critical parameter tweaks, and role assignments; can usually brick or fully reconfigure the system.

### A.3 Critical State Variables

Names in this subsection are taken from the prompt and thus **can be referenced directly**; everything else is conceptual and MUST be mapped.

- `_balances[address account]`  
  Logical user balance in the settlement layer – likely share-denominated or notional units representing claims on underlying telecom cash flows.

- `_rBalances[address account]`  
  "Raw" or "reserve" balance representation (e.g. scaled by global factor \(R\), or reflecting un-netted settlements). Typical pattern:  
  \[
  \_balances[a] = \frac{\_rBalances[a]}{R}
  \]  
  or the reverse (rebase-style). NEEDS_MAPPING for exact formula.

- `allowances[address owner][address spender]`  
  ERC‑20-style allowances; may be used for both direct transfers and permit-based / relayed operations.

- Vault mappings (all **NEEDS_MAPPING**):
  - `vaultOfShare[address shareToken] → address vault`
  - `vaultInfo[bytes32 vaultId] → {asset, shareToken, totalAssets, totalShares, …}`
  - `requestInfo[uint256 requestId] → {controller, owner, vault, assets, shares, state}` as in ERC‑7540 async requests.[4]

### A.4 Key Asynchronous Flows

Conceptual sequence for an async vault conforming broadly to ERC‑7540 (actual function names NEEDS_MAPPING).[3][4]

1. **Deposit Request**

   ```solidity
   // NEEDS_MAPPING
   function requestDeposit(
       address asset,
       uint256 assets,
       address controller,
       address owner
   ) external returns (uint256 requestId);
   ```

   - Transfers `assets` from `owner` into the Vault and moves state to Pending.[4]
   - Increases `pendingDepositRequest[controller]` for that vault.[4]

2. **Fulfillment (Off-chain / Manager-triggered)**

   ```solidity
   // NEEDS_MAPPING
   function fulfillDeposit(uint256 requestId, uint256 sharesOut) external;
   ```

   - After off-chain telecom settlement events, investment manager or automated process calls this to mark `requestId` as Claimable and fix `sharesOut`.

3. **Claim**

   ```solidity
   // NEEDS_MAPPING
   function depositClaim(
       uint256 requestId,
       address receiver
   ) external returns (uint256 shares);
   ```

   - Decrements claimable amounts and mints shares to `receiver`.[4]

4. **Async Redeem (Mirror)**

   - `requestRedeem` → Pending redemption.[4]
   - `fulfillRedeem` → Claimable assets.
   - `redeemClaim` → Transfer of underlying assets to owner.

Desync windows appear primarily between `request*` and `fulfill*`, and between `fulfill*` and `claim*`.

### A.5 `batchTransfers()` Flow

Conceptual flow for netted multi-party settlement in telecom voice traffic.

```solidity
// NEEDS_MAPPING
function batchTransfers(
    address[] calldata senders,
    address[] calldata receivers,
    int256[] calldata deltas // signed netted amounts
) external;
```

- Interprets `deltas[i]` as net settlement vs reference currency or traffic unit.
- Converts deltas into debits/credits on `_balances` and `_rBalances` for multiple parties in a single call.
- May apply FX or quality-of-service factors from validator attestations.

### A.6 Permit-based Transfer Flow

Generalized "meta-tx" or off-chain signed instruction pattern (actual signature format NEEDS_MAPPING).

```solidity
// NEEDS_MAPPING
function permitTransfer(
    PermitData calldata p,
    bytes calldata signature
) external;
```

- `PermitData` likely includes `owner`, `spender` or `relayer`, `value`, expiry, and a per-owner `nonce`.
- The SettlementCore verifies signature over an EIP‑712 domain; then updates `allowances` or performs a direct transfer in `_balances`.

---

## B. Protocol Summary

WERC7575 is the **on-chain settlement layer** for a multi-tier telecom wholesale voice traffic ecosystem, connecting DeFi liquidity (via multi-asset ERC‑7575/4626-style vaults) to real-world telecom receivable flows through profit-sharing debt instruments. The protocol uses **dual balances** (`_balances` / `_rBalances`) to represent both notional and reserve-adjusted positions, supports **batchTransfers()** to net multi-party settlements across routes and currencies, and leverages **permit-based transfers** to allow off-chain validators and relayers to submit user-authorized settlement adjustments without on-chain signatures every time. Async vault flows following an ERC‑7540-like pattern (`deposit → request → fulfill → claim`) handle telecom receivables with uncertain or delayed settlement, while role-based access control centralizes critical operations (KYC, validator attestations, investment management) for economic safety at the expense of trust minimization.[1][2][3][5][4]

---

## C. Critical Vulnerability Patterns

All file references are `NEEDS_MAPPING` in this primer.  
All code fragments marked `// NEEDS_MAPPING` must be aligned with the actual WERC7575 implementation before use.

### C.1 Batch Netting Underflow / Skipped Recipient in `batchTransfers`

- **Name:** C1 – Batch Netting Underflow / Skipped Recipient
- **Category:** ACCOUNTING
- **Short description:** Miscalculated net sums or incorrect loop bounds in `batchTransfers()` can allow an attacker to underpay, over-credit, or entirely skip certain senders/receivers without reverting.

#### Pattern

Predicate (pseudocode):

- There exists a call to `batchTransfers()` such that:

  - The implementation computes an aggregate `netDelta` but fails to assert:

    \[
    \sum_{i} debits_i = \sum_{j} credits_j
    \]

  - Or it iterates over arrays with mismatched lengths without strict `require` checks.

Pseudocode (NEEDS_MAPPING):

```solidity
// file: NEEDS_MAPPING, line: NEEDS_MAPPING
function batchTransfers(
    address[] calldata senders,
    address[] calldata receivers,
    int256[] calldata deltas
) external {
    // no strict length checks or partial ones only
    uint256 len = receivers.length;
    int256 totalDelta;

    for (uint256 i; i < len; ++i) {
        int256 d = deltas[i]; // assumes deltas.length >= receivers.length
        totalDelta += d;      // loses sign information per account

        if (d > 0) {
            _balances[receivers[i]] += uint256(d);
        } else {
            _balances[senders[i]] -= uint256(-d); // possible underflow
        }
    }

    // missing: require(totalDelta == 0);
}
```

- **Concrete vulnerable example:** `file: NEEDS_MAPPING, line: NEEDS_MAPPING`

#### Root Cause / Invariant Violated

- Violates **INV‑001 (Conservation of balances in batch netting)**: total credited amount must equal total debited amount.
- May also violate **INV‑002 (Per-account non-negativity)** if debit accounts can underflow.

#### Detection Heuristics

- Grep:

  - `"function batchTransfers"`  
  - `"int256[]"` with `_balances` mutations.
  - `"totalDelta"` or similar aggregate without final equality check.

- AST / symbolic checks:

  - Identify any function mutating `_balances` or `_rBalances` in loops where no invariant enforces sum(inputs) == 0.
  - Look for conversions from `int256` to `uint256` without explicit bound checks.

#### Property Tests & Fuzz Targets

- **Invariant test (Foundry, pseudocode):**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// NEEDS_MAPPING: update interface and addresses
interface IWERC7575Batch {
    function batchTransfers(
        address[] calldata senders,
        address[] calldata receivers,
        int256[] calldata deltas
    ) external;
    function balanceOf(address account) external view returns (uint256);
}

contract Invariant_BatchNetting is Test {
    IWERC7575Batch internal werc;

    address[] internal actors;

    function setUp() public {
        // NEEDS_MAPPING: deploy or bind IWERC7575Batch
        // populate actors
    }

    function invariant_INV_001_Conservation() public {
        uint256 total;
        for (uint256 i; i < actors.length; ++i) {
            total += werc.balanceOf(actors[i]);
        }
        // EXPECT: total == initialTotal
        // NEEDS_MAPPING: store initialTotal in setUp and assert equality
    }

    function fuzz_batchNetting(
        address[] memory senders,
        address[] memory receivers,
        int256[] memory deltas
    ) public {
        vm.prank(actors[0]); // controller / router
        // Wrap in try/catch to avoid invariant failing on revert
        try werc.batchTransfers(senders, receivers, deltas) {} catch {}
    }
}
```

- Fuzzing strategies:
  - Random but **balanced** deltas where sum(deltas) == 0.
  - Adversarial where `deltas.length != senders.length` or `deltas.length != receivers.length`.

#### Minimal Exploit Recipe

Preconditions:

- Attacker controls at least one `sender` address with some `_balances` > 0.
- `batchTransfers()` lacks strict conservation checks and/or length equality checks.

Steps:

1. Construct arrays:

   - `senders = [attacker, victim]`
   - `receivers = [attacker, victim]`
   - `deltas = [largePositiveForAttacker, smallNegativeForVictim]`

2. Call:

   ```solidity
   werc.batchTransfers(
       senders,
       receivers,
       deltas
   );
   ```

   - If contracts only sum `totalDelta` or ignore one side of the flow, the attacker may gain net balance.

3. Repeat with varied shapes until a combination passes local checks but violates conservation.

Calldata template (JSON, NEEDS_MAPPING):

```json
{
  "to": "0xWERC7575_CORE_NEEDS_MAPPING",
  "data": "0xBATCH_SELECTOR_NEEDS_MAPPING<encoded(senders,receivers,deltas)>",
  "value": "0x0"
}
```

Expected post-state (symbolic):

- `_balances[attacker] = _balances_before[attacker] + exploitGain`
- Sum of all `_balances` increased by `exploitGain` (inflation).

#### Proof Artifacts

- **Test path:** `test/WERC7575/BatchNettingAttack.t.sol::test_BatchNettingBreak_Critical` (NEEDS_MAPPING)
- **Command:**

  ```bash
  forge test --match-test test_BatchNettingBreak_Critical -vvv
  ```

#### Severity

- **Severity:** Critical  
- **Justification:** Direct ability to mint value to arbitrary addresses or mis-route telecom settlements; no off-chain recourse if unnoticed.

---

### C.2 Dual Balance Desynchronization (`_balances` vs `_rBalances`)

- **Name:** C2 – Dual Balance Desync
- **Category:** ACCOUNTING

Short description: Any path that updates `_balances` without updating `_rBalances` (or vice versa) breaks the invariant linking logical balances and raw reserves, enabling value extraction or denial-of-service through inconsistent accounting.

#### Pattern

Predicate:

- Exists a function \(f\) such that:

  - \(f\) mutates `_balances[account]` but does **not** adjust `_rBalances[account]` in the same function or in a clearly linked internal call; OR
  - vice versa.

Pseudocode (NEEDS_MAPPING):

```solidity
// file: NEEDS_MAPPING
function internalTransfer(address from, address to, uint256 amount) internal {
    _balances[from] -= amount;
    _balances[to]   += amount;
    // BUG: _rBalances are not changed
}
```

#### Root Cause / Invariant Violated

- Violates **INV‑003 (Functional consistency between `_balances` and `_rBalances`)**.
- May also break conservation if `_rBalances` underlie share conversion for vaults.

#### Detection Heuristics

- Grep:

  - `"_balances["` and `"_rBalances["`; flag any function that touches one but not the other.
  - Look for rebasing / scaling factor that is applied inconsistently.

- Static checks:

  - Dataflow: track all writes to `_balances` and `_rBalances`; require some relation or co-occurrence pattern.

#### Property Tests & Fuzz Targets

- Invariant test:

```solidity
// NEEDS_MAPPING
function invariant_INV_003_DualBalanceLink() public {
    for (uint256 i; i < actors.length; ++i) {
        address a = actors[i];
        uint256 b = werc.balanceOf(a);
        uint256 rb = werc.rBalanceOf(a); // NEEDS_MAPPING interface
        // At minimum, enforce that either mapping is never "behind"
        assertTrue(rb >= b, "raw balance must cover logical balance");
    }
}
```

- Fuzz on all public methods that can change balances: `transfer`, `batchTransfers`, async `claim`, etc.

#### Minimal Exploit Recipe

Preconditions:

- There exists at least one function path that updates `_balances` only.
- Some other function converts `_rBalances` to assets (e.g. redemption).

Steps:

1. Attack path A:  
   Use the flawed function to inflate `_balances[attacker]` without increasing `_rBalances[attacker]`.

2. Attack path B:  
   Use another function that **reads only `_balances`** when determining transfer or redemption entitlements (e.g. `transfer`, `redeemExactShares`).

3. Extract underlying assets or shares using inflated logical balance.

Gain model:

- Profit ≈ `inflationFactor × vaultAssetPrice` minus any protocol or FX fees.

#### Proof Artifacts

- Test path: `test/WERC7575/DualBalanceDesync.t.sol::test_DualBalance_Desync_Exploit` (NEEDS_MAPPING)
- Command:

  ```bash
  forge test --match-test test_DualBalance_Desync_Exploit -vvv
  ```

#### Severity

- **Severity:** Critical  
- **Justification:** Enables minting unbacked claims or locking honest users by creating unredeemable reserves.

---

### C.3 Async Request Double-Claim / Skipped State

- **Name:** C3 – Async Request Double-Claim
- **Category:** ACCOUNTING / LOGIC

Short description: Incorrect state transitions for async requests (deposit/redeem) can allow the same `requestId` to be claimed multiple times or to bypass Pending → Claimable → Claimed sequencing, enabling free shares or free redemptions.[4]

#### Pattern

Predicate:

- Exists async request handling logic similar to ERC‑7540 where:

  - A request moves from Pending → Claimable without enforcing a one-time transition; OR
  - `claim()` does not atomically and permanently mark the request as Claimed.

Pseudocode (NEEDS_MAPPING):

```solidity
// file: NEEDS_MAPPING
enum RequestState { None, Pending, Claimable } // missing Claimed

struct Request { 
    address controller;
    uint256 assets;
    uint256 shares;
    RequestState state;
}

function fulfillDeposit(uint256 id, uint256 shares) external {
    Request storage r = requests[id];
    require(r.state == RequestState.Pending, "bad state");
    r.shares = shares;
    r.state = RequestState.Claimable;
    // missing: event, replay protection
}

function depositClaim(uint256 id, address receiver) external {
    Request storage r = requests[id];
    require(r.state == RequestState.Claimable, "not claimable");

    _mint(receiver, r.shares);
    // BUG: r.state is never changed to Claimed or reset.
}
```

#### Root Cause / Invariant Violated

- Violates **INV‑004 (Each async request can be consumed at most once)**.
- Violates **INV‑005 (Requests must not skip Pending or Claimable states)**.

#### Detection Heuristics

- Grep:

  - `enum RequestState` or similar.
  - `requestDeposit`, `requestRedeem`, `claim`, `fulfill`.

- Check that:

  - There is an explicit terminal state (Claimed / Cancelled).
  - `claim` and `cancel` functions always transition state to terminal and cannot revert to Claimable.

#### Property Tests & Fuzz Targets

- Invariant:

```solidity
// NEEDS_MAPPING
function invariant_INV_004_RequestNonRepeatable() public {
    // For any requestId, track number of successful claims
    // We expect at most 1
}
```

- Fuzz target:

```solidity
function testFuzz_doubleClaim(uint256 assets) public {
    // 1. controller requests deposit
    // 2. manager fulfills
    // 3. attacker calls claim twice
    // Expect: second claim reverts
}
```

#### Minimal Exploit Recipe

Preconditions:

- `depositClaim` (or `redeemClaim`) does not mark request as consumed.

Steps:

1. Make or front-run a legit `requestDeposit` for a victim (or self).
2. Wait until `fulfillDeposit` sets state to Claimable.
3. Call `depositClaim(id, attacker)` repeatedly until some safety bound is hit.
4. Each call mints `shares` to attacker.

Post-state:

- Attacker's `vaultBalance` inflated by `N × request.shares`.
- Underlying assets backing shares may be insufficient, leading to later insolvency.

#### Proof Artifacts

- Test path: `test/WERC7575/AsyncDoubleClaim.t.sol::test_Async_Deposit_DoubleClaim` (NEEDS_MAPPING)

#### Severity

- **Severity:** Critical  
- **Justification:** Unlimited share or asset minting with essentially no capital.

---

### C.4 Async Fulfill Without Snapshot → Price / FX Race

- **Name:** C4 – Async Fulfill Price Race
- **Category:** ORACLE / ECONOMIC

Short description: If fulfillment uses **current** vault price / FX state rather than a snapshot from request time, an attacker can manipulate conditions between request and fulfill, extracting value from honest users.[3][4]

#### Pattern

Pseudocode (NEEDS_MAPPING):

```solidity
function fulfillDeposit(uint256 id) external onlyManager {
    Request storage r = requests[id];
    require(r.state == Pending);

    uint256 shares = previewDeposit(r.assets); // uses CURRENT price
    r.shares = shares;
    r.state = Claimable;
}
```

- If `previewDeposit` is manipulable (e.g. by attacker deposits just-in-time, or by oracles), attacker can create deposits at artificially low or high prices, then arbitrage.

#### Root Cause / Invariant Violated

- Violates **INV‑006 (Request valuation must be consistent with commitment time)**.
- Async standards emphasize clear semantics, but snapshotting remains implementation-specific.[4]

#### Detection Heuristics

- Look for:

  - `previewDeposit(request.assets)` or `convertToShares(request.assets)` inside `fulfill*`.
  - Absence of saved `priceAtRequest` or equivalent snapshot.

#### Property Tests & Fuzz Targets

- Fuzz scenario:

  1. User A makes `requestDeposit` when price is fair.
  2. Attacker manipulates price (e.g. deposit/withdraw or oracle).
  3. Manager calls `fulfillDeposit`.
  4. Compare actual shares to expected shares at request time.

- Invariant:

  - For any two users making equal `requestDeposit` at same block, they must receive equal shares regardless of later manipulations.

#### Minimal Exploit Recipe

Preconditions:

- Manager's `fulfillDeposit` uses current price.
- Attacker can manipulate vault price before manager calls fulfill.

Steps:

1. Observe large pending deposit by user A.
2. Manipulate vault:

   - Deposit large amount to skew price; or
   - Manipulate FX or telecom revenue oracle.

3. When price favorable, trigger `fulfillDeposit(id)` via manager or front-end.
4. Immediately reverse manipulation (withdraw / unwind) to restore price.

Gain model:

- Attacker captures difference between artificially favorable share price and true price.

#### Proof Artifacts

- Test path: `test/WERC7575/AsyncPriceRace.t.sol::test_Async_Fulfill_PriceManipulation` (NEEDS_MAPPING)

#### Severity

- **Severity:** High  
- **Justification:** Economic drain and fairness violation; typically bounded but can be large for big deposits.

---

### C.5 Permit Replay Across Vaults / Assets

- **Name:** C5 – Cross-Vault Permit Replay
- **Category:** ACCESS_CONTROL / AUTHENTICATION

Short description: If permit-style signatures are reusable across vaults, assets, or chains due to insufficient domain separation or nonce scoping, an attacker can replay a valid permit in another context to move funds or approvals.

#### Pattern

Pseudocode (NEEDS_MAPPING):

```solidity
// domainSeparator excludes vault or asset
bytes32 public constant PERMIT_TYPEHASH =
    keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

function permit(
    address owner,
    address spender,
    uint256 value,
    uint256 deadline,
    uint8 v, bytes32 r, bytes32 s
) external {
    // digest omits vaultId or asset
    bytes32 digest = keccak256(abi.encodePacked(
        "\x19\x01",
        domainSeparator,
        keccak256(abi.encode(
            PERMIT_TYPEHASH,
            owner,
            spender,
            value,
            nonces[owner]++, // global across vaults
            deadline
        ))
    ));

    // if ShareToken is shared across multiple vaults, this can be replayed
}
```

#### Root Cause / Invariant Violated

- Violates **INV‑007 (Permit signatures must be unique per {owner, context, nonce})**.
- EIP‑2612-style permits rely on correct domain separation; multi-asset setups require extra care.[2][1]

#### Detection Heuristics

- Check that:

  - `domainSeparator` includes chain ID and contract address.
  - If share token covers multiple vaults, either:

    - Nonces scoped per vault; or
    - Vault ID included in signed struct.

- Grep for:

  - `"Permit("`
  - `"nonces[owner]"` without vault scoping.

#### Property Tests & Fuzz Targets

- Fuzz:

  - Generate a valid permit for vault A.
  - Attempt to reuse signature on vault B or other asset flows.
  - Expect revert.

- Invariant:

  - For any two distinct operations \(\mathcal{O}_1, \mathcal{O}_2\) with same signature bytes, at most one can succeed.

#### Minimal Exploit Recipe

Preconditions:

- Shared `ShareToken` and nonces keyed only by `owner`.
- Permit does not bind to `vaultId` or asset.

Steps:

1. User signs `permit` with `spender = router` and `value = X` for vault A.
2. Attacker obtains signature (legit use or leakage).
3. Attacker passes same signature to a `permitTransfer` targeting vault B, where user holds more valuable assets.
4. Router or settlement core honors it, moving funds from vault B.

Gain model:

- Profit ≈ difference in values between contexts / assets.

#### Proof Artifacts

- Test path: `test/WERC7575/PermitReplay.t.sol::test_Permit_CrossVault_Replay` (NEEDS_MAPPING)

#### Severity

- **Severity:** High  
- **Justification:** Can drain users' positions across multiple vaults if any one context leaks signature.

---

### C.6 Permit-Based Transfer "Infinite Approval" to Relayers

- **Name:** C6 – Relayer Infinite Approval
- **Category:** ACCESS_CONTROL

Short description: If permit-based transfers allow an unbounded `value` or do not distinguish between one-shot and reusable permits, relayers can be granted unlimited spending rights unintentionally.

#### Pattern

- Permit sets `allowance[owner][relayer] = type(uint256).max` without UI or protocol-level cap.
- No per-relayer limits or revocation functions convenient for users.

#### Root Cause / Invariant Violated

- Violates **least privilege** principle; not a pure mathematical invariant but a strong security posture property.

#### Detection Heuristics

- Grep for `type(uint256).max` around allowances or permit.
- Look for absence of:

  - `revokePermit` / `cancelNonce` functions.

#### Property Tests & Fuzz Targets

- Test that:

  - Giving a permit of `value = V` does not silently convert to `maxUint`.
  - Revocation clears allowance as expected.

#### Minimal Exploit Recipe

Preconditions:

- User approves "router" or "relayer" via permit for convenience.
- Router contract or its key is compromised, or router delegates to a malicious relayer.

Steps:

1. Malicious relayer calls `transferFrom(owner, attacker, largeValue)` repeatedly until full user balance drained.
2. No on-chain mitigation except user revoking or moving funds (if they have time).

#### Proof Artifacts

- Test path: `test/WERC7575/PermitInfiniteApproval.t.sol::test_Permit_Unbounded_Risk` (NEEDS_MAPPING)

#### Severity

- **Severity:** Medium  
- **Justification:** Dangerous but standard EOA/allowance risk; many users accept such tradeoff in DeFi.

---

### C.7 Reentrancy in Batch or Async Flows

- **Name:** C7 – Reentrancy in `batchTransfers` / `claim`
- **Category:** REENTRANCY

Short description: If the protocol calls into user-supplied hooks (e.g., ERC777-like, onReceive, or callback to telecom route settlement contracts) before finalizing updates to `_balances` / `_rBalances` / request state, reentrancy can produce double credits or bypass checks.

#### Pattern

Pseudocode (NEEDS_MAPPING):

```solidity
function _credit(address to, uint256 amount) internal {
    _balances[to] += amount;

    if (isContract(to)) {
        IHook(to).onCredit(msg.sender, amount); // external call
    }
}
```

- If `onCredit` can call back into `batchTransfers` or `claim`, state may not yet be consistent.

#### Root Cause / Invariant Violated

- Violates checks-effects-interactions (CEI) pattern.
- Breaks invariants INV‑001, INV‑003, INV‑004 if reentrancy hits batch or async flows.
#### Detection Heuristics

- Grep for external calls to arbitrary `to` or `hook` in code that also mutates balances.
- Check for:

  - `nonReentrant` modifiers on `batchTransfers`, `claim`, `request*`.

#### Property Tests & Fuzz Targets

- Use reentrancy tester contract that calls back into vulnerable function while in hook.

```solidity
contract MaliciousReceiver {
    IWERC7575Batch public werc;

    function onCredit(address, uint256) external {
        // Reenter
        werc.batchTransfers(...); // NEEDS_MAPPING
    }
}
```

#### Minimal Exploit Recipe

Preconditions:

- SettlementCore or Vault calls `onCredit` / `onClaim` hook on arbitrary contracts.
- No `nonReentrant` guard or structured lock.

Steps:

1. Attacker deploys `MaliciousReceiver` as above.
2. Sets it as receiver in `batchTransfers` or `claim`.
3. On first credit, reenters before conservation constraints finalize; obtains multiple credits or manipulates request states.

#### Proof Artifacts

- Test path: `test/WERC7575/ReentrancyBatch.t.sol::test_Reentrancy_BatchTransfers` (NEEDS_MAPPING)

#### Severity

- **Severity:** Critical  
- **Justification:** Classic double-spend or arbitrary balance inflation.

---

### C.8 Role / Governance Misconfiguration

- **Name:** C8 – Role Centralization (Validator / Manager / KYC)
- **Category:** ACCESS_CONTROL

Short description: Single EOA, or weakly secured multisigs, controlling validators, vault managers, or KYC registries can arbitrarily mint, freeze, or misprice positions.

#### Pattern

- Direct ownership:

  ```solidity
  address public validator; // single EOA
  ```

- No timelock or multi-approval for:

  - Changing validator.
  - Upgrading contracts.
  - Draining funds via emergency paths.

#### Root Cause / Invariant Violated

- Violates **INV‑008 (Trusted roles must be constrained and auditable)** from an operational security standpoint.

#### Detection Heuristics

- Inspect `onlyOwner`, `onlyRole`, `onlyManager` modifiers on high-impact functions:

  - `fulfillDeposit`, `fulfillRedeem`
  - `setValidator`, `setRateCard`, `setFXOracle`
  - `pause`, `emergencyWithdraw`

#### Property Tests & Fuzz Targets

- Ensure that:

  - Non-privileged accounts can never call critical functions.
  - Privileged actions are limited by parameter bounds.

#### Minimal Exploit Recipe

- Operational attack, not purely technical; but if any privileged function allows direct transfer of all assets, on-chain attacker with compromised keys can drain system in one tx.

#### Severity

- **Severity:** High  
- **Justification:** Centralized failure point, particularly acute in RWA telecom context.

---

### C.9 Reserve Mismatch Between Vault Assets and Settlement Layer

- **Name:** C9 – Reserve Mismatch
- **Category:** ACCOUNTING / ECONOMIC

Short description: If sums of vault assets, protocol fees, and telecom receivable valuations do not match total user claims computed from `_balances` / `_rBalances`, vault can become under/over-collateralized.

#### Pattern

- No global invariant across:

  - Vault `totalAssets`, `totalSupply`.
  - Sum of `_balances` mapped to share token.
  - Off-chain receivables or pending settlements.

#### Root Cause / Invariant Violated

- Violates **INV‑009 (Global reserve sufficiency)**.

#### Detection Heuristics

- Cross-contract review essential:

  - SettlementCore vs Vault vs OracleGateway.

#### Property Tests & Fuzz Targets

- Fuzz long sequences of:

  - Deposits, redemptions, telecom settlements, fee accrual, rebases.

- Invariant function checks:

  - `vault.totalAssets() + protocolFees >= valueOfAllBalances`.

#### Minimal Exploit Recipe

- Typically not directly exploitable by a single on-chain actor, but:

  - Combined with C1/C2/C3 can allow targeted insolvency or socialization of losses.

#### Severity

- **Severity:** High  
- **Justification:** Systemic solvency risk and RWA investor losses.

---

### C.10 Upgradeability / Proxy Misconfig

- **Name:** C10 – Upgrade Hijack
- **Category:** UPGRADE

Short description: Misconfigured proxies or missing access control on `upgradeTo` can allow malicious implementation upgrades.

#### Pattern

- Proxy admin is EOA with no multi-sig or timelock.
- Storage collisions between implementation versions.

#### Root Cause / Invariant Violated

- Violates **INV‑010 (Code immutability or safe upgrade discipline)**.

#### Detection Heuristics

- Look for `TransparentUpgradeableProxy`, `UUPS`, or `delegatecall` with admin roles.

#### Severity

- **Severity:** High  

---

## D. Protocol-Wide Invariants

All invariants are conceptual; they MUST be implemented against real state variables in WERC7575.

### INV‑001 – Conservation of Value in Batch Netting

- **Formal expression:**

  \[
  \sum_{a \in Accounts} \_balances_{\text{after}}[a] = 
  \sum_{a \in Accounts} \_balances_{\text{before}}[a]
  \]

  for any pure settlement call (no external injection/removal of capital), e.g. `batchTransfers()`.

- **Mapping to flows:**

  - `batchTransfers()`
  - Internal multi-leg settlement routines in routers.

- **Breakpoints:**

  - `batchTransfers`
  - Any internal `_applyNetting` and `_multiTransfer` (NEEDS_MAPPING).

- **Foundry invariant stub:**

```solidity
// NEEDS_MAPPING
contract INV001_Conservation is Test {
    IWERC7575Batch werc;
    address[] actors;
    uint256 initialTotal;

    function setUp() public {
        // record initialTotal over actors
    }

    function invariant_INV_001() public {
        uint256 total;
        for (uint256 i; i < actors.length; ++i) {
            total += werc.balanceOf(actors[i]);
        }
        assertEq(total, initialTotal, "batch netting must conserve total balances");
    }
}
```

---

### INV‑002 – Non-Negative Balances

- **Expression:**

  \[
  \forall a: \_balances[a] \ge 0 \land \_rBalances[a] \ge 0
  \]

- **Mapping:**

  - All transfer, batch, async claim and redeem functions.

- **Breakpoints:**

  - `transfer`, `transferFrom`
  - `batchTransfers`
  - `depositClaim`, `redeemClaim`

---

### INV‑003 – Dual Balance Consistency

- **Expression:**

  There exists a function \(f\) such that:

  \[
  \forall a: \_balances[a] = f(\_rBalances[a], GlobalState)
  \]

  and this relation holds before and after any state transition affecting balances.

- **Mapping:**

  - Rebase routines; global scaling factor updates.
  - Any function mutating `_rBalances`.

---

### INV‑004 – Single Use of Async Requests

- **Expression:**

  \[
  \forall id: \text{claimsCount}(id) \le 1
  \]

- **Mapping:**

  - Async deposit and redeem flows.

- **Breakpoints:**

  - `fulfillDeposit`, `depositClaim`
  - `fulfillRedeem`, `redeemClaim`

---

### INV‑005 – Valid Request State Transitions

- **Expression:**

  State machine must be:

  - `None → Pending → Claimable → Claimed | Cancelled`

  with no other transitions.

- **Mapping:**

  - Request functions and any emergency/cancel paths.

---

### INV‑006 – Time-Consistent Valuation

- **Expression:**

  For a given request \(id\),

  \[
  shares_{id} = g(assets_{id}, PriceSnapshot_{t_{request}})
  \]

  not \(g(assets_{id}, Price_{t_{fulfill}})\), unless protocol explicitly discloses this semantic and mitigates manipulation.

---

### INV‑007 – Nonce & Domain Separation for Permits

- **Expression:**

  \[
  \forall \text{sig}: \text{if } \text{verify(sig)} \text{ succeeds for context } C_1, \text{ it fails for any } C_2 \ne C_1
  \]

  Where context includes contract address, chain ID, vault ID, and asset.

---

### INV‑008 – Constrained Privilege

- **Expression:**

  For any privileged function \(f\):

  - \(f\) is callable only by correct roles; and
  - There are no paths where external actors without roles can force-call \(f\).

---

### INV‑009 – Reserve Sufficiency

- **Expression:**

  \[
  \sum_{\text{vaults}} totalAssets_v + protocolFees \ge
  \sum_{a} value(\_balances[a])
  \]

- **Mapping:**

  - Entire cross-contract system.

---

### INV‑010 – Safe Upgrades

- **Expression:**

  - Only authorized admin can change implementation.
  - Storage layouts must be forward-compatible (no slot clashes).

---

## E. Cross-Contract Failure Modes

### Sequence-001 – Share Token vs Vault Desync (Multi-Asset ERC‑7575)

- **Steps (A → B → C):**

  1. **A – Vault** updates internal `totalAssets` / `totalShares` after telecom settlement.
  2. **B – ShareToken** (externalized ERC‑20 per ERC‑7575) mints/burns based on vault data.[1][2]
  3. **C – SettlementCore** reads `_balances` (share-denominated) and uses them for telecom batch settlement.

- **Desync Window:**

  - If Vault and ShareToken are updated in separate transactions or without atomicity, SettlementCore may operate on stale or inconsistent share balances.

- **Attack Simulation:**

  - Attacker times operations to mint/burn shares around telecom settlement events so that:

    - Vault sees one supply; SettlementCore sees another; or
    - Off-chain receivables update is applied only to some layers.

- **Hard Fixes:**

  - Use atomic operations or **snapshots** of share supply when performing telecom netting.
  - Ensure ShareToken implements ERC‑165 interface and strict handshake with Vault as per ERC‑7575.[1]
  - Apply CEI around any call bridging Vault ↔ ShareToken ↔ SettlementCore.

---

### Sequence-002 – Oracle/Validator → Vault → SettlementCore Misalignment

- **Steps:**

  1. **ValidatorGateway** posts telecom revenue / FX metrics.
  2. **Vault** uses them to reprice shares.
  3. **SettlementCore** uses repriced `_balances` for `batchTransfers` and interest allocations.

- **Desync Window:**

  - Validator update may fail or be delayed, but SettlementCore proceeds with outdated rates.

- **Attack Simulation:**

  - Attacker front-runs known oracle updates (e.g. new telecom rate card) with deposit or withdrawal operations, exploiting stale valuations.

- **Hard Fixes:**

  - Enforce maximum staleness window for oracle data.
  - Potentially **block** batch netting when validator data out-of-date.

---

### Sequence-003 – KYC Registry vs Async Requests

- **Steps:**

  1. User passes KYC and is whitelisted.
  2. User submits `requestDeposit`.
  3. KYC is later revoked (e.g., due to sanctions).
  4. Manager calls `fulfillDeposit`; user still can `claim`.

- **Desync Window:**

  - KYC gating might be applied only at `requestDeposit` time, not at `claim` or `redeem`.

- **Attack Simulation:**

  - Malicious user quickly requests large deposit before KYC revocation, then claims after being removed, effectively bypassing sanctions.

- **Hard Fixes:**

  - KYC check on **every** economically relevant action, not just initial request.
  - Store KYC status snapshot at request time and legal policy whether to honor or cancel.

---

## F. Attack Templates

Each template maps onto patterns above. All function names not explicitly given in the prompt are conceptual and **NEEDS_MAPPING**.

### F.1 Batch Netting Break (C1)

- **Preconditions:**

  - `batchTransfers()` implementation lacks strict sum equality / length checks.
  - Attacker with some non-zero `_balances`.

- **Step-by-Step Exploit:**

  1. Identify minimal set of counterparties in telephony routes where attacker is both sender and receiver.
  2. Craft `senders`, `receivers`, `deltas` such that:

     - `deltas` shape exploits any off-by-one, length mismatch, or sign logic bug.
     - Total credited > total debited.

  3. Call `batchTransfers()` via attacker-controlled router or partner.

- **Breakpoints:**

  - `SettlementCore.batchTransfers` implementation (file: NEEDS_MAPPING, line: NEEDS_MAPPING).

- **Gain Model:**

  - Let `Δ` be net positive amount the attacker can manufacture.  
    Profit per execution: \( \text{profit} = Δ \times P_{\text{unit}} \), where \(P_{\text{unit}}\) is the current pricing of telecom credits in on-chain terms.

- **Mitigations + Code Patch:**

  Pseudocode patch (NEEDS_MAPPING):

  ```solidity
  function batchTransfers(
      address[] calldata senders,
      address[] calldata receivers,
      int256[] calldata deltas
  ) external {
      uint256 len = senders.length;
      require(len == receivers.length && len == deltas.length, "length mismatch");

      int256 totalDelta;

      for (uint256 i; i < len; ++i) {
          int256 d = deltas[i];
          totalDelta += d;

          if (d > 0) {
              _debit(senders[i], uint256(d));
              _credit(receivers[i], uint256(d));
          } else if (d < 0) {
              _debit(receivers[i], uint256(-d));
              _credit(senders[i], uint256(-d));
          }
      }

      require(totalDelta == 0, "non-zero net delta");
  }
  ```

  Ensure `_debit` / `_credit` preserve `_balances` / `_rBalances` invariants.

---

### F.2 Dual Balance Desync (C2)

- **Preconditions:**

  - At least one flow updates `_balances` only.

- **Steps:**

  1. Locate functions where `_balances` is modified but `_rBalances` is untouched.
  2. Use those functions repeatedly to inflate `_balances[attacker]`.
  3. Use functions that rely solely on `_balances` for entitlement (e.g. telecom redemption or on-chain liquidation) to cash out.

- **Breakpoints:**

  - Internal transfer / netting functions (file: NEEDS_MAPPING).

- **Gain Model:**

  - Profit is any gap created between `_balances` and backing reserves.

- **Mitigations:**

  - Wrap all balance updates in a single internal function that manipulates both mappings consistently.
  - Consider eliminating `_rBalances` if unnecessary.

---

### F.3 Async Double-Claim (C3)

- **Preconditions:**

  - `depositClaim`/`redeemClaim` fails to set terminal state.

- **Steps:**

  1. Observe or create a large `requestDeposit`.
  2. Wait for manager to `fulfillDeposit`.
  3. Call `depositClaim` repeatedly, each time specifying `receiver = attacker`.

- **Breakpoints:**

  - `AsyncRequestHub.depositClaim` logic (file: NEEDS_MAPPING).

- **Gain Model:**

  - \( profit ≈ (N - 1) × shares_{id} × P_{\text{share}} \)

- **Mitigations / Patch:**

  ```solidity
  function depositClaim(uint256 id, address receiver) external {
      Request storage r = requests[id];
      require(r.state == RequestState.Claimable, "not claimable");

      r.state = RequestState.Claimed; // set BEFORE external actions
      _mint(receiver, r.shares);
  }
  ```

---

### F.4 KYC Bypass via Async Flow (Sequence‑003)

- **Preconditions:**

  - KYC checked at `requestDeposit`, not at `claim`.

- **Steps:**

  1. As soon as whitelisted, attacker submits max-size `requestDeposit`.
  2. KYC revoked by off-chain controllers (e.g., due to suspicion).
  3. Manager fulfills deposit; attacker calls `depositClaim` to get shares despite KYC revocation.

- **Gain Model:**

  - Ability to preserve positions or cash out after losing compliance; regulatory / reputational damage.

- **Mitigations:**

  - Add KYC checks in `claim` and `redeem`.
  - Optionally, if KYC revoked, enforce forced cancellation and return of underlying assets.

---

### F.5 Permit Replay (C5)

- **Preconditions:**

  - Domain separator or typed struct does not bind to vault ID.

- **Steps:**

  1. Victim signs permit for context A.
  2. Attacker reuses signature in context B (different share token/vault).
  3. Drains victim's positions across contexts.

- **Mitigations / Patch:**

  Pseudocode (NEEDS_MAPPING):

  ```solidity
  bytes32 public constant PERMIT_TYPEHASH =
      keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline,bytes32 vaultId)");

  function permit(
      address owner,
      address spender,
      uint256 value,
      uint256 deadline,
      bytes32 vaultId,
      uint8 v, bytes32 r, bytes32 s
  ) external {
      bytes32 structHash = keccak256(abi.encode(
          PERMIT_TYPEHASH,
          owner,
          spender,
          value,
          nonces[owner][vaultId]++,
          deadline,
          vaultId
      ));
      // ...
  }
  ```

---

### F.6 Async Price Race (C4)

- **Preconditions:**

  - `fulfillDeposit` uses latest price instead of snapshot.

- **Steps:**

  1. Monitor mempool for large `requestDeposit`.
  2. Create or remove large positions to push price to an extreme.
  3. Trigger or wait for `fulfillDeposit`.
  4. Reverse manipulation.

- **Mitigations:**

  - Store `priceAtRequest` (or equivalent telephony receivable valuation) when request is created.
  - Use it at fulfill time.

---

### F.7 Reentrancy in Batch or Claim (C7)

- **Preconditions:**

  - Hooks or external calls within core methods, no `nonReentrant`.

- **Steps:**

  1. Deploy malicious contract with callback to reenter.
  2. Use it as receiver in `batchTransfers` or `claim`.
  3. On callback, perform additional transfers/claims before state stabilizes.

- **Mitigations:**

  - Apply `nonReentrant` to critical methods.
  - Use CEI strictly: update state before external calls.

---

### F.8 Reserve Mismatch (C9) Combined with Other Bugs

- **Preconditions:**

  - No system-wide reserve invariant.

- **Steps:**

  1. Combine any of C1–C3 with asynchronous or multi-asset flows to siphon reserves undetected.
  2. Exploit the mismatch before monitoring or off-chain reconciliation.

- **Mitigations:**

  - Implement cross-contract invariant checks (see Section D).
  - Add periodic on-chain solvency assertions driven by governance.

---

## G. Testing & Repro Artifacts

Below are **runnable Foundry test stubs** and one Ethers.js script skeleton. Every interface, address, and selector is marked NEEDS_MAPPING and must be wired to the real WERC7575 deployment or local deployment.

### G.1 Foundry Test: Batch Netting Break (C1)

```solidity
// test/WERC7575/BatchNettingAttack.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

// NEEDS_MAPPING
interface IWERC7575Core {
    function batchTransfers(
        address[] calldata senders,
        address[] calldata receivers,
        int256[] calldata deltas
    ) external;
    function balanceOf(address account) external view returns (uint256);
}

contract BatchNettingAttackTest is Test {
    IWERC7575Core internal core;
    address internal attacker;
    address internal victim;

    function setUp() public {
        attacker = address(0xA11CE);
        victim = address(0xBEEF);
        // NEEDS_MAPPING: deploy or bind core, set balances
    }

    function test_BatchNettingBreak_Critical() public {
        uint256 beforeTotal = core.balanceOf(attacker) + core.balanceOf(victim);

        address[] memory senders = new address[](2);
        address[] memory receivers = new address[](2);
        int256[] memory deltas = new int256[](2);

        senders[0] = attacker;
        receivers[0] = attacker;
        deltas[0] = int256(100); // CREDIT attacker

        senders[1] = victim;
        receivers[1] = victim;
        deltas[1] = int256(-50); // DEBIT victim (mismatch)

        vm.prank(attacker);
        core.batchTransfers(senders, receivers, deltas);

        uint256 afterTotal = core.balanceOf(attacker) + core.balanceOf(victim);
        assertGt(afterTotal, beforeTotal, "inflation detected");
    }
}
```

**Command:**

```bash
forge test --match-test test_BatchNettingBreak_Critical -vvv
```

---

### G.2 Foundry Test: Dual Balance Desync (C2)

```solidity
// test/WERC7575/DualBalanceDesync.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

// NEEDS_MAPPING
interface IWERC7575Dual {
    function balanceOf(address) external view returns (uint256);
    function rBalanceOf(address) external view returns (uint256);
    function flawedTransfer(address to, uint256 amount) external;
}

contract DualBalanceDesyncTest is Test {
    IWERC7575Dual internal core;
    address internal attacker;

    function setUp() public {
        attacker = address(0xA11CE);
        // NEEDS_MAPPING: bind core, fund attacker
    }

    function test_DualBalance_Desync_Exploit() public {
        uint256 beforeB = core.balanceOf(attacker);
        uint256 beforeRB = core.rBalanceOf(attacker);

        // Act: call flawed function repeatedly
        vm.startPrank(attacker);
        core.flawedTransfer(attacker, 1 ether);
        core.flawedTransfer(attacker, 1 ether);
        vm.stopPrank();

        uint256 afterB = core.balanceOf(attacker);
        uint256 afterRB = core.rBalanceOf(attacker);

        assertGt(afterB, beforeB, "logical balance increased");
        assertEq(afterRB, beforeRB, "raw balance unchanged");
        assertGt(afterB, afterRB, "invariant broken");
    }
}
```

---

### G.3 Foundry Test: Async Double-Claim (C3)

```solidity
// test/WERC7575/AsyncDoubleClaim.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

// NEEDS_MAPPING
interface IWERC7575Async {
    function requestDeposit(uint256 assets) external returns (uint256);
    function fulfillDeposit(uint256 id, uint256 shares) external;
    function depositClaim(uint256 id, address receiver) external;
    function balanceOf(address) external view returns (uint256);
}

contract AsyncDoubleClaimTest is Test {
    IWERC7575Async internal vault;
    address internal attacker;
    address internal manager;

    function setUp() public {
        attacker = address(0xA11CE);
        manager = address(0xMANAGER);
        // NEEDS_MAPPING: bind vault, allocate roles, fund attacker
    }

    function test_Async_Deposit_DoubleClaim() public {
        vm.startPrank(attacker);
        uint256 id = vault.requestDeposit(100 ether);
        vm.stopPrank();

        vm.prank(manager);
        vault.fulfillDeposit(id, 100 ether);

        uint256 before = vault.balanceOf(attacker);

        vm.prank(attacker);
        vault.depositClaim(id, attacker);

        vm.prank(attacker);
        // Expected: revert; if it succeeds, double-claim bug exists
        bool secondClaimSucceeded;
        try vault.depositClaim(id, attacker) {
            secondClaimSucceeded = true;
        } catch {
            secondClaimSucceeded = false;
        }

        uint256 after = vault.balanceOf(attacker);

        assertFalse(secondClaimSucceeded, "double claim should revert");
        assertLe(after - before, 100 ether, "minted more than expected");
    }
}
```

---

### G.4 Foundry Test: Permit Replay Across Vaults (C5)

```solidity
// test/WERC7575/PermitReplay.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

// NEEDS_MAPPING
interface IShareToken {
    function permit(/* params NEEDS_MAPPING */) external;
    function balanceOf(address) external view returns (uint256);
}

contract PermitReplayTest is Test {
    IShareToken internal shareA;
    IShareToken internal shareB;
    address internal owner;
    address internal attacker;

    function setUp() public {
        owner = address(0x0WNER);
        attacker = address(0xA11CE);
        // NEEDS_MAPPING: deploy or bind shareA/shareB with shared domain/nonces
    }

    function test_Permit_CrossVault_Replay() public {
        bytes memory sig = hex"PERMIT_SIG_NEEDS_MAPPING";

        // Use of the same sig in context A
        vm.prank(attacker);
        shareA.permit(/* args NEEDS_MAPPING using sig */);

        uint256 before = shareB.balanceOf(attacker);

        // Replay in context B
        vm.prank(attacker);
        shareB.permit(/* SAME sig in different context */);

        uint256 after = shareB.balanceOf(attacker);

        assertEq(after, before, "cross-vault replay must not change balance");
    }
}
```

---

### G.5 Foundry Test: Reentrancy in BatchTransfers (C7)

```solidity
// test/WERC7575/ReentrancyBatch.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IWERC7575BatchCore {
    function batchTransfers(
        address[] calldata senders,
        address[] calldata receivers,
        int256[] calldata deltas
    ) external;
    function balanceOf(address) external view returns (uint256);
}

// Malicious receiver
contract ReenteringReceiver {
    IWERC7575BatchCore public core;
    address public target;
    bool internal inCallback;

    constructor(IWERC7575BatchCore _core, address _target) {
        core = _core;
        target = _target;
    }

    // NEEDS_MAPPING: hook name and signature
    function onCredit(address, uint256 amount) external {
        if (inCallback) return;
        inCallback = true;

        address[] memory senders = new address[](1);
        address[] memory receivers = new address[](1);
        int256[] memory deltas = new int256[](1);

        senders[0] = target;
        receivers[0] = address(this);
        deltas[0] = int256(amount);

        core.batchTransfers(senders, receivers, deltas);

        inCallback = false;
    }
}

contract ReentrancyBatchTest is Test {
    IWERC7575BatchCore internal core;
    ReenteringReceiver internal recv;
    address internal victim;

    function setUp() public {
        // NEEDS_MAPPING: deploy/bind core and recv
    }

    function test_Reentrancy_BatchTransfers() public {
        uint256 before = core.balanceOf(address(recv));

        // trigger batchTransfers that credits recv and triggers hook

        // NEEDS_MAPPING: craft call that causes onCredit
        // ...

        uint256 after = core.balanceOf(address(recv));
        assertEq(after, before, "should not gain via reentrancy");
    }
}
```

---

### G.6 Ethers.js Script Template: Async Price Race (C4)

```javascript
// scripts/asyncPriceRaceExploit.js
// NEEDS_MAPPING: fill addresses, ABIs

const { ethers } = require("ethers");

async function main() {
  const provider = new ethers.providers.JsonRpcProvider("RPC_URL_NEEDS_MAPPING");
  const attacker = new ethers.Wallet("ATTACKER_PK_NEEDS_MAPPING", provider);

  const vault = new ethers.Contract("VAULT_ADDR_NEEDS_MAPPING", VAULT_ABI, attacker);

  // 1. Observe pending deposit (e.g. via events)
  // 2. Manipulate price: deposit or withdraw to skew valuation
  await vault.deposit(/* large amount, NEEDS_MAPPING */);

  // 3. Trigger fulfillDeposit via manager or wait & front-run
  // 4. Reverse manipulation, then log profit

  console.log("Pre/post state calculations NEEDS_MAPPING");
}

main().catch(console.error);
```

Run:

```bash
node scripts/asyncPriceRaceExploit.
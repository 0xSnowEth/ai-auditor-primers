### Primer Chunk Metadata
Primer: Amy Vault ERC4626
Chunk: 3
Lines approx: 2001-3000
Version: v1.0
Focus: Critical Vulnerability Patterns


            shares
        );
    }
}

// In MetaVault
function _withdraw(..., uint256 baseAssets, ...) internal {
    depositedBase -= baseAssets; // Underflows when baseAssets includes yield
}
```

**Impact**:
- Deposited base tracking becomes corrupted
- Subsequent yield calculations amplify the error
- Attackers can drain entire protocol balance

**Mitigation**:
```solidity
uint256 assetsPlusYield = assets + previewYield(caller, shares);
uint sUSDeAssets = sUSDe.previewWithdraw(assetsPlusYield);
_withdraw(
    address(sUSDe),
    caller,
    receiver,
    owner,
    assets, // Only base assets, not including yield
    sUSDeAssets,
    shares
);
```

### 112. Multi-Vault Withdrawal Failures During Phase Transitions (High)
**Pattern**: Supported vault assets become inaccessible during yield phase due to incorrect withdrawal logic.

**Vulnerable Code Example** (Strata):
```solidity
function _withdraw(address caller, address receiver, address owner, uint256 assets, uint256 shares) internal override {
    if (PreDepositPhase.YieldPhase == currentPhase) {
        // Only handles sUSDe withdrawals
        uint sUSDeAssets = sUSDe.previewWithdraw(assets);
        _withdraw(address(sUSDe), ...);
        return;
    }
    
    // Points phase logic
    uint USDeBalance = USDe.balanceOf(address(this));
    if (assets > USDeBalance) {
        redeemRequiredBaseAssets(assets - USDeBalance);
    }
}
```

**Impact**: Users who deposited via supported vaults cannot withdraw their entitled assets during yield phase.

**Mitigation**: Add logic to handle supported vault withdrawals during yield phase or prevent adding vaults during yield phase.

### 113. Incomplete Multi-Vault Redemption Logic (Medium)
**Pattern**: `redeemRequiredBaseAssets` only withdraws from a vault if that single vault can satisfy the entire requested amount.

**Vulnerable Code Example** (Strata):
```solidity
function redeemRequiredBaseAssets(uint baseTokens) internal {
    for (uint i = 0; i < assetsArr.length; i++) {
        IERC4626 vault = IERC4626(assetsArr[i].asset);
        uint totalBaseTokens = vault.previewRedeem(vault.balanceOf(address(this)));
        if (totalBaseTokens >= baseTokens) { // Only withdraws if single vault sufficient
            vault.withdraw(baseTokens, address(this), address(this));
            break;
        }
    }
}
```

**Impact**:
- Withdrawals fail even when sufficient assets exist across multiple vaults
- Excess assets withdrawn remain unstaked

**Mitigation**: Implement logic to withdraw from multiple vaults and track remaining amount needed.

### 114. Preview Function Violations with Unchecked Reverts (Medium)
**Pattern**: Using `previewRedeem` instead of `maxWithdraw` for availability checks, causing DoS when vaults are paused or have limits.

**Vulnerable Code Example** (Strata):
```solidity
function redeemRequiredBaseAssets(uint baseTokens) internal {
    for (uint i = 0; i < assetsArr.length; i++) {
        IERC4626 vault = IERC4626(assetsArr[i].asset);
        // previewRedeem doesn't account for pause states or limits
        uint totalBaseTokens = vault.previewRedeem(vault.balanceOf(address(this)));
        if (totalBaseTokens >= baseTokens) {
            vault.withdraw(baseTokens, address(this), address(this));
        }
    }
}
```

**EIP-4626 Specification**: `previewRedeem` MUST NOT account for redemption limits and should act as though redemption would be accepted.

**Mitigation**: Use `maxWithdraw()` for availability

### 115. Value Leakage via Rounding Direction Errors (Medium)
**Pattern**: Using `previewWithdraw` (rounds up) to calculate amounts transferred out, causing value leakage.

**Vulnerable Code Example** (Strata):
```solidity
function _withdraw(...) internal override {
    if (PreDepositPhase.YieldPhase == currentPhase) {
        assets += previewYield(caller, shares);
        // previewWithdraw rounds UP (against protocol)
        uint sUSDeAssets = sUSDe.previewWithdraw(assets);
        
        // Transfer this rounded UP amount out
        SafeERC20.safeTransfer(IERC20(token), receiver, sUSDeAssets);
    }
}
```

**Impact**: Each redemption leaks value in favor of redeemer at expense of remaining depositors.

**Mitigation**: Use `convertToShares` which rounds down when calculating transfer amounts.

### 116. Share Price Manipulation via Donation During Yield Phase (Critical)
**Pattern**: `totalAssets()` not accounting for direct token transfers, enabling share price manipulation.

**Vulnerable Code Example** (Strata):
```solidity
function totalAssets() public view override returns (uint256) {
    return depositedBase; // Doesn't account for actual sUSDe balance
}

function previewYield(address caller, uint256 shares) public view returns (uint256) {
    uint total_sUSDe = sUSDe.balanceOf(address(this)); // Sees donated balance
    uint total_USDe = sUSDe.previewRedeem(total_sUSDe);
    uint total_yield_USDe = total_USDe - Math.min(total_USDe, depositedBase);
    // Inflated yield due to donations
}
```

**Attack Scenario**:
1. Deposit minimal amount when vault empty
2. Donate large sUSDe amount directly
3. Yield calculations see inflated balance
4. New depositors get fewer shares

**Mitigation**: Include actual token balances in `totalAssets()` during yield phase.

**Cross References**: See also #363 for meta vault variant.

### 117. Minimum Shares Protection Bypass in Multi-Vault (High)
**Pattern**: Alternative withdrawal paths that bypass minimum shares checks.

**Vulnerable Code Example** (Strata):
```solidity
// MetaVault withdrawal doesn't check minimum shares for non-base assets
function _withdraw(address token, ...) internal virtual {
    SafeERC20.safeTransfer(IERC20(token), receiver, tokenAssets);
    onAfterWithdrawalChecks(); // Only checks when withdrawing base asset
}

function onAfterWithdrawalChecks() internal view {
    if (totalSupply() < MIN_SHARES) {
        revert MinSharesViolation();
    }
}
```

**Impact**: First depositor attack protection can be bypassed via meta vault paths.

### 118. Cross-Function Reentrancy in State Updates (Medium)
**Pattern**: State updates split across multiple operations without reentrancy protection.

**Vulnerable Code Example** (Strata):
```solidity
function _deposit(address token, ...) internal virtual {
    depositedBase += baseAssets; // State update 1
    SafeERC20.safeTransferFrom(IERC20(token), caller, address(this), tokenAssets); // External call
    _mint(receiver, shares); // State update 2
}
```

**Impact**: ERC777 tokens or tokens with hooks can reenter between state updates.

### 119. Hardcoded Slippage Parameters (Medium)
**Pattern**: Fixed slippage tolerance that cannot adapt to market conditions.

**Vulnerable Code Example** (Strata):
```solidity
uint256 amountOutMin = (amount * 999) / 1000; // Only 0.1% slippage protection
```

**Impact**: DoS during high volatility or value loss during normal conditions.

### 120. Incorrect Function Routing in Multi-Level Calls (Low)
**Pattern**: Calling wrong function variant in vault hierarchies.

**Vulnerable Code Example** (Strata):
```solidity
function redeem(address token, uint256 shares, address receiver, address owner) public returns (uint256) {
    if (token == asset()) {
        return withdraw(shares, receiver, owner); // Should call redeem, not withdraw
    }
}
```

### 121. Duplicate Vault Array Entries (Low)
**Pattern**: Allowing duplicate entries in tracking arrays causing iteration issues.

**Vulnerable Code Example** (Strata):
```solidity
function addVaultInner(address vaultAddress) internal {
    TAsset memory vault = TAsset(vaultAddress, EAssetType.ERC4626);
    assetsMap[vaultAddress] = vault;
    assetsArr.push(vault); // No duplicate check
}
```

**Impact**: Gas waste, potential DoS, and removal failures.

### 122. Missing Asset Validation in Multi-Vault Systems (Low)
**Pattern**: Not validating that added vaults share the same underlying asset.

**Vulnerable Code Example** (Strata):
```solidity
function addVaultInner(address vaultAddress) internal {
    // No check that IERC4626(vaultAddress).asset() == asset()
    TAsset memory vault = TAsset(vaultAddress, EAssetType.ERC4626);
    assetsMap[vaultAddress] = vault;
}
```

**Impact**: Accounting corruption if vaults with different assets are added.

### 123. Phase Transition State Inconsistencies (Low)
**Pattern**: Removing vault support during phase transitions without clear reasoning.

**Vulnerable Code Example** (Strata):
```solidity
function startYieldPhase() external onlyOwner {
    setYieldPhaseInner();
    redeemMetaVaults(); // Also removes all vault support
    // But vaults can be re-added immediately after
}
```

### 124. EIP-4626 Compliance Violations in View Functions (Low)
**Pattern**: Max functions not accounting for pause states as required by EIP-4626.

**Vulnerable Code Example** (Strata):
```solidity
// Doesn't return 0 when withdrawals disabled as required by EIP-4626
function maxWithdraw(address owner) public view override returns (uint256) {
    return previewRedeem(balanceOf(owner));
    // Should check: if (!withdrawalsEnabled) return 0;
}
```

**Impact**: Integration failures with protocols expecting EIP-4626 compliance.

### 125. Storage Layout Risks in Upgradeable Contracts (Low)
**Pattern**: Upgradeable contracts without proper storage layout protection.

**Vulnerable Code Example** (Strata):
```solidity
abstract contract MetaVault is IMetaVault, PreDepositVault {
    uint256 public depositedBase;
    TAsset[] public assetsArr;
    mapping(address => TAsset) public assetsMap;
    // No storage gaps or ERC7201 namespacing
}
```

**Mitigation**: Use ERC7201 namespaced storage or storage gaps.

### 126. ERC4626 Vault Fee Bypass (Critical)
**Pattern**: Protocol doesn't transfer enough tokens from users to cover ERC4626 vault deposit/withdrawal fees.

**Vulnerable Code Example** (Burve):
```solidity
function addValue(...) external returns (uint256[MAX_TOKENS] memory requiredBalances) {
    // ...
    uint256 realNeeded = AdjustorLib.toReal(token, requiredNominal[i], true);
    requiredBalances[i] = realNeeded;
    TransferHelper.safeTransferFrom(token, msg.sender, address(this), realNeeded);
    Store.vertex(VertexLib.newId(i)).deposit(cid, realNeeded); // Fees charged here!
}
```

**Impact**:
- Users can avoid paying vault fees
- Protocol becomes undercollateralized
- Last users suffer losses when withdrawing

**Cross References**: Related to totalAssets misreporting in #363.

**Mitigation**: Calculate and transfer additional tokens to cover vault fees.

### 127. Adjustor Implementation Reversal (High)
**Pattern**: `toNominal` and `toReal` functions implemented backwards in ERC4626ViewAdjustor.

**Vulnerable Code Example** (Burve):
```solidity
function toNominal(address token, uint256 real, bool) external view returns (uint256 nominal) {
    IERC4626 vault = getVault(token);
    return vault.convertToShares(real); // WRONG: Should use convertToAssets
}

function toReal(address token, uint256 nominal, bool) external view returns (uint256 real) {
    IERC4626 vault = getVault(token);
    return vault.convertToAssets(nominal); // WRONG: Should use convertToShares
}
```

**Impact**: Users deposit more LST tokens than required, causing significant losses.

**Mitigation**: Reverse the implementation of the two functions.

### 128. Netting Logic Error in Vault Withdrawals (High)
**Pattern**: Incorrect netting calculation when both deposits and withdrawals are pending.

**Vulnerable Code Example** (Burve):
```solidity
if (assetsToWithdraw > assetsToDeposit) {
    assetsToDeposit = 0;
    assetsToWithdraw -= assetsToDeposit; // BUG: Subtracting 0!
}
```

**Impact**:
- Withdrawal fees paid on full amount instead of net
- Protocol efficiency loss
- Unnecessary gas costs

**Mitigation**: Subtract before setting to zero.

### 129. Single-Sided Fee Distribution Dilution (High)
**Pattern**: Tax distribution includes new LP in denominator before they should receive rewards.

**Vulnerable Code Example** (Burve):
```solidity
function addValueSingle(...) internal {
    self.valueStaked += value; // Updates state
    self.bgtValueStaked += bgtValue;
    // Tax calculation...
}

// Later in addEarnings:
self.earningsPerValueX128[idx] +=
    (reserveShares << 128) /
    (self.valueStaked - self.bgtValueStaked); // Includes new staker!
```

**Impact**: Existing LPs receive diluted fee share; new LP unfairly receives portion of their own tax.

**Mitigation**: Distribute tax before updating valueStaked.

### 130. Range Re-entry Fee Capture Attack (High)
**Pattern**: Attacker times deposits to capture accumulated fees when ranges come back in range.

**Attack Scenario** (Burve):
1. Burve ranges out of Uniswap V3 range
2. Fees accumulate in unwanted token
3. Attacker deposits right before range re-entry
4. Triggers fee compounding, capturing disproportionate share
5. Immediately withdraws with profit

**Impact**: Fee sniping attack stealing accumulated rewards from legitimate LPs.

**Mitigation**: Add small always-in-range position to ensure continuous fee compounding.

### 131. Fee Bypass in removeValueSingle (High)
**Pattern**: Zero `realTax` calculation due to reading uninitialized variable.

**Vulnerable Code Example** (Burve):
```solidity
function removeValueSingle(...) returns (uint256 removedBalance) {
    // ...
    uint256 realTax = FullMath.mulDiv(
        removedBalance,    // Still 0 here!
        nominalTax,
        removedNominal
    );
}
```

**Impact**: Complete fee bypass on single-token removals.

**Mitigation**: Use `realRemoved` instead of `removedBalance`.

### 132. NoopVault Donation Attack (High)
**Pattern**: Unprotected ERC4626 implementation vulnerable to classic donation attack.

**Attack Path** (Burve):
1. Attacker front-runs first deposit with 1 wei
2. Donates large amount directly to vault
3. Legitimate users receive 0 shares due to rounding
4. Attacker withdraws inflated amount

**Impact**: Complete drainage of user deposits.

**Mitigation**: Implement virtual shares or initial deposit protection.

### 133. Double Withdrawal in removeValueSingle (High)
**Pattern**: Tax not included in vault withdrawal amount, causing insufficient balance.

**Vulnerable Code Example** (Burve):
```solidity
Store.vertex(vid).withdraw(cid, realRemoved, false); // Doesn't include tax
// ...
c.addEarnings(vid, realTax); // Needs tax amount
removedBalance = realRemoved - realTax; // Not enough withdrawn!
```

**Impact**: Function reverts due to insufficient balance.

**Mitigation**: Withdraw `realRemoved + realTax` from vault.

### 134. Reserve Share Overflow Attack (Medium)
**Pattern**: Repeated small trims cause exponential share inflation.

**Vulnerable Code Example** (Burve):
```solidity
shares = (balance == 0)
    ? amount * SHARE_RESOLUTION
    : (amount * reserve.shares[idx]) / balance; // Explodes when balance ≈ 0
```

**Impact**:
- Share counter overflow
- Complete protocol DoS
- Irreversible state corruption

**Mitigation**: Enforce minimum balance thresholds for trimming.

### 135. Admin Parameter Change Front-running (Medium)
**Pattern**: Users can exploit efficiency factor changes without rebalancing.

**Attack Scenario** (Burve):
1. Admin increases efficiency factor `e`
2. Attacker backruns with `removeTokenForValue`
3. Crafts amount so `newTargetX128` equals original
4. Extracts excess tokens meant for reserve

**Impact**: Theft of rebalancing profits.

**Mitigation**: Force rebalancing when changing efficiency factors.

### 136. Missing acceptOwnership in Diamond (Medium)
**Pattern**: Function selector not added for ownership acceptance.

**Vulnerable Code Example** (Burve):
```solidity
adminSelectors[0] = BaseAdminFacet.transferOwnership.selector;
adminSelectors[1] = BaseAdminFacet.owner.selector;
adminSelectors[2] = BaseAdminFacet.adminRights.selector;
// Missing: acceptOwnership.selector
```

**Impact**: Ownership transfers cannot be completed.

**Mitigation**: Add `acceptOwnership` selector to admin facet.

### 137. Protocol Fee Loss During Vault Pause (Medium)
**Pattern**: Protocol fees incorrectly sent to users when vault disables withdrawals.

**Attack Scenario** (Burve):
1. Protocol fees accumulate in diamond
2. Vault temporarily disables withdrawals
3. User collects earnings
4. Withdrawal netting fails
5. Protocol fees transferred to user

**Impact**: Loss of protocol revenue.

**Mitigation**: Revert if vault withdrawals disabled.

### 138. Cross-Closure Value Token Arbitrage (Medium)
**Pattern**: Same ValueToken used across all closures despite different underlying values.

**Attack Path** (Burve):
1. Add liquidity to low-value closure
2. Mint ValueToken
3. Burn ValueToken in high-value closure
4. Withdraw more valuable tokens

**Impact**: Value extraction from legitimate LPs.

**Mitigation**: Use separate ValueTokens per closure.

### 139. Invariant Breaking via Uncapped Growth (Medium)
**Pattern**: Target value can grow beyond designed deMinimus bounds.

**Vulnerable Code Example** (Burve):
```solidity
self.targetX128 += valueX128 / self.n + ((valueX128 % self.n) > 0 ? 1 : 0);
// No check against: |value - target*n| <= deMinimus*n
```

**Impact**: Protocol invariant violation affecting swap pricing.

**Mitigation**: Recalculate target using `ValueLib.t` after additions.

### 140. Earnings Loss in removeValueSingle Ordering (Medium)
**Pattern**: Asset removal before `trimBalance` uses outdated earnings.

**Vulnerable Code Example** (Burve):
```solidity
Store.assets().remove(recipient, cid, value, bgtValue); // Uses old earnings
// ...
(uint256 removedNominal, uint256 nominalTax) = c.removeValueSingle(...);
// Updates earnings after!
```

**Impact**: Users lose >1% of earnings in inactive pools.

**Mitigation**: Call `trimBalance` before asset removal.

### 141. ERC4626 Strategy Return Value Confusion (BakerFi)
**Pattern**: Strategy functions returning shares instead of assets, causing accounting errors.

**Vulnerable Code Example** (BakerFi):
```solidity
// StrategySupplyERC4626
function _deploy(uint256 amount) internal override returns (uint256) {
    return _vault.deposit(amount, address(this)); // Returns shares, not assets!
}

function _undeploy(uint256 amount) internal override returns (uint256) {
    return _vault.withdraw(amount, address(this), address(this)); // Returns shares!
}

function _getBalance() internal view override returns (uint256) {
    return _vault.balanceOf(address(this)); // Returns shares, not assets!
}
```

**Impact**:
- Incorrect share calculations in vault
- Users unable to withdraw full deposits
- Permanent fund lockup

**Mitigation**:
```solidity
function _deploy(uint256 amount) internal override returns (uint256) {
    _vault.deposit(amount, address(this));
    return amount; // Return assets deployed
}

function _getBalance() internal view override returns (uint256) {
    return _vault.convertToAssets(_vault.balanceOf(address(this)));
}
```

### 142. Missing Access Control on Strategy Harvest (BakerFi)
**Pattern**: Anyone can call harvest to manipulate performance fee calculations.

**Vulnerable Code Example** (BakerFi):
```solidity
function harvest() external returns (int256 balanceChange) { // No access control!
    uint256 newBalance = getBalance();
    balanceChange = int256(newBalance) - int256(_deployedAmount);
    _deployedAmount = newBalance; // Updates state
}
```

**Impact**: Users can front-run rebalance calls to avoid performance fees.

**Mitigation**: Add `onlyOwner` modifier to harvest function.

### 143. Deployed Amount Not Updated on Undeploy (BakerFi)
**Pattern**: Strategy's `_deployedAmount` not decremented when assets withdrawn.

**Vulnerable Code Example** (BakerFi):
```solidity
function undeploy(uint256 amount) external returns (uint256) {
    uint256 withdrawalValue = _undeploy(amount);
    ERC20(_asset).safeTransfer(msg.sender, withdrawalValue);
    balance -= amount;
    // _deployedAmount not updated!
    return amount;
}
```

**Impact**:
- Incorrect harvest calculations showing losses
- Performance fees cannot be collected even with profits

**Mitigation**: Update `_deployedAmount` in undeploy function.

### 144. Multi-Strategy Decimal Handling Issues (BakerFi)
**Pattern**: Inconsistent decimal handling between vault (18 decimals) and strategies.

**Vulnerable Code Example** (BakerFi):
```solidity
// Vault assumes 18 decimals for shares
function _depositInternal(uint256 assets, address receiver) returns (uint256 shares) {
    uint256 deployedAmount = _deploy(assets); // May return different decimals
    shares = total.toBase(deployedAmount, false);
}

// Strategy returns native token decimals
function _deploy(uint256 amount) internal returns (uint256) {
    // Returns amount in token's native decimals (e.g., 6 for USDC)
}
```

**Impact**:
- Share calculation errors
- Withdrawal failures
- System incompatible with non-18 decimal tokens

**Mitigation**: Normalize all amounts to 18 decimals or align vault decimals with underlying token.

### 145. Vault Router Permit Vulnerability (BakerFi)
**Pattern**: Permit signatures can be front-run to steal user tokens.

**Vulnerable Code Example** (BakerFi):
```solidity
function pullTokensWithPermit(
    IERC20Permit token,
    uint256 amount,
    address owner,
    uint256 deadline,
    uint8 v,
    bytes32 r,
    bytes32 s
) internal virtual {
    IERC20Permit(token).permit(owner, address(this), amount, deadline, v, r, s);
    IERC20(address(token)).safeTransferFrom(owner, address(this), amount);
}
```

**Attack Scenario**:
1. User submits transaction with permit signature
2. Attacker sees it in mempool, extracts signature
3. Attacker calls router with user's signature
4. Attacker then calls `sweepTokens` to steal funds

**Impact**: Complete theft of user funds.

**Mitigation**: Remove permit functionality from router or implement nonce tracking.

### 146. Vault Router Allowance Exploitation (BakerFi)
**Pattern**: Anyone can drain approved tokens through router commands.

**Vulnerable Code Example** (BakerFi):
```solidity
// Commands allow arbitrary token movements
function pullTokenFrom(IERC20 token, address from, uint256 amount) internal {
    if (token.allowance(from, address(this)) < amount) revert NotEnoughAllowance();
    IERC20(token).safeTransferFrom(from, address(this), amount);
}

function pushTokenFrom(IERC20 token, address from, address to, uint256 amount) internal {
    if (token.allowance(from, address(this)) < amount) revert NotEnoughAllowance();
    IERC20(token).safeTransferFrom(from, to, amount);
}
```

**Impact**: Complete drainage of user funds if they approved router.

**Mitigation**: Restrict these commands to `msg.sender == from`.

### 147. ERC4626 Vault Operations Owner Bypass (BakerFi)
**Pattern**: Router allows anyone to redeem/withdraw other users' vault shares.

**Vulnerable Code Example** (BakerFi):
```solidity
function _handleVaultRedeem(bytes calldata data, ...) private returns (bytes memory) {
    IERC4626 vault;
    uint256 shares;
    address receiver;
    address owner;
    assembly {
        vault := calldataload(data.offset)
        shares := calldataload(add(data.offset, 0x20))
        receiver := calldataload(add(data.offset, 0x40))
        owner := calldataload(add(data.offset, 0x60)) // User-controlled!
    }
    uint256 assets = redeemVault(vault, shares, receiver, owner);
}
```

**Impact**: Anyone can steal vault shares by specifying victim as owner.

**Mitigation**: Force `owner = msg.sender` for vault operations.

### 148. Non-ERC4626 Compliant View Functions (BakerFi)
**Pattern**: View functions not following ERC4626 specifications.

**Issues**:
- `maxDeposit`/`maxMint` always return `type(uint256).max` ignoring limits
- Don't return 0 when paused
- `previewMint` rounds down instead of up
- `previewWithdraw` doesn't include fees and rounds down
- `previewRedeem` doesn't account for withdrawal fees

**Impact**: Integration failures with protocols expecting ERC4626 compliance.

**Mitigation**: Implement view functions according to ERC4626 specification.

### 149. Multi-Strategy New Strategy DoS (BakerFi)
**Pattern**: New strategies added without approval cause deposit/withdrawal failures.

**Vulnerable Code Example** (BakerFi):
```solidity
function addStrategy(IStrategy strategy) external onlyRole(VAULT_MANAGER_ROLE) {
    _strategies.push(strategy);
    _weights.push(0);
    // No approval given to strategy!
}
```

**Impact**: Vault operations fail when trying to deploy to unapproved strategy.

**Mitigation**: Approve strategy with max allowance when adding.

### 150. Leverage Strategy Removal Accounting Error (BakerFi)
**Pattern**: Removing leverage strategies fails due to incorrect received amount assumptions.

**Vulnerable Code Example** (BakerFi):
```solidity
function removeStrategy(uint256 index) external {
    uint256 strategyAssets = _strategies[index].totalAssets();
    if (strategyAssets > 0) {
        IStrategy(_strategies[index]).undeploy(strategyAssets);
        _allocateAssets(strategyAssets); // Assumes full amount received!
    }
}
```

**Impact**: Transaction reverts as leverage strategies return less than requested.

**Mitigation**: Use actual returned amount for allocation.

### 151. Vault Unusable with Direct Strategy Transfers (BakerFi)
**Pattern**: Direct token transfers to strategy make vault permanently unusable.

**Vulnerable Code Example** (BakerFi):
```solidity
function _depositInternal(uint256 assets, address receiver) returns (uint256 shares) {
    Rebase memory total = Rebase(totalAssets(), totalSupply());
    // Reverts if totalAssets > 0 but totalSupply == 0
    if (!((total.elastic == 0 && total.base == 0) || (total.base > 0 && total.elastic > 0))) {
        revert InvalidAssetsState();
    }
}
```

**Attack**: Send tokens directly to strategy before first deposit.

**Impact**: Permanent DoS of vault.

**Mitigation**: Add recovery mechanism for edge cases.

### 152. Deposit Limit Bypass Through Recipients (BakerFi)
**Pattern**: Max deposit limit only checks msg.sender, not recipient.

**Vulnerable Code Example** (BakerFi):
```solidity
function _depositInternal(uint256 assets, address receiver) returns (uint256 shares) {
    uint256 maxDepositLocal = getMaxDeposit();
    if (maxDepositLocal > 0) {
        uint256 depositInAssets = (balanceOf(msg.sender) * _ONE) / tokenPerAsset();
        // Only checks msg.sender, not receiver!
        if (newBalance > maxDepositLocal) revert MaxDepositReached();
    }
    _mint(receiver, shares);
}
```

**Impact**: Unlimited deposits by using different recipient addresses.

**Mitigation**: Track deposits by actual depositor in mapping.

### 153. Rebalance Not Paused with Vault (BakerFi)
**Pattern**: Rebalance remains callable when vault is paused.

**Vulnerable Code Example** (BakerFi):
```solidity
function rebalance(IVault.RebalanceCommand[] calldata commands)
    external nonReentrant onlyRole(VAULT_MANAGER_ROLE) { // No whenNotPaused!
    // Can collect performance fees while users can't withdraw
}
```

**Impact**: Performance fees collected while users locked out.

**Mitigation**: Add `whenNotPaused` modifier to rebalance.

### 154. Router Deposit Limit DoS (BakerFi)
**Pattern**: VaultRouter itself subject to deposit limits as msg.sender.

**Vulnerable Code Example** (BakerFi):
```solidity
// In vault:
if (maxDepositLocal > 0) {
    uint256 depositInAssets = (balanceOf(msg.sender) * _ONE) / tokenPerAsset();
    // msg.sender is VaultRouter!
}
```

**Attack**: Deposit through router until router hits limit, blocking all router deposits.

**Impact**: Complete DoS of router deposit functionality.

**Mitigation**: Exempt router from limits or track actual depositor.

### 155. Zero Amount Strategy Undeploy DoS (BakerFi)
**Pattern**: Strategies with no assets cause withdrawal DoS in multi-strategy vaults.

**Vulnerable Code Example** (BakerFi):
```solidity
function _deallocateAssets(uint256 amount) internal returns (uint256 totalUndeployed) {
    for (uint256 i = 0; i < strategiesLength; i++) {
        uint256 fractAmount = (amount * currentAssets[i]) / totalAssets;
        totalUndeployed += IStrategy(_strategies[i]).undeploy(fractAmount); // Reverts if 0!
    }
}
```

**Impact**: All withdrawals blocked if any strategy has zero assets.

**Mitigation**: Skip strategies with zero undeploy amounts.

### 156. Morpho Strategy Interest Calculation Error (BakerFi)
**Pattern**: `assetsMax` calculation missing accrued interest in undeploy.

**Vulnerable Code Example** (BakerFi):
```solidity
function _undeploy(uint256 amount) internal override returns (uint256) {
    uint256 totalSupplyAssets = _morpho.totalSupplyAssets(id); // Stale!
    uint256 totalSupplyShares = _morpho.totalSupplyShares(id);
    uint256 assetsMax = shares.toAssetsDown(totalSupplyAssets, totalSupplyShares);
    // But amount includes interest from expectedSupplyAssets!
}
```

**Impact**: Incorrect branch selection leading to user receiving extra funds.

**Mitigation**: Use `expectedSupplyAssets` for `assetsMax` calculation.

### 157. Paused Third-Party Strategy Lock (BakerFi)
**Pattern**: No way to handle paused third-party protocols in multi-strategy vaults.

**Vulnerable Code Example** (BakerFi):
```solidity
// All operations attempt to interact with all strategies
function _deallocateAssets(uint256 amount) internal {
    for (uint256 i = 0; i < strategiesLength; i++) {
        // Reverts if strategy's underlying protocol is paused
        totalUndeployed += IStrategy(_strategies[i]).undeploy(fractAmount);
    }
}
```

**Impact**: Single paused protocol locks entire multi-strategy vault.

**Mitigation**: Add emergency exclusion mechanism for paused strategies.

### 158. Last Strategy Removal Division by Zero (BakerFi)
**Pattern**: Removing last strategy causes division by zero.

**Vulnerable Code Example** (BakerFi):
```solidity
function removeStrategy(uint256 index) external {
    _totalWeight -= _weights[index];
    _weights[index] = 0; // Now _totalWeight = 0
    if (strategyAssets > 0) {
        IStrategy(_strategies[index]).undeploy(strategyAssets);
        _allocateAssets(strategyAssets); // Division by _totalWeight = 0!
    }
}
```

**Impact**: Cannot remove last strategy if it has assets.

**Mitigation**: Handle last strategy removal specially or prevent it.

### 159. Wrong Token Configuration in Morpho Strategy (BakerFi)
**Pattern**: Allowing mismatched asset and loan tokens in Morpho markets.

**Vulnerable Code Example** (BakerFi):
```solidity
constructor(address asset_, address morphoBlue, Id morphoMarketId) {
    _asset = asset_; // Can be different from market's loanToken!
    _marketParams = _morpho.idToMarketParams(morphoMarketId);
    if (!ERC20(asset_).approve(morphoBlue, type(uint256).max)) {
        // Approves wrong token!
    }
}
```

**Impact**: Strategy completely unusable due to token mismatch.

**Mitigation**: Validate `asset_ == _marketParams.loanToken`.

### 160. Strategy Undeploy Return Value Mismatch (BakerFi)
**Pattern**: Strategy returns requested amount instead of actual withdrawn amount.

**Vulnerable Code Example** (BakerFi):
```solidity
function undeploy(uint256 amount) external returns (uint256 undeployedAmount) {
    uint256 withdrawalValue = _undeploy(amount); // Actual amount
    ERC20(_asset).safeTransfer(msg.sender, withdrawalValue);
    return amount; // WRONG: Should return withdrawalValue!
}
```

**Impact**: Vault receives wrong amount, causing transfer failures.

**Mitigation**: Return actual withdrawn amount.

### 161. Non-Whitelisted Recipient Bypass (BakerFi)
**Pattern**: Whitelist restrictions only check caller, not recipient.

**Vulnerable Code Example** (BakerFi):
```solidity
function deposit(uint256 assets, address receiver) public override onlyWhiteListed {
    // Only checks if msg.sender is whitelisted
    // receiver can be anyone!
    return _depositInternal(assets, receiver);
}
```

**Impact**: Non-whitelisted users can receive shares and withdraw through router.

**Mitigation**: Check both caller and receiver are whitelisted.

### 162. Dispatch Command Parsing Error (BakerFi)
**Pattern**: Wrong variable used for PULL_TOKEN command check.

**Vulnerable Code Example** (BakerFi):
```solidity
} else if (action == Commands.PULL_TOKEN) { // Should be actionToExecute!
    output = _handlePullToken(data, callStack, inputMapping);
}
```

**Impact**: PULL_TOKEN with input mapping causes revert.

**Mitigation**: Use `actionToExecute` instead of `action`.

### 163. Reward Calculation Fee Bypass (LoopFi)
**Pattern**: Reward fees not deducted from user amount, causing DoS or fund theft.

**Vulnerable Code Example** (LoopFi):
```solidity
function claim(uint256[] memory amounts, uint256 maxAmountIn) external returns (uint256 amountIn) {
    // Distribute BAL rewards
    IERC20(BAL).safeTransfer(_config.lockerRewards, (amounts[0] * _config.lockerIncentive) / INCENTIVE_BASIS);
    IERC20(BAL).safeTransfer(msg.sender, amounts[0]); // Full amount sent, fee not deducted!
}
```

**Impact**:
- DoS when contract has insufficient rewards
- Users receive extra rewards, stealing from others

**Mitigation**: Deduct fees before sending to user.

### 164. Liquidation Penalty Not Applied to Collateral (LoopFi)
**Pattern**: Liquidators receive full collateral value despite penalty mechanism.

**Vulnerable Code Example** (LoopFi):
```solidity
function liquidatePosition(address owner, uint256 repayAmount) external {
    uint256 takeCollateral = wdiv(repayAmount, discountedPrice);
    uint256 deltaDebt = wmul(repayAmount, liqConfig_.liquidationPenalty);
    uint256 penalty = wmul(repayAmount, WAD - liqConfig_.liquidationPenalty);
    // Collateral calculation doesn't consider penalty!
}
```

**Impact**: Self-liquidation profitability despite penalty mechanism.

**Mitigation**: Apply penalty to collateral amount calculation.

### 165. Zero Rate Quota Interest Bypass (LoopFi)
**Pattern**: New quota tokens have zero rates, allowing interest-free borrowing.

**Vulnerable Code Example** (LoopFi):
```solidity
function addQuotaToken(address token) external override gaugeOnly {
    quotaTokensSet.add(token); // rates are 0 by default
    totalQuotaParams[token].cumulativeIndexLU = 1;
    emit AddQuotaToken(token);
}
```

**Impact**: Users can borrow at zero interest until rates are updated.

**Mitigation**: Set initial rates when adding quota tokens.

### 166. Missing Role Setup in Access Control (LoopFi)
**Pattern**: AccessControl roles never initialized, causing permanent DoS.

**Vulnerable Code Example** (LoopFi):
```solidity
contract AuraVault inherits AccessControl {
    // Constructor doesn't call _setupRole()

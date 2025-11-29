### Primer Chunk Metadata
Primer: Amy Vault ERC4626
Chunk: 1
Lines approx: 1-1000
Version: v1.0
Focus: Critical Vulnerability Patterns


# ERC4626 Vault Security Primer v13.5

## Overview
This primer consolidates critical security patterns and vulnerabilities discovered across multiple vault implementations, including ERC4626 vaults, yield-generating vaults, vault-like protocols, auto-redemption mechanisms, weighted pool implementations, cross-chain vault systems, multi-vault architectures, AMM-integrated vault systems, CDP vault implementations, position action patterns, fee distribution mechanisms, funding rate arbitrage systems, collateralized lending vaults, and stablecoin protocols. Use this as a reference when auditing new vault protocols to ensure comprehensive vulnerability detection.

**Latest Update**: Added pattern #364 Smart Wallet Approved Hashes integration bug.

## Critical Vulnerability Patterns

### 1. Non-Standard Token Support Issues
**Pattern**: Vaults assuming standard ERC20 behavior without accounting for fee-on-transfer, rebasing, or other non-standard tokens.

**Vulnerable Code Example**:
```solidity
// VULNERABLE: Assumes amount transferred equals amount received
token.safeTransferFrom(msg.sender, address(this), amount);
deposits.push(Deposit(msg.sender, amount, tokenAddress)); // Wrong for FOT tokens
```

**Secure Implementation**:
```solidity
uint256 balanceBefore = token.balanceOf(address(this));
token.safeTransferFrom(msg.sender, address(this), amount);
uint256 actualAmount = token.balanceOf(address(this)) - balanceBefore;
deposits.push(Deposit(msg.sender, actualAmount, tokenAddress));
```

**Detection Heuristics**:
- Look for direct use of transfer amounts in state updates
- Check if balance differences are calculated
- Search for assumptions about token behavior
- Verify handling of: FOT tokens, rebasing tokens, tokens with hooks (ERC777)
- Check for tokens with more than 18 decimals
- Verify DAI permit handling (non-standard signature)
- Check for blocklist tokens (USDT, USDC) that can block transfers
- Verify support for tokens that revert on zero transfers (LEND)
- Check for proper decimal handling in liquidation pricing
- Handle fee-on-transfer tokens in depositGlp() scenarios
- Verify vault internal accounting matches actual token balances (PoolTogether M-01)
- Check for tokens like BNB that revert on zero approvals (Silo M-03)

### 2. CEI Pattern Violations
**Pattern**: External calls made before state updates, enabling reentrancy attacks.

**Vulnerable Code Example**:
```solidity
// VULNERABLE: Transfer before state update
token.safeTransferFrom(msg.sender, address(this), amount);
deposits.push(Deposit(msg.sender, amount, tokenAddress));
```

**Secure Implementation**:
```solidity
// Update state first
deposits.push(Deposit(msg.sender, 0, tokenAddress));
uint256 index = deposits.length - 1;
// Then make external call
token.safeTransferFrom(msg.sender, address(this), amount);
deposits[index].amount = amount;
```

**Detection Heuristics**:
- Identify all external calls
- Check if state changes occur after external calls
- Look for potential reentrancy vectors
- Consider read-only reentrancy risks
- Watch for native ETH transfers that can re-enter
- Check for ERC777 token callback reentrancy
- Verify hook implementations don't enable reentrancy (PoolTogether M-02)

### 3. First Depositor Attack (ERC4626 Specific)
**Pattern**: Attacker manipulates share price by being first depositor with minimal amount, then donating tokens directly.

**Attack Scenario**:
1. Attacker deposits 1 wei to get 1 share
2. Attacker donates large amount directly to vault
3. Subsequent depositors get 0 shares due to rounding

**Vulnerable Code Example (Astaria)**:
```solidity
// ERC4626Cloned has inconsistent deposit/mint logic on first deposit
function previewDeposit(uint256 assets) public view virtual returns (uint256) {
  return convertToShares(assets);
}

function previewMint(uint256 shares) public view virtual returns (uint256) {
  uint256 supply = totalSupply();
  return supply == 0 ? 10e18 : shares.mulDivUp(totalAssets(), supply);
}
```

**Mitigation**:
- Virtual shares/assets
- Minimum deposit requirements
- Initial deposit by protocol
- Dead shares (like Uniswap V2)
- Consistent logic between deposit and mint functions
- Set virtual assets equal to virtual shares (Silo M-06)

### 4. Share Price Manipulation
**Pattern**: Attackers manipulate exchange rates through donations or complex interactions.

**Detection**:
- Check for direct token transfers to vault
- Verify share calculation logic
- Look for rounding vulnerabilities
- Analyze sandwich attack possibilities
- Check for minimum deposit bypass vulnerabilities
- Verify exchange rate can actually increase (PoolTogether H-01)

### 5. Inflation/Deflation Attacks
**Pattern**: Manipulating share prices to steal funds or cause loss of funds.

**Vulnerable Scenarios**:
- Vault with no initial shares
- Low liquidity vaults
- Vaults accepting direct transfers
- Inconsistent rounding between deposit/mint and withdraw/redeem
- Exchange rate capped by flawed logic (PoolTogether H-01)
- Market rounding exploitation causing share deflation (Silo M-06)

### 6. State Ordering Issues
**Pattern**: Functions called in wrong order causing incorrect behavior.

**Examples**:
```solidity
// WRONG: Calling _refreshiBGT before pulling funds
_refreshiBGT(amount);
SafeTransferLib.safeTransferFrom(ibgt, msg.sender, address(this), amount);

// CORRECT: Pull funds first
SafeTransferLib.safeTransferFrom(ibgt, msg.sender, address(this), amount);
_refreshiBGT(amount);
```

### 7. ETH Transfer Method Issues
**Pattern**: Using transfer() or send() with fixed 2300 gas limit.

**Vulnerable Code**:
```solidity
// VULNERABLE: May fail with smart contract wallets
recipient.transfer(amount);
```

**Secure Implementation**:
```solidity
(bool success, ) = recipient.call{value: amount}("");
require(success, "ETH transfer failed");
```

### 8. Signature Replay Vulnerabilities
**Pattern**: Improper nonce handling allowing signature reuse.

**Vulnerable Code Example (Astaria)**:
```solidity
// VULNERABLE: Same commitment can be used multiple times
function _validateCommitment(IAstariaRouter.Commitment calldata params, address receiver) internal view {
    // Only validates signature, not preventing replay
    address recovered = ecrecover(
        keccak256(_encodeStrategyData(s, params.lienRequest.strategy, params.lienRequest.merkle.root)),
        params.lienRequest.v,
        params.lienRequest.r,
        params.lienRequest.s
    );
}
```

**Secure Implementation**:
```solidity
mapping(address => uint256) public nonces;
mapping(bytes32 => bool) public usedSignatures;

function withdraw(uint256 amount, uint256 nonce, bytes signature) {
    require(nonce == nonces[msg.sender], "Invalid nonce");
    bytes32 hash = keccak256(abi.encode(msg.sender, amount, nonce));
    require(!usedSignatures[hash], "Signature already used");
    // ... verify signature ...
    usedSignatures[hash] = true;
    nonces[msg.sender]++;
}
```

### 9. Interest/Reward Calculation Issues
**Pattern**: Incorrect interest accrual or reward distribution logic.

**Common Issues**:
- Not updating state before calculations
- Rounding errors accumulating over time
- Wrong variable usage in calculations
- Integer overflow/underflow
- Compounding interest when claiming simple interest
- Strategist reward calculated on loan amount instead of payment amount
- Dynamic emission rate not handled properly
- Rewards lost due to rounding in small positions
- Fee shares minted after reward distribution (Silo M-05)
- Missing totalSupply sync before claiming rewards (Silo M-02)

### 10. Cross-Function Reentrancy
**Pattern**: Reentrancy through multiple functions sharing state.

**Example**:
```solidity
function redeemYield(uint256 amount) external {
    // Burn YT tokens
    YieldToken(yt).burnYT(msg.sender, amount);
    // Calculate and send rewards (reentrancy point)
    for(uint i; i < yieldTokens.length; i++) {
        SafeTransferLib.safeTransfer(yieldTokens[i], msg.sender, claimable);
    }
}
```

### 11. Access Control Issues
**Pattern**: Missing or incorrect access control on critical functions.

**Examples**:
- Functions that should be owner-only but aren't
- Incorrect modifier usage
- Missing validation of caller identity
- Flash action callbacks missing initiator validation
- Clearing house functions callable by anyone
- Public compound functions allowing MEV exploitation
- Anyone can mint yield fees to arbitrary recipient (PoolTogether H-04)
- Draw manager can be front-run and set by attacker (PoolTogether M-06)
- Missing access control on mint/burn functions (USSD H-8)

### 12. Decimal Precision Issues
**Pattern**: Incorrect handling of tokens with different decimal places.

**Vulnerable Code Example (Astaria)**:
```solidity
// Wrong starting price for non-18 decimal assets
listedOrder = s.COLLATERAL_TOKEN.auctionVault(
  ICollateralToken.AuctionVaultParams({
    settlementToken: stack[position].lien.token,
    collateralId: stack[position].lien.collateralId,
    maxDuration: auctionWindowMax,
    startingPrice: stack[0].lien.details.liquidationInitialAsk, // Assumes 18 decimals
    endingPrice: 1_000 wei
  })
);
```

**Secure Approach**:
- Always normalize to a standard precision (e.g., 18 decimals)
- Be explicit about decimal conversions
- Test with tokens of various decimal places
- Handle tokens with more than 18 decimals carefully
- Account for decimal mismatches in minDepositAmount calculations
- Never assume oracle decimals (USSD H-4)

### 13. Liquidation and Bad Debt Handling
**Pattern**: Improper handling of underwater positions or bad debt.

**Key Checks**:
- Ensure liquidation incentives are properly set
- Handle cases where collateral value < debt
- Prevent liquidation griefing
- Ensure liquidations can't be blocked by reverting transfers
- Account for liquidator rewards in debt calculations
- Prevent self-liquidation exploitation
- Handle epoch processing when liens are open
- Verify liquidation can occur before borrower is in default
- Check if borrower can be liquidated
- Ensure debt can't be closed without full repayment
- Prevent liquidation while repayments are paused
- Handle token disallow effects on existing positions
- Provide grace period after repayments resume
- Validate liquidator repayment amounts
- Prevent infinite loan rollover
- Avoid sending repayments to zero address
- Ensure borrowers can always repay loans
- Credit repayments fully across multiple loans
- Incentivize liquidation of small positions
- Ensure liquidation improves health scores

### 14. Oracle and Price Feed Issues
**Pattern**: Vulnerabilities in price feed integration.

**Security Measures**:
- Use multiple oracle sources
- Implement staleness checks
- Add price deviation limits
- Handle oracle failures gracefully
- Check sequencer uptime on L2s
- Validate roundId, price > 0, and timestamp
- Consider oracle manipulation during market turbulence
- Check for inverted base/rate tokens (USSD H-1)
- Verify oracle decimal assumptions (USSD H-4)
- Always check for stale prices (USSD M-1)
- Handle circuit breaker min/max prices (USSD M-7)
- Ensure oracle units match expected denomination (USSD H-11)

### 15. Upgrade and Migration Risks
**Pattern**: Issues when upgrading vault implementations or migrating funds.

**Considerations**:
- Storage layout preservation
- Proper initialization of new variables
- Migration function security
- Pause mechanisms during upgrades
- vGMX/vGLP token presence preventing migration

### 16. Self-Transfer Exploits
**Pattern**: Functions that don't correctly handle self-transfers, allowing infinite points/rewards.

**Vulnerable Code Example** (AllocationVesting):
```solidity
// VULNERABLE: Doesn't handle self-transfer correctly
allocations[from].points = uint24(fromAllocation.points - points);
allocations[to].points = toAllocation.points + uint24(points);
```

**Mitigation**:
```solidity
error SelfTransfer();
if(from == to) revert SelfTransfer();
```

### 17. Missing State Updates Before Reward Claims
**Pattern**: Failing to update integral states before claiming rewards, resulting in loss of accrued rewards.

**Vulnerable Pattern**:
```solidity
// VULNERABLE: Missing _updateIntegrals before _fetchRewards
function fetchRewards() external {
    _fetchRewards(); // Updates lastUpdate without capturing pending rewards
}
```

**Secure Implementation**:
```solidity
function fetchRewards() external {
    _updateIntegrals(address(0), 0, totalSupply);
    _fetchRewards();
}
```

### 18. Single Borrower Liquidation Failures
**Pattern**: Liquidation logic that fails when only one borrower exists.

**Vulnerable Code**:
```solidity
// VULNERABLE: Skips liquidation when troveCount == 1
while (trovesRemaining > 0 && troveCount > 1) {
    // liquidation logic
}
```

**Impact**: Cannot liquidate the last borrower, especially critical during sunsetting.

### 19. Token Loss from Disabled Receivers
**Pattern**: Permanently lost tokens when disabled emissions receivers don't claim allocated emissions.

**Vulnerable Flow**:
1. Receiver gets voting allocation
2. Receiver is disabled
3. If receiver doesn't call `allocateNewEmissions`, tokens are lost forever

**Mitigation**: Allow anyone to call `allocateNewEmissions` for disabled receivers.

### 20. Downcast Overflow in Critical Functions
**Pattern**: Unsafe downcasting causing loss of user funds.

**Vulnerable Code**:
```solidity
struct AccountData {
    uint32 locked; // DANGEROUS: Can overflow with large deposits
}
accountData.locked = uint32(accountData.locked + _amount);
```

**Mitigation**: Use SafeCast and enforce invariants:
```solidity
require(totalSupply <= type(uint32).max * lockToTokenRatio);
```

### 21. Preclaim Limit Bypass
**Pattern**: Vesting limits can be bypassed through point transfers.

**Attack Flow**:
1. User preclaims maximum allowed
2. Transfers points to new address
3. New address has 0 preclaimed, can preclaim again

**Mitigation**: Transfer preclaimed amounts proportionally with points.

### 22. Collateral Gain Double-Claim
**Pattern**: Missing state updates allowing multiple claims of the same collateral gains.

**Vulnerable Pattern**:
```solidity
// VULNERABLE: Doesn't call _accrueDepositorCollateralGain
function claimCollateralGains(address recipient, uint256[] calldata collateralIndexes) external {
    // Direct claim without accruing first
}
```

### 23. Precision Loss in Reward Distribution
**Pattern**: Division before multiplication causing permanent loss of rewards.

**Vulnerable Pattern**:
```solidity
// First divides by total weight
uint256 votePct = receiverWeight / totalWeight;
// Then multiplies by emissions
uint256 amount = votePct * weeklyEmissions;
```

**Mitigation**: Avoid intermediate divisions:
```solidity
uint256 amount = (weeklyEmissions * receiverWeight) / totalWeight;
```

### 24. Array Length Limitations
**Pattern**: Fixed-size arrays causing panic reverts when limits exceeded.

**Vulnerable Code**:
```solidity
mapping(address => uint256[256] deposits) public depositSums;
// Panic if more than 256 collaterals
```

**Mitigation**: Add explicit checks and limits on array growth.

### 25. Dust Handling in Withdrawals
**Pattern**: Incorrect state updates when dust rounding results in zero remaining balance.

**Impact**: Storage inconsistency where system believes user has active locks with 0 balance.

### 26. Oracle Decimal Handling Errors
**Pattern**: Price feed calculations that only work correctly for 8 decimal oracles.

**Vulnerable Code Example (Y2K)**:
```solidity
nowPrice = (price1 * 10000) / price2;
nowPrice = nowPrice * int256(10**(18 - priceFeed1.decimals()));
return nowPrice / 1000000;
```

**Impact**:
- With 6 decimal feeds: Returns 10 decimal number (4 orders of magnitude off)
- With 18 decimal feeds: Returns 0 or reverts
- Only correct for 8 decimal feeds

**Mitigation**:
```solidity
nowPrice = (price1 * 10000) / price2;
nowPrice = nowPrice * int256(10**(priceFeed1.decimals())) * 100;
return nowPrice / 1000000;
```

### 27. Sequencer Downtime Blocking Critical Operations
**Pattern**: Critical functions that depend on oracle prices fail during L2 sequencer downtime.

**Vulnerable Code Example (Y2K)**:
```solidity
function triggerEndEpoch(uint256 marketIndex, uint256 epochEnd) public {
    // ... logic ...
    emit DepegInsurance(
        // ...
        getLatestPrice(insrVault.tokenInsured()) // Reverts during sequencer downtime
    );
}
```

**Impact**: Winners cannot withdraw despite epoch being over

**Mitigation**: For non-critical price usage (like event emissions), handle oracle failures gracefully

### 28. Total Loss with No Counterparty
**Pattern**: Users lose all deposits when no one deposits in the counterparty vault.

**Vulnerable Code Example (Y2K)**:
```solidity
function triggerDepeg(uint256 marketIndex, uint256 epochEnd) public {
    // If only hedge vault has deposits, risk vault has 0
    insrVault.setClaimTVL(epochEnd, riskVault.idFinalTVL(epochEnd)); // Sets to 0
    riskVault.setClaimTVL(epochEnd, insrVault.idFinalTVL(epochEnd));
    
    insrVault.sendTokens(epochEnd, address(riskVault)); // Sends all to risk
    riskVault.sendTokens(epochEnd, address(insrVault)); // Sends nothing back
}
```

**Impact**: Complete loss of deposits for users in single-sided markets

**Mitigation**: Allow full withdrawal when no counterparty exists

### 29. Approval-Based Withdrawal Griefing
**Pattern**: Incorrect approval checks allowing anyone to force withdrawals.

**Vulnerable Code Example (Y2K)**:
```solidity
function withdraw(uint256 id, uint256 assets, address receiver, address owner) external {
    if(msg.sender != owner && isApprovedForAll(owner, receiver) == false)
        revert OwnerDidNotAuthorize(msg.sender, owner);
    // Anyone can withdraw if receiver is approved!
}
```

**Impact**: Attackers can force winners to withdraw at inopportune times

**Mitigation**: Check approval for msg.sender, not receiver:
```solidity
if(msg.sender != owner && isApprovedForAll(owner, msg.sender) == false)
    revert OwnerDidNotAuthorize(msg.sender, owner);
```

### 30. Upward Depeg Triggering Insurance
**Pattern**: Insurance pays out when pegged asset is worth MORE than underlying.

**Vulnerable Code Example (Y2K)**:
```solidity
if (price1 > price2) {
    nowPrice = (price2 * 10000) / price1;
} else {
    nowPrice = (price1 * 10000) / price2;
}
// Calculates ratio of lower price, triggering depeg when asset appreciates
```

**Impact**: Risk users must pay out when they shouldn't (asset appreciation is positive)

**Mitigation**: Always calculate ratio as pegged/underlying, not min/max

### 31. Protocol-Specific Withdraw Parameter Mismatch
**Pattern**: Incorrect assumptions about protocol-specific withdraw functions.

**Vulnerable Code Example (Swivel)**:
```solidity
// Assumes all protocols use underlying amount for withdrawals
return IYearnVault(c).withdraw(a) >= 0;
// But Yearn's withdraw() takes shares, not assets!
```

**Impact**:
- With insufficient shares: Transaction reverts
- With excess shares: More assets withdrawn than expected, funds locked

**Mitigation**:
```solidity
uint256 pricePerShare = IYearnVault(c).pricePerShare();
return IYearnVault(c).withdraw(a / pricePerShare) >= 0;
```

### 32. VaultTracker State Inconsistency After Maturity
**Pattern**: Exchange rate can exceed maturity rate, causing underflow in subsequent operations.

**Vulnerable Code Example (Swivel)**:
```solidity
function removeNotional(address o, uint256 a) external {
    uint256 exchangeRate = Compounding.exchangeRate(protocol, cTokenAddr);
    // After maturity, exchangeRate > maturityRate
    if (maturityRate > 0) {
        yield = ((maturityRate * 1e26) / vlt.exchangeRate) - 1e26; // Underflows!
    }
}
```

**Impact**: Users cannot withdraw or claim interest after maturity

**Mitigation**:
```solidity
vlt.exchangeRate = (maturityRate > 0 && maturityRate < exchangeRate) ? maturityRate : exchangeRate;
```

### 33. Interface Definition Causing Function Calls to Fail
**Pattern**: Interface mismatch between caller and implementation.

**Vulnerable Code Example (Swivel)**:
```solidity
// MarketPlace calls:
ISwivel(swivel).authRedeem(p, u, market.cTokenAddr, t, a);

// But Swivel only has:
function authRedeemZcToken(uint8 p, address u, address c, address t, uint256 a) external
```

**Impact**: Critical functions permanently fail, locking user funds

**Mitigation**: Ensure interface definitions match implementations

### 34. Compounding Interest Calculation Missing Accrued Interest
**Pattern**: Interest calculations ignore previously accrued redeemable amounts.

**Vulnerable Code Example (Swivel)**:
```solidity
function addNotional(address o, uint256 a) external {
    uint256 yield = ((exchangeRate * 1e26) / vlt.exchangeRate) - 1e26;
    uint256 interest = (yield * vlt.notional) / 1e26; // Only uses notional!
    // Should use vlt.notional + vlt.redeemable
}
```

**Impact**: Users receive less yield than entitled over time

**Mitigation**: Include redeemable in yield calculations

### 35. Division Before Multiplication Causing Fund Loss
**Pattern**: Mathematical operations ordered incorrectly causing precision loss.

**Enhanced Pattern from Dacian's Research**:
Division in Solidity rounds down, hence to minimize rounding errors always perform multiplication before division.

**Vulnerable Code Example (Y2K)**:
```solidity
// In beforeWithdraw:
entitledAmount = amount.divWadDown(idFinalTVL[id]).mulDivDown(idClaimTVL[id], 1 ether);
// Can return 0 for small amounts
```

**Additional Example (Numeon)**:
```solidity
// Division before multiplication causes precision loss
uint256 scale0 = Math.mulDiv(amount0, 1e18, liquidity) * token0Scale;
uint256 scale1 = Math.mulDiv(amount1, 1e18, liquidity) * token1Scale;
```

**Additional Example (USSD)**:
```solidity
// VULNERABLE: Extra division by 1e18 causes massive precision loss
uint256 amountToSellUnits = IERC20Upgradeable(collateral[i].token).balanceOf(USSD) *
    ((amountToBuyLeftUSD * 1e18 / collateralval) / 1e18) / 1e18;
```

**Impact**: Users can call withdraw and receive 0 tokens; significant precision loss in calculations

**Mitigation**: Multiply before dividing:
```solidity
entitledAmount = (amount * idClaimTVL[id]) / idFinalTVL[id];
// Or for Numeon:
uint256 scale0 = Math.mulDiv(amount0 * token0Scale, 1e18, liquidity);
uint256 scale1 = Math.mulDiv(amount1 * token1Scale, 1e18, liquidity);
```

**Advanced Detection**: Expand function calls to reveal hidden division before multiplication:
```solidity
// iRate = baseVbr + utilRate.wmul(slope1).wdiv(optimalUsageRate)
// Expands to: baseVbr + utilRate * (slope1 / 1e18) * (1e18 / optimalUsageRate)
// Fix: iRate = baseVbr + utilRate * slope1 / optimalUsageRate;
```

### 36. Stale Oracle Price Acceptance
**Pattern**: Accepting oracle prices with timestamp = 0 or very old timestamps.

**Vulnerable Code Example (Y2K)**:
```solidity
function getLatestPrice(address _token) public view returns (int256 nowPrice) {
    // ...
    if(timeStamp == 0) // Should check for staleness, not just 0
        revert TimestampZero();
    return price;
}
```

**Impact**: Protocol operates on outdated prices

**Mitigation**:
```solidity
uint constant observationFrequency = 1 hours;
if(timeStamp < block.timestamp - uint256(observationFrequency))
    revert StalePrice();
```

### 37. Depeg Trigger on Exact Strike Price
**Pattern**: Depeg event triggers when price equals strike price, not just below.

**Vulnerable Code Example (Y2K)**:
```solidity
modifier isDisaster(uint256 marketIndex, uint256 epochEnd) {
    if(vault.strikePrice() < getLatestPrice(vault.tokenInsured()))
        revert PriceNotAtStrikePrice();
    // Allows depeg when price = strike price
    _;
}
```

**Impact**: Incorrect triggering of insurance events

**Mitigation**: Use `<=` instead of `<`

### 38. Reward Token Recovery Backdoor
**Pattern**: Admin can withdraw reward tokens that should be distributed to users.

**Vulnerable Code Example (Y2K)**:
```solidity
function recoverERC20(address tokenAddress, uint256 tokenAmount) external onlyOwner {
    require(tokenAddress != address(stakingToken), "Cannot withdraw staking token");
    // Missing: require(tokenAddress != address(rewardsToken))
    ERC20(tokenAddress).safeTransfer(owner, tokenAmount);
}
```

**Impact**: Admin can rug pull reward tokens

**Mitigation**: Prevent withdrawal of both staking and reward tokens

### 39. Reward Rate Dilution Attack
**Pattern**: Notifying rewards with 0 amount to dilute reward rate.

**Vulnerable Code Example (Y2K)**:
```solidity
function notifyRewardAmount(uint256 reward) external {
    if (block.timestamp >= periodFinish) {
        rewardRate = reward.div(rewardsDuration);
    } else {
        uint256 remaining = periodFinish.sub(block.timestamp);
        uint256 leftover = remaining.mul(rewardRate);
        rewardRate = reward.add(leftover).div(rewardsDuration); // Diluted with 0
    }
}
```

**Impact**: Reward rate can be reduced by 20% repeatedly

**Mitigation**: Prevent extending duration on every call or maintain constant rate

### 40. Expired Vault Tokens Earning Rewards
**Pattern**: Worthless expired tokens continue earning rewards.

**Vulnerable Code Example (Y2K)**:
```solidity
// After triggerEndEpoch:
insrVault.setClaimTVL(epochEnd, 0); // Makes tokens worthless
// But StakingRewards doesn't know and continues rewarding
```

**Impact**: Rewards stolen from future valid epochs

**Mitigation**: Add expiry validation in StakingRewards

## Yield Vault Specific Patterns

### 41. Yield Position Liquidation Bypass
**Pattern**: Collateral deposited to yield-generating positions (like Gamma Hypervisors) not being affected by liquidations.

**Vulnerable Code**:
```solidity
function liquidate() external onlyVaultManager {
    // Only liquidates regular collateral, not yield positions
    for (uint256 i = 0; i < tokens.length; i++) {
        if (tokens[i].symbol != NATIVE) liquidateERC20(IERC20(tokens[i].addr));
    }
    // Hypervisor tokens not included!
}
```

**Impact**: Users can have collateral in yield positions, get liquidated, and still withdraw the yield collateral.

### 42. Direct Removal of Yield Position Tokens
**Pattern**: Yield position tokens (like Hypervisor shares) can be removed without collateralization checks.

**Vulnerable Code**:
```solidity
function removeAsset(address _tokenAddr, uint256 _amount, address _to) external onlyOwner {
    ITokenManager.Token memory token = getTokenManager().getTokenIfExists(_tokenAddr);
    if (token.addr == _tokenAddr && !canRemoveCollateral(token, _amount)) revert Undercollateralised();
    // Hypervisor tokens not in TokenManager, so check bypassed!
    IERC20(_tokenAddr).safeTransfer(_to, _amount);
}
```

### 43. Self-Backing Stablecoin Issues
**Pattern**: Stablecoins backing themselves through LP positions create systemic risks.

**Example**: USDs/USDC pool where USDs counts as collateral for USDs loans.

**Impact**:
- Death spiral during de-peg events
- Breaks economic incentives for peg maintenance
- Up to 50% self-backing possible

### 44. Hardcoded Stablecoin Price Assumptions
**Pattern**: Assuming USD stablecoins always equal $1.

**Vulnerable Code**:
```solidity
if (_token0 == address(USDs) || _token1 == address(USDs)) {
    // Assumes both tokens = $1
    _usds += _underlying0 * 10 ** (18 - ERC20(_token0).decimals());
    _usds += _underlying1 * 10 ** (18 - ERC20(_token1).decimals());
}
```

**Impact**: Over-collateralization during de-peg events.

### 45. Excessive Slippage Tolerance
**Pattern**: Allowing up to 10% loss on yield deposits/withdrawals.

**Vulnerable Code**:
```solidity
function significantCollateralDrop(uint256 _pre, uint256 _post) private pure returns (bool) {
    return _post < 9 * _pre / 10; // 10% loss accepted!
}
```

### 46. Hardcoded DEX Pool Fees
**Pattern**: Fixed pool fees preventing optimal routing.

**Vulnerable Code**:
```solidity
fee: 3000, // Always uses 0.3% pool
```

**Impact**: Higher slippage, failed swaps, potential DoS of yield features.

### 47. Yield Position Data Removal Issues
**Pattern**: Admin removal of Hypervisor data locks user funds.

**Vulnerable Flow**:
1. Users deposit to Hypervisor
2. Admin calls `removeHypervisorData`
3. Users cannot withdraw - funds locked

### 48. Token Symbol vs Address Confusion
**Pattern**: Inconsistent handling of native tokens vs WETH.

**Issue**: Both ETH and WETH symbols map to WETH address, causing swap failures.

## Auto-Redemption Specific Patterns

### 49. Hypervisor Collateral Redemption Slippage Issues
**Pattern**: Auto redemption of Hypervisor collateral lacks slippage protection during withdrawal and redeposit.

**Vulnerable Code**:
```solidity
// No slippage protection in withdrawal
IHypervisor(_hypervisor).withdraw(
    _thisBalanceOf(_hypervisor), address(this), address(this),
    [uint256(0), uint256(0), uint256(0), uint256(0)] // Empty slippage params!
);

// No minimum amount out in swaps
ISwapRouter(uniswapRouter).exactInputSingle(
    ISwapRouter.ExactInputSingleParams({
        amountOutMinimum: 0, // No slippage protection!
        ...
    })
);
```

**Impact**: Vaults can become undercollateralized due to MEV sandwich attacks during auto redemption.

**Mitigation**:
- Add collateralization checks after redemption
- Implement minimum collateral percentage checks
- Use proper slippage parameters

### 50. Incorrect Swap Path Configuration
**Pattern**: Using wrong swap paths (e.g., collateral -> USDC instead of collateral -> USDs).

**Vulnerable Pattern**:
```solidity
// Wrong: swaps to USDC but expects USDs
_amountOut = ISwapRouter(_swapRouterAddress).exactInput(
    ISwapRouter.ExactInputParams({
        path: _swapPath, // collateral -> USDC path
        ...
    })
);
// No USDs balance change, vault becomes liquidatable
uint256 _usdsBalance = USDs.balanceOf(address(this));
```

**Impact**: Vaults become erroneously liquidatable as collateral is converted to wrong token.

**Mitigation**:
- Validate swap paths include correct output token
- Use separate input/output paths
- Add post-swap validation

### 51. Empty Mapping DoS
**Pattern**: Critical mappings never populated, blocking all functionality.

**Vulnerable Code**:
```solidity
mapping(address => address) hypervisorCollaterals;
mapping(address => bytes) swapPaths;
// No functions to populate these mappings!
```

**Impact**: Complete DoS of auto redemption functionality requiring redeployment.

**Mitigation**:
- Pre-populate mappings in constructor
- Add setter functions with access control
- Query from external contracts

### 52. Insufficient Access Control on Critical Functions
**Pattern**: External functions callable by anyone enabling griefing attacks.

**Vulnerable Code**:
```solidity
function performUpkeep(bytes calldata performData) external {
    // No access control - anyone can call!
    if (lastRequestId == bytes32(0)) {
        triggerRequest();
    }
}
```

**Attack Vectors**:
- Repeatedly trigger redemptions regardless of price
- Send USDs to vault to cause underflow in fulfillment
- Drain Chainlink subscription funds

**Mitigation**:
- Add Chainlink Automation forwarder access control
- Re-check trigger conditions
- Use balance diffs instead of direct balanceOf

### 53. Fulfilment Revert DoS
**Pattern**: Any revert in fulfillment permanently disables auto redemption.

**Vulnerable Pattern**:
```solidity
function fulfillRequest(bytes32 requestId, bytes memory response, bytes memory err) internal {
    // Any revert here permanently sets lastRequestId != 0
    // ... risky operations ...
    lastRequestId = bytes32(0); // Never reached on revert
}
```

**Impact**: Permanent DoS requiring redeployment.

**Mitigation**:
- Never allow fulfillRequest to revert
- Validate response length/format
- Use try/catch for external calls
- Add admin reset function

### 54. Oracle Manipulation via Instantaneous Prices
**Pattern**: Using spot prices instead of TWAPs for trigger conditions.

**Vulnerable Code**:
```solidity
function checkUpkeep() external returns (bool upkeepNeeded, bytes memory) {
    (uint160 sqrtPriceX96,,,,,,) = pool.slot0(); // Spot price!
    upkeepNeeded = sqrtPriceX96 <= triggerPrice;
}
```

**Impact**:
- Force auto redemption via flash loan manipulation
- MEV bots can front-run with JIT liquidity
- Vault owners can force debt repayment avoiding fees

**Mitigation**:
- Use TWAP with 15-30 minute intervals
- Re-check conditions in performUpkeep
- Add Chainlink price oracle integration

### 55. Unsafe Signed-Unsigned Casting
**Pattern**: Casting signed liquidity values to unsigned without checking sign.

**Vulnerable Code**:
```solidity
(, int128 _liquidityNet,,,,,,) = pool.ticks(_lowerTick);
_liquidity += uint128(_liquidityNet); // Can underflow if negative!
```

**Impact**:
- Massive overestimation of USDs needed
- Full vault redemption
- Potential revert causing DoS

**Mitigation**:
```solidity
if (_liquidityNet >= 0) {
    _liquidity = _liquidity + uint128(_liquidityNet);
} else {
    _liquidity = _liquidity - uint128(-_liquidityNet);
}
```

### 56. Concentrated Liquidity Tick Calculation Errors
**Pattern**: Incorrect tick range calculations for positive ticks.

**Vulnerable Code**:
```solidity
// Wrong for positive non-multiple ticks due to rounding
int24 _upperTick = _tick / _spacing * _spacing;
int24 _lowerTick = _upperTick - _spacing;
```

**Impact**: Incorrect USDs calculations, though unlikely due to decimal differences.

**Mitigation**: Account for tick sign in range calculations.

### 57. Missing Response Validation
**Pattern**: Not validating Chainlink Functions response data.

**Missing Checks**:
- Token is valid collateral or Hypervisor
- TokenID exists and is minted
- Vault address is non-zero
- Response length matches expected format

**Mitigation**: Add comprehensive validation before using response data.

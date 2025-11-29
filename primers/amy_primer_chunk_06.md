### Primer Chunk Metadata
Primer: Amy Vault ERC4626
Chunk: 6
Lines approx: 5001-6000
Version: v1.0
Focus: Critical Vulnerability Patterns


        (_amountOut * FEE_PRECISION) / (FEE_PRECISION - _yieldFeePercentage) - _amountOut
    );
    
    _mint(_account, _amountOut);
}
```

**Impact**: Liquidation logic completely broken due to mixing asset and share amounts.

**Cross References**: Can combine with #363 in meta vaults.

**Mitigation**: Clearly separate asset and share amounts with proper conversion.

### 271. Yield Fee Minting Access Control (PoolTogether H-04)
**Pattern**: Anyone can mint yield fees to any recipient.

**Vulnerable Code Example** (PoolTogether):
```solidity
function mintYieldFee(uint256 _shares, address _recipient) external {
    _requireVaultCollateralized();
    if (_shares > _yieldFeeTotalSupply) revert YieldFeeGTAvailable(_shares, _yieldFeeTotalSupply);
    
    _yieldFeeTotalSupply -= _shares;
    _mint(_recipient, _shares); // Anyone can mint to any address!
    
    emit MintYieldFee(msg.sender, _recipient, _shares);
}
```

**Impact**: Complete theft of protocol yield fees.

**Mitigation**: Remove recipient parameter; only mint to designated yield fee recipient.

### 272. Forced Delegation Removal (PoolTogether H-05)
**Pattern**: sponsor() function can forcefully remove user delegations.

**Vulnerable Code Example** (PoolTogether):
```solidity
function sponsor(uint256 _amount, address _receiver) external {
    _deposit(msg.sender, _receiver, _amount, _amount);
    
    if (_twabController.delegateOf(address(this), _receiver) != SPONSORSHIP_ADDRESS) {
        _twabController.delegate(address(this), _receiver, SPONSORSHIP_ADDRESS);
    }
}
```

**Impact**: Attacker can remove all delegations by sponsoring 0 amount, manipulating lottery odds.

**Mitigation**: Only force delegation if receiver already delegated to sponsorship address.

### 273. Delegation to Zero Address (PoolTogether H-06)
**Pattern**: Delegating to address(0) permanently locks funds.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _delegate(address _vault, address _from, address _to) internal {
    address _currentDelegate = _delegateOf(_vault, _from);
    delegates[_vault][_from] = _to;
    
    _transferDelegateBalance(
        _vault,
        _currentDelegate,
        _to, // If _to is address(0), funds are lost!
        uint96(userObservations[_vault][_from].details.balance)
    );
}
```

**Impact**: Users lose all funds when attempting to reset delegation.

**Mitigation**: Prevent delegation to address(0).

### 274. Collateralization Check Timing (PoolTogether H-07)
**Pattern**: Collateralization checked at function start instead of end.

**Vulnerable Code Example** (PoolTogether):
```solidity
function mintYieldFee(uint256 _shares, address _recipient) external {
    _requireVaultCollateralized(); // Check at start
    
    _yieldFeeTotalSupply -= _shares;
    _mint(_recipient, _shares);
    // Vault may be under-collateralized now!
}
```

**Impact**: Operations can leave vault under-collateralized.

**Mitigation**: Move collateralization check to end of state-changing functions.

### 275. Reserve Accounting Bypass (PoolTogether H-08)
**Pattern**: Direct reserve increases don't update accounted balance.

**Vulnerable Code Example** (PoolTogether):
```solidity
function increaseReserve(uint104 _amount) external {
    _reserve += _amount;
    prizeToken.safeTransferFrom(msg.sender, address(this), _amount);
    // accountedBalance not updated!
}

function contributePrizeTokens(address _prizeVault, uint256 _amount) external {
    uint256 _deltaBalance = prizeToken.balanceOf(address(this)) - _accountedBalance();
    // Can steal reserve injections!
}
```

**Impact**: Vaults can steal reserve contributions, double-counting prize tokens.

**Mitigation**: Track reserve injections in accounted balance calculation.

### 276. ERC4626 Vault Compatibility (PoolTogether H-09)
**Pattern**: Using maxWithdraw for exchange rate can cause losses with certain vault types.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _currentExchangeRate() internal view returns (uint256) {
    uint256 _withdrawableAssets = _yieldVault.maxWithdraw(address(this));
    // Some vaults return less than actual balance!
}
```

**Impact**: Exchange rate manipulation with vaults that have borrowing mechanisms or withdrawal limits.

**Mitigation**: Document incompatible vault types or use different calculation method.

### 277. Hook-Based Attack Vectors (PoolTogether M-02)
**Pattern**: User-controlled hooks enable various attack vectors.

**Vulnerable Code Example** (PoolTogether):
```solidity
function setHooks(VaultHooks memory hooks) external {
    _hooks[msg.sender] = hooks; // No validation!
    emit SetHooks(msg.sender, hooks);
}

function _claimPrize(...) internal returns (uint256) {
    if (hooks.useBeforeClaimPrize) {
        recipient = hooks.implementation.beforeClaimPrize(_winner, _tier, _prizeIndex);
        // Can revert, manipulate state, or grief!
    }
}
```

**Impact**: Griefing attacks, reentrancy, unauthorized external calls, DoS.

**Mitigation**: Add gas limits and error handling for hook calls.

### 278. TWAB Time Range Safety (PoolTogether M-03)
**Pattern**: Missing time range validation for historical balance queries.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _getVaultUserBalanceAndTotalSupplyTwab(address _vault, address _user, uint256 _drawDuration) internal view returns (uint256 twab, uint256 twabTotalSupply) {
    uint32 _endTimestamp = uint32(_lastClosedDrawStartedAt + drawPeriodSeconds);
    uint32 _startTimestamp = uint32(_endTimestamp - _drawDuration * drawPeriodSeconds);
    
    twab = twabController.getTwabBetween(_vault, _user, _startTimestamp, _endTimestamp);
    // No isTimeRangeSafe check!
}
```

**Impact**: Inaccurate TWAB calculations affecting prize distribution.

**Mitigation**: Add isTimeRangeSafe validation before getTwabBetween calls.

### 279. Missing Maximum Mint Validation (PoolTogether M-04)
**Pattern**: deposit() doesn't check if resulting shares exceed maxMint.

**Vulnerable Code Example** (PoolTogether):
```solidity
function deposit(uint256 _assets, address _receiver) public returns (uint256) {
    if (_assets > maxDeposit(_receiver)) revert DepositMoreThanMax(_receiver, _assets, maxDeposit(_receiver));
    // No check if shares > maxMint!
}
```

**Impact**: Can mint shares exceeding protocol limits with under-collateralized vaults.

**Mitigation**: Add maxMint validation in deposit function.

### 280. Sponsorship Address Balance Invariant (PoolTogether M-05)
**Pattern**: Transfers to SPONSORSHIP_ADDRESS break total supply accounting.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _transferBalance(...) internal {
    if (_to != address(0)) {
        _increaseBalances(_vault, _to, _amount, _isToDelegate ? _amount : 0);
        
        if (!_isToDelegate && _toDelegate != SPONSORSHIP_ADDRESS) {
            _increaseBalances(_vault, _toDelegate, 0, _amount);
        }
        // SPONSORSHIP_ADDRESS balance increases but total doesn't!
    }
}
```

**Impact**: Sum of individual balances exceeds total supply, skewing odds.

**Mitigation**: Disallow transfers to SPONSORSHIP_ADDRESS.

### 281. Draw Manager Front-Running (PoolTogether M-06)
**Pattern**: Anyone can set draw manager if not already set.

**Vulnerable Code Example** (PoolTogether):
```solidity
function setDrawManager(address _drawManager) external {
    if (drawManager != address(0)) {
        revert DrawManagerAlreadySet();
    }
    drawManager = _drawManager; // No access control!
    emit DrawManagerSet(_drawManager);
}
```

**Impact**: Malicious draw manager can withdraw reserves and manipulate draws.

**Mitigation**: Add access control or set in constructor only.

### 282. Math Library Pow() Inconsistencies (PoolTogether M-07)
**Pattern**: PRBMath pow() function returns inconsistent values.

**Impact**: Incorrect tier odds and draw accumulator calculations.

**Mitigation**: Upgrade to PRBMath v4 and Solidity 0.8.19.

### 283. CREATE1 Deployment Front-Running (PoolTogether M-08)
**Pattern**: Vault deployments vulnerable to front-running.

**Vulnerable Code Example** (PoolTogether):
```solidity
function deployVault(...) external returns (address) {
    vault = address(new Vault{salt: salt}(...)); // CREATE1 deployment
}
```

**Impact**: Attacker can deploy malicious vault at same address.

**Mitigation**: Use CREATE2 with vault config as salt.

### 284. Incentive Cap at Minimum Prize (PoolTogether M-09)
**Pattern**: Claimer fees capped at smallest prize size.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _computeMaxFee(uint8 _tier, uint8 _numTiers) internal view returns (uint256) {
    uint8 _canaryTier = _numTiers - 1;
    if (_tier != _canaryTier) {
        return _computeMaxFee(prizePool.getTierPrizeSize(_canaryTier - 1));
    }
}
```

**Impact**: No incentive to claim large prizes when gas costs exceed minimum prize.

**Mitigation**: Base max fee on actual tier prize size.

### 285. Prize Size Downcast Overflow (PoolTogether M-10)
**Pattern**: Unsafe downcast from uint256 to uint96 for prize sizes.

**Vulnerable Code Example** (PoolTogether):
```solidity
tier.prizeSize = uint96(
    _computePrizeSize(
        _tier,
        _numberOfTiers,
        fromUD34x4toUD60x18(tier.prizeTokenPerShare),
        fromUD34x4toUD60x18(prizeTokenPerShare)
    )
);
```

**Impact**: Incorrect prize sizes when value exceeds uint96.

**Mitigation**: Add safe casting with overflow checks.

### 286. Permit Function DoS (PoolTogether M-11)
**Pattern**: mintWithPermit vulnerable to front-running.

**Vulnerable Code Example** (PoolTogether):
```solidity
function mintWithPermit(uint256 _shares, address _receiver, uint256 _deadline, uint8 _v, bytes32 _r, bytes32 _s) external {
    uint256 _assets = _beforeMint(_shares, _receiver);
    _permit(IERC20Permit(asset()), msg.sender, address(this), _assets, _deadline, _v, _r, _s);
    // _assets can change between signature and execution!
}
```

**Impact**: Function unusable due to exchange rate manipulation.

**Mitigation**: Remove mintWithPermit functionality.

### 287. Tier Odds Calculation Error (PoolTogether M-12)
**Pattern**: Highest standard tier doesn't have odds of 1.

**Vulnerable Code Example** (PoolTogether):
```solidity
// Canary tier has odds of 1
SD59x18 internal constant TIER_ODDS_2_3 = SD59x18.wrap(1000000000000000000);
// But highest standard tier doesn't!
SD59x18 internal constant TIER_ODDS_1_3 = SD59x18.wrap(52342392259021369);
```

**Impact**: Prize distribution doesn't match intended design.

**Mitigation**: Recalculate tier odds with correct algorithm.

### 288. Observation Creation Manipulation (PoolTogether M-13)
**Pattern**: Users can prevent new observation creation to manipulate averages.

**Vulnerable Code Example** (PoolTogether):
```solidity
if (currentPeriod == 0 || currentPeriod > newestObservationPeriod) {
    return (
        uint16(RingBufferLib.wrap(_accountDetails.nextObservationIndex, MAX_CARDINALITY)),
        newestObservation,
        true
    );
}
// Small frequent deposits keep periods equal, preventing new observations
```

**Impact**: Users can manipulate their average balance for draws.

**Mitigation**: Align TWAB queries on period boundaries.

### 289. Tier Expansion with Single Canary Claim (PoolTogether M-14)
**Pattern**: One canary claim causes tier count to increase.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _computeNextNumberOfTiers(uint8 _numTiers) internal view returns (uint8) {
    uint8 _nextNumberOfTiers = largestTierClaimed + 2;
    
    if (_nextNumberOfTiers >= _numTiers && /* threshold checks */) {
        _nextNumberOfTiers = _numTiers + 1;
    }
    
    return _nextNumberOfTiers; // Always returns increased count!
}
```

**Impact**: Rapid tier expansion diluting prizes.

**Mitigation**: Only expand tiers when thresholds are met.

### 290. Tier Maintenance DoS (PoolTogether M-15)
**Pattern**: Single user can keep unprofitable tiers active.

**Attack**: Claim one prize from highest tier at a loss to maintain tier count.

**Impact**: Prevents tier reduction, keeping prizes unprofitable to claim.

**Mitigation**: Improve tier shrinking logic.

### 291. Maximum Tier Threshold Bypass (PoolTogether M-16)
**Pattern**: Threshold check skipped when reaching maximum tiers.

**Vulnerable Code Example** (PoolTogether):
```solidity
if (_nextNumberOfTiers >= MAXIMUM_NUMBER_OF_TIERS) {
    return MAXIMUM_NUMBER_OF_TIERS; // Skips threshold validation!
}
```

**Impact**: Adds 15th tier without meeting claim thresholds.

**Mitigation**: Always validate thresholds before tier expansion.

### 292. CREATE2 Front-Running Prevention (PoolTogether M-08 Mitigation)
**Pattern**: Using CREATE2 with deterministic addresses prevents front-running.

**Secure Implementation**:
```solidity
function deployVault(...) external returns (address vault) {
    bytes32 salt = keccak256(abi.encode(_name, _symbol, _yieldVault, _prizePool, _claimer, _yieldFeeRecipient, _yieldFeePercentage, _owner));
    vault = address(new Vault{salt: salt}(...));
}
```

**Impact**: Prevents malicious vault deployment at predicted addresses.

### 293. Vault Decimal Precision Loss (PoolTogether M-22)
**Pattern**: Loss of precision treated as vault loss.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _currentExchangeRate() internal view returns (uint256) {
    uint256 _withdrawableAssets = _yieldVault.maxWithdraw(address(this));
    // 1 wei precision loss triggers under-collateralized mode!
}
```

**Impact**: Normal precision loss blocks deposits.

**Mitigation**: Add 1 wei tolerance for precision loss.

### 294. ERC4626 View Function Compliance (PoolTogether M-23)
**Pattern**: maxDeposit/maxMint don't check yield vault limits.

**Vulnerable Code Example** (PoolTogether):
```solidity
function maxDeposit(address) public view virtual override returns (uint256) {
    return _isVaultCollateralized() ? type(uint96).max : 0;
    // Ignores _yieldVault.maxDeposit()!
}
```

**Impact**: Integration failures with protocols expecting ERC4626 compliance.

**Mitigation**: Return minimum of vault limit and yield vault limit.

### 295. Claimer Prize Claim Front-Running (PoolTogether M-24)
**Pattern**: Bots can be griefed by front-running last prize in batch.

**Vulnerable Code Example** (PoolTogether):
```solidity
function claimPrizes(...) external returns (uint256 totalFees) {
    vault.claimPrizes(tier, winners, prizeIndices, feePerClaim, _feeRecipient);
    // Reverts if any prize already claimed!
}
```

**Impact**: Claim bots lose gas costs, reduced claiming incentive.

**Mitigation**: Allow silent failure for already claimed prizes.

### 296. Permit Caller Restriction (PoolTogether M-25)
**Pattern**: Permit functions only work for direct signers.

**Vulnerable Code Example** (PoolTogether):
```solidity
function depositWithPermit(...) external returns (uint256) {
    _permit(IERC20Permit(asset()), msg.sender, address(this), _assets, _deadline, _v, _r, _s);
    // Always uses msg.sender, not _receiver!
}
```

**Impact**: Contracts cannot deposit on behalf of users with permits.

**Mitigation**: Use _receiver as permit owner.

### 297. Silent Transfer Overflow (PoolTogether M-26)
**Pattern**: Transfer amounts silently truncated to uint96.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _transfer(address _from, address _to, uint256 _shares) internal virtual override {
    _twabController.transfer(_from, _to, uint96(_shares)); // Silent truncation!
}
```

**Impact**: Accounting errors in integrated protocols.

**Mitigation**: Use SafeCast for all conversions.

### 298. Canary Claim Fee Exclusion (PoolTogether M-27)
**Pattern**: Fee calculations don't include canary claims.

**Vulnerable Code Example** (PoolTogether):
```solidity
uint96 feePerClaim = uint96(
    _computeFeePerClaim(
        _computeMaxFee(tier, prizePool.numberOfTiers()),
        claimCount,
        prizePool.claimCount() // Should include canaryClaimCount!
    )
);
```

**Impact**: Incorrect fee calculations for claimers.

**Mitigation**: Include canary claims in total count.

### 299. Initial Deposit Manipulation in ERC4626 AutoRollers (Sense)
**Pattern**: First depositor inflates share price by depositing large amounts, forcing subsequent depositors to contribute disproportionate values.

**Vulnerable Code Example** (Sense):
```solidity
function previewMint(uint256 shares) public view virtual returns (uint256) {
    uint256 supply = totalSupply;
    return supply == 0 ? shares : shares.mulDivUp(totalAssets(), supply);
}
```

**Impact**: Future depositors forced to deposit huge values, effectively DoSing the vault for regular users.

**Mitigation**:
- Require minimum initial mint with portion burned or sent to DAO
- Deploy with initial seed liquidity
- Virtual shares offset

### 300. Public Approval Function DoS (Sense)
**Pattern**: Unprotected public `approve()` functions can be front-run to set allowance to 0.

**Vulnerable Code Example** (Sense):
```solidity
function approve(ERC20 token, address to, uint256 amount) public payable {
    token.safeApprove(to, amount); // Anyone can call with amount = 0
}
```

**Impact**: Complete DoS of deposit/mint functionality.

**Mitigation**: Restrict approve() to authorized callers or only allow max approvals.

### 301. Yield Theft Through Exit Mechanisms (Sense)
**Pattern**: Exit functions that combine yield-bearing positions can accidentally transfer entire protocol yield to single user.

**Vulnerable Code Example** (Sense):
```solidity
function eject(...) public returns (uint256 assets, uint256 excessBal, bool isExcessPTs) {
    (excessBal, isExcessPTs) = _exitAndCombine(shares);
    _burn(owner, shares);
    
    // Transfers entire balance including yield from all YTs!
    assets = asset.balanceOf(address(this));
    asset.transfer(receiver, assets);
}
```

**Impact**: User receives yield from entire vault, not just their proportional share.

**Mitigation**: Calculate and transfer only user's proportional share of combined assets.

### 302. Series Creation Race Conditions (Sense)
**Pattern**: Multiple contracts creating series on same adapter can brick each other through maturity conflicts.

**Vulnerable Code Example** (Sense):
```solidity
function create(address adapter, uint256 maturity) external returns (address pool) {
    _require(pools[adapter][maturity] == address(0), Errors.POOL_ALREADY_EXISTS);
    // Reverts if another AutoRoller created series at same maturity
}
```

**Attack**: Create AutoRoller with different duration that produces conflicting maturity timestamps.

**Impact**: Original AutoRoller permanently bricked, cannot roll to new series.

**Mitigation**: Allow joining existing series or implement conflict resolution.

### 303. Admin Function Sandwich Attack in Concentrated Liquidity Vaults (Beefy)
**Pattern**: Admin functions that redeploy liquidity without calm period checks can be sandwiched to drain funds.

**Vulnerable Code Example** (Beefy):
```solidity
function setPositionWidth(int24 _width) external onlyOwner {
    _claimEarnings();
    _removeLiquidity();
    positionWidth = _width;
    _setTicks(); // Gets current tick without calm check
    _addLiquidity(); // Deploys at manipulated price
}

function unpause() external onlyManager {
    _isPaused = false;
    _setTicks(); // Gets current tick without calm check
    _addLiquidity(); // Deploys at manipulated price
}
```

**Attack Flow**:
1. Attacker front-runs with large swap pushing price up
2. Admin transaction executes, deploying liquidity at inflated range
3. Attacker back-runs, selling into deployed liquidity at inflated prices

**Impact**: Complete drainage of protocol funds ($1.2M+ demonstrated).

**Mitigation**: Add `onlyCalmPeriods` modifier to admin functions or to `_setTicks`.

### 304. Missing Slippage Protection in Fee Swaps (Beefy)
**Pattern**: Protocol fee swaps with `amountOutMinimum: 0` vulnerable to MEV.

**Vulnerable Code Example** (Beefy):
```solidity
function swap(address _router, bytes memory _path, uint256 _amountIn) internal returns (uint256 amountOut) {
    IUniswapRouterV3.ExactInputParams memory params = IUniswapRouterV3.ExactInputParams({
        path: _path,
        recipient: address(this),
        deadline: block.timestamp,
        amountIn: _amountIn,
        amountOutMinimum: 0 // No slippage protection!
    });
}
```

**Impact**: Reduced protocol fees due to sandwich attacks.

**Mitigation**: Calculate minimum output off-chain and pass as parameter.

### 305. Fee Accumulation from Rounding Errors (Beefy)
**Pattern**: Division rounding in fee distribution causes permanent token accumulation.

**Vulnerable Code Example** (Beefy):
```solidity
function _chargeFees() private {
    uint256 callFeeAmount = nativeEarned * fees.call / DIVISOR;
    IERC20(native).safeTransfer(_callFeeRecipient, callFeeAmount);
    
    uint256 beefyFeeAmount = nativeEarned * fees.beefy / DIVISOR;
    IERC20(native).safeTransfer(beefyFeeRecipient, beefyFeeAmount);
    
    uint256 strategistFeeAmount = nativeEarned * fees.strategist / DIVISOR;
    IERC20(native).safeTransfer(strategist, strategistFeeAmount);
    // Remainder stuck due to rounding
}
```

**Impact**: Cumulative loss of fees permanently stuck in contract.

**Mitigation**: Send remainder to one recipient:
```solidity
uint256 beefyFeeAmount = nativeEarned - callFeeAmount - strategistFeeAmount;
```

### 306. Stale Allowances on Router Updates (Beefy)
**Pattern**: Token allowances not removed when router addresses are updated.

**Vulnerable Code Example** (Beefy):
```solidity
function setUnirouter(address _unirouter) external onlyOwner {
    unirouter = _unirouter; // Old router keeps allowances!
    emit SetUnirouter(_unirouter);
}

function _giveAllowances() private {
    IERC20(lpToken0).forceApprove(unirouter, type(uint256).max);
    IERC20(lpToken1).forceApprove(unirouter, type(uint256).max);
}
```

**Impact**: Old router can continue spending protocol tokens.

**Mitigation**: Override `setUnirouter` to remove allowances before update.

### 307. Calm Period MIN/MAX Tick Edge Cases (Beefy)
**Pattern**: `onlyCalmPeriods` check fails at tick boundaries.

**Vulnerable Code Example** (Beefy):
```solidity
function _onlyCalmPeriods() private view {
    int24 tick = currentTick();
    int56 twapTick = twap();
    
    if(twapTick - maxTickDeviationNegative > tick || // Can underflow below MIN_TICK
       twapTick + maxTickDeviationPositive < tick) revert NotCalm();
}
```

**Impact**: DoS of deposits, withdrawals, and harvests at extreme prices.

**Mitigation**:
```solidity
int56 minCalmTick = max(twapTick - maxTickDeviationNegative, MIN_TICK);
int56 maxCalmTick = min(twapTick + maxTickDeviationPositive, MAX_TICK);
```

### 308. Share Price Manipulation via Recycled Deposits (Beefy)
**Pattern**: First depositor can massively inflate share count through deposit/withdrawal cycles.

**Attack Flow**:
1. First depositor deposits initial amount
2. Repeatedly: withdraw all → deposit all
3. Share count inflates with each cycle

**Impact**: While share count inflates, no direct theft mechanism found.

**Mitigation**: Rework share calculation logic to prevent recycling benefits.

### 309. Concentrated Liquidity Tick Update Gaps (Beefy)
**Pattern**: Missing tick updates before liquidity deployment in certain paths.

**Vulnerable Code Example** (Beefy):
```solidity
function withdraw() external {
    _removeLiquidity();
    // Missing _setTicks() here!
    _addLiquidity(); // Uses stale tick data
}
```

**Impact**: Non-optimal liquidity positions, reduced LP rewards.

**Mitigation**: Ensure `_setTicks()` called before all `_addLiquidity()` calls.

### 310. Zero Share Minting Despite Positive Deposits (Beefy)
**Pattern**: Rounding and minimum share subtraction can result in zero shares.

**Vulnerable Code Example** (Beefy):
```solidity
function deposit() external {
    uint256 shares = _amount1 + (_amount0 * price / PRECISION);
    if (_totalSupply == 0 && shares > 0) {
        shares = shares - MINIMUM_SHARES; // Can make shares = 0!
        _mint(address(0), MINIMUM_SHARES);
    }
    _mint(receiver, shares); // Mints 0 shares!
}
```

**Impact**: Users lose deposited tokens with no shares received.

**Mitigation**: Add zero share check after all calculations.

### 311. Price Calculation Overflow for Large sqrtPriceX96 (Beefy)
**Pattern**: Square operation in price calculation overflows for valid Uniswap prices.

**Vulnerable Code Example** (Beefy):
```solidity
function price(uint160 sqrtPriceX96) internal pure returns (uint256 _price) {
    _price = FullMath.mulDiv(uint256(sqrtPriceX96) ** 2, PRECISION, (2 ** 192));
    // Overflows for sqrtPriceX96 > 3.4e38
}
```

**Impact**: DoS of deposits and other price-dependent functions.

**Mitigation**: Refactor to avoid intermediate overflow.

### 312. Block.timestamp as Deadline Provides No Protection (Beefy)
**Pattern**: Using current timestamp as deadline in swaps.

**Vulnerable Code Example** (Beefy):
```solidity
IUniswapRouterV3.ExactInputParams memory params = IUniswapRouterV3.ExactInputParams({
    deadline: block.timestamp, // Always passes!
    // ...
});
```

**Impact**: No protection against transaction delays or validator manipulation.

**Mitigation**: Accept deadline as parameter from caller.

### 313. Concentrated Liquidity pool.slot0 Manipulation Risks (Beefy)
**Pattern**: Reading current price/tick from slot0 enables various attacks.

**Usage Points**:
- Setting liquidity ranges
- Calculating deposit shares
- Price conversions

**Impact**: Despite calm period checks, any implementation gaps enable draining attacks.

**Mitigation**: Maintain strict calm period enforcement, consider TWAP for critical operations.

### 314. Storage Gaps Missing in Upgradeable Contracts (Beefy)
**Pattern**: Upgradeable contracts without storage gaps risk slot collisions.

**Vulnerable Code Example** (Beefy):
```solidity
contract StratFeeManagerInitializable is Initializable, OwnableUpgradeable {
    // State variables but no __gap!
}
```

**Impact**: Storage collision on upgrades can corrupt child contract state.

**Mitigation**: Add storage gap: `uint256[50] private __gap;`

### 315. Upgradeable Contracts Missing disableInitializers (Beefy)
**Pattern**: Implementation contracts can be initialized when they shouldn't be.

**Vulnerable Code Example** (Beefy):
```solidity
contract StrategyPassiveManagerUniswap is StratFeeManagerInitializable {
    // No constructor calling _disableInitializers()!
}
```

**Mitigation**:
```solidity
/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
}
```

### 316. Owner Rug-Pull via Calm Period Parameter Manipulation (Beefy)
**Pattern**: Owner can disable protection mechanisms to drain funds.

**Attack Flow**:
1. Owner calls `setDeviation` with large values or `setTwapInterval(1)`
2. Manipulate pool price via flash loan
3. Deposit at inflated share price
4. Withdraw at normal price for profit

**Mitigation**: Enforce minimum safe parameter bounds.

### 317. Withdrawal Returns Zero Tokens for Positive Shares (Beefy)
**Pattern**: Rounding in withdrawal calculation can return nothing.

**Vulnerable Code Example** (Beefy):
```solidity
function withdraw(uint256 _shares) external {
    uint256 _amount0 = (_bal0 * _shares) / _totalSupply; // Can round to 0
    uint256 _amount1 = (_bal1 * _shares) / _totalSupply; // Can round to 0
}
```

**Mitigation**: Revert if both amounts are zero.

### 318. Permanent Token Lock from Donated Shares (Beefy)
**Pattern**: First depositor's donated shares create permanently locked tokens.

**Mechanism**: `MINIMUM_SHARES` sent to address(0) represent tokens that can never be withdrawn.

**Mitigation**: Add end-of-life function to recover when `totalSupply == MINIMUM_SHARES`.

### 319. Multi-Market Deposit Coordination Failure (Silo M-01)
**Pattern**: Vault attempts to deposit entire amount to each market without checking individual market limits.

**Vulnerable Code Example** (Silo):
```solidity
function _supplyERC4626(uint256 _assets) internal virtual {
    for (uint256 i; i < supplyQueue.length; ++i) {
        IERC4626 market = supplyQueue[i];
        uint256 toSupply = UtilsLib.min(UtilsLib.zeroFloorSub(supplyCap, supplyAssets), _assets);
        
        if (toSupply != 0) {
            try market.deposit(toSupply, address(this)) { // Reverts if toSupply > market.maxDeposit!
                _assets -= toSupply;
            } catch {}
        }
    }
}
```

**Impact**: Deposits fail even when sufficient space exists across multiple markets.

**Mitigation**: Check market.maxDeposit before attempting deposit:
```solidity
toSupply = Math.min(market.maxDeposit(address(this)), toSupply);
```

### 320. Reward Accrual Timing Error During Transfers (Silo M-02)
**Pattern**: Transfer hooks claim rewards without first updating totalSupply through fee accrual.

**Vulnerable Code Example** (Silo):
```solidity
function _update(address _from, address _to, uint256 _value) internal virtual override {
    _claimRewards(); // Claims without updating totalSupply first!
    super._update(_from, _to, _value);
}
```

**Impact**: Incorrect reward distribution due to stale totalSupply.

**Mitigation**: Add _accrueFee() before _claimRewards() in transfer flow.

### 321. Market Removal DOS for Zero-Reverting Tokens (Silo M-03)
**Pattern**: Tokens that revert on zero approval prevent market removal.

**Vulnerable Code Example** (Silo):
```solidity
function setCap(...) external {
    if (_supplyCap > 0) {
        approveValue = type(uint256).max;
    }
    // approveValue remains 0 for cap = 0
    
    IERC20(_asset).forceApprove(address(_market), approveValue); // Reverts for BNB!
}
```

**Impact**: Markets with zero-reverting tokens cannot be removed.

**Mitigation**: Set approveValue to 1 instead of 0 when removing markets.

### 322. Missing Slippage Protection in Core Operations (Silo M-04)
**Pattern**: No user-specified slippage tolerance in deposit/withdraw/redeem functions.

**Vulnerable Code Example** (Silo):
```solidity
function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
    // No minShares parameter!
    shares = previewDeposit(assets);
    _deposit(msg.sender, receiver, assets, shares);
}
```

**Impact**: Users vulnerable to sandwich attacks and unfavorable price movements.

**Mitigation**: Add minShares/minAssets parameters to protect users.

### 323. Fee Share Minting Order Causing Reward Loss (Silo M-05)
**Pattern**: Fee shares minted after reward distribution, missing current period rewards.

**Vulnerable Code Example** (Silo):
```solidity
function claimRewards() public virtual {
    _updateLastTotalAssets(_accrueFee()); // Mints fee shares
    _claimRewards(); // But rewards already distributed in _accrueFee!
}

function _accrueFee() internal virtual returns (uint256 newTotalAssets) {
    if (feeShares != 0) _mint(feeRecipient, feeShares); // Triggers _update
}

function _update(address _from, address _to, uint256 _value) internal virtual override {
    _claimRewards(); // Distributes rewards before fee shares are minted!
    super._update(_from, _to, _value);
}
```

**Impact**: Fee recipient permanently loses rewards for each interest accrual period.

**Mitigation**: Implement flag-based logic to handle fee share minting specially.

### 324. Deflation Attack Through Market Rounding (Silo M-06)
**Pattern**: Market rounding can be exploited to deflate share price until near overflow.

**Vulnerable Code Example** (Silo):
```solidity
// First deposit of 1 wei
market.deposit(1, address(this)); // Market rounds to 0, returns no shares
// Next deposit calculates shares as:
// 1 wei * (10**decimalsOffset + 1) / (0 + 1) = 2 * 10**decimalsOffset shares
// Repeated 1 wei deposits double totalSupply each time!
```

**Impact**: Share price deflation enabling vault bricking or reward monopolization.

**Mitigation**: Set virtual assets equal to virtual shares (10**DECIMALS_OFFSET).

### 325. Unchecked 2-Step Ownership Transfer (Dacian)
**Pattern**: Second step of ownership transfer doesn't verify first step was initiated.

**Vulnerable Code Example**:
```solidity
function completeNodeOwnerTransfer(uint64 id) external {
    uint64 newOwner = pendingNodeOwnerTransfers[id]; // 0 if not started
    uint64 accountId = accounts.resolveId(msg.sender); // 0 if not registered
    
    if (newOwner != accountId) revert NotAuthorizedForNode();
    
    nodes[id].owner = newOwner; // Sets to 0!
    delete pendingNodeOwnerTransfers[id];
}
```

**Impact**: Attacker can brick node ownership by setting owner to zero.

**Mitigation**: Require newOwner != 0 or validate transfer was initiated.

### 326. Unexpected Matching Inputs (Dacian)
**Pattern**: Functions assume different inputs but fail catastrophically with identical inputs.

**Vulnerable Code Example**:
```solidity
function _getTokenIndexes(IERC20 t1, IERC20 t2) internal pure returns (uint i, uint j) {
    for (uint k; k < _tokens.length; ++k) {
        if (t1 == _tokens[k]) i = k;
        else if (t2 == _tokens[k]) j = k; // Never executes if t1==t2!
    }
}
```

**Impact**: Returns (i, 0) when t1==t2, breaking invariants and enabling fund drainage.

**Mitigation**: Add validation: require(t1 != t2) or handle identical inputs properly.

### 327. Unexpected Empty Input Arrays (Dacian)
**Pattern**: Functions assume non-empty arrays, allowing validation bypass.

**Vulnerable Code Example**:
```solidity
function verifyAndSend(SigData[] calldata signatures) external {
    for (uint i; i<signatures.length; i++) {
        // verify signatures
    }
    // Empty array skips verification!
    (bool sent,) = payable(msg.sender).call{value: 1 ether}("");
    require(sent, "Failed");
}
```

**Impact**: Complete bypass of signature verification.

**Mitigation**: Require signatures.length > 0 before processing.

### 328. Unchecked Return Values (Dacian)
**Pattern**: Critical functions' return values ignored, enabling state corruption.

**Vulnerable Code Example**:
```solidity
function commitCollateral(uint loanId, address token, uint amount) external {
    CollateralInfo storage collateral = _loanCollaterals[loanId];
    
    collateral.collateralAddresses.add(token); // Returns false if already exists!
    collateral.collateralInfo[token] = amount; // Overwrites existing amount!
}
```

**Impact**: Borrowers can reduce collateral to 0 after loan approval.

**Mitigation**: Always check return values: require(collateral.collateralAddresses.add(token), "Already exists");

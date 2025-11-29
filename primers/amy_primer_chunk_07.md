### Primer Chunk Metadata
Primer: Amy Vault ERC4626
Chunk: 7
Lines approx: 6001-7000
Version: v1.0
Focus: Critical Vulnerability Patterns



### 329. Rounding Down to Zero (Enhanced)
**Pattern**: Division in Solidity rounds down, which can result in critical values becoming zero, especially with small numbers.

**Vulnerable Code Example (Cooler)**:
```solidity
function errorRepay(uint repaid) external {
    // If repaid small enough, decollateralized will round down to 0
    uint decollateralized = loanCollateral * repaid / loanAmount;
    
    loanAmount     -= repaid;
    loanCollateral -= decollateralized;
}
```

**Impact**: Loans can be repaid without reducing collateral, allowing borrowers to extract value.

**Mitigation**:
```solidity
function correctRepay(uint repaid) external {
    uint decollateralized = loanCollateral * repaid / loanAmount;
    
    // Don't allow loan repayment without deducting from collateral
    if(decollateralized == 0) { revert("Round down to zero"); }
    
    loanAmount     -= repaid;
    loanCollateral -= decollateralized;
}
```

**Detection Heuristics**:
- Look for divisions where the result is used to update critical state
- Check if small input values can cause rounding to zero
- Consider whether zero results break protocol invariants

### 330. No Precision Scaling (Enhanced)
**Pattern**: Combining amounts of tokens with different decimal precision without proper scaling.

**Vulnerable Code Example (Notional)**:
```solidity
function errorGetWeightedBalance(...) external view returns (uint256 primaryAmount) {
    uint256 primaryBalance   = token1Amount * lpPoolTokens / poolTotalSupply;
    uint256 secondaryBalance = token2Amount * lpPoolTokens / poolTotalSupply;
    
    uint256 secondaryAmountInPrimary = secondaryBalance * lpPoolTokensPrecision / oraclePrice;
    
    // Adding balances with different precisions!
    primaryAmount = (primaryBalance + secondaryAmountInPrimary) * token1Precision / lpPoolTokensPrecision;
}
```

**Impact**: Dramatic undervaluation of LP tokens by ~50% in DAI/USDC pools.

**Mitigation**:
```solidity
function correctGetWeightedBalance(...) external view returns (uint256 primaryAmount) {
    uint256 primaryBalance   = token1Amount * lpPoolTokens / poolTotalSupply;
    uint256 secondaryBalance = token2Amount * lpPoolTokens / poolTotalSupply;
    
    // Scale secondary token to primary token's precision first
    secondaryBalance = secondaryBalance * token1Precision / token2Precision;
    
    uint256 secondaryAmountInPrimary = secondaryBalance * lpPoolTokensPrecision / oraclePrice;
    primaryAmount = primaryBalance + secondaryAmountInPrimary;
}
```

### 331. Excessive Precision Scaling (Enhanced)
**Pattern**: Applying precision scaling multiple times to already-scaled values.

**Impact**: Token amounts become excessively inflated, breaking calculations.

**Detection**: Trace token amount flows through functions to identify repeated scaling operations.

### 332. Mismatched Precision Scaling (Enhanced)
**Pattern**: Different modules using different precision assumptions (decimals vs 1e18).

**Vulnerable Code Example (Yearn)**:
```solidity
// Vault.vy uses token decimals
def pricePerShare() -> uint256:
    return self._shareValue(10 ** self.decimals)

// YearnYield uses hardcoded 1e18
function getTokensForShares(uint256 shares) public view returns (uint256) {
    amount = IyVault(liquidityToken[asset]).getPricePerFullShare().mul(shares).div(1e18);
}
```

**Impact**: Incorrect calculations for non-18 decimal tokens.

**Mitigation**: Ensure consistent precision handling across all modules.

### 333. Rounding Leaks Value From Protocol (Enhanced)
**Pattern**: Fee calculations that round in favor of users instead of the protocol.

**Vulnerable Code Example (SudoSwap)**:
```solidity
// Rounding down favors traders
protocolFee = outputValue.mulWadDown(protocolFeeMultiplier);
tradeFee = outputValue.mulWadDown(feeMultiplier);
```

**Mitigation**:
```solidity
// Round up to favor protocol
protocolFee = outputValue.mulWadUp(protocolFeeMultiplier);
tradeFee = outputValue.mulWadUp(feeMultiplier);
```

**Impact**: Systematic value leakage from protocol to traders over time.

### 334. Liquidation Timing Vulnerabilities
**Pattern**: Complex vulnerabilities around when and how liquidations can occur.

**Key Sub-Patterns**:
- **Liquidation Before Default**: Borrowers liquidated before missing payments
- **Grace Period Absence**: No recovery time after unpausing
- **Partial Liquidation Gaming**: Using partial liquidations to avoid bad debt
- **Whale Position Blocking**: Large positions impossible to liquidate without flash loans
- **Immediate Post-Resume Liquidation**: Liquidation bots advantage after unpause

**Detection Heuristics**:
- Verify liquidation only possible after actual default
- Check for grace periods after state changes
- Ensure partial liquidations properly handle bad debt
- Validate whale positions can be liquidated
- Test liquidation timing around pause/unpause cycles

### 335. Bad Debt and Incentive Misalignment
**Pattern**: Protocols failing to properly incentivize liquidations or handle insolvent positions.

**Key Sub-Patterns**:
- **No Liquidation Incentive**: Missing rewards for liquidators
- **Small Position Accumulation**: Dust positions not worth liquidating
- **Profitable Collateral Withdrawal**: Users removing collateral while in profit
- **Insurance Fund Depletion**: Bad debt exceeding insurance capacity
- **Fixed Bonus Reverts**: Liquidation failing when collateral < 110%

**Vulnerable Example**:
```solidity
// Fixed 10% bonus causes revert when user has < 110% collateral
uint256 bonusCollateral = (tokenAmountFromDebtCovered * LIQUIDATION_BONUS) / LIQUIDATION_PRECISION;
_redeemCollateral(collateral, tokenAmountFromDebtCovered + bonusCollateral, user, msg.sender);
```

**Mitigation**: Cap bonus to available collateral, implement dynamic incentives

### 336. Liquidation DoS Attack Vectors
**Pattern**: Various methods attackers use to prevent their own liquidation.

**Attack Vectors**:
- **Many Small Positions**: Gas exhaustion iterating positions
- **Front-Run Prevention**: Nonce increment, partial self-liquidation
- **Pending Action Blocking**: Withdrawals blocking liquidation
- **Malicious Callbacks**: ERC721/ERC777 revert on receive
- **Yield Vault Hiding**: Collateral in external protocols
- **Array Manipulation**: Corrupting position ordering

**Example**:
```solidity
// Attacker creates many positions to cause OOG
function getItemIndex(uint256[] memory items, uint256 item) internal pure returns (uint256) {
    for (uint256 i = 0; i < items.length; i++) { // OOG with many items
        if (items[i] == item) return i;
    }
}
```

### 337. Liquidation Calculation Errors
**Pattern**: Mathematical errors in liquidation reward and fee calculations.

**Common Issues**:
- **Decimal Precision Mismatches**: Debt/collateral decimal differences
- **Protocol Fee Miscalculation**: Fees based on seized amount not profit
- **Reward Scaling Errors**: Linear scaling breaking with multiple accounts
- **Interest Exclusion**: Not including accrued interest in calculations
- **Wrong Token Amounts**: Using internal amounts without scaling

**Example**:
```solidity
// Liquidator reward uses debt decimals (6) for collateral calculation (18)
uint256 liquidatorReward = Math.mulDivUp(
    debtPosition.futureValue, // 6 decimals
    state.feeConfig.liquidationRewardPercent,
    PERCENT
); // Result in wrong decimals for WETH collateral
```

### 338. Cross-Protocol Liquidation Issues
**Pattern**: Problems arising from liquidation mechanics across different collateral types.

**Key Issues**:
- **Liquidator Collateral Selection**: Choosing stable over volatile collateral
- **Health Score Degradation**: Liquidation making positions worse
- **Priority Order Corruption**: Wrong liquidation sequence
- **Multi-Collateral Calculations**: Incorrect aggregate health scores

**Mitigation**:
```solidity
// Validate borrower health improves after liquidation
uint256 healthBefore = calculateHealthScore(borrower);
// ... perform liquidation ...
uint256 healthAfter = calculateHealthScore(borrower);
require(healthAfter > healthBefore, "Liquidation must improve health");
```

### 339. Oracle Price Inversion (USSD)
**Pattern**: Using inverted base/rate tokens for oracle price calculations, causing massive pricing errors.

**Vulnerable Code Example**:
```solidity
// Uses WETH/DAI from Uniswap pool
uint256 DAIWethPrice = DAIEthOracle.quoteSpecificPoolsWithTimePeriod(
    1000000000000000000, // 1 Eth
    0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2, // WETH (base)
    0x6B175474E89094C44Da98b954EedeAC495271d0F, // DAI (quote)
    pools,
    600
);

// But uses DAI/ETH from Chainlink
(, int256 price, , , ) = priceFeedDAIETH.latestRoundData();

// Averages incompatible price formats!
return (wethPriceUSD * 1e18) / ((DAIWethPrice + uint256(price) * 1e10) / 2);
```

**Impact**: Incorrect average calculation leads to wildly inaccurate prices.

**Mitigation**: Ensure both price sources use same base/quote order or invert one before averaging.

### 340. Logical Operator Errors (USSD)
**Pattern**: Using || instead of && in conditional checks, causing incorrect logic execution.

**Vulnerable Code Example**:
```solidity
// WRONG: Should be && to exclude DAI
if (collateral[i].token != uniPool.token0() || collateral[i].token != uniPool.token1()) {
    // Always true - will try to sell DAI even though it has no path
    IUSSD(USSD).UniV3SwapInput(collateral[i].pathsell, amountToSellUnits);
}
```

**Impact**: Attempts to sell DAI without a sell path, causing rebalancing to revert.

**Mitigation**: Use correct logical operators:
```solidity
if (collateral[i].token != uniPool.token0() && collateral[i].token != uniPool.token1())
```

### 341. Price Calculation Formula Errors (USSD)
**Pattern**: Incorrect mathematical formulas in price calculations for Uniswap V3.

**Vulnerable Code Example**:
```solidity
// When token0 is USSD
price = uint(sqrtPriceX96)*(uint(sqrtPriceX96))/(1e6) >> (96 * 2);
// Should multiply by 1e6, not divide!

// When token1 is USSD
price = uint(sqrtPriceX96)*(uint(sqrtPriceX96))*(1e18) >> (96 * 2);
// Should use 1e6, not 1e18!
```

**Impact**: Massive pricing errors affecting all rebalancing operations.

**Mitigation**: Use correct Uniswap V3 price calculation formulas per documentation.

### 342. Oracle Decimal Assumptions (USSD)
**Pattern**: Assuming fixed decimal values for oracle responses when they vary.

**Vulnerable Code Example**:
```solidity
// Assumes DAI/ETH oracle returns 8 decimals
return (wethPriceUSD * 1e18) / ((DAIWethPrice + uint256(price) * 1e10) / 2);
// But DAI/ETH actually returns 18 decimals!
```

**Impact**: 10^10 overvaluation of DAI price, allowing massive exploitation.

**Mitigation**: Check oracle decimals() or verify actual decimal count.

### 343. Uniswap V3 Slot0 Price Manipulation (USSD)
**Pattern**: Using instantaneous slot0 price instead of TWAP, enabling flash loan attacks.

**Vulnerable Code Example**:
```solidity
function getOwnValuation() public view returns (uint256 price) {
    (uint160 sqrtPriceX96,,,,,,) = uniPool.slot0();
    // Uses manipulatable spot price!
}
```

**Impact**: Attacker can manipulate price to trigger favorable rebalancing.

**Mitigation**: Use TWAP price over reasonable period (e.g., 30 minutes).

### 344. Missing Access Control on Critical Functions (USSD)
**Pattern**: Functions that mint/burn tokens lack proper access control.

**Vulnerable Code Example**:
```solidity
function mintRebalancer(uint256 amount) public override {
    _mint(address(this), amount); // Anyone can call!
}

function burnRebalancer(uint256 amount) public override {
    _burn(address(this), amount); // Anyone can call!
}
```

**Impact**: Attacker can mint up to max supply, manipulate totalSupply for rebalancing.

**Mitigation**: Add `onlyBalancer` modifier to restrict access.

### 345. Uniswap V3 Balance-Based Price Assumptions (USSD)
**Pattern**: Assuming pool token balances reflect price in concentrated liquidity.

**Vulnerable Code Example**:
```solidity
function getSupplyProportion() public view returns (uint256, uint256) {
    return (IERC20Upgradeable(USSD).balanceOf(uniPool), IERC20(DAI).balanceOf(uniPool));
}
// Balances don't represent price in Uniswap V3!
```

**Impact**: Rebalancing calculations completely incorrect, can cause underflow.

**Mitigation**: Use proper Uniswap V3 liquidity calculations, not raw balances.

### 346. Oracle Address Configuration Errors (USSD)
**Pattern**: Wrong contract addresses for critical oracles.

**Examples**:
- StableOracleWBTC using ETH/USD feed instead of BTC/USD
- StableOracleDAI with wrong DAIEthOracle address
- StableOracleDAI ethOracle set to address(0)
- StableOracleWBGL using pool address instead of oracle

**Impact**: Completely incorrect prices for all operations.

**Mitigation**: Verify all oracle addresses before deployment.

### 347. Oracle Price Unit Mismatch (USSD)
**Pattern**: Oracle prices denominated in wrong currency for intended use.

**Issue**: All oracles return USD prices but system expects DAI prices for peg maintenance.

**Attack Scenario**:
1. When DAI > $1, users mint USSD with DAI at inflated rate
2. Sell USSD for more DAI than deposited
3. System rebalances incorrectly, depleting collateral

**Impact**: Complete destruction of peg mechanism.

**Mitigation**: Convert all oracle prices to DAI denomination.

### 348. Rebalancing Underflow Vulnerabilities (USSD)
**Pattern**: Subtraction operations that can underflow during rebalancing.

**Vulnerable Code Example**:
```solidity
amountToBuyLeftUSD -= (IERC20Upgradeable(baseAsset).balanceOf(USSD) - amountBefore);
// Can underflow if actual swap returns more than expected
```

**Impact**: Rebalancing reverts, protocol becomes unable to maintain peg.

**Mitigation**: Check if result would underflow, cap at zero if needed.

### 349. Array Index Out of Bounds (USSD)
**Pattern**: Flutter index can exceed array bounds when collateral factor is high.

**Vulnerable Code Example**:
```solidity
for (flutter = 0; flutter < flutterRatios.length; flutter++) {
    if (cf < flutterRatios[flutter]) {
        break;
    }
}
// flutter can equal flutterRatios.length after loop

// Later accesses out of bounds:
if (collateralval * 1e18 / ownval < collateral[i].ratios[flutter]) {
```

**Impact**: Rebalancing always reverts when collateral factor exceeds all flutter ratios.

**Mitigation**: Check flutter < flutterRatios.length before array access.

### 350. Missing Collateral Asset Accounting (USSD)
**Pattern**: Removed collateral assets not included in collateral factor calculation.

**Vulnerable Code Example**:
```solidity
function removeCollateral(uint256 _index) public onlyControl {
    collateral[_index] = collateral[collateral.length - 1];
    collateral.pop();
    // Removed asset still held by contract but not counted!
}
```

**Impact**: Collateral factor underreported, affecting risk assessment.

**Mitigation**: Transfer removed collateral out or continue counting it.

### 351. DAI Collateral Handling Inconsistency (USSD)
**Pattern**: DAI as collateral not handled consistently in sell operations.

**Vulnerable Code Example**:
```solidity
// First branch handles DAI correctly
if (collateralval > amountToBuyLeftUSD) {
    if (collateral[i].pathsell.length > 0) {
        // Sell collateral
    } else {
        // Don't sell DAI
    }
} else {
    // Second branch missing DAI check!
    IUSSD(USSD).UniV3SwapInput(collateral[i].pathsell, ...);
}
```

**Impact**: Attempts to sell DAI without path cause revert.

**Mitigation**: Add pathsell.length check in else branch.

### 352. Wrapped Asset Depeg Risk (USSD)
**Pattern**: Using BTC price for WBTC without considering depeg possibility.

**Issue**: StableOracleWBTC uses BTC/USD feed, assumes 1:1 parity.

**Impact**: If WBTC depegs:
- Protocol values worthless WBTC at full BTC price
- Bad debt accumulation
- Continued minting against devalued collateral

**Mitigation**: Implement double oracle with WBTC/BTC ratio check.

### 353. Partial Collateral Sale Precision Loss (USSD)
**Pattern**: Complex division operations can round to zero for partial sales.

**Vulnerable Code Example**:
```solidity
uint256 amountToSellUnits = IERC20Upgradeable(collateral[i].token).balanceOf(USSD) *
    ((amountToBuyLeftUSD * 1e18 / collateralval) / 1e18) / 1e18;
// Multiple divisions can cause result to be 0
```

**Impact**: Rebalancing fails to sell any collateral when it should sell partial amounts.

**Mitigation**: Reorder operations to minimize precision loss.

### 354. Arbitrage Through Oracle Deviation (USSD)
**Pattern**: Minting at stale oracle prices enables risk-free profit.

**Attack**: When market price < oracle price by more than deviation threshold:
1. Mint USSD with collateral at oracle price
2. Sell for DAI at market price
3. Profit from difference

**Impact**: Continuous value extraction, depleting protocol collateral quality.

**Mitigation**: Add minting fee > max oracle deviation (e.g., 1%).

### 355. Missing Redeem Functionality (USSD)
**Pattern**: Only deposit or mint functions exists but no redeem or withdraw functions.

**Issue**: No way to burn USSD for underlying collateral, only one-way conversion.

**Impact**:
- Users cannot exit positions
- No arbitrage mechanism to maintain peg from below
- Breaks fundamental stablecoin mechanics

**Mitigation**: Implement redeem functionality so users can withdraw.

### 356. Synthetic Token Minter Depeg Vulnerability
**Pattern**: Minter contracts that perform 1:1 conversion between collateral assets and synthetic tokens without validating the current market value of the collateral.

**Vulnerable Code Example**:
```solidity
function mint(address to, uint256 amount) external {
   baseAsset.safeTransferFrom(msg.sender, address(this), amount);
   syntheticToken.mint(to, amount); // 1:1 conversion regardless of baseAsset value!
}
```

**Attack Scenarios**:
1. Depegged Wrapped Assets: User buys depegged wBTC at $40k, mints hBTC worth $100k
2. Wrong Asset Type: User deposits 1e6 USDC ($1), receives 1e6 hBTC ($100k+ value)
3. Cross-decimal Exploitation: Mixing 6-decimal stablecoins with 8-decimal BTC synthetics

**Impact**: Complete protocol insolvency as attackers drain liquidity pools with overvalued synthetic tokens.

**Mitigation**:
- Enforce decimal matching between collateral and synthetic
- Integrate price oracles (Chainlink) to verify collateral value
- Implement depeg protection with maximum deviation thresholds
- Add circuit breakers/pausing for emergency response
- Match synthetic tokens to equivalent base asset types

**Detection Heuristics**:
- Look for minter contracts with 1:1 conversion logic
- Check if price validation exists between input and output tokens
- Verify decimal handling for different asset types
- Search for assumptions about stable asset values
- Check for oracle integration in mint/burn functions

### 357. Permit2 Partial Transfer State Mismatch
**Pattern**: Protocol stores permitted amount in state while permit2 transfers a different requested amount, creating a mismatch between recorded and actual values.

**Vulnerable Code Example** (Redacted):
```solidity
function deposit(
    ISignatureTransfer.PermitTransferFrom memory permit,
    ISignatureTransfer.SignatureTransferDetails memory transferDetails,
    address depositor,
    DepositWitness memory witness,
    bytes memory signature
) external returns (bytes32 depositId) {
    // Stores permit.permitted.amount in state
    s_activeDeposits[depositId] = DepositInfo({
        amount: permit.permitted.amount,  // e.g., 1000 USDC
        // ... other fields
    });
    
    // But transfers transferDetails.requestedAmount
    i_permit2.permitWitnessTransferFrom(
        permit,
        transferDetails,  // Uses requestedAmount (can be 1 wei!)
        depositor,
        witnessHash,
        DEPOSIT_WITNESS_TYPE_STRING,
        signature
    );
}
```

**Attack Scenario**:
1. Attacker signs permit for full amount with themselves as controller
2. Sets `transferDetails.requestedAmount = 1 wei` before calling deposit
3. Protocol stores full amount but only receives 1 wei
4. Attacker withdraws/refunds full amount, draining protocol

**Impact**: Complete protocol drainage through state/transfer mismatch

**Mitigation**:
```solidity
require(
    permit.permitted.amount == transferDetails.requestedAmount,
    "Amount mismatch"
);
// Or have protocol create transferDetails internally
```

**Detection Heuristics**:
- Look for protocols using permit2 with separate storage of amounts
- Check if permitted amount and requested amount are validated to match
- Verify state updates match actual transferred amounts
- Search for scenarios where partial transfers could break invariants

**Cross References**: ID generation should include nonce to prevent #364.

### 358. Permit2 Witness Hash Computation Error
**Pattern**: Protocol computes witness hash using raw encoding instead of EIP-712 struct hash format required by Permit2.

**Vulnerable Code Example** (Redacted):
```solidity
// INCORRECT: Using raw keccak256 encoding
bytes32 witnessHash = keccak256(abi.encode(witness.requestId, witness.reserver, witness.releaser));

// CORRECT: Using EIP-712 struct hash
bytes32 witnessHash = keccak256(
    abi.encode(
        keccak256("DepositWitness(bytes32 requestId,address reserver,address releaser)"),
        witness.requestId,
        witness.reserver,
        witness.releaser
    )
);
```

**Impact**: Standard Permit2 signing libraries won't work, causing integration failures and temporary DoS for users expecting standard behavior.

**Mitigation**: Always use EIP-712 struct hash format when computing witness hashes for Permit2.

**Detection Heuristics**:
- Look for `permitWitnessTransferFrom` calls
- Check if witness hash uses `keccak256(abi.encode(...))` without type hash
- Verify witness hash follows EIP-712 struct encoding standards
- Compare against Uniswap Permit2 documentation examples

### 359. Permit2 Witness Type String Misconfiguration
**Pattern**: Incorrect or incomplete witness type string format when calling Permit2, missing required type definitions or format elements.

**Vulnerable Code Example** (Redacted):
```solidity
// INCORRECT: Missing witness prefix and TokenPermissions definition
string private constant DEPOSIT_WITNESS_TYPE_STRING =
    "DepositWitness(bytes32 requestId,address reserver,address releaser)";

// CORRECT: Complete type string with all required components
string private constant DEPOSIT_WITNESS_TYPE_STRING =
    "DepositWitness witness)DepositWitness(bytes32 requestId,address reserver,address releaser)TokenPermissions(address token,uint256 amount)";
```

**Impact**: Permit2 witness validation fails with standard signing tools, requiring custom implementations and causing integration issues.

**Mitigation**:
- Include the witness type name followed by ` witness)`
- Add all struct definitions including referenced types like `TokenPermissions`
- Follow exact format from Uniswap documentation

**Detection Heuristics**:
- Check all Permit2 witness type strings for completeness
- Verify format matches: `"TypeName witness)TypeDefinition...ReferencedTypeDefinitions..."`
- Ensure TokenPermissions definition is included when using PermitTransferFrom
- Compare against working implementations in other protocols

### 360. ERC1271 Signature Validation Bypass for DoS
**Pattern**: When depositIds or similar identifiers are derived solely from signatures, attackers can deploy malicious ERC1271 contracts that claim any signature is valid, enabling griefing attacks.

**Vulnerable Code Example** (Redacted):
```solidity
// VULNERABLE: DepositId only based on signature
depositId = keccak256(signature);

// Attacker deploys contract that always returns valid:
contract MaliciousERC1271 {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        return 0x1626ba7e; // Always claims signature is valid
    }
}

// Attacker can:
// 1. Use victim's signature with their malicious contract as depositor
// 2. Modify parameters (like amount to 1 wei)
// 3. Front-run, blocking subsequent legitimate deposit since depositId already exists
```

**Attack Scenario**:
1. Victim publishes signature for legitimate operation
2. Attacker deploys ERC1271 contract that always validates
3. Attacker uses victim's signature with modified parameters
4. Creates record with same ID, blocking legitimate operation
5. Costs attacker minimal funds (1 wei) to grief

**Impact**: Complete DoS of protocol operations at negligible cost

**Mitigation**:
```solidity
// Include the signer/depositor in ID generation
depositId = keccak256(abi.encode(depositor, signature));
// Or validate depositor matches expected signer
```

**Detection Heuristics**:
- Look for IDs derived only from signatures
- Check if protocol accepts ERC1271 contract signatures
- Verify depositor/signer validation
- Search for griefing opportunities via signature replay
- Check if attackers can claim signatures with different parameters

**Cross References**: See also #364 for approved hash collision issues.

### 361. Permit2 Witness Hash Computation Error
**Pattern**: Computing witness hash using raw encoding instead of EIP-712 struct hash format required by Permit2.

**Vulnerable Code Example** (Redacted):
```solidity
// INCORRECT: Raw keccak256 encoding
bytes32 witnessHash = keccak256(abi.encode(witness.requestId, witness.reserver, witness.releaser));

// CORRECT: EIP-712 struct hash with type hash first
bytes32 witnessHash = keccak256(
    abi.encode(
        keccak256("DepositWitness(bytes32 requestId,address reserver,address releaser)"),
        witness.requestId,
        witness.reserver,
        witness.releaser
    )
);
```

**Impact**: Standard Permit2 signing libraries fail, causing integration issues and DoS for users

**Mitigation**: Always use EIP-712 struct hash format with type hash as first parameter

**Detection Heuristics**:
- Look for `permitWitnessTransferFrom` calls
- Check witness hash computation includes type hash
- Verify against Uniswap Permit2 documentation
- Test with standard signing libraries

### 362. Permit2 Witness Type String Misconfiguration
**Pattern**: Missing required components in witness type string when calling Permit2's permitWitnessTransferFrom.

**Vulnerable Code Example** (Redacted):
```solidity
// INCORRECT: Missing prefix and referenced types
string private constant WITNESS_TYPE =
    "DepositWitness(bytes32 requestId,address reserver,address releaser)";

// CORRECT: Complete format
string private constant WITNESS_TYPE =
    "DepositWitness witness)DepositWitness(bytes32 requestId,address reserver,address releaser)TokenPermissions(address token,uint256 amount)";
```

**Required Format**:
- Type name followed by ` witness)`
- Full struct definition
- All referenced types (like TokenPermissions)

**Impact**: Permit2 validation fails with standard tools, requiring custom implementations

**Mitigation**: Follow exact Permit2 documentation format including all components

**Detection Heuristics**:
- Check for `witness)` prefix in type string
- Verify TokenPermissions definition included
- Compare against working Permit2 integrations
- Test with standard signing tools

### 363. EIP-4626 totalAssets() Accounting Mismatch in Meta Vaults
**Pattern**: Meta vaults (vaults composed of other vaults) commonly misimplement `totalAssets()` by either summing all strategy assets regardless of ownership, or failing to properly value yield-bearing vault positions, breaking the fundamental EIP-4626 invariant.

**Vulnerable Code Example 1** (Yield Exclusion):
```solidity
// WRONG: Ignores yield from underlying vaults
function totalAssets() public view override returns (uint256) {
    // Excludes yield from nested vaults; this vault is entitled to part
    // of that yield as users deposited their nested vault shares into this vault!
    return depositedBase;
}
```

**Vulnerable Code Example 2** (Yield Overreporting):
```solidity
// WRONG: Counts ALL assets in strategies, not just owned portion
function totalAssets() public view override returns (uint256 total) {
    for (uint256 i = 0; i < length; i++) {
        // includes all assets from nested vaults, not just those
        // belonging to this vault!
        total += strategies[i].totalAssets();
    }
}
```

**Attack Scenarios**:

*Underreporting Bug:*
1. Vault holds 1000 shares from nested Vault, worth 1100 base asset tokens
2. totalAssets() returns 1000 (depositedBase asset tokens)
3. When users redeem from the main Vault, they don't receive yield from the nested vaults
4. Yield from nested vaults is effectively "lost" as the main vault doesn't account for it

*Overreporting Attack:*
1. Attacker deposits into meta vault, gets shares
2. Deposits directly into strategy, inflating totalAssets()
3. Redeems meta vault shares at inflated price
4. Withdraws from strategy separately

**Impact**:
- Theft of depositor funds through share price manipulation
- Loss of yield from nested vaults for depositors in main vault
- Violation of EIP-4626 core invariant
- Broken integrations with other protocols
- Permanent accounting corruption

**Correct Implementation**:
```solidity
// For vaults holding one yield-bearing underlying vault:
function totalAssets() public view override returns (uint256) {
    // Return actual value of ALL assets under management
    return underlyingVault.previewRedeem(underlyingVault.balanceOf(address(this)));
}

// For meta vaults with multiple underlying strategies or nested vaults:
function totalAssets() public view override returns (uint256 total) {
    for (uint256 i = 0; i < strategies.length; i++) {
        // Only count assets THIS vault owns via shares
        total += strategies[i].convertToAssets(strategies[i].balanceOf(address(this)));
    }
}
```

**Root Cause**: Misunderstanding of EIP-4626's `totalAssets()` requirement - it must return the **exact** amount of underlying assets that back the vault's issued shares, no more, no less.

**Detection Heuristics**:
- Verify `totalAssets()` only includes assets backing issued shares
- Check for yield-bearing positions properly valued
- Ensure no external deposits can affect totalAssets/totalSupply ratio
- Test: `deposit(x)` then immediate `redeem()` should return ≈x (minus fees and rounding)
- Validate: Direct transfers/deposits to strategies don't affect meta vault share price
- Confirm totalAssets changes proportionally with deposits/withdrawals

This is a subtle but important bug related to smart contract wallet signatures. Let me create a new vulnerability pattern for the primer:

### 364. Smart Contract Wallet Signature Collision in ID Generation

**Pattern**: Using signature data as part of unique identifier generation causes collisions when smart contract wallets use approved hashes with zero-length signatures, limiting them to one active operation.

**Vulnerable Code Example** (Redacted):
```solidity
// Generates ID from depositor and signature
depositId = keccak256(abi.encode(depositor, signature));

// Problem: Smart contract wallets using approved hashes always pass empty signature
// All deposits from same wallet get same depositId!
```

**Technical Background**:
Smart contract wallets like Safe (Gnosis) support two signature verification methods:
1. **Threshold signatures**: Normal signatures passed in calldata
2. **Approved hashes**: Pre-approved hashes with zero-length signature

When using approved hashes:
```solidity
// Safe wallet verification logic
if (signature.length == 0) {
    // Check pre-approved hashes
    require(safe.signedMessages(messageHash) != 0, "Hash not approved");
} else {
    // Normal signature verification
    safe.checkSignatures(address(0), messageHash, signature);
}
```

**Attack/DoS Scenario**:
1. Smart contract wallet approves hash for first deposit
2. Calls deposit with `signature = ""` (empty bytes)
3. `depositId = keccak256(abi.encode(walletAddress, ""))`
4. Attempts second deposit with different parameters
5. Also uses `signature = ""` for approved hash
6. Same `depositId` generated - transaction reverts with `DepositAlreadyExists`

**Impact**:
- Smart contract wallets limited to one active deposit at a time
- Must wait for deposit to complete before making another
- Severely limits protocol usability for DAOs and multisigs
- Not exploitable for theft but significant UX degradation

**Mitigation**:
```solidity
// Include unique permit data in ID generation
depositId = keccak256(abi.encode(
    depositor,
    permit.nonce,        // Unique per permit
    signature
));
```

**Detection Heuristics**:
- Look for ID generation using `(address, signature)` tuples
- Check if protocol supports ERC1271 contract signatures
- Verify handling of zero-length signatures
- Test with smart contract wallets using approved hashes
- Search for collision potential in identifier generation

**Related Patterns**:
- Similar to #360 (ERC1271 validation bypass) but for DoS rather than griefing
- Relates to deterministic ID generation vulnerabilities

**Key Insight**: When supporting smart contract wallets via ERC1271, remember that approved hashes use zero-length signatures. Any logic depending on signature uniqueness breaks for these wallets. Always include additional unique data (nonce, deadline, request ID) when generating identifiers.

This pattern highlights how ERC1271 support introduces subtle edge cases that aren't immediately obvious, especially around approved hash functionality that major wallets like Safe rely on.


## Common Attack Vectors

### 1. Sandwich Attacks
- Front-running large deposits/withdrawals
- Manipulating share price before/after user transactions
- Exploiting yield position entries/exits
- Auto redemption MEV exploitation
- Multi-step operation sandwiching (withdraw/swap/redeposit)
- Weight update timing exploitation
- Hook-based re-entrancy sandwiching
- Cross-chain message front-running
- Range re-entry timing attacks
- Admin parameter change exploitation
- Strategy harvest manipulation
- Permit signature front-running
- Liquidation front-running
- Interest rate manipulation timing
- Partial liquidation manipulation
- Position action swap sandwiching
- ERC4626 exchange rate manipulation
- Discount fee trading exploitation
- yDUSD vault deposit sandwiching
- FundingRateArbitrage share price manipulation
- Refinancing attacks before liquidation
- Commitment replay exploitation
- Dutch auction price manipulation
- Buyout lien front-running
- Compound function MEV exploitation
- Exchange rate donation attacks (PoolTogether)
- Hook execution timing attacks (PoolTogether)
- Permit-based operation front-running (PoolTogether)
- Series creation front-running (Sense)
- Admin function sandwich attacks in CL vaults (Beefy)
- Multi-market deposit timing exploitation (Silo)
- Oracle update sandwich for self-liquidation

### 2. Flash Loan Attacks
- Manipulating oracle prices
- Temporary collateral for operations
- Interest rate manipulation
- Amplifying self-backing issues
- Forcing auto redemption triggers
- JIT liquidity manipulation in concentrated pools
- Weight ratio manipulation in weighted pools
- Re-entrancy guard bypass amplification
- CCIP message manipulation
- Share price manipulation before donations
- Self-liquidation amplification
- Compound interest exploitation
- CDP position manipulation
- Bypassing liquidation ratios
- Position lever exploitation
- Reward distribution timing attacks
- Discount fee amplification
- Short position manipulation
- FundingRateArbitrage index manipulation
- Liquidation price manipulation
- Buyout validation bypass
- Public vault slope manipulation
- Exchange rate manipulation for profit (PoolTogether)
- Reserve accounting exploitation (PoolTogether)
- Concentrated liquidity range manipulation (Beefy)
- Market rounding exploitation (Silo)
- Profitable self-liquidation via oracle updates
- Oracle price manipulation through Uniswap V3 slot0
- Exploiting oracle price inversion for arbitrage
- Manipulating rebalancing triggers via spot price changes
- Creating artificial collateral valuations through TWAP manipulation
- Forced rebalancing at unfavorable rates
- Oracle deviation arbitrage (minting at stale prices)

### 3. Grief Attacks
- Blocking operations through minimal deposits
- DOS through excessive gas consumption
- Manipulation of sorted data structures
- Blocking liquidations with reverting tokens
- Spamming auto redemption to drain funds
- Sending tokens directly to vaults to cause underflow
- Preventing weight updates by manipulating timing parameters
- Exploiting queued withdrawal grace periods
- Blocking cross-chain messages
- Triggering reserve share overflow
- Direct transfers to strategies before first deposit
- Router deposit limit blocking
- Front-running liquidations with dust repayments
- Reward distribution period extensions
- Minimum shares violations
- Daily reward vesting spam
- Permit nonce exhaustion
- Position action auxiliary swap blocking
- Emission schedule manipulation
- Balance-based calculation manipulation
- yDUSD vault donation attacks
- Withdrawal request spam in FundingRateArbitrage
- Lien transfer to uncreated vaults
- Clearing house arbitrary calls
- Zero transfer reverts
- ERC777 callback reverts
- Strategist buyout prevention
- GMX cooldown exploitation ($3.5k/year to block all redemptions)
- vGMX/vGLP transfer blocking
- Forced delegation removal (PoolTogether)
- Single canary claim tier expansion (PoolTogether)
- Hook-based DoS attacks (PoolTogether)
- Zero amount sponsorship attacks (PoolTogether)
- Public approval DoS (Sense)
- Share recycling inflation (Beefy)
- Zero-reverting token market removal DoS (Silo)
- Liquidation DoS via many small positions
- Pending action liquidation blocking
- Forcing rebalancing operations to revert through calculated trades
- Exploiting array out-of-bounds to permanently break rebalancing
- Manipulating flutter ratios to cause systematic failures
- Creating positions that force underflow in rebalancing calculations
- ERC1271 signature validation bypass for DoS
- Deterministic ID griefing via signature replay

### 4. MEV Exploitation
- Transaction ordering manipulation
- Bundle attacks on liquidations
- Arbitrage of price updates
- Yield deposit/withdrawal exploitation
- Auto redemption front-running
- Multi-operation sandwich attacks
- Weight update front-running
- Cross-pool rebalance arbitrage
- Cross-chain arbitrage
- Fee capture during range transitions
- Cross-closure arbitrage with ValueTokens

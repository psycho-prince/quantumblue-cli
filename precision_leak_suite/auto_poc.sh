#!/bin/bash
# QuantumBlue Auto-PoC Generator

TARGET_ADDR=$1
FORK_URL=$2

if [ -z "$TARGET_ADDR" ] || [ -z "$FORK_URL" ]; then
    echo "Usage: $0 <TARGET_ADDR> <FORK_URL>"
    exit 1
fi

mkdir -p test

cat <<EOF > test/PrecisionLoss.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";

contract PrecisionLossTest is Test {
    address target = $TARGET_ADDR;

    function setUp() public {
        vm.createSelectFork("$FORK_URL");
    }

    function test_AutomatedDustCheck() public {
        // We simulate a 18-decimal transfer with 12-decimal dust
        uint256 amountWithDust = 1 ether + 999999999999;
        
        // Use staticcall to quote the send (OFT standard)
        (bool success, bytes memory data) = target.staticcall(
            abi.encodeWithSignature("quoteSend((uint32,bytes32,uint256,uint256,bytes,bytes,bytes),bool)", 
            1, bytes32(uint256(uint160(address(this)))), amountWithDust, 0, "", "", "", false)
        );

        if (success) {
            (uint256 amountSentLD, ) = abi.decode(data, (uint256, uint256));
            uint256 loss = amountWithDust - amountSentLD;
            
            console.log("Dust Loss Detected:", loss);
            assertGt(loss, 0, "No precision loss found.");
        } else {
            console.log("Staticcall failed. Target might not be an OFT or uses different signature.");
        }
    }
}
EOF

forge test --match-test test_AutomatedDustCheck -vv

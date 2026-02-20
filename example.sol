// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract VulnerableContract {
    using ECDSA for bytes32;

    function verify(bytes32 hash, bytes memory signature) public pure returns (address) {
        return hash.toEthSignedMessageHash().recover(signature);
    }

    function classicRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
        return ecrecover(hash, v, r, s);
    }
}

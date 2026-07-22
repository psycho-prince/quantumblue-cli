// Vulnerable.sol
pragma solidity ^0.8.0;

contract VulnerableContract {
    function weakRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
        // ecrecover is vulnerable to signature malleability
        return ecrecover(hash, v, r, s);
    }

    function weakHash(string memory data) public pure returns (bytes32) {
        // keccak256 is classical
        return keccak256(abi.encodePacked(data));
    }
}

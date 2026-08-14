// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @title LargeContract
/// @notice Deploys caller-provided runtime code to test initcode and contract-size limits.
contract LargeContract {
    constructor(bytes memory runtimeCode) {
        assembly ("memory-safe") {
            return(add(runtimeCode, 0x20), mload(runtimeCode))
        }
    }
}

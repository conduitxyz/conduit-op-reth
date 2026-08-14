// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @title GasBurner
/// @notice Consumes transaction gas without modifying state.
contract GasBurner {
    /// @notice Expands and hashes memory, then burns the remaining gas down to a safe reserve.
    function burn(uint256 memoryBytes, uint256 gasReserve) external payable returns (bytes32 hash) {
        bytes memory data = new bytes(memoryBytes);
        hash = keccak256(data);

        while (gasleft() > gasReserve) {}
    }
}

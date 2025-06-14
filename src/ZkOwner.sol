// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { ISignatureValidator } from "./Safe/ISignatureValidator.sol";

contract ZkOwner is ISignatureValidator {
  address public safeProxyAddress;
  bytes public singersInitCode;
  bool public isInitialized;

  function initialize(address _safeProxyAddress, bytes memory _singersInitCode) external {
    require(!isInitialized, "ZkOwner: already initialized");
    safeProxyAddress = _safeProxyAddress;
    singersInitCode = _singersInitCode;
    isInitialized = true;
  }

  function isValidSignature(
    bytes32 _hash,
    bytes memory _signature
  ) external view override returns (bytes4) {
    return EIP1271_MAGIC_VALUE;
  }

  function getNonce() external view returns (uint256) {
    // call safe proxy to get nonce
    bytes memory data = abi.encodeWithSignature("nonce()");
    (bool success, bytes memory result) = safeProxyAddress.staticcall(data);
    if (!success) {
      revert("Failed to get nonce");
    }
    return abi.decode(result, (uint256));
  }

  function getThreshold() external view returns (uint256) {
    // call safe proxy to get threshold
    bytes memory data = abi.encodeWithSignature("threshold()");
    (bool success, bytes memory result) = safeProxyAddress.staticcall(data);
    if (!success) {
      revert("Failed to get threshold");
    }
    return abi.decode(result, (uint256));
  }

}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { ISignatureValidator } from "./Safe/ISignatureValidator.sol";


interface IVerifier {
    function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external view returns (bool);
}

contract ZkOwner is ISignatureValidator {
  address public safeProxyAddress;
  address public verifier;
  bool public isInitialized;
  uint256 public threshold;
  bytes32[] public identifiers;
  bytes32 public hashed_identifiers;

  function initialize(
    address _safeProxyAddress, 
    uint256 _threshold, 
    address _verifier, 
    bytes32[] memory _identifiers
    ) external {
    require(!isInitialized, "ZkOwner: already initialized");
    safeProxyAddress = _safeProxyAddress;

    isInitialized = true;
    threshold = _threshold;
    verifier = _verifier;
    identifiers = _identifiers;
    hashed_identifiers = keccak256(abi.encodePacked(identifiers));
  }

  function isValidSignature(
    bytes32 _hash,
    bytes memory _signature // ( calldata?)
  ) external view override returns (bytes4) {
    
    (bytes memory proof, bytes32[] memory publicInputs) = abi.decode(_signature, (bytes, bytes32[]));

    IVerifier(verifier).verify(proof, publicInputs);
    if (hashed_identifiers != keccak256(abi.encodePacked(publicInputs))) {
      revert("Invalid signature");
    }
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

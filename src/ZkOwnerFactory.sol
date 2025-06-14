// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { SafeProxyFactory } from "./Safe/SafeProxyFactory.sol";

/**
 * @title Create2Factory
 * @dev Factory contract for deploying contracts using CREATE2 opcode
 * @notice This contract allows for deterministic contract deployment
 */
interface IZkOwner {
  function init(
    address _owner,
    address _endpointAddress,
    address[] memory _stargateAddresses,
    address[] memory _tokenAddresses,
    address _portalRouterAddress,
    uint256 _stargateFee
  ) external;
}

contract ZkOwnerFactory {
  // Events
  event ContractDeployed(address indexed deployedAddress, bytes32 indexed salt);
  event DeploymentFailed(bytes32 indexed salt, string reason);

  bytes public implBytecode;
  uint256 public nonce;
  address public safeProxyFactoryAddress;
  address public safeFallbackHandlerAddress;

  constructor(
    bytes memory _implBytecode,
    address _safeProxyFactoryAddress,
    address _safeFallbackHandlerAddress
  ) {
    implBytecode = _implBytecode;
    safeProxyFactoryAddress = _safeProxyFactoryAddress;
    safeFallbackHandlerAddress = _safeFallbackHandlerAddress;
  }

  function setBytecode(bytes memory _implBytecode) external {
    implBytecode = _implBytecode;
  }

  /*
   * @dev Deploys a contract using CREATE2
   * @param owner The owner address to use as salt
   * @return deployedAddress The address of the deployed contract
   */
  function deploy(
    bytes32 initCode
  ) public returns (address deployedAddress) /*OnlySigner*/ {
    nonce++;

    // Create salt from msg.sender
    bytes32 salt = keccak256(abi.encodePacked(msg.sender, nonce));
    bytes memory bytecode = implBytecode;
    // Deploy the contract using CREATE2
    assembly {
      deployedAddress := create2(
        0, // value
        add(bytecode, 0x20), // start of bytecode
        mload(bytecode), // length of bytecode
        salt // salt
      )
    }

    require(deployedAddress != address(0), "ZkOwnerFactory: deployment failed");

    // SafeProxy init code - setup function parameters
    address[] memory owners = new address[](1); //1/1 safe
    owners[0] = address(deployedAddress);

    bytes memory safeProxyInitCode = abi.encodeWithSignature(
      "setup(address[],uint256,address,bytes,address,address,uint256,address)",
      owners, // _owners
      1, // _threshold
      address(0), // to
      "", // data
      safeFallbackHandlerAddress, // fallbackHandler sepolia
      address(0), // paymentToken
      0, // payment
      address(0) // paymentReceiver
    );

    // Deploy the SafeProxy
    SafeProxyFactory(safeProxyFactoryAddress).createProxyWithNonce(
      deployedAddress,
      safeProxyInitCode,
      0
    );

    emit ContractDeployed(deployedAddress, salt);
  }
}

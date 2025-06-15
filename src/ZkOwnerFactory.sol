// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { SafeProxyFactory } from "./Safe/SafeProxyFactory.sol";
import { SafeProxy } from "./Safe/SafeProxy.sol";
import { ZkOwner } from "./ZkOwner.sol";

contract ZkOwnerFactory {
  // Events
  event ContractDeployed(
    address indexed safeProxyAddress,
    address indexed deployedAddress,
    bytes32 indexed salt
  );
  event DeploymentFailed(bytes32 indexed salt, string reason);

  bytes public implBytecode;
  uint256 public nonce;
  address public safeProxyFactoryAddress;
  address public safeSingletonAddress;
  address public safeFallbackHandlerAddress;
  address public recursiveVerifier;
  mapping(address => uint256) public nonceByDeployer;

  constructor(
    bytes memory _implBytecode,
    address _safeProxyFactoryAddress,
    address _safeSingletonAddress,
    address _safeFallbackHandlerAddress,
    address _verifier
  ) {
    implBytecode = _implBytecode;
    safeProxyFactoryAddress = _safeProxyFactoryAddress;
    safeSingletonAddress = _safeSingletonAddress;
    safeFallbackHandlerAddress = _safeFallbackHandlerAddress;
    recursiveVerifier = _verifier;
  }

  //for testing purposes
  function setBytecode(bytes memory _implBytecode) external {
    implBytecode = _implBytecode;
  }

  function precomputeAddress(
    address deployer,
    uint256 _nonce
  ) public view returns (address) {
    bytes32 salt = keccak256(abi.encodePacked(deployer, _nonce));
    bytes32 hash = keccak256(
      abi.encodePacked(
        bytes1(0xff),
        address(this),
        salt,
        keccak256(implBytecode)
      )
    );
    return address(uint160(uint256(hash)));
  }

  /*
   * @dev Deploys a contract using CREATE2
   * @param owner The owner address to use as salt
   * @return deployedAddress The address of the deployed contract
   */
  function deploy(
    uint256 threshold, 
    bytes32[] memory identifiers
  ) public returns (address deployedAddress) /*OnlySigner*/ {
    uint256 lastNonce = nonceByDeployer[msg.sender];
    nonceByDeployer[msg.sender] = lastNonce + 1;

    // Create salt from msg.sender
    bytes32 salt = keccak256(abi.encodePacked(msg.sender, lastNonce));
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
    SafeProxy safeProxy = SafeProxyFactory(safeProxyFactoryAddress)
      .createProxyWithNonce(safeSingletonAddress, safeProxyInitCode, 0);
    address safeProxyAddress = address(safeProxy);
    require(
      safeProxyAddress != address(0),
      "ZkOwnerFactory: safe proxy deployment failed"
    );

    // Initialize ZkOwner
    ZkOwner zkOwner = ZkOwner(deployedAddress);
    zkOwner.initialize(safeProxyAddress, threshold, recursiveVerifier, identifiers);
    require(
      zkOwner.isInitialized(),
      "ZkOwnerFactory: zk owner initialization failed"
    );

    emit ContractDeployed(safeProxyAddress, deployedAddress, salt);
  }
}

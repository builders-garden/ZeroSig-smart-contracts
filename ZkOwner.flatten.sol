// SPDX-License-Identifier: MIT
pragma solidity <0.9.0 >=0.7.0 ^0.8.17;

// src/Safe/ISignatureValidator.sol

/* solhint-disable one-contract-per-file */

abstract contract ISignatureValidatorConstants {
    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant EIP1271_MAGIC_VALUE = 0x1626ba7e;
}

abstract contract ISignatureValidator is ISignatureValidatorConstants {
    /**
     * @notice EIP1271 method to validate a signature.
     * @param _hash Hash of the data signed on the behalf of address(this).
     * @param _signature Signature byte array associated with _data.
     *
     * MUST return the bytes4 magic value 0x1626ba7e when function passes.
     * MUST NOT modify state (using STATICCALL for solc < 0.5, view modifier for solc > 0.5)
     * MUST allow external calls
     */
    function isValidSignature(bytes32 _hash, bytes memory _signature) external view virtual returns (bytes4);
}

// src/Safe/SafeProxy.sol

/* solhint-disable one-contract-per-file */

/**
 * @title IProxy - Helper interface to access the singleton address of the Proxy on-chain.
 * @author Richard Meissner - @rmeissner
 */
interface IProxy {
    function masterCopy() external view returns (address);
}

/**
 * @title SafeProxy - Generic proxy contract allows to execute all transactions applying the code of a master contract.
 * @author Stefan George - <stefan@gnosis.io>
 * @author Richard Meissner - <richard@gnosis.io>
 */
contract SafeProxy {
    // Singleton always needs to be first declared variable, to ensure that it is at the same location in the contracts to which calls are delegated.
    // To reduce deployment costs this variable is internal and needs to be retrieved via `getStorageAt`
    address internal singleton;

    /**
     * @notice Constructor function sets address of singleton contract.
     * @param _singleton Singleton address.
     */
    constructor(address _singleton) {
        require(_singleton != address(0), "Invalid singleton address provided");
        singleton = _singleton;
    }

    /// @dev Fallback function forwards all transactions and returns all received return data.
    fallback() external payable {
        // Note that this assembly block is **intentionally** not marked as memory-safe. First of all, it isn't memory
        // safe to begin with, and turning this into memory-safe assembly would just make it less gas efficient.
        // Additionally, we noticed that converting this to memory-safe assembly had no affect on optimizations of other
        // contracts (as it always gets compiled alone in its own compilation unit anyway). Because the assembly block
        // always halts and never returns control back to Solidity, disrespecting Solidity's memory safety invariants
        // is not an issue.
        /* solhint-disable no-inline-assembly */
        assembly {
            let _singleton := sload(0)
            // 0xa619486e == uint32(bytes4(keccak256("masterCopy()"))). Only the 4 first bytes of calldata are
            // considered to make it 100% Solidity ABI conformant.
            if eq(shr(224, calldataload(0)), 0xa619486e) {
                // We mask the singleton address when handling the `masterCopy()` call to ensure that it is correctly
                // ABI-encoded. We do this by shifting the address left by 96 bits (or 12 bytes) and then storing it in
                // memory with a 12 byte offset from where the return data starts. Note that we **intentionally** only
                // do this for the `masterCopy()` call, since the EVM `DELEGATECALL` opcode ignores the most-significant
                // 12 bytes from the address, so we do not need to make sure the top bytes are cleared when proxying
                // calls to the `singleton`. This saves us a tiny amount of gas per proxied call. Additionally, we write
                // to the "zero-memory" slot instead of the scratch space, which guarantees that 12 bytes of memory
                // preceding the singleton address are zero (which would not be guaranteed for the scratch space) [1].
                // This ensures that the data we return has the leading 12 bytes set to zero and conforms to the
                // Solidity ABI [2].
                //
                // [1]: https://docs.soliditylang.org/en/v0.7.6/internals/layout_in_memory.html
                // [2]: https://docs.soliditylang.org/en/v0.7.6/abi-spec.html#formal-specification-of-the-encoding
                mstore(0x6c, shl(96, _singleton))
                return(0x60, 0x20)
            }
            calldatacopy(0, 0, calldatasize())
            let success := delegatecall(gas(), _singleton, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(success) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
        /* solhint-enable no-inline-assembly */
    }
}

// src/Safe/SafeProxyFactory.sol

/**
 * @title Proxy Factory - Allows to create a new proxy contract and execute a message call to the new proxy within one transaction.
 * @author Stefan George - @Georgi87
 */
contract SafeProxyFactory {
    event ProxyCreation(SafeProxy indexed proxy, address singleton);
    event ProxyCreationL2(SafeProxy indexed proxy, address singleton, bytes initializer, uint256 saltNonce);
    event ChainSpecificProxyCreationL2(SafeProxy indexed proxy, address singleton, bytes initializer, uint256 saltNonce, uint256 chainId);

    /// @dev Allows to retrieve the creation code used for the Proxy deployment. With this it is easily possible to calculate predicted address.
    function proxyCreationCode() public pure returns (bytes memory) {
        return type(SafeProxy).creationCode;
    }

    /**
     * @notice Internal method to create a new proxy contract using CREATE2. Optionally executes an initializer call to a new proxy.
     * @param _singleton Address of singleton contract. Must be deployed at the time of execution.
     * @param initializer (Optional) Payload for a message call to be sent to a new proxy contract.
     * @param salt Create2 salt to use for calculating the address of the new proxy contract.
     * @return proxy Address of the new proxy contract.
     */
    function deployProxy(address _singleton, bytes memory initializer, bytes32 salt) internal returns (SafeProxy proxy) {
        require(isContract(_singleton), "Singleton contract not deployed");

        bytes memory deploymentData = abi.encodePacked(type(SafeProxy).creationCode, uint256(uint160(_singleton)));
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            proxy := create2(0x0, add(0x20, deploymentData), mload(deploymentData), salt)
        }
        /* solhint-enable no-inline-assembly */
        require(address(proxy) != address(0), "Create2 call failed");

        if (initializer.length > 0) {
            /* solhint-disable no-inline-assembly */
            /// @solidity memory-safe-assembly
            assembly {
                if iszero(call(gas(), proxy, 0, add(initializer, 0x20), mload(initializer), 0, 0)) {
                    let ptr := mload(0x40)
                    returndatacopy(ptr, 0x00, returndatasize())
                    revert(ptr, returndatasize())
                }
            }
            /* solhint-enable no-inline-assembly */
        }
    }

    /**
     * @notice Deploys a new proxy with `_singleton` singleton and `saltNonce` salt. Optionally executes an initializer call to a new proxy.
     * @param _singleton Address of singleton contract. Must be deployed at the time of execution.
     * @param initializer Payload for a message call to be sent to a new proxy contract.
     * @param saltNonce Nonce that will be used to generate the salt to calculate the address of the new proxy contract.
     */
    function createProxyWithNonce(address _singleton, bytes memory initializer, uint256 saltNonce) public returns (SafeProxy proxy) {
        // If the initializer changes the proxy address should change too. Hashing the initializer data is cheaper than just concatenating it
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
        proxy = deployProxy(_singleton, initializer, salt);
        emit ProxyCreation(proxy, _singleton);
    }

    /**
     * @notice Deploys a new proxy with `_singleton` singleton and `saltNonce` salt. Optionally executes an initializer call to a new proxy.
     * @dev Emits an extra event to allow tracking of `initializer` and `saltNonce`.
     * @param _singleton Address of singleton contract. Must be deployed at the time of execution.
     * @param initializer Payload for a message call to be sent to a new proxy contract.
     * @param saltNonce Nonce that will be used to generate the salt to calculate the address of the new proxy contract.
     */
    function createProxyWithNonceL2(address _singleton, bytes memory initializer, uint256 saltNonce) public returns (SafeProxy proxy) {
        proxy = createProxyWithNonce(_singleton, initializer, saltNonce);
        emit ProxyCreationL2(proxy, _singleton, initializer, saltNonce);
    }

    /**
     * @notice Deploys a new chain-specific proxy with `_singleton` singleton and `saltNonce` salt. Optionally executes an initializer call to a new proxy.
     * @dev Allows to create a new proxy contract that should exist only on 1 network (e.g. specific governance or admin accounts)
     *      by including the chain id in the create2 salt. Such proxies cannot be created on other networks by replaying the transaction.
     * @param _singleton Address of singleton contract. Must be deployed at the time of execution.
     * @param initializer Payload for a message call to be sent to a new proxy contract.
     * @param saltNonce Nonce that will be used to generate the salt to calculate the address of the new proxy contract.
     */
    function createChainSpecificProxyWithNonce(
        address _singleton,
        bytes memory initializer,
        uint256 saltNonce
    ) public returns (SafeProxy proxy) {
        // If the initializer changes the proxy address should change too. Hashing the initializer data is cheaper than just concatenating it
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce, getChainId()));
        proxy = deployProxy(_singleton, initializer, salt);
        emit ProxyCreation(proxy, _singleton);
    }

    /**
     * @notice Deploys a new chain-specific proxy with `_singleton` singleton and `saltNonce` salt. Optionally executes an initializer call to a new proxy.
     * @dev Allows to create a new proxy contract that should exist only on 1 network (e.g. specific governance or admin accounts)
     *      by including the chain id in the create2 salt. Such proxies cannot be created on other networks by replaying the transaction.
     *      Emits an extra event to allow tracking of `initializer` and `saltNonce`.
     * @param _singleton Address of singleton contract. Must be deployed at the time of execution.
     * @param initializer Payload for a message call to be sent to a new proxy contract.
     * @param saltNonce Nonce that will be used to generate the salt to calculate the address of the new proxy contract.
     */
    function createChainSpecificProxyWithNonceL2(
        address _singleton,
        bytes memory initializer,
        uint256 saltNonce
    ) public returns (SafeProxy proxy) {
        proxy = createChainSpecificProxyWithNonce(_singleton, initializer, saltNonce);
        emit ChainSpecificProxyCreationL2(proxy, _singleton, initializer, saltNonce, getChainId());
    }

    /**
     * @notice Returns true if `account` is a contract.
     * @dev This function will return false if invoked during the constructor of a contract,
     *      as the code is not created until after the constructor finishes.
     * @param account The address being queried
     * @return True if `account` is a contract
     */
    function isContract(address account) internal view returns (bool) {
        uint256 size;
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            size := extcodesize(account)
        }
        /* solhint-enable no-inline-assembly */
        return size > 0;
    }

    /**
     * @notice Returns the ID of the chain the contract is currently deployed on.
     * @return The ID of the current chain as a uint256.
     */
    function getChainId() public view returns (uint256) {
        uint256 id;
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            id := chainid()
        }
        /* solhint-enable no-inline-assembly */
        return id;
    }
}

// src/ZkOwner.sol

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

// src/ZkOwnerFactory.sol

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
  address public safeFallbackHandlerAddress;
  address public recursiveVerifier;
  mapping(address => uint256) public nonceByDeployer;

  constructor(
    bytes memory _implBytecode,
    address _safeProxyFactoryAddress,
    address _safeFallbackHandlerAddress,
    address _verifier
  ) {
    implBytecode = _implBytecode;
    safeProxyFactoryAddress = _safeProxyFactoryAddress;
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
      .createProxyWithNonce(deployedAddress, safeProxyInitCode, 0);
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

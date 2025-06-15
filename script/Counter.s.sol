// SPDX-License-Identifier: UNLICENSED from MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {ZkOwnerFactory} from "../src/ZkOwnerFactory.sol";
import {ZkOwner} from "../src/ZkOwner.sol";
import { HonkVerifier } from "../src/Verifier.sol";

contract ZkOwnerFactoryScript is Script {
    ZkOwnerFactory public zkOwnerFactory;
    address public verifier;
    address public safeFallbackHandler_base_sepolia = 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99;
    address public safeProxyFactory_base_sepolia = 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        verifier = address(new HonkVerifier());
        zkOwnerFactory = new ZkOwnerFactory(
            abi.encodePacked(type(ZkOwner).creationCode),
            address(0),
            address(0),     
            verifier
        );

        vm.stopBroadcast();
    }
}

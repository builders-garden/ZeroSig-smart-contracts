// SPDX-License-Identifier: UNLICENSED from MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {ZkOwnerFactory} from "../src/ZkOwnerFactory.sol";
import {ZkOwner} from "../src/ZkOwner.sol";
contract ZkOwnerFactoryScript is Script {
    ZkOwnerFactory public zkOwnerFactory;
    address public verifier;
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        zkOwnerFactory = new ZkOwnerFactory(
            abi.encodePacked(type(ZkOwner).creationCode),
            address(0),
            address(0),     
            verifier
        );

        vm.stopBroadcast();
    }
}

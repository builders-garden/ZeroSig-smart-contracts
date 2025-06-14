// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {ZkOwnerFactory} from "../src/ZkOwnerFactory.sol";

contract ZkOwnerFactoryScript is Script {
    ZkOwnerFactory public zkOwnerFactory;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        zkOwnerFactory = new ZkOwnerFactory(
            bytes(""),
            address(0),
            address(0)
        );

        vm.stopBroadcast();
    }
}

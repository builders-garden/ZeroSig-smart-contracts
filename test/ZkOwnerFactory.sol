// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {ZkOwnerFactory} from "../src/ZkOwnerFactory.sol";

contract ZkOwnerFactoryTest is Test {
    ZkOwnerFactory public zkOwnerFactory;

    function setUp() public {
        zkOwnerFactory = new ZkOwnerFactory(
            bytes(""),
            address(0),
            address(0),
            address(0)            
        );
    }

}

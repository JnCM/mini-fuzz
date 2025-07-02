// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract DocumentRegistry {
    address public admin;
    mapping(bytes32 => bool) public registeredDocs;

    constructor() {
        admin = msg.sender;
    }

    function registerDocument(bytes32 docHash) public {
        require(tx.origin == admin, "Not authorized");
        registeredDocs[docHash] = true;
    }
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MessageDigest {
    struct DigestRecord {
        bytes32 hash;
        uint256 timestamp;
        address submitter;
    }

    mapping(uint256 => DigestRecord) public records;
    uint256 public recordCount;
    address public owner;

    event DigestRecorded(uint256 indexed id, bytes32 indexed hash, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorised");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function recordDigest(bytes32 _hash) external onlyOwner returns (uint256) {
        uint256 id = recordCount++;
        records[id] = DigestRecord(_hash, block.timestamp, msg.sender);
        emit DigestRecorded(id, _hash, block.timestamp);
        return id;
    }

    function getRecord(uint256 id) external view returns (bytes32, uint256, address) {
        DigestRecord memory r = records[id];
        return (r.hash, r.timestamp, r.submitter);
    }
}
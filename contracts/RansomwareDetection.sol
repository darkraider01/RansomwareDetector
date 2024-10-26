// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RansomwareDetection {
    struct Detection {
        string fileHash;
        string timestamp;
        address reporter;
        bool isConfirmed;
    }
    
    mapping(string => Detection) public detections;
    mapping(address => bool) public trustedReporters;
    address public owner;
    
    event NewDetection(string fileHash, string timestamp, address reporter);
    event DetectionConfirmed(string fileHash);
    
    constructor() {
        owner = msg.sender;
        trustedReporters[msg.sender] = true;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }
    
    modifier onlyTrustedReporter() {
        require(trustedReporters[msg.sender], "Only trusted reporters can perform this action");
        _;
    }
    
    function addTrustedReporter(address reporter) public onlyOwner {
        trustedReporters[reporter] = true;
    }
    
    function reportDetection(string memory fileHash, string memory timestamp) public onlyTrustedReporter {
        require(bytes(detections[fileHash].fileHash).length == 0, "Hash already reported");
        
        detections[fileHash] = Detection({
            fileHash: fileHash,
            timestamp: timestamp,
            reporter: msg.sender,
            isConfirmed: false
        });
        
        emit NewDetection(fileHash, timestamp, msg.sender);
    }
    
    function confirmDetection(string memory fileHash) public onlyOwner {
        require(bytes(detections[fileHash].fileHash).length > 0, "Detection not found");
        require(!detections[fileHash].isConfirmed, "Detection already confirmed");
        
        detections[fileHash].isConfirmed = true;
        emit DetectionConfirmed(fileHash);
    }
    
    function getDetection(string memory fileHash) public view returns (Detection memory) {
        require(bytes(detections[fileHash].fileHash).length > 0, "Detection not found");
        return detections[fileHash];
    }
}
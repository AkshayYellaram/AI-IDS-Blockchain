// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AlertStorage {

    struct Alert {
        uint256 id;
        string alertHash;
        string timestamp;
        string srcIp;
        string dstIp;
        uint256 srcPort;
        uint256 dstPort;
        string protocol;
        uint256 attackProbability;
    }

    uint256 public alertCount;

    mapping(uint256 => Alert) public alerts;

    event AlertStored(
        uint256 indexed id,
        string alertHash,
        string timestamp,
        string srcIp,
        string dstIp,
        uint256 attackProbability
    );

    function storeAlert(
        string memory _alertHash,
        string memory _timestamp,
        string memory _srcIp,
        string memory _dstIp,
        uint256 _srcPort,
        uint256 _dstPort,
        string memory _protocol,
        uint256 _attackProbability
    ) public {

        alertCount++;

        alerts[alertCount] = Alert(
            alertCount,
            _alertHash,
            _timestamp,
            _srcIp,
            _dstIp,
            _srcPort,
            _dstPort,
            _protocol,
            _attackProbability
        );

        emit AlertStored(
            alertCount,
            _alertHash,
            _timestamp,
            _srcIp,
            _dstIp,
            _attackProbability
        );
    }

    function getAlert(uint256 _id)
        public
        view
        returns (Alert memory)
    {
        return alerts[_id];
    }
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.6;

// import "../interfaces/IERC165.sol";
import "@openzeppelin/contracts/metatx/MinimalForwarder.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
struct txPendingSruct {
    bytes32 txHash;
    uint256 blockDeadline;
    bytes signature;
}

contract TwoFactorSigner is MinimalForwarder {
    using ECDSA for bytes32;
    mapping(address => mapping(address => bool)) isAuthorizer;
    mapping(address => mapping(uint256 => txPendingSruct)) txPending;
    event TxPending(uint256 indexed blockNumber, bytes request, bytes32 txHash, address indexed signer);
    uint256 blockTimeout;

    constructor(uint256 _blockTimeout) {
        require(_blockTimeout != 0, "No block timeout specified");
        blockTimeout = _blockTimeout;
    }

    function isSignatureAuthenticated(signature,signer,destinatinon,nonce)
    {
        
    }

    function checkAndInvalidate(signature,signer,destination)
    {

    }

    function validateApproval(
        ForwardRequest calldata req,
        bytes calldata signature,
        bytes memory approverSig
    ) internal view returns (bool) {
        txPendingSruct storage record = txPending[req.from][req.nonce];
        bytes32 txHash = _hashTypedDataV4(
            keccak256(abi.encode(_TYPEHASH, req.from, req.to, req.value, req.gas, req.nonce, keccak256(req.data)))
        );
        require(record.blockDeadline < block.number, "2FA01: timeout");
        require(record.txHash != txHash, "2FA02: hashes missmach");
        txPendingSruct storage pending = txPending[req.from][req.nonce];
        require(keccak256(pending.signature) == keccak256(signature), "Signatures do not match");
        require(keccak256(req.data) == pending.txHash, "Hashes do not match");
        address signer = txHash.recover(approverSig);
        require(isAuthorizer[req.from][signer], "Authorizer is not 2FA signer");
        return true;
    }

    function submitTx(
        ForwardRequest calldata req,
        bytes calldata signature
    ) public payable returns (bool, bytes memory) {
        require(MinimalForwarder.verify(req, signature), "wrong tx or signature");
        bytes32 txHash = _hashTypedDataV4(
            keccak256(abi.encode(_TYPEHASH, req.from, req.to, req.value, req.gas, req.nonce, keccak256(req.data)))
        );
        txPending[req.from][req.nonce].txHash = txHash;
        txPending[req.from][req.nonce].blockDeadline = blockTimeout + block.number;
        txPending[req.from][req.nonce].signature = signature;
        emit TxPending(block.number, req.data, txHash, req.from);
    }

    bytes32 private constant _TYPEHASH =
        keccak256("ApproveRequest(address from,address to,uint256 value,uint256 gas,uint256 nonce,bytes data)");

    function approveAndExecute(
        ForwardRequest calldata req,
        bytes calldata signature,
        bytes memory approverSig
    ) public payable returns (bool, bytes memory) {
        validateApproval(req, signature, approverSig);
        (bool status, bytes memory retval) = MinimalForwarder.execute(req, signature);
        return (status, retval);
    }
}

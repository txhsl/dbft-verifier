// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

struct ProofOutputs {
    bytes32 prevHeader;
    bytes32 newHeader;
    bytes32 executionStateRoot;
    bytes32 consensusHash;
    bytes32 nextConsensusHash;
}

/// @title SP1DBFT.
/// @author Succinct Labs
/// @notice This contract implements a protocol of Neo X light client verification.
contract SP1DBFT {
    /// @notice The address of the SP1 verifier contract.
    /// @dev This can either be a specific SP1Verifier for a specific version, or the
    ///      SP1VerifierGateway which can be used to verify proofs for any version of SP1.
    ///      For the list of supported verifiers on each chain, see:
    ///      https://github.com/succinctlabs/sp1-contracts/tree/main/contracts/deployments
    address public verifier;
    /// @notice The verification key for the DBFT program.
    bytes32 public dbftProgramVKey;

    /// @notice The latest header hash.
    bytes32 public latestHeader;
    /// @notice The latest state root.
    bytes32 public latestStateRoot;
    /// @notice The next consensus hash.
    bytes32 public nextConsensus;

    error InvalidTrustedHeader();

    constructor(
        address _verifier,
        bytes32 _dbftProgramVKey,
        bytes32 _latestHeader,
        bytes32 _latestStateRoot,
        bytes32 _nextConsensus
    ) {
        verifier = _verifier;
        dbftProgramVKey = _dbftProgramVKey;
        latestHeader = _latestHeader;
        latestStateRoot = _latestStateRoot;
        nextConsensus = _nextConsensus;
    }

    /// @notice The entrypoint for verifying the proof of a DBFT block.
    /// @param proofBytes The encoded proof.
    /// @param publicValues The encoded public values.
    function verifyDBFTProof(
        bytes calldata proofBytes,
        bytes calldata publicValues
    ) public {
        ISP1Verifier(verifier).verifyProof(
            dbftProgramVKey,
            publicValues,
            proofBytes
        );
        ProofOutputs memory output = abi.decode(
            publicValues,
            (ProofOutputs)
        );
        if (output.prevHeader != latestHeader || output.consensusHash != nextConsensus) {
            revert InvalidTrustedHeader();
        }
        latestHeader = output.newHeader;
        latestStateRoot = output.executionStateRoot;
        nextConsensus = output.nextConsensusHash;
    }
}

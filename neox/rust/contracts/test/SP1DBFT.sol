// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {SP1DBFT} from "../src/SP1DBFT.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";

struct SP1ProofFixtureJson {
    bytes32 prevHeader;
    bytes32 newHeader;
    bytes32 executionStateRoot;
    bytes32 consensusHash;
    bytes32 nextConsensusHash;
    bytes proof;
    bytes publicValues;
    bytes32 vkey;
}

contract SP1DBFTGroth16Test is Test {
    using stdJson for string;

    address verifier;
    SP1DBFT public dbft;

    function loadFixture() public view returns (SP1ProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/groth16-fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SP1ProofFixtureJson));
    }

    function setUp() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        verifier = address(new SP1VerifierGateway(address(1)));
        // The data of a parent block is necessary here.
        dbft = new SP1DBFT(verifier, fixture.vkey, fixture.prevHeader, "0x", fixture.consensusHash);
    }

    function test_ValidDBFTProof() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        vm.mockCall(verifier, abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector), abi.encode(true));

        dbft.verifyDBFTProof(fixture.publicValues, fixture.proof);
        assert(fixture.newHeader == dbft.latestHeader());
        assert(fixture.executionStateRoot == dbft.latestStateRoot());
        assert(fixture.nextConsensusHash == dbft.nextConsensus());
    }

    function testRevert_InvalidDBFTProof() public {
        vm.expectRevert();

        SP1ProofFixtureJson memory fixture = loadFixture();

        // Create a fake proof.
        bytes memory fakeProof = new bytes(fixture.proof.length);

        dbft.verifyDBFTProof(fixture.publicValues, fakeProof);
    }
}


contract SP1DBFTPlonkTest is Test {
    using stdJson for string;

    address verifier;
    SP1DBFT public dbft;

    function loadFixture() public view returns (SP1ProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/plonk-fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SP1ProofFixtureJson));
    }

    function setUp() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        verifier = address(new SP1VerifierGateway(address(1)));
        // The data of a parent block is necessary here.
        dbft = new SP1DBFT(verifier, fixture.vkey, fixture.prevHeader, "0x", fixture.consensusHash);
    }

    function test_ValidDBFTProof() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        vm.mockCall(verifier, abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector), abi.encode(true));

        dbft.verifyDBFTProof(fixture.publicValues, fixture.proof);
        assert(fixture.newHeader == dbft.latestHeader());
        assert(fixture.executionStateRoot == dbft.latestStateRoot());
        assert(fixture.nextConsensusHash == dbft.nextConsensus());
    }

    function testRevert_InvalidDBFTProof() public {
        vm.expectRevert();

        SP1ProofFixtureJson memory fixture = loadFixture();

        // Create a fake proof.
        bytes memory fakeProof = new bytes(fixture.proof.length);

        dbft.verifyDBFTProof(fixture.publicValues, fakeProof);
    }
}

//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can have an
//! EVM-Compatible proof generated which can be verified on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system groth16
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system plonk
//! ```

use alloy_sol_types::SolType;
use clap::{Parser, ValueEnum};
use neox_dbft_verifier_lib::ProofOutputs;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    include_elf, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};
use std::path::PathBuf;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const VERIFIER_ELF: &[u8] = include_elf!("neox-dbft-verifier-program");

/// The arguments for the EVM command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct EVMArgs {
    #[arg(long, default_value = "./script/files/block_17.json")]
    parent: String,
    #[arg(long, default_value = "./script/files/block_18.json")]
    current: String,
    #[arg(long, value_enum, default_value = "groth16")]
    system: ProofSystem,
}

/// Enum representing the available proof systems
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProofSystem {
    Plonk,
    Groth16,
}

/// A fixture that can be used to test the verification of SP1 zkVM proofs inside Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DBFTVerificationProofFixture {
    prev_header: String,
    new_header: String,
    execution_state_root: String,
    consensus_hash: String,
    next_consensus_hash: String,
    vkey: String,
    public_values: String,
    proof: String,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = EVMArgs::parse();

    // Read the parent and current block headers from the provided files.
    let parent_header: alloy_rpc_types::Header =
        serde_json::from_str(&std::fs::read_to_string(args.parent).unwrap()).unwrap();

    let current_header: alloy_rpc_types::Header =
        serde_json::from_str(&std::fs::read_to_string(args.current).unwrap()).unwrap();
    println!("New block height: {}", current_header.number);

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Setup the program.
    let (pk, vk) = client.setup(VERIFIER_ELF);

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    let encoded_1 = serde_json::to_vec(&parent_header).unwrap();
    let encoded_2 = serde_json::to_vec(&current_header).unwrap();
    stdin.write_vec(encoded_1);
    stdin.write_vec(encoded_2);

    println!("Proof System: {:?}", args.system);

    // Generate the proof based on the selected proof system.
    let proof = match args.system {
        ProofSystem::Plonk => client.prove(&pk, &stdin).plonk().run(),
        ProofSystem::Groth16 => client.prove(&pk, &stdin).groth16().run(),
    }
    .expect("failed to generate proof");

    create_proof_fixture(&proof, &vk, args.system);
}

/// Create a fixture for the given proof.
fn create_proof_fixture(
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    system: ProofSystem,
) {
    // Deserialize the public values.
    let bytes = proof.public_values.as_slice();
    let ProofOutputs {
        prevHeader,
        newHeader,
        executionStateRoot,
        consensusHash,
        nextConsensusHash,
    } = ProofOutputs::abi_decode(bytes).unwrap();

    // Create the testing fixture so we can test things end-to-end.
    let fixture = DBFTVerificationProofFixture {
        prev_header: format!("0x{}", hex::encode(prevHeader)),
        new_header: format!("0x{}", hex::encode(newHeader)),
        execution_state_root: format!("0x{}", hex::encode(executionStateRoot)),
        consensus_hash: format!("0x{}", hex::encode(consensusHash)),
        next_consensus_hash: format!("0x{}", hex::encode(nextConsensusHash)),
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(bytes)),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };

    // The verification key is used to verify that the proof corresponds to the execution of the
    // program on the given input.
    //
    // Note that the verification key stays the same regardless of the input.
    println!("Verification Key: {}", fixture.vkey);

    // The public values are the values which are publicly committed to by the zkVM.
    //
    // If you need to expose the inputs or outputs of your program, you should commit them in
    // the public values.
    println!("Public Values: {}", fixture.public_values);

    // The proof proves to the verifier that the program was executed with some inputs that led to
    // the give public values.
    println!("Proof Bytes: {}", fixture.proof);

    // Save the fixture to a file.
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    std::fs::write(
        fixture_path.join(format!("{:?}-fixture.json", system).to_lowercase()),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");
}

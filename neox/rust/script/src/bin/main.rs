//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use neox_dbft_verifier_lib::ProofOutputs;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const VERIFIER_ELF: &[u8] = include_elf!("neox-dbft-verifier-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    #[arg(long, default_value = "./script/files/block_17.json")]
    parent: String,

    #[arg(long, default_value = "./script/files/block_18.json")]
    current: String,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Read the parent and current block headers from the provided files.
    let parent_header: alloy_rpc_types::Header =
        serde_json::from_str(&std::fs::read_to_string(args.parent).unwrap()).unwrap();

    let current_header: alloy_rpc_types::Header =
        serde_json::from_str(&std::fs::read_to_string(args.current).unwrap()).unwrap();
    println!("New block height: {}", current_header.number);

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    let encoded_1 = serde_json::to_vec(&parent_header).unwrap();
    let encoded_2 = serde_json::to_vec(&current_header).unwrap();
    stdin.write_vec(encoded_1);
    stdin.write_vec(encoded_2);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(VERIFIER_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let decoded = ProofOutputs::abi_decode(output.as_slice()).unwrap();
        let ProofOutputs {
            prevHeader,
            newHeader,
            executionStateRoot,
            consensusHash,
            nextConsensusHash,
        } = decoded;
        println!("prevHeader: {}", prevHeader);
        println!("newHeader: {}", newHeader);
        println!("executionStateRoot: {}", executionStateRoot);
        println!("consensusHash: {}", consensusHash);
        println!("nextConsensusHash: {}", nextConsensusHash);

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(VERIFIER_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}

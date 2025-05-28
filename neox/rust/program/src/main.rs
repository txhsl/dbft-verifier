//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_rpc_types::Header;
use alloy_sol_types::SolValue;
use neox_dbft_verifier_lib::{verify_update_header, ProofOutputs};

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let encoded_1 = sp1_zkvm::io::read_vec();
    let encoded_2 = sp1_zkvm::io::read_vec();

    // Decode the headers.
    let header_1: Header = serde_json::from_slice(encoded_1.as_slice()).unwrap();
    let header_2: Header = serde_json::from_slice(encoded_2.as_slice()).unwrap();

    // Verify the header with its parent using a function from the workspace lib crate.
    let valid = verify_update_header(
        header_1.clone().into_consensus(),
        header_2.clone().into_consensus(),
    );
    assert!(valid, "invalid header update");

    // Encode the public values of the program.
    let bytes = ProofOutputs::abi_encode(&ProofOutputs {
        prevHeader: header_1.hash_slow(),
        newHeader: header_2.hash_slow(),
        executionStateRoot: header_2.state_root,
        consensusHash: header_1.mix_hash,
        nextConsensusHash: header_2.mix_hash,
    });

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}

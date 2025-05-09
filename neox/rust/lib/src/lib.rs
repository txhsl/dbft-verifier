use alloy_consensus::{Header};
use alloy_rlp::Encodable;
use alloy_sol_types::sol;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct ProofOutputs {
        /// The previous block header hash.
        bytes32 prevHeader;
        /// The new block header hash.
        bytes32 newHeader;
        /// The execution state root from the execution payload of the new block.
        bytes32 executionStateRoot;
        /// The consensus hash of the current block.
        bytes32 consensusHash;
        /// The consensus hash of the next block.
        bytes32 nextConsensusHash;
    }
}

// Const values in verification.
const EXTRA_V0: u8 = 0;
const EXTRA_V1: u8 = 1;
const EXTRA_V2: u8 = 2;

const EXTRA_V1_ECDSA_SCHEME: u8 = 0;
const EXTRA_V1_THRESHOLD_SCHEME: u8 = 1;

const HASHABLE_EXTRA_V0_LEN: usize = 1;
const HASHABLE_EXTRA_V1_LEN: usize = 34;

const BLS_PUBLIC_KEY_LEN: usize = 48;
const BLS_SIGNATURE_LEN: usize = 96;

// Verify a new block header based on its previous one.
pub fn verify_update_header(parent: Header, current: Header) -> (bool, Option<Vec<u8>>) {
    // Check basic
    if current.parent_hash != parent.hash_slow() {
        return (false, None)
    }
    if current.number != parent.number + 1 {
        return (false, None)
    }
    if current.timestamp <= parent.timestamp {
        return (false, None)
    }
    let expect_consensus = parent.mix_hash;
    if current.extra_data.length() < 1 {
        return (false, None)
    }
    match current.extra_data[0] {
        EXTRA_V0 => {
            // Check format
            if current.extra_data.length() != HASHABLE_EXTRA_V0_LEN+7*20+5*65 {
                return (false, None)
            }
            // Get CNs and sigs

            // Verify CNs

            // Get seal hash

            // Verify sigs
            return (true, Some(Vec::new()))
        }
        EXTRA_V1 | EXTRA_V2 => {
            if current.extra_data.length() < 2 {
                return (false, None)
            }
            match current.extra_data[1] {
                EXTRA_V1_ECDSA_SCHEME => {
                    // Check format

                    // Get CNs and sigs

                    // Verify CNs

                    // Get seal hash

                    // Verify sigs
                    return (true, Some(Vec::new()))
                }
                EXTRA_V1_THRESHOLD_SCHEME => {
                    // Check format

                    // Get CNs and sigs

                    // Verify CNs

                    // Get seal hash

                    // Verify sigs
                    return (true, Some(Vec::new()))
                }
                _ => return (false, None)
            }
        }
        _ => return (false, None)
    }
}

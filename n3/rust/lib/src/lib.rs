use alloy_sol_types::sol;
use neo3::{
    crypto::hash::HashableForString, neo_builder::InteropService, neo_protocol::NeoBlock,
    neo_types::OpCode,
};
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    elliptic_curve::sec1::FromEncodedPoint,
    EncodedPoint, PublicKey,
};
use rustc_serialize::{base64::FromBase64, hex::ToHex};

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct ProofOutputs {
        /// The previous block header hash.
        bytes32 prevHeader;
        /// The new block header hash.
        bytes32 newHeader;
        /// The transaction root from the execution payload of the new block.
        bytes32 transactionRoot;
        /// The consensus hash of the current block.
        bytes32 consensusHash;
        /// The consensus hash of the next block.
        bytes32 nextConsensusHash;
    }
}

const PUBKEY_LEN: usize = 35;
const SIGNATURE_LEN: usize = 64;

const PUBKEY_DATA_LEN: usize = PUBKEY_LEN + 2; // PUSHDATA1 + key length + public key
const SIGNATURE_DATA_LEN: usize = SIGNATURE_LEN + 2; // PUSHDATA1 + signature length + signature

// Verify a new block header based on its previous one.
pub fn verify_update_header(parent: NeoBlock, current: NeoBlock) -> bool {
    // Check basic
    if current.prev_block_hash != parent.hash {
        return false;
    }
    if current.index != parent.index + 1 {
        return false;
    }
    if current.time <= parent.time {
        return false;
    }
    // Format verification
    let expected_consensus = parent.next_consensus;
    let witness = current.witnesses.unwrap();
    let exact_consensus = witness.first().unwrap();
    if exact_consensus.verification.hash160() != expected_consensus {
        return false;
    }
    let verification_script = exact_consensus.verification.from_base64().unwrap();
    let invocation_script = exact_consensus.invocation.from_base64().unwrap();
    if verification_script.len() < 7 * PUBKEY_DATA_LEN + 7 {
        return false;
    }
    if invocation_script.len() < 5 * SIGNATURE_DATA_LEN {
        return false;
    }
    // Content verification
    // Verification script, need to analyze the script outside
    // Ref https://github.com/nspcc-dev/neo-go/blob/1436de45bfbe44b5e60710dafb117b647adddb24/pkg/smartcontract/contract.go#L16
    if verification_script[0] != OpCode::Push5 as u8 {
        return false;
    }
    let mut pubs = Vec::with_capacity(7);
    for i in 0..7 {
        if verification_script[i * PUBKEY_DATA_LEN + 1] != OpCode::PushData1 as u8 {
            return false;
        }
        // Key length
        if verification_script[i * PUBKEY_DATA_LEN + 2] != PUBKEY_LEN as u8 {
            return false;
        }
        // Key data
        pubs.push(
            verification_script[i * PUBKEY_DATA_LEN + 3..(i + 1) * PUBKEY_DATA_LEN + 1].to_vec(),
        );
    }
    // Check the exact pubkey array length
    if verification_script[7 * PUBKEY_DATA_LEN + 1] != OpCode::Push7 as u8 {
        return false;
    }
    // Check the syscall
    if verification_script[7 * PUBKEY_DATA_LEN + 2] != OpCode::Syscall as u8 {
        return false;
    }
    if verification_script[7 * PUBKEY_DATA_LEN + 3..7 * PUBKEY_DATA_LEN + 7]
        .to_vec()
        .to_hex()
        != InteropService::SystemCryptoCheckMultiSig.hash()
    {
        return false;
    }
    // Invocation script, need to analyze the script outside
    // Ref https://github.com/nspcc-dev/neo-go/blob/1436de45bfbe44b5e60710dafb117b647adddb24/internal/testchain/address.go#L129
    let mut sigs = Vec::with_capacity(5);
    for i in 0..5 {
        if invocation_script[i * SIGNATURE_DATA_LEN] != OpCode::PushData1 as u8 {
            return false;
        }
        // Signature length
        if invocation_script[i * SIGNATURE_DATA_LEN + 1] != SIGNATURE_LEN as u8 {
            return false;
        }
        // Signature data
        sigs.push(
            invocation_script[i * SIGNATURE_DATA_LEN + 2..(i + 1) * SIGNATURE_DATA_LEN].to_vec(),
        );
    }
    verify_multi_sigs(current.hash.as_bytes(), &pubs, &sigs)
}

// Note: the complexity of this function is O(n * m), where n is the number of public keys and m is the number of signatures.
// This is unacceptable for ZK proving, so we need to optimize it later.
fn verify_multi_sigs(hash: &[u8], pubs: &[Vec<u8>], sigs: &[Vec<u8>]) -> bool {
    let mut valid_sigs = 0;
    for pub_data in pubs {
        let p = EncodedPoint::from_bytes(pub_data).unwrap();
        let pk = PublicKey::from_encoded_point(&p).unwrap();
        let vk = VerifyingKey::from(&pk);
        for sig in sigs {
            let sig = Signature::from_slice(sig).unwrap();
            if vk.verify(hash, &sig).is_ok() {
                valid_sigs += 1;
                break; // Only count each pubkey once
            }
        }
    }
    valid_sigs >= 5
}

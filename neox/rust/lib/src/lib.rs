use alloy_consensus::{crypto::K256, Header};
use alloy_primitives::{keccak256, Address, Bytes, FixedBytes, U256};
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
pub fn verify_update_header(parent: Header, current: Header) -> bool {
    // Check basic
    if current.parent_hash != parent.hash_slow() {
        return false;
    }
    if current.number != parent.number + 1 {
        return false;
    }
    if current.timestamp <= parent.timestamp {
        return false;
    }
    let expect_consensus = parent.mix_hash;
    if current.extra_data.length() < 1 {
        return false;
    }
    match current.extra_data[0] {
        EXTRA_V0 => {
            // Check format
            if current.extra_data.length() != HASHABLE_EXTRA_V0_LEN + 7 * 20 + 5 * 65 {
                return false;
            }
            // Get CNs and sigs
            let addr_bytes = current
                .extra_data
                .slice(HASHABLE_EXTRA_V0_LEN..HASHABLE_EXTRA_V0_LEN + 7 * 20);
            let sig_bytes = current.extra_data.slice(HASHABLE_EXTRA_V0_LEN + 7 * 20..);
            let mut addrs = Vec::<Address>::new();
            for i in 0..7 {
                addrs.push(Address.from_slice(addr_bytes.slice(i * 20..(i + 1) * 20)));
            }
            let mut sigs = Vec::<Bytes>::new();
            for i in 0..5 {
                sigs.push(sig_bytes.slice(i * 65..(i + 1) * 65));
            }
            // Verify CNs
            let exact_consensus = keccak256(addr_bytes);
            if exact_consensus != expect_consensus {
                return false;
            }
            // Get seal hash
            match encode_sig_header(current) {
                Ok(out) => {
                    // Verify sigs
                    let hash = keccak256(out);
                    return verify_multi_sigs(hash, sigs, addrs);
                }
                Err(_) => return false,
            }
        }
        EXTRA_V1 | EXTRA_V2 => {
            if current.extra_data.length() < 2 {
                return false;
            }
            match current.extra_data[1] {
                EXTRA_V1_ECDSA_SCHEME => {
                    // Check format
                    if current.extra_data.length() != HASHABLE_EXTRA_V1_LEN + 7 * 20 + 5 * 65 {
                        return false;
                    }
                    // Get CNs and sigs
                    let addr_bytes = current
                        .extra_data
                        .slice(HASHABLE_EXTRA_V1_LEN..HASHABLE_EXTRA_V1_LEN + 7 * 20);
                    let sig_bytes = current.extra_data.slice(HASHABLE_EXTRA_V1_LEN + 7 * 20..);
                    let mut addrs = Vec::<Address>::new();
                    for i in 0..7 {
                        addrs.push(Address.from_slice(addr_bytes.slice(i * 20..(i + 1) * 20)));
                    }
                    let mut sigs = Vec::<Bytes>::new();
                    for i in 0..5 {
                        sigs.push(sig_bytes.slice(i * 65..(i + 1) * 65));
                    }
                    // Verify CNs
                    let exact_consensus = keccak256(addr_bytes);
                    if exact_consensus != expect_consensus {
                        return false;
                    }
                    // Get seal hash
                    match encode_sig_header(current) {
                        Ok(out) => {
                            // Verify sigs
                            let hash = keccak256(out);
                            return verify_multi_sigs(hash, sigs, addrs);
                        }
                        Err(_) => return false,
                    }
                }
                EXTRA_V1_THRESHOLD_SCHEME => {
                    // Check format
                    if current.extra_data.length()
                        != HASHABLE_EXTRA_V1_LEN + BLS_PUBLIC_KEY_LEN + BLS_SIGNATURE_LEN
                    {
                        return false;
                    }
                    // Get CNs and sigs

                    // Verify CNs

                    // Get seal hash

                    // Verify sigs
                    return true;
                }
                _ => return false,
            }
        }
        _ => return false,
    }
}

fn encode_sig_header(header: Header) -> Result<Vec<u8>, String> {
    let mut out = Vec::<u8>::new();
    let hashable_extra_len: usize;
    match header.extra_data[0] {
        EXTRA_V0 => hashable_extra_len = HASHABLE_EXTRA_V0_LEN,
        EXTRA_V1 => hashable_extra_len = HASHABLE_EXTRA_V1_LEN,
        _ => return Err("unexpected extra version".to_string()),
    }
    let list_header = alloy_rlp::Header {
        list: true,
        payload_length: header_payload_length(header.clone()) - 7 * 20 - 5 * 65,
    };
    list_header.encode(&mut out);
    header.parent_hash.encode(&mut out);
    header.ommers_hash.encode(&mut out);
    header.beneficiary.encode(&mut out);
    header.state_root.encode(&mut out);
    header.transactions_root.encode(&mut out);
    header.receipts_root.encode(&mut out);
    header.logs_bloom.encode(&mut out);
    header.difficulty.encode(&mut out);
    U256::from(header.number).encode(&mut out);
    U256::from(header.gas_limit).encode(&mut out);
    U256::from(header.gas_used).encode(&mut out);
    header.timestamp.encode(&mut out);
    header
        .extra_data
        .slice(..hashable_extra_len)
        .encode(&mut out);
    header.mix_hash.encode(&mut out);
    header.nonce.encode(&mut out);

    // Encode all the fork specific fields
    if let Some(ref base_fee) = header.base_fee_per_gas {
        U256::from(*base_fee).encode(&mut out);
    }
    if let Some(ref root) = header.withdrawals_root {
        root.encode(&mut out);
    }
    Ok(out)
}

fn header_payload_length(header: Header) -> usize {
    let mut length = 0;
    length += header.parent_hash.length();
    length += header.ommers_hash.length();
    length += header.beneficiary.length();
    length += header.state_root.length();
    length += header.transactions_root.length();
    length += header.receipts_root.length();
    length += header.logs_bloom.length();
    length += header.difficulty.length();
    length += U256::from(header.number).length();
    length += U256::from(header.gas_limit).length();
    length += U256::from(header.gas_used).length();
    length += header.timestamp.length();
    length += header.extra_data.length();
    length += header.mix_hash.length();
    length += header.nonce.length();

    if let Some(base_fee) = header.base_fee_per_gas {
        // Adding base fee length if it exists.
        length += U256::from(base_fee).length();
    }

    if let Some(root) = header.withdrawals_root {
        // Adding withdrawals_root length if it exists.
        length += root.length();
    }

    length
}

fn verify_multi_sigs(hash: FixedBytes<32>, sigs: Vec<Bytes>, addrs: Vec<Address>) -> bool {
    let mut signers = Vec::new();
    return false;
}

fn verify_bls_sig() {}

// fn recover_signer_unchecked(sig: &[u8; 65], msg: &[u8; 32]) -> Result<Address, Error> {
//     let sig =
//         RecoverableSignature::from_compact(&sig[0..64], RecoveryId::try_from(sig[64] as i32)?)?;

//     let public = SECP256K1.recover_ecdsa(&Message::from_digest(*msg), &sig)?;
//     Ok(public_key_to_address(public))
// }

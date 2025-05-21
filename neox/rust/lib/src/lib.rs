use alloy_consensus::Header;
use alloy_primitives::{keccak256, Address, Signature, B256, U256};
use alloy_rlp::Encodable;
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    pairing, G1Affine, G2Affine, G2Projective,
};
use sha2::Sha256;

// Const values in verification.
const EXTRA_V0: u8 = 0;
const EXTRA_V1: u8 = 1;
const EXTRA_V2: u8 = 2;

const EXTRA_V1_ECDSA_SCHEME: u8 = 0;
const EXTRA_V1_THRESHOLD_SCHEME: u8 = 1;

const HASHABLE_EXTRA_V0_LEN: usize = 1;
const HASHABLE_EXTRA_V1_LEN: usize = 34;

const ADDRESS_LEN: usize = 20;
const ECDSA_SIGNATURE_LEN: usize = 65;

const BLS_PUBLIC_KEY_LEN: usize = 48;
const BLS_SIGNATURE_LEN: usize = 96;

const BLS_DOMAIN: &[u8; 43] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

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
            if current.extra_data.length()
                != HASHABLE_EXTRA_V0_LEN + 7 * ADDRESS_LEN + 5 * ECDSA_SIGNATURE_LEN
            {
                return false;
            }
            // Get CNs and sigs
            let addr_bytes = current
                .extra_data
                .slice(HASHABLE_EXTRA_V0_LEN..HASHABLE_EXTRA_V0_LEN + 7 * ADDRESS_LEN);
            let sig_bytes = current.extra_data.slice(
                HASHABLE_EXTRA_V0_LEN + 7 * ADDRESS_LEN
                    ..HASHABLE_EXTRA_V0_LEN + 7 * ADDRESS_LEN + 5 * ECDSA_SIGNATURE_LEN,
            );
            let mut addrs = Vec::<Address>::new();
            for i in 0..7 {
                addrs.push(Address::from_slice(
                    &addr_bytes.slice(i * ADDRESS_LEN..(i + 1) * ADDRESS_LEN),
                ));
            }
            let mut sigs = Vec::<Signature>::new();
            for i in 0..5 {
                sigs.push(
                    Signature::from_raw(
                        &sig_bytes.slice(i * ECDSA_SIGNATURE_LEN..(i + 1) * ECDSA_SIGNATURE_LEN),
                    )
                    .unwrap(),
                );
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
                    verify_multi_sigs(hash, sigs, addrs)
                }
                Err(_) => false,
            }
        }
        EXTRA_V1 | EXTRA_V2 => {
            if current.extra_data.length() < 2 {
                return false;
            }
            match current.extra_data[1] {
                EXTRA_V1_ECDSA_SCHEME => {
                    // Check format
                    if current.extra_data.length()
                        != HASHABLE_EXTRA_V1_LEN + 7 * ADDRESS_LEN + 5 * ECDSA_SIGNATURE_LEN
                    {
                        return false;
                    }
                    // Get CNs and sigs
                    let addr_bytes = current
                        .extra_data
                        .slice(HASHABLE_EXTRA_V1_LEN..HASHABLE_EXTRA_V1_LEN + 7 * ADDRESS_LEN);
                    let sig_bytes = current.extra_data.slice(
                        HASHABLE_EXTRA_V1_LEN + 7 * ADDRESS_LEN
                            ..HASHABLE_EXTRA_V1_LEN + 7 * ADDRESS_LEN + 5 * ECDSA_SIGNATURE_LEN,
                    );
                    let mut addrs = Vec::<Address>::new();
                    for i in 0..7 {
                        addrs.push(Address::from_slice(
                            &addr_bytes.slice(i * ADDRESS_LEN..(i + 1) * ADDRESS_LEN),
                        ));
                    }
                    let mut sigs = Vec::<Signature>::new();
                    for i in 0..5 {
                        sigs.push(
                            Signature::from_raw(
                                &sig_bytes
                                    .slice(i * ECDSA_SIGNATURE_LEN..(i + 1) * ECDSA_SIGNATURE_LEN),
                            )
                            .unwrap(),
                        );
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
                            verify_multi_sigs(hash, sigs, addrs)
                        }
                        Err(_) => false,
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
                    let pub_bytes = current
                        .extra_data
                        .slice(HASHABLE_EXTRA_V1_LEN..HASHABLE_EXTRA_V1_LEN + BLS_PUBLIC_KEY_LEN);
                    let sig_bytes = current.extra_data.slice(
                        HASHABLE_EXTRA_V1_LEN + BLS_PUBLIC_KEY_LEN
                            ..HASHABLE_EXTRA_V1_LEN + BLS_PUBLIC_KEY_LEN + BLS_SIGNATURE_LEN,
                    );
                    let pub_key = G1Affine::from_compressed(
                        pub_bytes.to_vec().as_slice().try_into().unwrap(),
                    )
                    .unwrap();
                    let mut sig = G2Affine::from_compressed(
                        sig_bytes.to_vec().as_slice().try_into().unwrap(),
                    )
                    .unwrap();
                    if current.extra_data[0] == EXTRA_V1 {
                        sig = -sig;
                    }
                    // Verify CNs
                    let exact_consensus = keccak256(pub_bytes);
                    if exact_consensus != expect_consensus {
                        return false;
                    }
                    // Get seal hash
                    match encode_sig_header(current) {
                        Ok(out) => {
                            // Verify sigs
                            let hash =
                                <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
                                    [out],
                                    BLS_DOMAIN,
                                );
                            verify_bls_sig(hash.into(), sig, pub_key)
                        }
                        Err(_) => false,
                    }
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn encode_sig_header(header: Header) -> Result<Vec<u8>, String> {
    let mut out = Vec::<u8>::new();
    let hashable_extra_len: usize = match header.extra_data[0] {
        EXTRA_V0 => HASHABLE_EXTRA_V0_LEN,
        EXTRA_V1 => HASHABLE_EXTRA_V1_LEN,
        _ => return Err("unexpected extra version".to_string()),
    };
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

fn verify_multi_sigs(hash: B256, sigs: Vec<Signature>, addrs: Vec<Address>) -> bool {
    let mut signers = Vec::new();
    for _i in 0..5 {
        signers.push(sigs[0].recover_address_from_prehash(&hash).unwrap())
    }
    signers.sort();
    let mut vi = 0;
    for signer in signers {
        let mut m = false;
        while vi < addrs.len() {
            if addrs[vi] == signer {
                m = true;
            }
            vi += 1;
            if m {
                break;
            }
        }
        if !m {
            return false;
        }
    }
    true
}

fn verify_bls_sig(hash: G2Affine, sig: G2Affine, pub_key: G1Affine) -> bool {
    let g1 = G1Affine::generator();
    pairing(&pub_key, &hash) == pairing(&g1, &sig)
}

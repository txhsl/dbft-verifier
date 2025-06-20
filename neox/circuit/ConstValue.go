package circuit

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/ethereum/go-ethereum/common"
)

const (
	// ExtraV0 is the zero version of block's Extra. Extra of this version includes sorted
	// list of validators addresses followed by BFT number validators signatures.
	ExtraV0 byte = 0x00
	// ExtraV1 is the 1-st version of block's Extra. Extra of this version includes global
	// TPKE public key followed by aggregated validators' threshold signature.
	ExtraV1 byte = 0x01
	// ExtraV2 is the 2-nd version of block's Extra. Extra of this version includes global
	// TPKE public key followed by aggregated validators' threshold signature compatible
	// with Ethereum CL.
	ExtraV2 byte = 0x02
	// ExtraV1ECDSAScheme denotes fallback ECDSA multisignature block signing scheme
	// for ExtraV1 extra.
	ExtraV1ECDSAScheme byte = 0x00
	// ExtraV1ThresholdScheme denotes primary threshold signature block signing scheme
	// for ExtraV1 extra.
	ExtraV1ThresholdScheme byte = 0x01
	// HashableExtraV0Len is the length of hashable part of block extra data for
	// ExtraV0 extra version.
	HashableExtraV0Len = 1
	// HashableExtraV1Len is the length of hashable part of block extra data for
	// ExtraV1 extra version.
	HashableExtraV1Len = 1 + 1 + common.HashLength
	// BLSPublicKeyLen is the length of global public key for signature verification.
	BLSPublicKeyLen = bls12381.SizeOfG1AffineCompressed
	// BLSSignatureLen is the length of block signature.
	BLSSignatureLen = bls12381.SizeOfG2AffineCompressed
)

var (
	BLSDomain = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
)

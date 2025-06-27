package circuit

import (
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/core/types"
	"testing"
)

func TestMultiSigVerifyCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	header := new(types.Header)
	err := header.UnmarshalJSON([]byte(
		`{
    "baseFeePerGas": "0x4a817c800",
    "difficulty": "0x2",
    "extraData": "0x0101072bc064323344cba6d63cad4ca88afbea585fc612919e3e351f457ea3704f76a5b5119bdcba3022c77f07b13bea98239781492b075fb8a1dff6895377dcd5251c3134660c973244d84101814ad14fa9a2267aebbca32f4f307ffe32c1d387b78585335d413747522953d7eccdfdb54fec71d9c8d28ce456ce51fadbf3dd059a15c42c964250c71107c987966a23d49f086cadf981f812d8deab403047cd8b8438fc8ca79cb6ee9290b3780f80007838",
    "gasLimit": "0x1c9c380",
    "gasUsed": "0x0",
    "hash": "0x72273a91d87952260ff37c86839d69d1e1b6d3bbfc6e00a55198950bbcf182dc",
    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "miner": "0x1212000000000000000000000000000000000003",
    "mixHash": "0xc1a8ea569ae7daff411094c088d4dd58cd439d241d9c31af61a537c6505761a5",
    "nonce": "0x0000000000000006",
    "number": "0x2970da",
    "parentHash": "0xecd8bd1c514fd33d9e01184783af6f2dd58f3a213b294fe8019aab5271140633",
    "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    "size": "0x2db",
    "stateRoot": "0xf675a08553de3363c8abc70879a9cc6ca6c6be517ae21a7f6601835fb6181ff9",
    "timestamp": "0x680b3b56",
    "totalDifficulty": "0x5023a7",
    "transactions": [],
    "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    "uncles": [],
    "withdrawals": [],
    "withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
}`,
	))
	data, err := encodeSigHeader(header)
	if err != nil {
		panic(err)
	}
	hash, _ := bls12381.HashToG2(data, BLSDomain)

	pubBytes := header.Extra[HashableExtraV1Len : HashableExtraV1Len+BLSPublicKeyLen]
	sigBytes := header.Extra[HashableExtraV1Len+BLSPublicKeyLen : HashableExtraV1Len+BLSPublicKeyLen+BLSSignatureLen]
	var pk bls12381.G1Affine
	_, err = pk.SetBytes(pubBytes)
	if err != nil {
		panic(err)
	}
	xBytes := make([]frontend.Variable, len(pk.Bytes()))
	for i := 0; i < len(xBytes); i++ {
		xBytes[i] = frontend.Variable(pk.Bytes()[i])
	}
	_, _, g1, _ := bls12381.Generators()
	g1.Neg(&g1)
	var sig bls12381.G2Affine
	_, err = sig.SetBytes(sigBytes)
	circuit := BlsSigVerifyWrapper{
		Pub:  sw_bls12381.NewG1Affine(pk),
		Sig:  sw_bls12381.NewG2Affine(sig),
		Hash: sw_bls12381.NewG2Affine(hash),
		PK:   xBytes,
	}
	witness := BlsSigVerifyWrapper{
		Pub:  sw_bls12381.NewG1Affine(pk),
		Sig:  sw_bls12381.NewG2Affine(sig),
		Hash: sw_bls12381.NewG2Affine(hash),
		PK:   xBytes,
	}
	//_, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	assert.NoError(err)
}

func Sub64(x, y, borrow uint64) (diff, borrowOut uint64) {
	diff = x - y - borrow
	// See Sub32 for the bit logic.
	borrowOut = ((^x & y) | (^(x ^ y) & diff)) >> 63
	return
}

type BlsSigVerifyWrapper struct {
	Hash sw_bls12381.G2Affine
	Sig  sw_bls12381.G2Affine
	Pub  sw_bls12381.G1Affine
	PK   []frontend.Variable
}

const (
	mMask                 byte = 0b111 << 5
	mUncompressed         byte = 0b000 << 5
	_                     byte = 0b001 << 5 // invalid
	mUncompressedInfinity byte = 0b010 << 5
	_                     byte = 0b011 << 5 // invalid
	mCompressedSmallest   byte = 0b100 << 5
	mCompressedLargest    byte = 0b101 << 5
	mCompressedInfinity   byte = 0b110 << 5
	_                     byte = 0b111 << 5 // invalid
)

// Define declares the circuit's constraints
func (c *BlsSigVerifyWrapper) Define(api frontend.API) error {
	cr, err := sw_emulated.New[sw_bls12381.BaseField, sw_bls12381.ScalarField](api, sw_emulated.GetCurveParams[sw_bls12381.BaseField]())
	if err != nil {
		panic(err)
	}
	pkBits := cr.MarshalG1(c.Pub)
	pkBytes := make([]frontend.Variable, len(pkBits)/8)
	for i := 0; i < len(pkBytes); i++ {
		tbits := pkBits[i*8 : (i+1)*8]
		treversebits := make([]frontend.Variable, len(tbits))
		for j := 0; j < len(tbits); j++ {
			treversebits[j] = tbits[len(tbits)-j-1]
		}
		pkBytes[i] = api.FromBinary(treversebits...)
	}
	msbMask := mCompressedSmallest

	/*	// compressed, we need to know if Y is lexicographically bigger than -Y
		// if p.Y ">" -p.Y
		if c.Pub.Y.LexicographicallyLargest() {
			msbMask = mCompressedLargest
		}*/
	cr, err = sw_emulated.New[sw_bls12381.BaseField, sw_bls12381.ScalarField](api, sw_emulated.GetCurveParams[sw_bls12381.BaseField]())
	if err != nil {
		panic(err)
	}
	xBytes := pkBytes[0:48]
	xbits := bits.ToBinary(api, xBytes[0])
	mbits := bits.ToBinary(api, msbMask)
	rbits := make([]frontend.Variable, len(xbits))
	for i := 0; i < len(xbits); i++ {
		rbits[i] = api.Or(xbits[i], mbits[i])
	}
	xBytes[0] = bits.FromBinary(api, rbits)
	for i := 0; i < len(xBytes); i++ {
		api.AssertIsEqual(xBytes[i], c.PK[i])
	}
	verify := NewBlsSigVerify(api)
	verify.Verify(api, &c.Hash, &c.Sig, &c.Pub)
	return nil
}

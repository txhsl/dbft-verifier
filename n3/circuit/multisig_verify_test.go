package circuit

import (
	native_crypto "crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	gc_ecdsa "github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"math/big"
	_ "math/big"
	"math/rand"
	"strconv"
	"testing"
	"time"
)

func TestMultiSigVerifyCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	key, err := ecies.GenerateKey(rand, crypto.S256(), nil)
	publicKey := native_crypto.PublicKey{key.PublicKey.Curve, key.PublicKey.X, key.PublicKey.Y}
	pubBytes := crypto.CompressPubkey(&publicKey)
	privateKey := native_crypto.PrivateKey{publicKey, key.D}

	fmt.Printf("publicKeys:")
	fmt.Printf(hex.EncodeToString(pubBytes))
	fmt.Printf("\n")

	// sign
	data := []byte("testing ECDSA (pre-hashed)")
	msg := sha256.Sum256(data)
	/*	native_crypto.Sign(rand,&privateKey,msg[:])
	 */
	sign, err := crypto.Sign(msg[:], &privateKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("signature length:" + strconv.Itoa(len(sign)))
	fmt.Printf("\n")
	fmt.Printf("signature:")
	fmt.Printf(hex.EncodeToString(sign))
	fmt.Printf("\n")
	/*	var sig gc_ecdsa.Signature
		_, err = sig.SetBytes(sign)
		if err != nil {
			panic(err)
		}*/
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sign[:32])
	s.SetBytes(sign[32:64])

	flag := native_crypto.Verify(&publicKey, msg[:], r, s)
	if !flag {
		t.Errorf("can't verify signature")
	}
	hash := gc_ecdsa.HashToInt(msg[:])

	MsgScript := make([]frontend.Variable, len(msg))
	for i := 0; i < len(msg); i++ {
		MsgScript[i] = msg[i]
	}
	PubScript := make([]frontend.Variable, len(pubBytes))
	for i := 0; i < len(pubBytes); i++ {
		PubScript[i] = pubBytes[i]
	}
	SigScript := make([]frontend.Variable, len(sign))
	for i := 0; i < len(sign); i++ {
		SigScript[i] = sign[i]
	}
	circuit := TempVerifyStruct[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		PubScript: make([]frontend.Variable, len(pubBytes)),
		SigScript: make([]frontend.Variable, len(sign)),
		MsgScript: make([]frontend.Variable, len(msg)),
	}

	witness := TempVerifyStruct[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		MsgScript: MsgScript,
		PubScript: PubScript,
		PubKey: ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](publicKey.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](publicKey.Y),
		},
		Sig: ecdsa.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](r),
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		},
		Hash:      emulated.ValueOf[emulated.Secp256k1Fr](hash),
		SigScript: SigScript,
	}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	_, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(err)
}

type TempVerifyStruct[T, S emulated.FieldParams] struct {
	MsgScript []frontend.Variable
	PubScript []frontend.Variable
	SigScript []frontend.Variable
	PubKey    ecdsa.PublicKey[T, S]
	Sig       ecdsa.Signature[S]
	Hash      emulated.Element[S]
}

// Define declares the circuit's constraints
func (c *TempVerifyStruct[T, S]) Define(api frontend.API) error {
	pubsPoint := c.PubKey
	compressByte := c.PubScript[0]
	pubBytes := c.PubScript[1:]
	field, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}
	field2, err := emulated.NewField[S](api)
	if err != nil {
		return err
	}
	xbits := field.ToBits(&pubsPoint.X)
	ybits := field.ToBits(&pubsPoint.Y)

	//check&calculate first byte(compressed)=0x02 or0x03
	twoBits := bits.ToBinary(api, byte(2), bits.WithNbDigits(8))
	compressedBits := make([]frontend.Variable, len(twoBits))
	for z := range twoBits {
		if z == 0 {
			compressedBits[z] = api.Or(twoBits[z], ybits[0])
		} else {
			compressedBits[z] = twoBits[z]
		}
	}
	compressed := bits.FromBinary(api, compressedBits, bits.WithNbDigits(8))
	api.AssertIsEqual(compressed, compressByte)

	//check compress pubKey x bytes =pub.x
	pubReverseBytes := make([]frontend.Variable, len(pubBytes))
	for i := 0; i < len(pubReverseBytes); i++ {
		index := len(pubReverseBytes) - 1 - i
		pubReverseBytes[i] = pubBytes[index]
	}
	var pubReverseXBits []frontend.Variable
	for i := 0; i < len(pubReverseBytes); i++ {
		tempBits := bits.ToBinary(api, pubReverseBytes[i], bits.WithNbDigits(8))
		pubReverseXBits = append(pubReverseXBits, tempBits...)
	}
	api.AssertIsEqual(len(pubReverseXBits), len(xbits))
	for k := range xbits {
		api.AssertIsEqual(pubReverseXBits[k], xbits[k])
	}
	//check signatures
	rBits := field2.ToBits(&c.Sig.R)
	sBits := field2.ToBits(&c.Sig.S)

	var rBytes []frontend.Variable
	for i := 0; i < 32; i++ {
		temp := bits.FromBinary(api, rBits[i*8:(i+1)*8])
		rBytes = append(rBytes, temp)
	}
	var sBytes []frontend.Variable
	for i := 0; i < 32; i++ {
		temp := bits.FromBinary(api, sBits[i*8:(i+1)*8])
		sBytes = append(sBytes, temp)
	}
	rReverseBytes := make([]frontend.Variable, len(rBytes))
	for i := 0; i < len(rReverseBytes); i++ {
		index := len(rReverseBytes) - 1 - i
		rReverseBytes[i] = rBytes[index]
	}
	sReverseBytes := make([]frontend.Variable, len(sBytes))
	for i := 0; i < len(sReverseBytes); i++ {
		index := len(sReverseBytes) - 1 - i
		sReverseBytes[i] = sBytes[index]
	}
	var tSigBytes []frontend.Variable
	tSigBytes = append(tSigBytes, rReverseBytes...)
	tSigBytes = append(tSigBytes, sReverseBytes...)
	sigBytes := c.SigScript

	api.AssertIsEqual(len(tSigBytes), len(sigBytes)-1)
	for k := range tSigBytes {
		api.AssertIsEqual(tSigBytes[k], sigBytes[k])
	}
	//verify sign
	pubsPoint.Verify(api, sw_emulated.GetCurveParams[T](), &c.Hash, &c.Sig)
	return nil
}

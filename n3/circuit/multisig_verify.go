package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/nspcc-dev/neo-go/pkg/core/interop/interopnames"
	"github.com/nspcc-dev/neo-go/pkg/vm/opcode"
)

const (
	PublickeyLen     = 33               // Length of public key in bytes.
	SignatureLen     = 64               // Length of signature in bytes.
	PublicKeyDataLen = PublickeyLen + 2 // Length of public key data in PubScript (PUSHDATA1 + key length + public key).
	SignatureDataLen = SignatureLen + 2 // Length of signature data in PubScript (PUSHDATA1 + signature length + signature).
)

type MultiSigVerifyWrapper[T, S emulated.FieldParams] struct {
	InvocationScript   []frontend.Variable
	VerificationScript []frontend.Variable
	Data               []emulated.Element[S]
	PubKeys            []ecdsa.PublicKey[T, S]
	Sigs               []ecdsa.Signature[S]
	MappingRules       [][]frontend.Variable
}

// Define declares the circuit's constraints
func (c *MultiSigVerifyWrapper[T, S]) Define(api frontend.API) error {
	verifyer := NewMultiSigVerify[T, S](api)
	verifyer.Verify(api, c.PubKeys, c.Sigs, c.Data, c.MappingRules, c.InvocationScript, c.VerificationScript)
	return nil
}

func NewMultiSigVerify[T, S emulated.FieldParams](api frontend.API) MultiSigVerify[T, S] {
	return MultiSigVerify[T, S]{api: api}
}

type MultiSigVerify[T, S emulated.FieldParams] struct {
	api frontend.API
}

func (multiSigVerify *MultiSigVerify[T, S]) Verify(api frontend.API, pubsPoint []ecdsa.PublicKey[T, S], sigsPoint []ecdsa.Signature[S], data []emulated.Element[S], mappingRules [][]frontend.Variable, InvocationScript []frontend.Variable, VerificationScript []frontend.Variable) {
	cr, err := sw_emulated.New[T, S](api, sw_emulated.GetCurveParams[T]())
	if err != nil {
		panic(err)
	}
	field, err := emulated.NewField[T](api)
	if err != nil {
		return
	}
	//check VerificationScript length
	api.AssertIsLessOrEqual(7*PublicKeyDataLen+7, len(VerificationScript))
	//check InvocationScript length
	api.AssertIsLessOrEqual(5*SignatureDataLen, len(InvocationScript))
	// Content verification
	// Verification PubScript, need to analyze the PubScript outside
	// Ref https://github.com/nspcc-dev/neo-go/blob/1436de45bfbe44b5e60710dafb117b647adddb24/pkg/smartcontract/contract.go#L16
	api.AssertIsEqual(VerificationScript[0], byte(opcode.PUSH5))

	pubs := make([][]frontend.Variable, 7)
	for i := 0; i < 7; i++ {
		api.AssertIsEqual(VerificationScript[i*PublicKeyDataLen+1], byte(opcode.PUSHDATA1))
		// Key length
		api.AssertIsEqual(VerificationScript[i*PublicKeyDataLen+2], byte(PublickeyLen))
		// Key data
		pubs[i] = VerificationScript[i*PublicKeyDataLen+4 : (i+1)*PublicKeyDataLen+1] //原本是3
		compressByte := VerificationScript[i*PublicKeyDataLen+3]
		//check pub
		cr.AssertIsOnCurve((*sw_emulated.AffinePoint[T])(&pubsPoint[i]))
		xBits := field.ToBits(&pubsPoint[i].X)
		yBits := field.ToBits(&pubsPoint[i].Y)
		pubReverseBytes := make([]frontend.Variable, len(pubs[i]))
		for j := 0; j < len(pubReverseBytes); j++ {
			index := len(pubReverseBytes) - 1 - j
			pubReverseBytes[j] = pubs[i][index]
		}
		var pubReverseXBits []frontend.Variable
		for j := 0; i < len(pubReverseBytes); j++ {
			tempBits := bits.ToBinary(api, pubReverseBytes[j], bits.WithNbDigits(8))
			pubReverseXBits = append(pubReverseXBits, tempBits...)
		}
		for j := range xBits {
			api.AssertIsEqual(pubReverseXBits[j], xBits[j])
		}
		api.AssertIsEqual(len(pubReverseXBits), len(xBits))
		//calculate first byte(compressed)=0x02 or0x03
		twoBits := bits.ToBinary(api, byte(2), bits.WithNbDigits(8))
		compressedBits := make([]frontend.Variable, len(twoBits))
		for z := range twoBits {
			if z == 0 {
				compressedBits[z] = api.Or(twoBits[z], yBits[0])
			} else {
				compressedBits[z] = twoBits[z]
			}
		}
		compressed := bits.FromBinary(api, compressedBits, bits.WithNbDigits(8))
		api.AssertIsEqual(compressed, compressByte)
	}
	// Check the exact pubkey array length
	api.AssertIsEqual(VerificationScript[7*PublicKeyDataLen+1], byte(opcode.PUSH7))
	// Check the syscall
	api.AssertIsEqual(VerificationScript[7*PublicKeyDataLen+2], byte(opcode.SYSCALL))
	/*	if binary.LittleEndian.Uint32(VerificationScript[7*PublicKeyDataLen+3:7*PublicKeyDataLen+7]) != interopnames.ToID([]byte(interopnames.SystemCryptoCheckMultisig)) {
		return false
	}*/
	tempIDs := VerificationScript[7*PublicKeyDataLen+3 : 7*PublicKeyDataLen+7]
	interIDs := uints.NewU32(interopnames.ToID([]byte(interopnames.SystemCryptoCheckMultisig)))
	api.AssertIsEqual(len(tempIDs), len(interIDs))
	for j := range interIDs {
		api.AssertIsEqual(interIDs[j], tempIDs[j])
	}

	sigs := make([][]frontend.Variable, 5)
	for i := 0; i < 5; i++ {
		api.AssertIsEqual(InvocationScript[i*SignatureDataLen], byte(opcode.PUSHDATA1))
		// Sig length
		api.AssertIsEqual(InvocationScript[i*SignatureDataLen+1], byte(SignatureLen))
		// Sig data
		sigs[i] = InvocationScript[i*SignatureDataLen+2 : (i+1)*SignatureDataLen]
	}

	for i := 0; i < len(sigs); i++ {
		//Convert index bits,eg.[0001] ,to index int,eg.1
		mapping := mappingRules[i]
		index := 0
		for j := 0; j < len(mapping); j++ {
			if mapping[j] == 1 {
				index = index + (1 << (len(mapping) - j - 1))
			}
		}
		//verify sign
		pubsPoint[i].Verify(api, sw_emulated.GetCurveParams[T](), &data[i], &sigsPoint[index])
	}
}

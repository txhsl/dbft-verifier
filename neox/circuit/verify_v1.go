package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/uints"
	"math"
)

type VerifyWrapper struct {
	Current HeaderParameters
	Parent  HeaderParameters
	Hash    sw_bls12381.G2Affine
	Sig     sw_bls12381.G2Affine
	Pub     sw_bls12381.G1Affine
}

// Define declares the circuit's constraints
func (c *VerifyWrapper) Define(api frontend.API) error {
	verify := NewVerify(api)
	verify.Verify(api, c.Current, c.Parent, c.Pub, c.Sig)
	return nil
}

func NewVerify(api frontend.API) Verify {
	return Verify{api: api}
}

type Verify struct {
	api frontend.API
}

func (verify *Verify) Verify(api frontend.API, current HeaderParameters, parent HeaderParameters, pk sw_bls12381.G1Affine, sig sw_bls12381.G2Affine) {
	// Check basic
	parentHash := rlpHash(api, parent)
	for i := 0; i < len(current.ParentHash); i++ {
		api.AssertIsEqual(current.ParentHash[i], parentHash[i])
	}
	//check current number=parent+1
	cn := frontend.Variable(0)
	for i := 0; i < len(current.Number); i++ {
		exp := math.Pow(256, float64(i))
		tcn := api.Mul(current.Number[i], frontend.Variable(exp))
		cn = api.Add(cn, tcn)
	}
	pn := frontend.Variable(0)
	for i := 0; i < len(parent.Number); i++ {
		exp := math.Pow(256, float64(i))
		tpn := api.Mul(parent.Number[i], frontend.Variable(exp))
		pn = api.Add(pn, tpn)
	}
	api.IsZero(api.Cmp(cn, api.Add(pn, frontend.Variable(1))))

	//compre time ,current.Time should bigger than parent
	ct := frontend.Variable(0)
	for i := 0; i < len(current.Time); i++ {
		exp := math.Pow(256, float64(i))
		tct := api.Mul(current.Time[i], frontend.Variable(exp))
		ct = api.Add(ct, tct)
	}
	pt := frontend.Variable(0)
	for i := 0; i < len(parent.Time); i++ {
		exp := math.Pow(256, float64(i))
		tpt := api.Mul(parent.Time[i], frontend.Variable(exp))
		pt = api.Add(ct, tpt)
	}
	cmp := api.Cmp(ct, pt)
	api.AssertIsEqual(cmp, frontend.Variable(1))

	expectConsensus := parent.MixDigest
	extraLength := len(current.Extra)
	api.AssertIsLessOrEqual(2, frontend.Variable(extraLength))
	v0 := current.Extra[0]
	//Extra[0] should be ExtraV1 | ExtraV2
	rangeCheck(api, v0, []frontend.Variable{frontend.Variable(ExtraV1), frontend.Variable(ExtraV2)})
	v1 := current.Extra[1]
	//Extra[1] should be ExtraV1ThresholdScheme
	api.AssertIsEqual(v1, frontend.Variable(ExtraV1ThresholdScheme))
	// Check format
	api.AssertIsEqual(frontend.Variable(extraLength), frontend.Variable(HashableExtraV1Len+BLSPublicKeyLen+BLSSignatureLen))
	// Get global public key and sig
	pubBytes := current.Extra[HashableExtraV1Len : HashableExtraV1Len+BLSPublicKeyLen]
	sigBytes := current.Extra[HashableExtraV1Len+BLSPublicKeyLen : HashableExtraV1Len+BLSPublicKeyLen+BLSSignatureLen]

	cr, err := sw_emulated.New[sw_bls12381.BaseField, sw_bls12381.ScalarField](api, sw_emulated.GetCurveParams[sw_bls12381.BaseField]())
	if err != nil {
		return
	}
	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		return
	}
	pkBytes := cr.MarshalG1(pk)
	sgBytes := g2.MarshalG2(sig)
	for i := 0; i < len(pkBytes); i++ {
		api.AssertIsEqual(pkBytes[i], pubBytes)
	}
	for i := 0; i < len(sigBytes); i++ {
		api.AssertIsEqual(sgBytes[i], sigBytes)
	}

	// Verify global public key
	keccak256 := NewKeccak256(api)
	exactConsensus := keccak256.Compute(pubBytes)
	for i := 0; i < len(expectConsensus); i++ {
		api.AssertIsEqual(exactConsensus[i], expectConsensus[i])
	}
	// Get seal hash
	headencode := NewHeaderEncode(api)
	data := headencode.EncodeSigHeader(api, current)
	u8data := make([]uints.U8, len(data))
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	for i := 0; i < len(data); i++ {
		u8data[i] = uapi.ByteValueOf(data[i])
	}
	hash, err := g2.HashToG2(api, u8data, BLSDomain)
	if err != nil {
		panic(err)
	}
	/*	hash, _ := bls12381.HashToG2(data, BLSDomain)*/
	// Negate the sig in V1,current.Extra[0] == ExtraV1
	negSig := g2.Neg(&sig)
	/*	flag := api.Cmp(v0, frontend.Variable(ExtraV1))

		r := api.Select(flag, sig, negSig)*/
	// Verify sig
	blsVerify := NewBlsSigVerify(api)
	blsVerify.Verify(api, hash, negSig, &pk)
}

func rlpHash(api frontend.API, head HeaderParameters) []frontend.Variable {
	headencode := NewHeaderEncode(api)
	edata := headencode.EncodeHeader(api, head)
	keccak256 := NewKeccak256(api)
	keccak256.Compute(edata)
	return keccak256.Compute(edata)
}

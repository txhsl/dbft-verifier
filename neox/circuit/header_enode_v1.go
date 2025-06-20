package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

type HeaderParameters struct {
	ParentHash  []frontend.Variable
	UncleHash   []frontend.Variable
	Coinbase    []frontend.Variable
	Root        []frontend.Variable
	TxHash      []frontend.Variable
	ReceiptHash []frontend.Variable
	Bloom       []frontend.Variable
	Difficulty  []frontend.Variable
	Number      []frontend.Variable
	GasLimit    []frontend.Variable
	GasUsed     []frontend.Variable
	Time        []frontend.Variable
	Extra       []frontend.Variable
	MixDigest   []frontend.Variable
	Nonce       []frontend.Variable

	BaseFee         []frontend.Variable
	WithdrawalsHash []frontend.Variable
}

func NewHeaderEncode(api frontend.API) HeaderEncode {
	return HeaderEncode{api: api}
}

type HeaderEncode struct {
	api frontend.API
}

func switchFilter2(api frontend.API, x frontend.Variable, limits []frontend.Variable, results []frontend.Variable) frontend.Variable {
	fbits := make([]frontend.Variable, len(limits))
	xbits := bits.ToBinary(api, x)
	for i := 0; i < len(limits); i++ {
		//if x is a member within the value range, the result of XOR with the member of the value range is 0
		lbits := bits.ToBinary(api, limits[i])
		tbits := make([]frontend.Variable, len(lbits))
		for j := 0; j < len(lbits); j++ {
			tbits[j] = api.Xor(xbits[j], lbits[j])
		}
		ri := frontend.Variable(false)
		for j := 0; j < len(tbits)-1; j++ {
			ri = api.Or(ri, api.And(tbits[j], tbits[j+1]))
		}
		fbits[i] = ri
	}
	flag := frontend.Variable(true)
	result := results[0]
	//If an XOR result is 0, then x is within the value range
	for i := 0; i < len(fbits); i++ {
		flag = api.And(flag, fbits[i])
		result = api.Select(fbits[i], result, results[i])
	}
	//neg
	flag = api.Select(flag, frontend.Variable(false), frontend.Variable(true))
	//check if x is in limits
	api.AssertIsEqual(flag, frontend.Variable(true))
	return result
}

func rangeCheck(api frontend.API, x frontend.Variable, limits []frontend.Variable) {
	flag := frontend.Variable(false)
	for i := 0; i < len(limits); i++ {
		subValue := api.Sub(x, limits[i])
		f := api.IsZero(subValue)
		flag = api.Select(f, f, flag)
	}
	//check if x is in limits
	api.AssertIsEqual(flag, frontend.Variable(1))
}

func (headerEncode *HeaderEncode) EncodeSigHeader(api frontend.API, header HeaderParameters) []frontend.Variable {
	hashableExtraLen := HashableExtraV1Len
	v := header.Extra[0]
	//Extra[0] should be ExtraV1 | ExtraV2
	rangeCheck(api, v, []frontend.Variable{frontend.Variable(ExtraV1), frontend.Variable(ExtraV2)})

	rlp := NewRlpEncode(api)
	encodeHeader := make([][]frontend.Variable, 17)
	encodeHeader[0] = rlp.EncodeRule2(api, header.ParentHash)
	encodeHeader[1] = rlp.EncodeRule2(api, header.UncleHash)
	encodeHeader[2] = rlp.EncodeRule2(api, header.Coinbase)
	encodeHeader[3] = rlp.EncodeRule2(api, header.Root)
	encodeHeader[4] = rlp.EncodeRule2(api, header.TxHash)
	encodeHeader[5] = rlp.EncodeRule2(api, header.ReceiptHash)
	encodeHeader[6] = rlp.EncodeRule3_TwoBytes(api, header.Bloom)
	encodeHeader[7] = rlp.EncodeRule1(api, header.Difficulty)
	encodeHeader[8] = rlp.EncodeRule2(api, header.Number)
	encodeHeader[9] = rlp.EncodeRule2(api, header.GasLimit)
	encodeHeader[10] = rlp.EncodeRule2(api, header.GasUsed)
	encodeHeader[11] = rlp.EncodeRule2(api, header.Time)
	encodeHeader[12] = rlp.EncodeRule2(api, header.Extra[:hashableExtraLen])
	encodeHeader[13] = rlp.EncodeRule2(api, header.MixDigest)
	encodeHeader[14] = rlp.EncodeRule2(api, header.Nonce)
	encodeHeader[15] = rlp.EncodeRule2(api, header.BaseFee)
	encodeHeader[16] = rlp.EncodeRule2(api, header.WithdrawalsHash)

	return rlp.EncodeRule5_TwoBytes(api, encodeHeader)
	//api.Println(extraData)
	/*	enc := make([]frontend.Variable, 0)
		enc = append(enc, header.ParentHash...)
		enc = append(enc, header.UncleHash...)
		enc = append(enc, header.Coinbase...)
		enc = append(enc, header.Root...)
		enc = append(enc, header.TxHash...)
		enc = append(enc, header.ReceiptHash...)
		enc = append(enc, header.Bloom...)
		enc = append(enc, header.Difficulty)
		enc = append(enc, header.Number)
		enc = append(enc, header.GasLimit)
		enc = append(enc, header.GasUsed)
		enc = append(enc, header.Time)
		enc = append(enc, header.Extra[:hashableExtraLen]...) // Yes, this will panic if extra is too short
		enc = append(enc, header.MixDigest...)
		enc = append(enc, header.Nonce...)
		/*	if header.BaseFee != nil {
			enc = append(enc, header.BaseFee)
		}*/
	//enc = append(enc, header.BaseFee)
	/*	if header.WithdrawalsHash != nil {
		enc = append(enc, header.WithdrawalsHash)
	}*/
	//enc = append(enc, header.WithdrawalsHash...)
	//return rlp.EncodeToBytes(enc)
	//return enc*/
}

func (headerEncode *HeaderEncode) EncodeHeader(api frontend.API, header HeaderParameters) []frontend.Variable {
	//hashableExtraLen := HashableExtraV1Len
	v := header.Extra[0]
	//Extra[0] should be ExtraV1 | ExtraV2
	rangeCheck(api, v, []frontend.Variable{frontend.Variable(ExtraV1), frontend.Variable(ExtraV2)})

	rlp := NewRlpEncode(api)
	encodeHeader := make([][]frontend.Variable, 17)
	encodeHeader[0] = rlp.EncodeRule2(api, header.ParentHash)
	encodeHeader[1] = rlp.EncodeRule2(api, header.UncleHash)
	encodeHeader[2] = rlp.EncodeRule2(api, header.Coinbase)
	encodeHeader[3] = rlp.EncodeRule2(api, header.Root)
	encodeHeader[4] = rlp.EncodeRule2(api, header.TxHash)
	encodeHeader[5] = rlp.EncodeRule2(api, header.ReceiptHash)
	encodeHeader[6] = rlp.EncodeRule3_TwoBytes(api, header.Bloom)
	encodeHeader[7] = rlp.EncodeRule1(api, header.Difficulty)
	encodeHeader[8] = rlp.EncodeRule2(api, header.Number)
	encodeHeader[9] = rlp.EncodeRule2(api, header.GasLimit)
	encodeHeader[10] = rlp.EncodeRule2(api, header.GasUsed)
	encodeHeader[11] = rlp.EncodeRule2(api, header.Time)
	encodeHeader[12] = rlp.EncodeRule3_OneByte(api, header.Extra)
	encodeHeader[13] = rlp.EncodeRule2(api, header.MixDigest)
	encodeHeader[14] = rlp.EncodeRule2(api, header.Nonce)
	encodeHeader[15] = rlp.EncodeRule2(api, header.BaseFee)
	encodeHeader[16] = rlp.EncodeRule2(api, header.WithdrawalsHash)

	return rlp.EncodeRule5_TwoBytes(api, encodeHeader)
	//api.Println(extraData)
	/*	enc := make([]frontend.Variable, 0)
		enc = append(enc, header.ParentHash...)
		enc = append(enc, header.UncleHash...)
		enc = append(enc, header.Coinbase...)
		enc = append(enc, header.Root...)
		enc = append(enc, header.TxHash...)
		enc = append(enc, header.ReceiptHash...)
		enc = append(enc, header.Bloom...)
		enc = append(enc, header.Difficulty)
		enc = append(enc, header.Number)
		enc = append(enc, header.GasLimit)
		enc = append(enc, header.GasUsed)
		enc = append(enc, header.Time)
		enc = append(enc, header.Extra[:hashableExtraLen]...) // Yes, this will panic if extra is too short
		enc = append(enc, header.MixDigest...)
		enc = append(enc, header.Nonce...)
		/*	if header.BaseFee != nil {
			enc = append(enc, header.BaseFee)
		}*/
	//enc = append(enc, header.BaseFee)
	/*	if header.WithdrawalsHash != nil {
		enc = append(enc, header.WithdrawalsHash)
	}*/
	//enc = append(enc, header.WithdrawalsHash...)
	//return rlp.EncodeToBytes(enc)
	//return enc*/
}

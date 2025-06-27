package circuit

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/consensys/gnark/frontend"
	"slices"
)

func NewRlpEncode(api frontend.API) RlpEncode {
	return RlpEncode{api: api}
}

type RlpEncode struct {
	api frontend.API
}

// Rule1: data length =1
func (rlpEncode *RlpEncode) EncodeRule1(api frontend.API, data []frontend.Variable) []frontend.Variable {
	dataLength := len(data)
	api.AssertIsEqual(frontend.Variable(dataLength), frontend.Variable(1))
	return data
}

// Rule2: data length <=55
func (rlpEncode *RlpEncode) EncodeRule2(api frontend.API, data []frontend.Variable) []frontend.Variable {
	dataLength := len(data)
	api.AssertIsLessOrEqual(frontend.Variable(dataLength), frontend.Variable(55))
	prefix := frontend.Variable(byte(128) + byte(dataLength))
	var result []frontend.Variable
	result = append(result, prefix)
	result = append(result, data...)
	return result
}

// Rule3: data length >55,data length can be expressed in one byte
func (rlpEncode *RlpEncode) EncodeRule3_OneByte(api frontend.API, data []frontend.Variable) []frontend.Variable {
	dataLength := len(data)
	api.AssertIsLessOrEqual(frontend.Variable(55), frontend.Variable(dataLength))
	api.AssertIsLessOrEqual(frontend.Variable(dataLength), frontend.Variable(255))
	prefix1 := frontend.Variable(byte(183) + 1)
	prefix2 := frontend.Variable(byte(dataLength))
	var result []frontend.Variable
	result = append(result, prefix1)
	result = append(result, prefix2)
	result = append(result, data...)
	return result
}

// Rule3: data length >55,data length can be expressed in two byte
func (rlpEncode *RlpEncode) EncodeRule3_TwoBytes(api frontend.API, data []frontend.Variable) []frontend.Variable {
	dataLength := len(data)
	api.AssertIsLessOrEqual(frontend.Variable(55), frontend.Variable(dataLength))
	api.AssertIsLessOrEqual(frontend.Variable(255), frontend.Variable(dataLength))
	api.AssertIsLessOrEqual(frontend.Variable(dataLength), frontend.Variable(65535))
	prefix1 := frontend.Variable(byte(183) + 2)
	dataLengthBytes := IntToBytes(dataLength)
	prefix2 := frontend.Variable(dataLengthBytes[2])
	prefix3 := frontend.Variable(dataLengthBytes[3])
	var result []frontend.Variable
	result = append(result, prefix1)
	result = append(result, prefix2)
	result = append(result, prefix3)
	result = append(result, data...)
	return result
}

// Rule4: data list length <55
func (rlpEncode *RlpEncode) EncodeRule4(api frontend.API, data [][]frontend.Variable) []frontend.Variable {
	dataLength := 0
	for i := 0; i < len(data); i++ {
		dataLength = dataLength + len(data[i])
	}
	api.AssertIsLessOrEqual(frontend.Variable(dataLength), frontend.Variable(55))
	prefix1 := frontend.Variable(byte(192) + byte(dataLength))
	var result []frontend.Variable
	result = append(result, prefix1)
	for i := 0; i < len(data); i++ {
		result = append(result, data[i]...)
	}
	return result
}

// Rule5: data list length >55,data list length can be expressed in one byte
func (rlpEncode *RlpEncode) EncodeRule5_OneByte(api frontend.API, data [][]frontend.Variable) []frontend.Variable {
	dataLength := 0
	for i := 0; i < len(data); i++ {
		dataLength = dataLength + len(data[i])
	}
	api.AssertIsLessOrEqual(frontend.Variable(55), frontend.Variable(dataLength))
	api.AssertIsLessOrEqual(frontend.Variable(dataLength), frontend.Variable(255))
	prefix1 := frontend.Variable(byte(247) + 1)
	prefix2 := frontend.Variable(byte(dataLength))
	var result []frontend.Variable
	result = append(result, prefix1)
	result = append(result, prefix2)
	for i := 0; i < len(data); i++ {
		result = append(result, data[i]...)
	}
	return result
}

// Rule5: data list length >55,data list length can be expressed in two bytes
func (rlpEncode *RlpEncode) EncodeRule5_TwoBytes(api frontend.API, data [][]frontend.Variable) []frontend.Variable {
	dataLength := 0
	for i := 0; i < len(data); i++ {
		dataLength = dataLength + len(data[i])
	}
	api.AssertIsLessOrEqual(frontend.Variable(55), frontend.Variable(dataLength))
	api.AssertIsLessOrEqual(frontend.Variable(255), frontend.Variable(dataLength))
	api.AssertIsLessOrEqual(frontend.Variable(dataLength), frontend.Variable(65535))
	prefix1 := frontend.Variable(byte(247) + 2)
	dataLengthBytes := IntToBytes(dataLength)
	prefix2 := frontend.Variable(dataLengthBytes[2])
	prefix3 := frontend.Variable(dataLengthBytes[3])
	var result []frontend.Variable
	result = append(result, prefix1)
	result = append(result, prefix2)
	result = append(result, prefix3)
	for i := 0; i < len(data); i++ {
		result = append(result, data[i]...)
	}
	return result
}

func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

// Rule1: data length =1
func (rlpEncode *RlpEncode) EncodeRule1Slice(api frontend.API, data PaddingSlice) PaddingSlice {
	dataLength := data.Len(api)
	api.AssertIsEqual(dataLength, frontend.Variable(1))
	return data
}

// Rule2: data length <=55
func (rlpEncode *RlpEncode) EncodeRule2Slice(api frontend.API, data PaddingSlice) PaddingSlice {
	dataLength := data.Len(api)
	api.AssertIsLessOrEqual(dataLength, frontend.Variable(55))
	prefixBytes := IntToBytesVarible(api, api.Add(frontend.Variable(128), dataLength))
	prefix := prefixBytes[len(prefixBytes)-1]
	sliceApi := NewSliceApi(api)
	fmt.Println(prefix)
	result := sliceApi.Append(data, []frontend.Variable{prefix}, false, true)
	fmt.Println(111, data, result)
	return result
}

// Rule3: data length >55,data length can be expressed in one byte
func (rlpEncode *RlpEncode) EncodeRule3_OneByteSlice(api frontend.API, data PaddingSlice) PaddingSlice {
	dataLength := data.Len(api)
	api.AssertIsLessOrEqual(frontend.Variable(55), dataLength)
	api.AssertIsLessOrEqual(dataLength, frontend.Variable(255))
	prefix1 := frontend.Variable(byte(183) + 1)
	prefix2 := dataLength
	var prefixArray []frontend.Variable
	prefixArray = append(prefixArray, prefix1)
	prefixArray = append(prefixArray, prefix2)
	sliceApi := NewSliceApi(api)
	return sliceApi.Append(data, prefixArray, data.IsLittleEndian, true)
}

// Rule3: data length >55,data length can be expressed in two byte
func (rlpEncode *RlpEncode) EncodeRule3_TwoBytesSlice(api frontend.API, data PaddingSlice) PaddingSlice {
	dataLength := data.Len(api)
	api.AssertIsLessOrEqual(frontend.Variable(55), dataLength)
	api.AssertIsLessOrEqual(frontend.Variable(255), dataLength)
	api.AssertIsLessOrEqual(dataLength, frontend.Variable(65535))
	prefix1 := frontend.Variable(183 + 2)
	dataLengthBytes := IntToBytesVarible(api, dataLength)
	prefix2 := dataLengthBytes[2]
	prefix3 := dataLengthBytes[3]
	var prefixArray []frontend.Variable
	prefixArray = append(prefixArray, prefix1)
	prefixArray = append(prefixArray, prefix2)
	prefixArray = append(prefixArray, prefix3)
	sliceApi := NewSliceApi(api)
	return sliceApi.Append(data, prefixArray, data.IsLittleEndian, true)
}

// Rule4: data list length <55
func (rlpEncode *RlpEncode) EncodeRule4Slice(api frontend.API, data []PaddingSlice) PaddingSlice {
	dataLength := frontend.Variable(0)
	for i := 0; i < len(data); i++ {
		dataLength = api.Add(dataLength, data[i].Len(api))
	}
	api.AssertIsLessOrEqual(dataLength, frontend.Variable(55))
	prefix1 := IntToBytesVarible(api, api.Add(frontend.Variable(192), dataLength))[3]
	sliceApi := NewSliceApi(api)
	var prefixArray []frontend.Variable
	prefixArray = append(prefixArray, prefix1)
	var result = data[0]
	for i := 0; i < len(data); i++ {
		result = sliceApi.concat(result, data[i], data[i].IsLittleEndian)
	}
	return sliceApi.Append(result, prefixArray, result.IsLittleEndian, true)
}

// Rule5: data list length >55,data list length can be expressed in one byte
func (rlpEncode *RlpEncode) EncodeRule5_OneByteSlice(api frontend.API, data []PaddingSlice) PaddingSlice {
	dataLength := frontend.Variable(0)
	for i := 0; i < len(data); i++ {
		dataLength = api.Add(dataLength, data[i].Len(api))
	}
	api.AssertIsLessOrEqual(frontend.Variable(55), dataLength)
	api.AssertIsLessOrEqual(dataLength, frontend.Variable(255))
	prefix1 := frontend.Variable(byte(247) + 1)
	dataLengthBytes := IntToBytesVarible(api, dataLength)
	prefix2 := dataLengthBytes[3]
	var prefixArray []frontend.Variable
	prefixArray = append(prefixArray, prefix1)
	prefixArray = append(prefixArray, prefix2)
	var result = data[0]
	sliceApi := NewSliceApi(api)
	for i := 0; i < len(data); i++ {
		result = sliceApi.concat(result, data[i], data[i].IsLittleEndian)
	}
	return sliceApi.Append(result, prefixArray, result.IsLittleEndian, true)
}

// Rule5: data list length >55,data list length can be expressed in two bytes
func (rlpEncode *RlpEncode) EncodeRule5_TwoBytesSlice(api frontend.API, data []PaddingSlice) PaddingSlice {
	dataLength := frontend.Variable(0)
	for i := 0; i < len(data); i++ {
		dataLength = api.Add(dataLength, data[i].Len(api))
	}
	api.AssertIsLessOrEqual(frontend.Variable(55), dataLength)
	api.AssertIsLessOrEqual(frontend.Variable(255), dataLength)
	api.AssertIsLessOrEqual(dataLength, frontend.Variable(65535))
	prefix1 := frontend.Variable(byte(247) + 2)
	dataLengthBytes := IntToBytesVarible(api, dataLength)
	prefix2 := dataLengthBytes[2]
	prefix3 := dataLengthBytes[3]
	var prefixArray []frontend.Variable
	prefixArray = append(prefixArray, prefix1)
	prefixArray = append(prefixArray, prefix2)
	prefixArray = append(prefixArray, prefix3)
	sliceApi := NewSliceApi(api)
	var result = data[0]
	for i := 0; i < len(data); i++ {
		result = sliceApi.concat(result, data[i], data[i].IsLittleEndian)
	}
	return sliceApi.Append(result, prefixArray, result.IsLittleEndian, true)
}

func IntToBytesVarible(api frontend.API, x frontend.Variable) []frontend.Variable {
	xbits := api.ToBinary(x)
	xbits = append(xbits, frontend.Variable(0), frontend.Variable(0))
	result := make([]frontend.Variable, len(xbits)/8)
	for i := 0; i < len(result); i++ {
		result[i] = api.FromBinary(xbits[i*8 : (i+1)*8]...)
	}
	slices.Reverse(result)
	return result
}

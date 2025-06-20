package circuit

import (
	"bytes"
	"encoding/binary"
	"github.com/consensys/gnark/frontend"
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

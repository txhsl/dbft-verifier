package circuit

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

type Keccak256 struct {
	api frontend.API
}

func NewKeccak256(api frontend.API) Keccak256 {
	return Keccak256{api: api}
}
func (c *Keccak256) Compute(PreImage []frontend.Variable) []frontend.Variable {
	inputSizeInBytes := len(PreImage)
	api := c.api

	var state [25]uints.U64
	for i := range state {
		state[i] = uints.NewU64(0)
	}

	inputSizeInUint64 := (inputSizeInBytes + 8 - 1) / 8
	paddedPreImageLength := inputSizeInUint64 + 17 - (inputSizeInUint64 % 17)
	paddedPreImage := make([]frontend.Variable, paddedPreImageLength)
	for i := 0; i < inputSizeInUint64; i++ {
		binUint64 := make([]frontend.Variable, 0)
		for j := 0; j < 8; j++ {
			if i*8+j < inputSizeInBytes {
				binUint64 = append(binUint64, api.ToBinary(PreImage[i*8+j], 8)...)
			} else {
				binUint64 = append(binUint64, api.ToBinary(0, 8)...)
			}
		}
		paddedPreImage[i] = api.FromBinary(binUint64...)
	}
	for i := inputSizeInUint64; i < paddedPreImageLength; i++ {
		paddedPreImage[i] = 0
	}

	lastUint64ByteCount := inputSizeInBytes % 8
	if lastUint64ByteCount > 0 {
		paddedPreImage[inputSizeInUint64-1] = padWith0x1(api, paddedPreImage[inputSizeInUint64-1], lastUint64ByteCount)
	} else {
		paddedPreImage[inputSizeInUint64] = padWith0x1(api, paddedPreImage[inputSizeInUint64], lastUint64ByteCount)
	}

	toPad := api.ToBinary(paddedPreImage[paddedPreImageLength-1], 64)
	toPad[63] = 1
	paddedPreImage[paddedPreImageLength-1] = api.FromBinary(toPad...)

	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		panic(err)
	}
	for i := 0; i < len(paddedPreImage); i += 17 {
		for j := 0; j < 17; j++ {
			state[j] = uapi.Xor(state[j], uapi.ValueOf(paddedPreImage[i+j]))
		}
		state = keccakf.Permute(uapi, state)
	}
	keyHash := state[:4]
	keyHashBits := make([]frontend.Variable, 0)
	for i := 0; i < len(keyHash); i++ {
		for j := 0; j < len(keyHash[i]); j++ {
			//api.Println(keyHash[i][j].Val, api.ToBinary(keyHash[i][j].Val, 8))
			keyHashBits = append(keyHashBits, api.ToBinary(keyHash[i][j].Val, 8)...) // little-endian
		}
	}
	if len(keyHashBits) != 256 {
		fmt.Println(len(keyHashBits))
		panic(fmt.Errorf("len(keyHashBytes) != 256"))
	}

	// transform to [32]byte
	keyHashBytes := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		index := i * 8
		keyHashBytes[i] = api.FromBinary(keyHashBits[index : index+8]...) // little-endian
		//api.Println(keyHashBytes[i], keyHashBits[index:index+8])
	}
	return keyHashBytes
}

func padWith0x1(api frontend.API, i1 frontend.Variable, pos int) frontend.Variable {
	lastUint64Binary := api.ToBinary(i1, 64)
	lastUint64Binary[(pos)*8] = 1
	return api.FromBinary(lastUint64Binary...)
}

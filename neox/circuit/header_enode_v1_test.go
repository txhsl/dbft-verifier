package circuit

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/core/types"
	"testing"
)

func TestHeaderEncodeV1Circuit(t *testing.T) {
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
	ParentHash := make([]frontend.Variable, len(header.ParentHash))
	for i := 0; i < len(header.ParentHash); i++ {
		ParentHash[i] = header.ParentHash[i]
	}
	UncleHash := make([]frontend.Variable, len(header.UncleHash))
	for i := 0; i < len(header.UncleHash); i++ {
		UncleHash[i] = header.UncleHash[i]
	}
	Coinbase := make([]frontend.Variable, len(header.Coinbase))
	for i := 0; i < len(header.Coinbase); i++ {
		Coinbase[i] = header.Coinbase[i]
	}
	Root := make([]frontend.Variable, len(header.Root))
	for i := 0; i < len(header.Root); i++ {
		Root[i] = header.Root[i]
	}
	TxHash := make([]frontend.Variable, len(header.TxHash))
	for i := 0; i < len(header.TxHash); i++ {
		TxHash[i] = header.TxHash[i]
	}
	ReceiptHash := make([]frontend.Variable, len(header.ReceiptHash))
	for i := 0; i < len(header.ReceiptHash); i++ {
		ReceiptHash[i] = header.ReceiptHash[i]
	}
	Bloom := make([]frontend.Variable, len(header.Bloom))
	for i := 0; i < len(header.Bloom); i++ {
		Bloom[i] = header.Bloom[i]
	}
	difficulty := header.Difficulty.Bytes()
	Difficulty := make([]frontend.Variable, len(difficulty))
	for i := 0; i < len(difficulty); i++ {
		Difficulty[i] = difficulty[i]
	}
	number := header.Number.Bytes()
	Number := make([]frontend.Variable, len(number))
	for i := 0; i < len(number); i++ {
		Number[i] = number[i]
	}
	buf1 := new(bytes.Buffer)
	err = binary.Write(buf1, binary.BigEndian, header.GasLimit)
	if err != nil {
		fmt.Println("Error encoding uint64:", err)
		return
	}
	gl := buf1.Bytes()
	gl = removeUnusedZeroBytes(gl)
	GasLimit := make([]frontend.Variable, len(gl))
	for i := 0; i < len(gl); i++ {
		GasLimit[i] = gl[i]
	}
	buf2 := new(bytes.Buffer)
	err = binary.Write(buf2, binary.BigEndian, header.GasUsed)
	if err != nil {
		fmt.Println("Error encoding uint64:", err)
		return
	}
	gu := buf2.Bytes()
	gu = removeUnusedZeroBytes(gu)
	GasUsed := make([]frontend.Variable, len(gu))
	for i := 0; i < len(gu); i++ {
		GasUsed[i] = gu[i]
	}
	buf3 := new(bytes.Buffer)
	err = binary.Write(buf3, binary.BigEndian, header.Time)
	if err != nil {
		fmt.Println("Error encoding uint64:", err)
		return
	}
	time := buf3.Bytes()
	time = removeUnusedZeroBytes(time)
	Time := make([]frontend.Variable, len(time))
	for i := 0; i < len(time); i++ {
		Time[i] = time[i]
	}
	Extra := make([]frontend.Variable, len(header.Extra))
	for i := 0; i < len(header.Extra); i++ {
		Extra[i] = header.Extra[i]
	}
	MixDigest := make([]frontend.Variable, len(header.MixDigest))
	for i := 0; i < len(header.MixDigest); i++ {
		MixDigest[i] = header.MixDigest[i]
	}
	Nonce := make([]frontend.Variable, len(header.Nonce))
	for i := 0; i < len(header.Nonce); i++ {
		Nonce[i] = header.Nonce[i]
	}
	bf := header.BaseFee.Bytes()
	BaseFee := make([]frontend.Variable, len(bf))
	for i := 0; i < len(bf); i++ {
		BaseFee[i] = bf[i]
	}
	WithdrawalsHash := make([]frontend.Variable, len(header.WithdrawalsHash))
	for i := 0; i < len(header.WithdrawalsHash); i++ {
		WithdrawalsHash[i] = header.WithdrawalsHash[i]
	}
	pheader := HeaderParameters{
		ParentHash:  ParentHash,
		UncleHash:   UncleHash,
		Coinbase:    Coinbase,
		Root:        Root,
		TxHash:      TxHash,
		ReceiptHash: ReceiptHash,
		Bloom:       Bloom,
		Difficulty:  Difficulty,
		Number:      Number,
		GasLimit:    GasLimit,
		GasUsed:     GasUsed,
		Time:        Time,
		Extra:       Extra,
		MixDigest:   MixDigest,
		Nonce:       Nonce,

		BaseFee:         BaseFee,
		WithdrawalsHash: WithdrawalsHash,
	}

	data, err := encodeSigHeader(header)
	if err != nil {
		panic(err)
	}
	Data := make([]frontend.Variable, len(data))
	for i := 0; i < len(Data); i++ {
		Data[i] = data[i]
	}
	fmt.Printf("%v\n", data)
	circuit := HeaderEncodeWrapper{
		Header: pheader,
		Data:   make([]frontend.Variable, len(data)),
	}
	witness := HeaderEncodeWrapper{
		Header: pheader,
		Data:   Data,
	}
	//_, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	assert.NoError(err)
}

type HeaderEncodeWrapper struct {
	Header HeaderParameters
	Data   []frontend.Variable
}

// Define declares the circuit's constraints
func (c *HeaderEncodeWrapper) Define(api frontend.API) error {
	encode := NewHeaderEncode(api)
	edata := encode.EncodeSigHeader(api, c.Header)
	api.Println(edata)
	api.Println(c.Data)
	for i := 0; i < len(edata); i++ {
		api.AssertIsEqual(edata[i], c.Data[i])
	}
	return nil
}

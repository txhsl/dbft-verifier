package circuit

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"testing"
)

func TestKecc256Circuit(t *testing.T) {
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
	pubBytes := header.Extra[HashableExtraV1Len : HashableExtraV1Len+BLSPublicKeyLen]
	k := common.BytesToHash(crypto.Keccak256(pubBytes))
	kHash := make([]frontend.Variable, 32)
	for i := 0; i < len(kHash); i++ {
		kHash[i] = k[i]
	}
	pB := make([]frontend.Variable, len(pubBytes))
	for i := 0; i < len(pubBytes); i++ {
		pB[i] = pubBytes[i]
	}

	circuit := Keccak256Wrapper{
		PreImage: pB,
		Hash:     make([]frontend.Variable, 32),
	}
	witness := Keccak256Wrapper{
		PreImage: pB,
		Hash:     kHash,
	}
	//_, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	assert.NoError(err)
}

type Keccak256Wrapper struct {
	PreImage []frontend.Variable // byte array
	Hash     []frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
func (c *Keccak256Wrapper) Define(api frontend.API) error {
	keccak256 := NewKeccak256(api)
	hash := keccak256.Compute(c.PreImage)
	api.Println(c.Hash[:])
	for j := 0; j < len(c.Hash); j++ {
		api.AssertIsEqual(hash[j], c.Hash[j])
	}
	return nil
}

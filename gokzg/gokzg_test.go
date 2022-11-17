package gokzg_fuzz

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/roots_of_unity"
	"github.com/ethereum/go-ethereum/crypto/kzg"
	protobls "github.com/protolambda/go-kzg/bls"
)

func TestRootsOfUnity(t *testing.T) {
	// Unmarshall json test vector
	file, _ := ioutil.ReadFile("../generated/roots_of_unity.json")
	data := roots_of_unity.RootsOfUnityJson{}
	_ = json.Unmarshal([]byte(file), &data)

	// Roots from test vector
	expectedRoots := data.PermutedRoots

	for i, expRoot := range expectedRoots {
		expRootBytes, err := hex.DecodeString(expRoot)
		if err != nil {
			t.Error(err)
		}
		result := FromBytesReversed(expRootBytes)
		if !protobls.EqualFr(&kzg.DomainFr[i], &result) {
			t.Error("domains are not the same ")
		}
	}

}

// Bytes are reversed because test vectors are in big endian
func FromBytesReversed(b []byte) protobls.Fr {
	s0 := (*[32]byte)(ReverseBytes(b))
	var fr protobls.Fr
	ok := protobls.FrFrom32(&fr, *s0)
	if !ok {
		panic("fr not valid")
	}
	return fr
}

func ReverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

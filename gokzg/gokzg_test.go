package gokzg_fuzz

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	agg_proof "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/agg_proof"
	"github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/precompile"
	"github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/roots_of_unity"
	"github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/verify_kzg_proof"

	"github.com/protolambda/go-kzg/bls"
	"github.com/protolambda/go-kzg/eth"
)

func TestRootsOfUnity(t *testing.T) {
	// Unmarshall json test vector

	file, _ := os.ReadFile("../generated/roots_of_unity.json")
	data := roots_of_unity.RootsOfUnityJson{}
	_ = json.Unmarshal([]byte(file), &data)

	// Roots from test vector
	expectedRoots := data.PermutedRoots

	for i, expRoot := range expectedRoots {
		expRootBytes, err := hex.DecodeString(expRoot)
		if err != nil {
			t.Error(err)
		}

		result := FrfromBytes(expRootBytes)
		if !bls.EqualFr(&eth.DomainFr[i], &result) {
			t.Error("domains are not the same ")
		}
	}

}

const FieldElementsPerBlob = 4096

type BLSFieldElement = [32]byte
type Blob [FieldElementsPerBlob]BLSFieldElement

// eth.Blob interface
func (blob Blob) Len() int {
	return len(blob)
}

// eth.Blob interface
func (blob Blob) At(i int) [32]byte {
	return [32]byte(blob[i])
}

type Blobs []Blob

// eth.BlobSequence interface
func (blobs Blobs) Len() int {
	return len(blobs)
}

// eth.BlobSequence interface
func (blobs Blobs) At(i int) eth.Blob {
	return blobs[i]
}

func TestPrecompile(t *testing.T) {
	// Unmarshall json test vector
	file, err := os.ReadFile("../generated/public_precompile.json")
	if err != nil {
		panic("could not read file")
	}
	data := precompile.PrecompileJson{}
	_ = json.Unmarshal([]byte(file), &data)

	expectedPrecompileReturnValueBytes, err := hex.DecodeString(data.PrecompileReturnValue)
	if err != nil {
		t.Error(err)
	}
	for _, testCase := range data.TestCases {

		inputBytes, err := hex.DecodeString(testCase.Input)
		if err != nil {
			t.Fatal(err)
		}
		returnValBytes, err := eth.PointEvaluationPrecompile(inputBytes)

		if testCase.Valid {
			// There should be no error
			if err != nil {
				t.Fatalf("expected a true value, however an error was returned from the precompile: %v", err)
			}

			// Now check that the return value is correct
			//
			// If there were no errors then the precompile should return the `PrecompileReturnValue`
			// which is specified in EIP-4844
			if !bytes.Equal(returnValBytes, expectedPrecompileReturnValueBytes) {
				fmt.Println(testCase.Valid, err)
				t.Fatalf("unexpected precompile return value, \nexpected: %v, \ngot %v", expectedPrecompileReturnValueBytes, returnValBytes)
			}
		}

		if !testCase.Valid {
			// Since we used invalid input data, we expect an error
			if err == nil {
				t.Fatalf("input data was invalid, however no error was returned.")
			}

		}
	}
}
func TestAggProof(t *testing.T) {
	var blobs Blobs

	// Unmarshall json test vector
	file, _ := os.ReadFile("../generated/public_agg_proof.json")
	data := agg_proof.AggProofJson{}
	_ = json.Unmarshal([]byte(file), &data)

	for _, testCase := range data.TestCases {
		for i := 0; i < testCase.NumPolys; i++ {
			blob := chunkBlob(testCase.Polynomials[i])
			blobs = append(blobs, blob)
		}

		fmt.Println("comm0: ", testCase.Commitments[0])

		proof, err := eth.ComputeAggregateKZGProof(blobs)

		if err != nil {
			panic(err)
		}

		expected_proof, _ := hex.DecodeString(testCase.Proof)

		if !bytes.Equal(proof[:], expected_proof) {
			panic("proofs do not match")
		}
	}
}
func TestVerifyKZGProof(t *testing.T) {

	// Unmarshall json test vector
	file, _ := os.ReadFile("../generated/public_verify_kzg_proof.json")
	data := verify_kzg_proof.VerifyKZGProofJson{}
	_ = json.Unmarshal([]byte(file), &data)

	for _, testCase := range data.TestCases {
		commBytes, err := hex.DecodeString(testCase.Commitment)
		if err != nil {
			panic(err)
		}
		proofBytes, err := hex.DecodeString(testCase.Proof)
		if err != nil {
			panic(err)
		}
		inputPointBytes, err := hex.DecodeString(testCase.InputPoint)
		if err != nil {
			panic(err)
		}
		claimedValueBytes, err := hex.DecodeString(testCase.ClaimedValue)
		if err != nil {
			panic(err)
		}

		inputPoint := (*[32]byte)(inputPointBytes)
		claimedValue := (*[32]byte)(claimedValueBytes)
		comm := (*[48]byte)(commBytes)
		proof := (*[48]byte)(proofBytes)
		ok, err := eth.VerifyKZGProof(*comm, *inputPoint, *claimedValue, *proof)
		if err != nil {
			panic(err)
		}
		if !ok {
			panic("invalid proof")
		}
	}
}

func ReverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func FrfromBytes(b []byte) bls.Fr {
	s0 := (*[32]byte)(b)
	var fr bls.Fr
	ok := bls.FrFrom32(&fr, *s0)
	if !ok {
		panic("fr not valid")
	}
	return fr
}

const chunkSize = 32

func chunkBlob(blobStr string) Blob {

	blobBytes, _ := hex.DecodeString(blobStr)
	if len(blobBytes)%chunkSize != 0 {
		// Maybe return an error here, and put it in the test vectors
		panic("length of blob should be a multiple of 32")
	}

	var chunks Blob
	index := 0
	for {
		if len(blobBytes) == 0 {
			break
		}

		if len(blobBytes) < chunkSize {
			panic("this only happens if the blobBytes cannot be chopped into equal chunkSize parts")
		}

		chunk := blobBytes[0:chunkSize]
		chunkArr := (*[chunkSize]byte)(chunk)
		chunks[index] = BLSFieldElement(*chunkArr)
		blobBytes = blobBytes[chunkSize:]
		index += 1
	}

	return chunks
}

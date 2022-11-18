package gokzg_fuzz

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"

	agg_proof "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/agg_proof"
	"github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/blob_commit"
	"github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/roots_of_unity"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg"
	protobls "github.com/protolambda/go-kzg/bls"
	// protobls "github.com/protolambda/go-kzg/bls"
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
		result := FrfromBytesReversed(expRootBytes)
		if !protobls.EqualFr(&kzg.DomainFr[i], &result) {
			t.Error("domains are not the same ")
		}
	}

}

type Blob = types.Blob

func TestBlobCommit(t *testing.T) {
	// Unmarshall json test vector
	file, _ := ioutil.ReadFile("../generated/blob_commit.json")
	data := blob_commit.BlobCommitJson{}
	_ = json.Unmarshal([]byte(file), &data)

	for i := 0; i < data.NumBlobs; i++ {

		blob := chunkBlob(data.Blobs[i])
		expected_comm, _ := hex.DecodeString(data.Commitments[i])

		got_comm, ok := kzg.BlobToKZGCommitment(blob)
		if !ok {
			panic("could not compute commitment to the blob")
		}

		if !bytes.Equal(expected_comm, got_comm[:]) {
			panic("expected commitment does not match computed commitment")
		}
	}
}

func TestAggProof(t *testing.T) {
	var blobs types.Blobs

	// Unmarshall json test vector
	file, _ := ioutil.ReadFile("../generated/agg_proof.json")
	data := agg_proof.AggProofJson{}
	_ = json.Unmarshal([]byte(file), &data)

	for i := 0; i < data.NumPolys; i++ {
		blob := chunkBlob(data.Polynomials[i])
		blobs = append(blobs, blob)
	}

	fmt.Println("comm0: ", data.Commitments[0])

	proof, err := kzg.ComputeAggregateKZGProof(blobs)

	if err != nil {
		panic(err)
	}

	expected_proof, _ := hex.DecodeString(data.Proof)

	if !bytes.Equal(proof[:], expected_proof) {
		panic("proofs do not match")
	}
}

// Bytes are reversed because test vectors are in big endian
func FrfromBytesReversed(b []byte) protobls.Fr {
	s0 := (*[32]byte)(b)
	var fr protobls.Fr
	ok := protobls.FrFrom32(&fr, *s0)
	if !ok {
		panic("fr not valid")
	}
	return fr
}

const chunkSize = 32

func chunkBlob(blobStr string) types.Blob {

	blobBytes, _ := hex.DecodeString(blobStr)
	if len(blobBytes)%chunkSize != 0 {
		// Maybe return an error here, and put it in the test vectors
		panic("length of blob should be a multiple of 32")
	}

	var chunks types.Blob
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
		chunks[index] = types.BLSFieldElement(*chunkArr)
		blobBytes = blobBytes[chunkSize:]
		index += 1
	}

	return chunks
}

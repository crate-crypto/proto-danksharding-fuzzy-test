package blob_commit

import (
	context "github.com/crate-crypto/go-proto-danksharding-crypto"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialisation"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	helpers "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors"
)

type TestCase struct {
	// Each blob is a flat stream of bytes
	Blob       string
	Commitment string
}

type BlobCommitJson struct {
	BlobDegree   int
	NumTestCases uint32
	TestCases    []TestCase
}

func Generate(c *context.Context) BlobCommitJson {

	numRandPolys := 10
	polys := helpers.GeneratePolys4096(numRandPolys)

	polys = addEdgeCases(polys)

	// Serialise all of the polynomials
	blobs := make([]serialisation.Blob, len(polys))
	for index, poly := range polys {
		blobs[index] = serialisation.SerialisePoly(poly)
	}

	// Commit to Blobs and return serialised commitment
	commitments, err := c.BlobsToCommitments(blobs)
	if err != nil {
		panic(err)
	}

	testCases := make([]TestCase, len(polys))
	for i := 0; i < len(polys); i++ {
		tc := TestCase{
			Blob:       helpers.BytesToHex(blobs[i][:]),
			Commitment: helpers.BytesToHex(commitments[i][:]),
		}
		testCases[i] = tc
	}

	return BlobCommitJson{
		BlobDegree:   helpers.NUM_EVALUATIONS_IN_POLYNOMIALS,
		NumTestCases: uint32(len(testCases)),
		TestCases:    testCases,
	}
}

func addEdgeCases(polys [][]fr.Element) [][]fr.Element {
	// 1. Add zero polynomial to the test case
	zeroPoly := make([]fr.Element, helpers.NUM_EVALUATIONS_IN_POLYNOMIALS)
	polys = append(polys, zeroPoly)

	// 2. Add unit polynomial
	for i := 0; i < helpers.NUM_EVALUATIONS_IN_POLYNOMIALS/32; i++ {
		unitPoly := make([]fr.Element, helpers.NUM_EVALUATIONS_IN_POLYNOMIALS)
		unitPoly[i].SetInt64(-1)
		polys = append(polys, unitPoly)
	}

	return polys
}

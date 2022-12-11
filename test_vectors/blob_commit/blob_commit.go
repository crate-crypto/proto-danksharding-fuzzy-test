package blob_commit

import (
	context "github.com/crate-crypto/go-proto-danksharding-crypto"
	"github.com/crate-crypto/go-proto-danksharding-crypto/agg_kzg"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	helpers "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors"
)

type TestCase struct {
	// Each blob is a flat stream of bytes
	BlobDegree  int
	NumBlobs    int
	Blobs       []string
	Commitments []string
}

type BlobCommitJson struct {
	NumTestCases uint32
	TestCases    []TestCase
}

func Generate(c *context.Context, polyDegree int) BlobCommitJson {

	numRandPolys := 10
	polys := helpers.GeneratePolys(numRandPolys, polyDegree)

	polys = addEdgeCases(polys, polyDegree)

	// Commit to all of the polynomials
	ck := c.CommitKey()
	commitments, err := agg_kzg.CommitToPolynomials(polys, &ck)
	if err != nil {
		panic(err)
	}

	// Flatten and serialise all of the polynomials
	serPolys := make([][]byte, len(polys))
	for i, poly := range polys {
		serPolys[i] = helpers.SerialiseFlattenPoly(poly)
	}

	// Serialise ech commitment
	serComms := make([][]byte, len(polys))
	for i, comm := range commitments {
		serComms[i] = helpers.SerialiseG1Point(comm)
	}

	var testCases = []TestCase{TestCase{NumBlobs: len(serPolys), BlobDegree: polyDegree, Blobs: helpers.ByteSlicesToHex(serPolys), Commitments: helpers.ByteSlicesToHex(serComms)}}

	return BlobCommitJson{
		NumTestCases: uint32(len(testCases)),
		TestCases:    testCases,
	}
}

func addEdgeCases(polys [][]fr.Element, polyDegree int) [][]fr.Element {
	// 1. Add zero polynomial to the test case
	zeroPoly := make([]fr.Element, polyDegree)
	polys = append(polys, zeroPoly)

	// 2. Add unit polynomial
	for i := 0; i < polyDegree/32; i++ {
		unitPoly := make([]fr.Element, polyDegree)
		unitPoly[i].SetInt64(-1)
		polys = append(polys, unitPoly)
	}

	return polys
}

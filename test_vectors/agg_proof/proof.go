package agg_proof

import (
	context "github.com/crate-crypto/go-proto-danksharding-crypto"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialisation"
	helpers "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors"
)

type TestCase struct {
	NumPolys    int
	PolyDegree  int
	Polynomials []string
	Proof       string
	Commitments []string
}

type AggProofJson struct {
	NumTestCases uint32
	TestCases    []TestCase
}

func Generate(c *context.Context) AggProofJson {
	numPolys := 2

	polys := helpers.GeneratePolys4096(numPolys)

	// Serialise polynomials into Blobs
	blobs := make([]serialisation.Blob, len(polys))
	for index, poly := range polys {
		blobs[index] = serialisation.SerialisePoly(poly)
	}

	proof, comms, err := c.ComputeAggregateKZGProof(blobs)
	if err != nil {
		panic(err)
	}

	var testCases = []TestCase{{
		NumPolys:    numPolys,
		PolyDegree:  helpers.NUM_EVALUATIONS_IN_POLYNOMIALS,
		Polynomials: helpers.BlobsToHex(blobs),
		Proof:       helpers.BytesToHex(proof[:]),
		Commitments: helpers.CommitmentsToHex(comms),
	}}

	return AggProofJson{
		NumTestCases: uint32(len(testCases)),
		TestCases:    testCases,
	}
}

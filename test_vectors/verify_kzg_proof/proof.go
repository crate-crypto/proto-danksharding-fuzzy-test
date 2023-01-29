package verify_kzg_proof

import (
	context "github.com/crate-crypto/go-proto-danksharding-crypto"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialisation"
	helpers "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors"
)

type TestCase struct {
	PolyDegree   int
	Polynomial   string
	Proof        string
	Commitment   string
	InputPoint   string
	ClaimedValue string
}

type VerifyKZGProofJson struct {
	NumTestCases uint32
	TestCases    []TestCase
}

// This method takes a seed as it is also called
// from the precompile test case and we want to generate different
// inputs
func Generate(c *context.Context, numPolys int, seed string) VerifyKZGProofJson {

	polys := helpers.GeneratePolys4096(numPolys)

	testCases := make([]TestCase, numPolys)

	scalars := helpers.GenerateScalars(seed, uint(numPolys))

	for index, poly := range polys {

		inputPoint := scalars[index]

		inputPointBytes := serialisation.SerialiseScalar(inputPoint)
		polyBytes := serialisation.SerialisePoly(poly)

		proof, polyComm, claimedValue, err := c.ComputeKZGProof(polyBytes, inputPointBytes)
		if err != nil {
			panic(err)
		}

		tc := TestCase{
			PolyDegree:   helpers.NUM_EVALUATIONS_IN_POLYNOMIALS,
			Polynomial:   helpers.BytesToHex(polyBytes[:]),
			Proof:        helpers.BytesToHex(proof[:]),
			Commitment:   helpers.BytesToHex(polyComm[:]),
			InputPoint:   helpers.BytesToHex(inputPointBytes[:]),
			ClaimedValue: helpers.BytesToHex(claimedValue[:]),
		}
		testCases[index] = tc
	}

	return VerifyKZGProofJson{
		NumTestCases: uint32(len(testCases)),
		TestCases:    testCases,
	}

}

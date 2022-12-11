package verify_kzg_proof

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	context "github.com/crate-crypto/go-proto-danksharding-crypto"
	"github.com/crate-crypto/go-proto-danksharding-crypto/utils"
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

func Generate(c *context.Context, polyDegree int) VerifyKZGProofJson {
	numPolys := 2

	polys := helpers.GeneratePolys(numPolys, polyDegree)

	testCases := make([]TestCase, numPolys)

	for index, poly := range polys {
		var inputPoint fr.Element
		// Set the point such that it is not a value in the domain
		// The opening algorithm and the specs do not explicitly handle this case
		inputPoint.SetInt64(int64(index + 2*polyDegree))

		inputPointBytes := inputPoint.Bytes()
		utils.ReverseArray(&inputPointBytes) // Reverse so that it is in little endian format

		polyBytes := helpers.SerialisePoly(poly)

		proof, polyComm, claimedValue, err := c.ComputeKzgProof(polyBytes, inputPointBytes)
		if err != nil {
			panic(err)
		}
		polyBytesFlattened := helpers.FlattenBytes(polyBytes)

		tc := TestCase{
			PolyDegree:   polyDegree,
			Polynomial:   helpers.BytesToHex(polyBytesFlattened),
			Proof:        helpers.BytesToHex(proof),
			Commitment:   helpers.BytesToHex(polyComm),
			InputPoint:   helpers.BytesToHex(inputPointBytes[:]),
			ClaimedValue: helpers.BytesToHex(claimedValue[:]),
		}
		testCases[index] = tc
	}

	return VerifyKZGProofJson{
		NumTestCases: uint32(len(testCases)),
		TestCases:    testCases,
	}

	// var eval fr.Element
	// eval.SetInt64(int64(2561234561))
	// inputPointBytes := eval.Bytes()
	// utils.ReverseArray(&inputPointBytes)

	// polyBytes := helpers.SerialisePoly(polys[0])
	// proof, polyComm, claimedValue, err := c.ComputeKzgProof(polyBytes, inputPointBytes)
	// if err != nil {
	// 	panic(err)
	// }
	// polyBytesFlattened := helpers.FlattenBytes(polyBytes)

	// return VerifyKZGProofJson{
	// 	TestCases: []TestCase{
	// 		TestCase{
	// 			PolyDegree:   polyDegree,
	// 			Polynomial:   helpers.BytesToHex(polyBytesFlattened),
	// 			Proof:        helpers.BytesToHex(proof),
	// 			Commitment:   helpers.BytesToHex(polyComm),
	// 			InputPoint:   helpers.BytesToHex(inputPointBytes[:]),
	// 			ClaimedValue: helpers.BytesToHex(claimedValue[:]),
	// 		},
	// 	},
	// }

}

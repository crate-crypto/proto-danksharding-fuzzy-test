package proof

import (
	context "github.com/crate-crypto/go-proto-danksharding-crypto"
	helpers "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors"
)

type AggProofJson struct {
	NumPolys    int
	PolyDegree  int
	Polynomials []string
	Proof       string
	Commitments []string
}

func Generate(c *context.Context, polyDegree int) AggProofJson {
	numPolys := 2

	polys := helpers.GeneratePolys(numPolys, polyDegree)
	serPolys := helpers.SerialisePolys(polys)

	proof, comms, err := c.ComputeAggregateKzgProofAlt(serPolys, uint(polyDegree))
	if err != nil {
		panic(err)
	}

	return AggProofJson{
		NumPolys:    numPolys,
		PolyDegree:  polyDegree,
		Polynomials: helpers.ByteSlicesToHex(serPolys),
		Proof:       helpers.BytesToHex(proof),
		Commitments: helpers.ByteSlicesToHex(comms),
	}
}

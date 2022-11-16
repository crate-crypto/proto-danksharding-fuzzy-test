package trusted_setup

import (
	context "github.com/crate-crypto/go-proto-danksharding-crypto"
	helpers "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// This struct will hold the trusted setup.
// This file is empty because we need to create a method on the context to
// export the trusted setup files
type TrustedSetupJson struct {
	Secret     int
	NumG1      int
	NumG2      int
	G1Elements []string
	G2Elements []string
}

func Generate(c *context.Context, secret int, polyDegree int) TrustedSetupJson {

	// For KZG/Proto danksharding, this is always 2
	numG2 := 2

	g1Points := c.CommitKey().G1
	serG1Points := helpers.SerialiseG1Points(g1Points)

	degree0G2 := c.OpenKeyKey().GenG2
	degree1G2 := c.OpenKeyKey().AlphaG2

	g2Points := []curve.G2Affine{degree0G2, degree1G2}
	serG2Points := helpers.SerialiseG2Points(g2Points)

	return TrustedSetupJson{
		Secret:     secret,
		NumG1:      polyDegree,
		NumG2:      numG2,
		G1Elements: helpers.ByteSlicesToHex(serG1Points),
		G2Elements: helpers.ByteSlicesToHex(serG2Points),
	}

}

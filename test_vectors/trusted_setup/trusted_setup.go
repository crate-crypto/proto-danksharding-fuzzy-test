package trusted_setup

import (
	context "github.com/crate-crypto/go-proto-danksharding-crypto"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialisation"
	helpers "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// This struct will hold the trusted setup.
// This file is empty because we need to create a method on the context to
// export the trusted setup files
type TrustedSetupJson struct {
	Secret             int
	NumG1              int
	NumG2              int
	G1Gen              string
	G2Gen              string
	PermutedG1Elements []string
	G2Elements         []string
}

func Generate(c *context.Context) TrustedSetupJson {

	// For KZG/Proto danksharding, this is always 2
	numG2 := 2

	g1Points := c.CommitKey().G1
	serG1Points := serialisation.SerialiseG1Points(g1Points)

	degree0G2 := c.OpenKeyKey().GenG2
	degree1G2 := c.OpenKeyKey().AlphaG2

	g2Points := []curve.G2Affine{degree0G2, degree1G2}
	serG2PointDeg0 := serialisation.SerialiseG2Point(g2Points[0])
	serG2PointDeg1 := serialisation.SerialiseG2Point(g2Points[1])
	serG2Points := [][]byte{serG2PointDeg0[:], serG2PointDeg1[:]}

	var serGenG1 = serialisation.SerialiseG1Point(c.OpenKeyKey().GenG1)
	var serGenG2 = serialisation.SerialiseG2Point(c.OpenKeyKey().GenG2)

	return TrustedSetupJson{
		Secret:             helpers.SECRET,
		NumG1:              helpers.NUM_EVALUATIONS_IN_POLYNOMIALS,
		NumG2:              numG2,
		G1Gen:              helpers.BytesToHex(serGenG1[:]),
		G2Gen:              helpers.BytesToHex(serGenG2[:]),
		PermutedG1Elements: helpers.CommitmentsToHex(serG1Points),
		G2Elements:         helpers.ByteSlicesToHex(serG2Points),
	}

}

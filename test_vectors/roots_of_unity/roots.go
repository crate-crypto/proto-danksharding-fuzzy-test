package roots_of_unity

import (
	context "github.com/crate-crypto/go-proto-danksharding-crypto"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialisation"
	helpers "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors"
)

type RootsOfUnityJson struct {
	NumRoots      int
	PermutedRoots []string
}

func Generate(c *context.Context) RootsOfUnityJson {

	domain := c.Domain()

	roots := domain.Roots
	numRoots := len(roots)

	serRoots := make([][]byte, numRoots)
	for i := 0; i < numRoots; i++ {
		serialisedScalar := serialisation.SerialiseScalar(roots[i])
		serRoots[i] = serialisedScalar[:]
	}

	return RootsOfUnityJson{
		NumRoots:      numRoots,
		PermutedRoots: helpers.ByteSlicesToHex(serRoots),
	}
}

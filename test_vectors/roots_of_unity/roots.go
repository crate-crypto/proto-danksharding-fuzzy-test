package roots_of_unity

import (
	context "github.com/crate-crypto/go-proto-danksharding-crypto"
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
	serRoots := helpers.SerialisePoly(roots)
	return RootsOfUnityJson{
		NumRoots:      numRoots,
		PermutedRoots: helpers.ByteSlicesToHex(serRoots),
	}
}

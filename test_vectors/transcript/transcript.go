package transcript

import (
	"encoding/hex"

	helpers "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors"

	"github.com/crate-crypto/go-proto-danksharding-crypto/agg_kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/fiatshamir"
)

type TranscriptJson struct {
	NumPolys    int
	PolyDegree  int
	Polynomials []string
	Commitments []string
	challenge   string
}

func Generate(polyDegree int) TranscriptJson {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)
	numPolys := 12

	points := helpers.GeneratePoints(numPolys)
	polys := helpers.GeneratePolys(numPolys, polyDegree)

	transcript.AppendPointsPolys(points, polys)

	challenge := transcript.ChallengeScalar()
	bytes := challenge.Bytes()
	challengeHex := hex.EncodeToString(bytes[:])

	serPolys := helpers.SerialisePolys(polys)
	serComms := helpers.SerialiseG1Points(points)

	return TranscriptJson{
		NumPolys:    numPolys,
		PolyDegree:  polyDegree,
		Polynomials: helpers.ByteSlicesToHex(serPolys),
		Commitments: helpers.ByteSlicesToHex(serComms),
		challenge:   challengeHex,
	}
}

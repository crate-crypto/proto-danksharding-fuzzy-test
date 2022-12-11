package transcript

import (
	"encoding/hex"

	helpers "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors"

	"github.com/crate-crypto/go-proto-danksharding-crypto/agg_kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/fiatshamir"
)

type TestCase struct {
	NumPolys    int
	PolyDegree  int
	Polynomials []string
	Commitments []string
	challenge   string
}

type TranscriptJson struct {
	NumTestCases uint32
	TestCases    []TestCase
}

func Generate(polyDegree int) TranscriptJson {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)
	numPolys := 12

	points := helpers.GeneratePoints(numPolys)
	polys := helpers.GeneratePolys(numPolys, polyDegree)

	transcript.AppendPointsPolys(points, polys)

	challenges := transcript.ChallengeScalars(2)
	bytes := challenges[0].Bytes()
	challengeHex := hex.EncodeToString(bytes[:])

	serPolys := helpers.SerialisePolys(polys)
	serComms := helpers.SerialiseG1Points(points)

	var testCases = []TestCase{
		TestCase{
			NumPolys:    numPolys,
			PolyDegree:  polyDegree,
			Polynomials: helpers.ByteSlicesToHex(serPolys),
			Commitments: helpers.ByteSlicesToHex(serComms),
			challenge:   challengeHex,
		}}

	return TranscriptJson{
		NumTestCases: uint32(len(testCases)),
		TestCases:    testCases,
	}
}

package helpers

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialisation"
)

// The degree of the polynomial is fixed at 4095
// So each polynomial will have 4096 evaluations
const NUM_EVALUATIONS_IN_POLYNOMIALS = 4096

// The secret being used to generate the insecure trusted setup
const SECRET = 1337

// TODO: have this take a seed, so we can generate different polynomials
func GeneratePolys4096(numPolys int) [][]fr.Element {
	polys := make([][]fr.Element, numPolys)
	offset := 0
	for i := 0; i < numPolys; i++ {
		polys[i] = offsetPoly(offset)
		offset += NUM_EVALUATIONS_IN_POLYNOMIALS
	}
	return polys
}

func GenerateScalars(seed string, numScalars uint) []fr.Element {

	seedByte := []byte(seed)

	scalars := make([]fr.Element, numScalars)
	for i := 0; i < int(numScalars); i++ {
		scalar := hashIndexToField(seedByte, i)
		scalars[i] = scalar
	}

	return scalars
}

func hashIndexToField(byts []byte, index int) fr.Element {

	sha := sha256.New()

	indexByte := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexByte, uint32(index))

	shaInput := append(byts, indexByte...)
	hashOutput := sha.Sum(shaInput)

	var scalar fr.Element
	scalar.SetBytes(hashOutput)

	return scalar
}

func offsetPoly(offset int) []fr.Element {
	poly := make([]fr.Element, NUM_EVALUATIONS_IN_POLYNOMIALS)
	for i := 0; i < NUM_EVALUATIONS_IN_POLYNOMIALS; i++ {
		var eval fr.Element
		eval.SetInt64(int64(offset + i))
		poly[i] = eval
	}
	return poly
}

func GeneratePoints(size int) []curve.G1Affine {
	points := make([]curve.G1Affine, size)
	_, _, g1Gen, _ := curve.Generators()

	for i := 0; i < size; i++ {
		points[i] = g1Gen
		g1Gen.Add(&g1Gen, &g1Gen)
	}

	return points
}

func BytesToHex(slice []byte) string {
	return hex.EncodeToString(slice)
}
func HexToBytes(hexString string) []byte {
	byts, err := hex.DecodeString(hexString)
	if err != nil {
		panic(err)
	}
	return byts
}
func ByteSlicesToHex(slice [][]byte) []string {
	res := make([]string, len(slice))
	for i, byts := range slice {
		res[i] = BytesToHex(byts)
	}
	return res
}
func BlobsToHex(blobs []serialisation.Blob) []string {
	res := make([]string, len(blobs))
	for i, blob := range blobs {
		res[i] = BytesToHex(blob[:])
	}
	return res
}
func CommitmentsToHex(comms []serialisation.Commitment) []string {
	res := make([]string, len(comms))
	for i, comm := range comms {
		res[i] = BytesToHex(comm[:])
	}
	return res
}
func HexToCommitment(hexString string) serialisation.Commitment {

	byts, err := hex.DecodeString(hexString)
	if err != nil {
		panic(fmt.Sprintf("hex string is not decodable: %v", err))
	}
	comm := (*[serialisation.COMPRESSED_G1_SIZE]byte)(byts)

	return *comm
}

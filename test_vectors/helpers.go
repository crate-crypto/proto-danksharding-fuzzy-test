package helpers

import (
	"encoding/hex"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func GeneratePolys(numPolys int, degree int) [][]fr.Element {
	polys := make([][]fr.Element, numPolys)
	offset := 0
	for i := 0; i < numPolys; i++ {
		polys[i] = OffsetPoly(offset, degree)
		offset += degree
	}
	return polys
}

func FlattenBytes(matrix [][]byte) []byte {
	var flattenedBytes []byte
	for _, byteSlice := range matrix {
		flattenedBytes = append(flattenedBytes, byteSlice...)
	}
	return flattenedBytes
}

func SerialisePolys(polys [][]fr.Element) [][]byte {
	var serialisedPolys [][]byte
	for _, poly := range polys {
		serialisedPolys = append(serialisedPolys, SerialisePoly(poly))
	}
	return serialisedPolys
}
func SerialiseG1Points(points []curve.G1Affine) [][]byte {
	var serialisedPoints [][]byte
	for _, point := range points {
		serPoint := point.Bytes()
		serialisedPoints = append(serialisedPoints, serPoint[:])
	}
	return serialisedPoints
}
func SerialiseG2Points(points []curve.G2Affine) [][]byte {
	var serialisedPoints [][]byte
	for _, point := range points {
		serPoint := point.Bytes()
		serialisedPoints = append(serialisedPoints, serPoint[:])
	}
	return serialisedPoints
}
func SerialisePoly(poly []fr.Element) []byte {
	var serialisedPoly []byte
	for _, eval := range poly {
		bytes := eval.Bytes()
		serialisedPoly = append(serialisedPoly, bytes[:]...)
	}
	return serialisedPoly
}

func OffsetPoly(offset int, polyDegree int) []fr.Element {
	poly := make([]fr.Element, polyDegree)
	for i := 0; i < polyDegree; i++ {
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
func ByteSlicesToHex(slice [][]byte) []string {
	res := make([]string, len(slice))
	for i, byts := range slice {
		res[i] = BytesToHex(byts)
	}
	return res
}

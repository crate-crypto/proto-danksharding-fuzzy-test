package precompile

import (
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialisation"
	helpers "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors"
	"github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/verify_kzg_proof"
	"github.com/holiman/uint256"
)

type FailureMode = string

// A list of constants that usually produce edge cases
var ZEROES_32 [32]byte
var ZEROES_48 [48]byte
var ZERO_FF_32 = [32]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
var ZERO_FF_48 = [48]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
var ZERO_POINT_ENCODED = serialisation.SerialiseG1Point(curve.G1Affine{})

const (
	incorrectVersionHash        FailureMode = "incorrectVersionHash"
	incorrectPrecompileLength   FailureMode = "incorrectPrecompileLength"
	nonCanonicalInputPoint      FailureMode = "nonCanonicalInputPoint"
	nonCanonicalOutputPoint     FailureMode = "nonCanonicalOutputPoint"
	cannotDeserialiseProof      FailureMode = "cannotDeserialiseProof"
	cannotDeserialiseCommitment FailureMode = "cannotDeserialiseCommitment"
	// TODO: add low order points as a failure mode here
	invalidOpening FailureMode = "invalidOpening"
)

// Precompiles have a fixed length and so the empty input case
// falls under the `incorrectPrecompileLength` failure mode
func nullTestCase() TestCase {
	return TestCase{
		Input:       "",
		FailureMode: incorrectPrecompileLength,
		Valid:       false,
	}
}

func incorrectLengthCases(tc verify_kzg_proof.TestCase) []TestCase {
	tcNull := nullTestCase()

	precompileInput := PrecompileInputFromVerifyKZGTestCase(tc)

	// Half the input length
	//
	byts := precompileInput.takeBytes(PRECOMPILE_INPUT_LENGTH / 2)
	tcHalf := TestCase{
		Input:       helpers.BytesToHex(byts),
		FailureMode: incorrectPrecompileLength,
		Valid:       false,
	}

	// Double the input length
	//
	byts = precompileInput.Bytes()
	doubleBytes := append(byts, byts...)
	tcDouble := TestCase{
		Input:       helpers.BytesToHex(doubleBytes),
		FailureMode: incorrectPrecompileLength,
		Valid:       false,
	}

	return []TestCase{tcNull, tcHalf, tcDouble}
}

func incorrectVersionHashCases(tc verify_kzg_proof.TestCase) []TestCase {

	// First zero out version hash
	//
	precompileInput := PrecompileInputFromVerifyKZGTestCase(tc)

	versionHashZeroBytes := precompileInput.mutateVersionHash(ZEROES_32).Bytes()
	tcVersionHashZero := TestCase{
		Input:       helpers.BytesToHex(versionHashZeroBytes[:]),
		FailureMode: incorrectVersionHash,
		Valid:       false,
	}

	// Now make version hash all 0xFF
	versionHashFFBytes := precompileInput.mutateVersionHash(ZERO_FF_32).Bytes()
	tcVersionHashFF := TestCase{
		Input:       helpers.BytesToHex(versionHashFFBytes[:]),
		FailureMode: incorrectVersionHash,
		Valid:       false,
	}

	return []TestCase{tcVersionHashZero, tcVersionHashFF}
}
func nonCanonicalScalarsCases(tc verify_kzg_proof.TestCase) []TestCase {

	precompileInput := PrecompileInputFromVerifyKZGTestCase(tc)

	inputPointPlusModulus := addModulusToScalar(precompileInput.inputPoint)
	inputPointOverflowBytes := precompileInput.mutateInputPoint(inputPointPlusModulus).Bytes()

	outputPointPlusModulus := addModulusToScalar(precompileInput.outputPoint)
	outputPointOverflowBytes := precompileInput.mutateOutputPoint(outputPointPlusModulus).Bytes()

	tcInputPointOverflow := TestCase{
		Input:       helpers.BytesToHex(inputPointOverflowBytes),
		FailureMode: nonCanonicalInputPoint,
		Valid:       false,
	}
	tcOutputPointOverflow := TestCase{
		Input:       helpers.BytesToHex(outputPointOverflowBytes),
		FailureMode: nonCanonicalOutputPoint,
		Valid:       false,
	}

	return []TestCase{tcInputPointOverflow, tcOutputPointOverflow}

}
func cannotDeserialiseG1PointsCase(tc verify_kzg_proof.TestCase) []TestCase {

	precompileInput := PrecompileInputFromVerifyKZGTestCase(tc)

	// Mangle Commitment
	//
	commitmentZeroWrongEncodedBytes := precompileInput.mutateCommitment(ZEROES_48).Bytes()
	tcCommitmentZero := TestCase{
		Input:       helpers.BytesToHex(commitmentZeroWrongEncodedBytes),
		FailureMode: cannotDeserialiseCommitment,
		Valid:       false,
	}
	commitmentFFWrongEncodedBytes := precompileInput.mutateCommitment(ZERO_FF_48).Bytes()
	tcCommitmentFF := TestCase{
		Input:       helpers.BytesToHex(commitmentFFWrongEncodedBytes),
		FailureMode: cannotDeserialiseCommitment,
		Valid:       false,
	}

	// Mangle Proof
	//
	proofZeroWrongEncodedBytes := precompileInput.mutateProof(ZEROES_48).Bytes()
	tcProofZero := TestCase{
		Input:       helpers.BytesToHex(proofZeroWrongEncodedBytes),
		FailureMode: cannotDeserialiseProof,
		Valid:       false,
	}
	proofFFWrongEncodedBytes := precompileInput.mutateProof(ZERO_FF_48).Bytes()
	tcProofFF := TestCase{
		Input:       helpers.BytesToHex(proofFFWrongEncodedBytes),
		FailureMode: cannotDeserialiseProof,
		Valid:       false,
	}

	return []TestCase{tcCommitmentZero, tcCommitmentFF, tcProofZero, tcProofFF}
}
func invalidOpeningCases(tc verify_kzg_proof.TestCase) []TestCase {

	precompileInput := PrecompileInputFromVerifyKZGTestCase(tc)

	var testCases []TestCase

	// Change the scalars
	//
	// If it is not zero, then we test the zero case
	if !checkIfZero(precompileInput.inputPoint) {
		zeroInputPointBytes := precompileInput.mutateInputPoint(ZEROES_32).Bytes()

		testCases = append(testCases, TestCase{
			Input:       helpers.BytesToHex(zeroInputPointBytes),
			FailureMode: invalidOpening,
			Valid:       false,
		})
	}
	if !checkIfZero(precompileInput.outputPoint) {
		zeroOutputPointBytes := precompileInput.mutateOutputPoint(ZEROES_32).Bytes()

		testCases = append(testCases, TestCase{
			Input:       helpers.BytesToHex(zeroOutputPointBytes),
			FailureMode: invalidOpening,
			Valid:       false,
		})
	}

	// Change the points
	//
	// Check the identity point case
	identityCommBytes := precompileInput.mutateCommitment(ZERO_POINT_ENCODED).Bytes()
	testCases = append(testCases, TestCase{
		Input:       helpers.BytesToHex(identityCommBytes),
		FailureMode: invalidOpening,
		Valid:       false,
	})
	identityProofBytes := precompileInput.mutateProof(ZERO_POINT_ENCODED).Bytes()
	testCases = append(testCases, TestCase{
		Input:       helpers.BytesToHex(identityProofBytes),
		FailureMode: invalidOpening,
		Valid:       false,
	})

	return testCases
}

func addModulusToScalar(serialisedScalar serialisation.Scalar) serialisation.Scalar {
	scalar, err := serialisation.DeserialiseScalar(serialisedScalar)
	if err != nil {
		panic(err)
	}

	scalarBigInt := &big.Int{}
	scalar.ToBigIntRegular(scalarBigInt)
	scalarPlusModulus := addModP(*scalarBigInt)

	unreducedScalar, overflow := uint256.FromBig(&scalarPlusModulus)
	if overflow {
		panic("number does not have multiple representations mod 2^256")
	}
	return unreducedScalar.Bytes32()
}
func addModP(x big.Int) big.Int {
	modulus := fr.Modulus()

	var x_plus_modulus big.Int
	x_plus_modulus.Add(&x, modulus)

	return x_plus_modulus
}

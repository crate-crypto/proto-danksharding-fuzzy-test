package precompile

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	context "github.com/crate-crypto/go-proto-danksharding-crypto"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialisation"
	helpers "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors"
	"github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/verify_kzg_proof"
	"github.com/holiman/uint256"
)

type TestCase struct {
	Input       string
	FailureMode FailureMode
	Valid       bool
}

type PrecompileJson struct {
	TrustedSetupSecret    uint32
	PrecompileReturnValue string
	NumTestCases          uint32
	TestCases             []TestCase
}

// See: https://github.com/ethereum/EIPs/blob/739e75c93b94fc49e8005943d052fa4e1ac1be80/EIPS/eip-4844.md#point-evaluation-precompile
func Generate(c *context.Context) PrecompileJson {

	verifyKZGTestCases := verify_kzg_proof.Generate(c, 20, "precompile")

	// Convert commitments in `hex` format into `KZGCommitment` type
	kzgComms := make([]serialisation.Commitment, verifyKZGTestCases.NumTestCases)
	for i := 0; i < int(verifyKZGTestCases.NumTestCases); i++ {
		tc := verifyKZGTestCases.TestCases[i]
		kzgComms[i] = helpers.HexToCommitment(tc.Commitment)
	}

	var precompileTestCases []TestCase

	for _, tc := range verifyKZGTestCases.TestCases {
		precompileInput := PrecompileInputFromVerifyKZGTestCase(tc)
		tc := TestCase{
			Input: helpers.BytesToHex(precompileInput.Bytes()),
			Valid: true,
		}

		precompileTestCases = append(precompileTestCases, tc)
	}

	// Take the first test case and mutate it to fail tests
	firstTestCase := verifyKZGTestCases.TestCases[0]

	// Add Failure modes
	//
	precompileTestCases = append(precompileTestCases, incorrectLengthCases(firstTestCase)...)
	precompileTestCases = append(precompileTestCases, incorrectVersionHashCases(firstTestCase)...)
	precompileTestCases = append(precompileTestCases, nonCanonicalScalarsCases(firstTestCase)...)
	precompileTestCases = append(precompileTestCases, cannotDeserialiseG1PointsCase(firstTestCase)...)
	precompileTestCases = append(precompileTestCases, invalidOpeningCases(firstTestCase)...)

	precompReturnValue := precompileReturnValue()

	return PrecompileJson{
		TrustedSetupSecret:    helpers.SECRET,
		PrecompileReturnValue: helpers.BytesToHex(precompReturnValue[:]),
		NumTestCases:          uint32(len(precompileTestCases)),
		TestCases:             precompileTestCases,
	}
}

func precompileReturnValue() [64]byte {
	// The following two lines of comment, were taken from the EIP
	//
	//  # Return FIELD_ELEMENTS_PER_BLOB and BLS_MODULUS as padded 32 byte big endian values
	// return Bytes(U256(FIELD_ELEMENTS_PER_BLOB).to_be_bytes32() + U256(BLS_MODULUS).to_be_bytes32())

	// The field elements per blob is the number of evaluations
	// one can have in the polynomial, ie the degree of the polynomial + 1
	//
	fieldElementsPerBlob := helpers.NUM_EVALUATIONS_IN_POLYNOMIALS
	bigInt := uint256.NewInt(uint64(fieldElementsPerBlob))
	fieldElementsPerBlobBytesBE := bigInt.Bytes32()

	// The modulus of the scalar field
	// Since we use big.Int here which may return a variable
	// number of bytes. We add an additional 32 byte check
	modulusBytesBE := fr.Modulus().Bytes()
	if len(modulusBytesBE) != 32 {
		panic("modulus should be representable in 32 bytes")
	}

	var precompileReturnValue [64]byte
	copy(precompileReturnValue[0:32], fieldElementsPerBlobBytesBE[:])
	copy(precompileReturnValue[32:64], modulusBytesBE)

	return precompileReturnValue
}

package precompile

import (
	"fmt"

	"github.com/crate-crypto/go-proto-danksharding-crypto/serialisation"
	helpers "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors"
	"github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/verify_kzg_proof"
	"github.com/protolambda/go-kzg/eth"
)

const PRECOMPILE_INPUT_LENGTH = serialisation.SERIALISED_SCALAR_SIZE*3 + 2*serialisation.COMPRESSED_G1_SIZE

type PrecompileInput struct {
	versionHash serialisation.Scalar
	inputPoint  serialisation.Scalar
	outputPoint serialisation.Scalar
	commitment  serialisation.Commitment
	kzgProof    serialisation.Commitment
}

func PrecompileInputFromVerifyKZGTestCase(tc verify_kzg_proof.TestCase) PrecompileInput {
	// First compute the version hash from the commitment
	//
	// Commitment
	//
	commitment := helpers.HexToCommitment(tc.Commitment)
	versionHash := eth.KZGToVersionedHash(commitment)

	// Input point
	//
	inputPointBytes := helpers.HexToBytes(tc.InputPoint)
	inputPoint := (*[serialisation.SERIALISED_SCALAR_SIZE]byte)(inputPointBytes)
	// Output point
	//
	outputPointBytes := helpers.HexToBytes(tc.ClaimedValue)
	outputPoint := (*[serialisation.SERIALISED_SCALAR_SIZE]byte)(outputPointBytes)

	// Proof
	//
	kzgProofBytes := helpers.HexToBytes(tc.Proof)
	kzgProof := (*[serialisation.COMPRESSED_G1_SIZE]byte)(kzgProofBytes)

	return PrecompileInput{
		versionHash: versionHash,
		inputPoint:  *inputPoint,
		outputPoint: *outputPoint,
		commitment:  commitment,
		kzgProof:    *kzgProof,
	}
}

func (p PrecompileInput) Bytes() []byte {
	precompileInputBytes := append(p.versionHash[:], p.inputPoint[:]...)
	precompileInputBytes = append(precompileInputBytes, p.outputPoint[:]...)
	precompileInputBytes = append(precompileInputBytes, p.commitment[:]...)
	precompileInputBytes = append(precompileInputBytes, p.kzgProof[:]...)

	return precompileInputBytes
}

func (p PrecompileInput) mutateVersionHash(versionHash eth.VersionedHash) PrecompileInput {
	p.versionHash = versionHash
	return p
}
func (p PrecompileInput) mutateInputPoint(inputPoint serialisation.Scalar) PrecompileInput {
	p.inputPoint = inputPoint
	return p
}
func (p PrecompileInput) mutateOutputPoint(outputPoint serialisation.Scalar) PrecompileInput {
	p.outputPoint = outputPoint
	return p
}
func (p PrecompileInput) mutateCommitment(comm serialisation.Commitment) PrecompileInput {
	p.commitment = comm
	return p
}
func (p PrecompileInput) mutateProof(proof serialisation.Commitment) PrecompileInput {
	p.kzgProof = proof
	return p
}

func checkIfZero(serScalar serialisation.Scalar) bool {
	scalar, err := serialisation.DeserialiseScalar(serScalar)
	if err != nil {
		panic(err)
	}
	return scalar.IsZero()
}

// Takes the first `numBytes` bytes from the serialised
// precompile input
func (p PrecompileInput) takeBytes(numBytes int) []byte {

	precompBytes := p.Bytes()
	lenBytes := len(precompBytes)

	if numBytes > lenBytes {
		panic(fmt.Sprintf("precompile produces %d bytes, cannot take %d number of bytes", lenBytes, numBytes))
	}
	return precompBytes[:numBytes-1]
}

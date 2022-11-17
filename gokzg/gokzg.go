package gokzg_fuzz

import (
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg"
)

type Blob = types.Blob
type Blobs = types.Blobs

func foo() {
	zero_blob := Blob{}
	kzg.BlobToKZGCommitment(zero_blob)
	poly := kzg.Polynomial{}
	kzg.PolynomialToKZGCommitment(poly)
}

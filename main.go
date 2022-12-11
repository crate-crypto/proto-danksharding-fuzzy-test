package main

import (
	"encoding/json"
	"errors"
	"os"

	context "github.com/crate-crypto/go-proto-danksharding-crypto"
	agg_proof "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/agg_proof"
	blob_commit "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/blob_commit"
	roots_of_unity "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/roots_of_unity"
	transcript "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/transcript"
	trusted_setup "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/trusted_setup"
	verify_kzg_proof "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/verify_kzg_proof"
)

// run this file to generate the json test vector files

const POLY_DEGREE = 4096
const SECRET = 1337

// Name of the directory that the json files will be added to
const DIR_NAME = "generated"

func main() {

	c := context.NewContextInsecure(POLY_DEGREE, SECRET)

	createTestVectorDir()

	saveAsJson(agg_proof.Generate(c, POLY_DEGREE), location("/public_agg_proof.json"))
	saveAsJson(transcript.Generate(POLY_DEGREE), location("transcript.json"))
	saveAsJson(blob_commit.Generate(c, POLY_DEGREE), location("public_blob_commit.json"))
	saveAsJson(trusted_setup.Generate(c, SECRET, POLY_DEGREE), location("trusted_setup_lagrange.json"))
	saveAsJson(roots_of_unity.Generate(c), location("roots_of_unity.json"))
	saveAsJson(verify_kzg_proof.Generate(c, POLY_DEGREE), location("public_verify_kzg_proof.json"))
}

func saveAsJson(data interface{}, fileName string) {
	file, _ := json.MarshalIndent(data, "", " ")
	_ = os.WriteFile(fileName, file, 0644)
}

func location(fileName string) string {
	return DIR_NAME + "/" + fileName
}

func createTestVectorDir() {
	if _, err := os.Stat(DIR_NAME); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(DIR_NAME, os.ModePerm)
		if err != nil {
			panic(err)
		}
	}
}

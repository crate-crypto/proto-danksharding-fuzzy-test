package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	context "github.com/crate-crypto/go-proto-danksharding-crypto"
	agg_proof "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/agg_proof"
	blob_commit "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/blob_commit"
	precompile "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/precompile"
	roots_of_unity "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/roots_of_unity"
	trusted_setup "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/trusted_setup"
	verify_kzg_proof "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/verify_kzg_proof"
)

// run this file to generate the json test vector files

// Name of the directory that the json files will be added to
const DIR_NAME = "generated"

func main() {

	c, err := context.NewContext4096Insecure1337()
	if err != nil {
		panic(fmt.Sprintf("failed to create context: %v", err))
	}

	createTestVectorDir()

	saveAsJson(agg_proof.Generate(c), location("public_agg_proof.json"))
	saveAsJson(blob_commit.Generate(c), location("public_blob_commit.json"))
	saveAsJson(trusted_setup.Generate(c), location("trusted_setup_lagrange.json"))
	saveAsJson(roots_of_unity.Generate(c), location("roots_of_unity.json"))
	saveAsJson(verify_kzg_proof.Generate(c, 2, "verify_kzg_proof"), location("public_verify_kzg_proof.json"))
	saveAsJson(precompile.Generate(c), location("public_precompile.json"))
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

package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	context "github.com/crate-crypto/go-proto-danksharding-crypto"
	proof "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/agg_proof"
	"github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/blob_commit"
	transcript "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/transcript"
	trusted_setup "github.com/crate-crypto/proto-danksharding-fuzz/test_vectors/trusted_setup"
)

// run this file to generate the json test vector files

const POLY_DEGREE = 4096
const SECRET = 1337

// Name of the directory that the json files will be added to
const DIR_NAME = "generated_vectors"

func main() {

	c := context.NewContextInsecure(POLY_DEGREE, SECRET)

	createTestVectorDir()

	saveAsJson(proof.Generate(c, POLY_DEGREE), location("/agg_proof.json"))
	saveAsJson(transcript.Generate(POLY_DEGREE), location("transcript.json"))
	saveAsJson(blob_commit.Generate(c, POLY_DEGREE), location("blob_commit.json"))
	saveAsJson(trusted_setup.Generate(c, SECRET, POLY_DEGREE), location("trusted_setup.json"))
}

func saveAsJson(data interface{}, fileName string) {
	file, _ := json.MarshalIndent(data, "", " ")
	_ = ioutil.WriteFile(fileName, file, 0644)
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

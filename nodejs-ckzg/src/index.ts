import { loadTrustedSetup, computeAggregateKzgProof, blobToKzgCommitment, transformTrustedSetupJSON, freeTrustedSetup, verifyKzgProof } from "c-kzg";

import * as blobCommitJson from './blob_commit.json';
import * as aggProofJson from './agg_proof.json';
import * as verifyKZGJson from './public_verify_kzg_proof.json';


const SETUP_FILE_PATH = "./src/testing_trusted_setup.json"

async function main() {
    const file = await transformTrustedSetupJSON(SETUP_FILE_PATH);
    loadTrustedSetup(file);

    // await testBlobCommit()
    await testAggProof()

    freeTrustedSetup()
}

async function testBlobCommit() {

    // Convert blobs as hex string to uint8arrays
    let numBlobs = blobCommitJson.NumTestCases;

    for (let i = 0; i < numBlobs; i++) {
        let testCase = blobCommitJson.TestCases[i];

        let blobHexStr = testCase.Blob;
        let commHexStr = testCase.Commitment;

        let blobBytes = Uint8Array.from(Buffer.from(blobHexStr, 'hex'));
        let expectedCommBytes = Uint8Array.from(Buffer.from(commHexStr, 'hex'));

        // Compute the commitment
        let gotCommBytes = blobToKzgCommitment(blobBytes)

        if (expectedCommBytes.toString() != gotCommBytes.toString()) {
            throw new Error("commitments do not match ")
        }

    }


    console.log("Blob commit test passed")
}

async function testAggProof() {


    let numTestCases = aggProofJson.TestCases.length


    // For each test case
    for (let i = 0; i < numTestCases; i++) {

        let testCase = aggProofJson.TestCases[i]

        // 1. Convert blobs as hex string to uint8arrays
        let blobs = new Array(testCase.NumPolys)

        for (let j = 0; j < testCase.NumPolys; j++) {
            let blobHexStr = testCase.Polynomials[j]
            let blobBytes = Uint8Array.from(Buffer.from(blobHexStr, 'hex'));
            blobs[j] = blobBytes;
        }

        // 2. Compute the kzg proof based off of the blobs
        let gotProofBytes = computeAggregateKzgProof(blobs)

        let expectedProofStr = testCase.Proof;
        let expectedProofBytes = Uint8Array.from(Buffer.from(expectedProofStr, 'hex'));

        if (expectedProofBytes.toString() != gotProofBytes.toString()) {
            throw new Error("kzg proofs do not match ")
        }

        console.log("Agg Proof test passed")
    }
}


async function testVerifyKzg() {
    let numTestCases = verifyKZGJson.NumTestCases
    for (let i = 0; i < numTestCases; i++) {
        let testCase = verifyKZGJson.TestCases[i]

        let polyBytes = Uint8Array.from(Buffer.from(testCase.Polynomial, 'hex'));
        let proofBytes = Uint8Array.from(Buffer.from(testCase.Proof, 'hex'));
        let commBytes = Uint8Array.from(Buffer.from(testCase.Commitment, 'hex'));
        let inputPointBytes = Uint8Array.from(Buffer.from(testCase.InputPoint, 'hex'));
        let claimedValueBytes = Uint8Array.from(Buffer.from(testCase.ClaimedValue, 'hex'));

        let ok = verifyKzgProof(commBytes, inputPointBytes, claimedValueBytes, proofBytes)
        if (ok == false) {
            throw new Error("verify kzg proof function should return true")
        }
    }

    console.log("verify kzg proof passed.")

}

main().catch(console.error)


// f

// const file = await transformTrustedSetupJSON(SETUP_FILE_PATH);
// loadTrustedSetup(file);

// freeTrustedSetup();

// let blobs = new Array(2).fill(0).map(generateRandomBlob);
// let commitments = blobs.map(blobToKzgCommitment);
// let proof = computeAggregateKzgProof(blobs);
// expect(verifyAggregateKzgProof(blobs, commitments, proof)).toBe(true);
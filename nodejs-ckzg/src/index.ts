import { loadTrustedSetup, computeAggregateKzgProof, blobToKzgCommitment, transformTrustedSetupJSON, freeTrustedSetup } from "c-kzg";

import * as blobCommitJson from './blob_commit.json';
import * as aggProofJson from './agg_proof.json';


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
    let blobs = new Array(blobCommitJson.NumBlobs)
    for (let i = 0; i < blobCommitJson.NumBlobs; i++) {
        let blobHexStr = blobCommitJson.Blobs[i]

        let blobBytes = Uint8Array.from(Buffer.from(blobHexStr, 'hex'));

        blobs[i] = blobBytes;
    }

    // Compute the commitment for each blob
    let commitments = blobs.map(blobToKzgCommitment);

    for (let i = 0; i < blobCommitJson.NumBlobs; i++) {
        let gotComm = commitments[i];

        let expectedCommStr = blobCommitJson.Commitments[i];
        let expectedComm = Uint8Array.from(Buffer.from(expectedCommStr, 'hex'));

        if (expectedComm.toString() != gotComm.toString()) {
            throw new Error("commitments do not match ")
        }
    }

    console.log("Blob commit test passed")
}

async function testAggProof() {

    // Convert blobs as hex string to uint8arrays
    let blobs = new Array(aggProofJson.NumPolys)
    for (let i = 0; i < aggProofJson.NumPolys; i++) {
        let blobHexStr = aggProofJson.Polynomials[i]

        let blobBytes = Uint8Array.from(Buffer.from(blobHexStr, 'hex'));

        blobs[i] = blobBytes;
    }

    let gotProof = computeAggregateKzgProof(blobs)

    let expectedProofStr = aggProofJson.Proof;
    let expectedProof = Uint8Array.from(Buffer.from(expectedProofStr, 'hex'));

    if (expectedProof.toString() != gotProof.toString()) {
        throw new Error("kzg proofs do not match ")
    }

    console.log("Agg Proof test passed")
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
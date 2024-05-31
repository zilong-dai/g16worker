package utils

import "github.com/consensys/gnark-crypto/ecc"

const CURVE_ID = ecc.BLS12_381
const KEY_STORE_PATH = "/tmp/groth16-keystore/"

const CIRCUIT_PATH = "circuit_groth16.bin"
const VK_PATH  = "vk_groth16.bin"
const PK_PATH  = "pk_groth16.bin"
const PROOF_PATH  = "proof_groth16.bin"
const WITNESS_PATH  = "witness_groth16.bin"

const COMMON_CIRCUIT_DATA_FILE = "common_circuit_data.json"
const PROOF_WITH_PUBLIC_INPUTS_FILE = "proof_with_public_inputs.json"
const VERIFIER_ONLY_CIRCUIT_DATA_FILE = "verifier_only_circuit_data.json"
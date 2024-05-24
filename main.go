package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	gl "github.com/zilong-dai/gnark-plonky2-verifier/goldilocks"
	"github.com/zilong-dai/gnark-plonky2-verifier/plonk/gates"
	"github.com/zilong-dai/gnark-plonky2-verifier/types"
	"github.com/zilong-dai/gnark-plonky2-verifier/variables"
	"github.com/zilong-dai/gnark-plonky2-verifier/verifier"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/backend/witness"
	"github.com/zilong-dai/gnark/constraint"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

const CURVE_ID = ecc.BLS12_381
const KEY_STORE_PATH = "/tmp/groth16-keystore/"

var CIRCUIT_PATH string = "circuit_groth16.bin"
var VK_PATH string = "vk_groth16.bin"
var PK_PATH string = "pk_groth16.bin"
var PROOF_PATH string = "proof_groth16.bin"
var WITNESS_PATH string = "witness_groth16.bin"

func main() {

	path := "./testdata/f2/"
	comm_data_str, proof_str, verify_str := ReadPlonky2Data(path)

	groth16Worker, err := NewGroth16Worker()
	if err != nil {
		panic(err)
	}
	if err := groth16Worker.GenerateProof(comm_data_str, proof_str, verify_str); err != nil {
		panic(err)
	}

	if err := groth16Worker.VerifyProof(); err != nil {
		panic(err)
	}

	path = "./testdata/f2/"

	comm_data_str, proof_str, verify_str = ReadPlonky2Data(path)

	groth16Worker2, err := NewGroth16Worker()
	if err != nil {
		panic(err)
	}
	if err := groth16Worker2.GenerateProof(comm_data_str, proof_str, verify_str); err != nil {
		panic(err)
	}

	if err := groth16Worker2.VerifyProof(); err != nil {
		panic(err)
	}

}

type Groth16Worker struct {
	PK           groth16.ProvingKey
	VK           groth16.VerifyingKey
	r1cs         constraint.ConstraintSystem
	proof        groth16.Proof
	publicInputs witness.Witness
	// IsSetup bool
}

func NewGroth16Worker() (*Groth16Worker, error) {

	pk := groth16.NewProvingKey(CURVE_ID)

	vk := groth16.NewVerifyingKey(CURVE_ID)

	r1cs := groth16.NewCS(CURVE_ID)

	proof := groth16.NewProof(CURVE_ID)

	witness, err := witness.New(CURVE_ID.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	if pk == nil || vk == nil || r1cs == nil || proof == nil || witness == nil {
		return nil, fmt.Errorf("pk, vk or r1cs is null")
	}

	w := Groth16Worker{
		PK:           pk,
		VK:           vk,
		r1cs:         r1cs,
		proof:        proof,
		publicInputs: witness,
		// IsSetup: false,
	}
	return &w, nil
}

func (w *Groth16Worker) GenerateProof(common_circuit_data string, proof_with_public_inputs string, verifier_only_circuit_data string) error {

	commonCircuitData, err := ReadCommonCircuitDataRaw(common_circuit_data)
	if err != nil {
		panic(err)
	}
	circuitDataRaw, err := ReadVerifierOnlyCircuitDataRaw(verifier_only_circuit_data)

	if err != nil {
		panic(err)
	}

	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(circuitDataRaw)

	rawProofWithPis, err := ReadProofWithPublicInputsRaw(proof_with_public_inputs)
	if err != nil {
		panic(err)
	}
	proofWithPis := variables.DeserializeProofWithPublicInputs(rawProofWithPis)

	two := big.NewInt(2)

	blockStateHashAcc := big.NewInt(0)
	sighashAcc := big.NewInt(0)
	for i := 255; i >= 0; i-- {
		blockStateHashAcc = new(big.Int).Mul(blockStateHashAcc, two)
		blockStateHashAcc = new(big.Int).Add(blockStateHashAcc, new(big.Int).SetUint64(rawProofWithPis.PublicInputs[i]))
	}
	for i := 511; i >= 256; i-- {
		sighashAcc = new(big.Int).Mul(sighashAcc, two)
		sighashAcc = new(big.Int).Add(sighashAcc, new(big.Int).SetUint64(rawProofWithPis.PublicInputs[i]))
	}
	blockStateHash := frontend.Variable(blockStateHashAcc)
	sighash := frontend.Variable(sighashAcc)

	circuit := CRVerifierCircuit{
		PublicInputs:            []frontend.Variable{blockStateHash, sighash},
		Proof:                   proofWithPis.Proof,
		OriginalPublicInputs:    proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	assignment := CRVerifierCircuit{
		PublicInputs:            circuit.PublicInputs,
		Proof:                   circuit.Proof,
		OriginalPublicInputs:    circuit.OriginalPublicInputs,
		VerifierOnlyCircuitData: circuit.VerifierOnlyCircuitData,
	}

	// NewWitness() must be called before Compile() to avoid gnark panicking.
	// ref: https://github.com/Consensys/gnark/issues/1038
	witness, err := frontend.NewWitness(&assignment, CURVE_ID.ScalarField())
	if err != nil {
		fmt.Println("failed to create witness: %v", err)
		panic(err)
	}

	if !CheckKeysExist(KEY_STORE_PATH) {
		fmt.Println("setup keys")

		w.r1cs, err = frontend.Compile(CURVE_ID.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			panic(err)
		}

		w.PK, w.VK, err = groth16.Setup(w.r1cs)
		if err != nil {
			panic(err)
		}

		if err := WriteCircuit(w.r1cs, KEY_STORE_PATH+CIRCUIT_PATH); err != nil {
			panic(err)
		}
		if err := WriteVerifyingKey(w.VK, KEY_STORE_PATH+VK_PATH); err != nil {
			panic(err)
		}

		if err := WriteProvingKey(w.PK, KEY_STORE_PATH+PK_PATH); err != nil {
			panic(err)
		}
		fmt.Println("setup keys end")
	} else {
		fmt.Println("reading keys")
		w.VK, err = ReadVerifyingKey(ecc.BLS12_381, KEY_STORE_PATH+VK_PATH)
		if err != nil {
			panic(err)
		}

		w.PK, err = ReadProvingKey(ecc.BLS12_381, KEY_STORE_PATH+PK_PATH)
		if err != nil {
			panic(err)
		}

		w.r1cs, err = ReadCircuit(ecc.BLS12_381, KEY_STORE_PATH+CIRCUIT_PATH)
		if err != nil {
			panic(err)
		}
		fmt.Println("reading keys end")
	}

	proof, err := groth16.Prove(w.r1cs, w.PK, witness)
	if err != nil {
		panic(err)
	}
	w.proof = proof

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	w.publicInputs = publicWitness

	err = groth16.Verify(proof, w.VK, publicWitness)
	if err != nil {
		panic(err)
	}

	return nil
}

func (w *Groth16Worker) VerifyProof() error {

	return groth16.Verify(w.proof, w.VK, w.publicInputs)
}

func ReadCommonCircuitDataRaw(common_circuit_data_str string) (types.CommonCircuitData, error) {
	var raw types.CommonCircuitDataRaw
	var commonCircuitData types.CommonCircuitData
	if err := json.Unmarshal([]byte(common_circuit_data_str), &raw); err != nil {
		return commonCircuitData, fmt.Errorf("Failed to unmarshal proof with public inputs: %v", err)
	}

	commonCircuitData.Config.NumWires = raw.Config.NumWires
	commonCircuitData.Config.NumRoutedWires = raw.Config.NumRoutedWires
	commonCircuitData.Config.NumConstants = raw.Config.NumConstants
	commonCircuitData.Config.UseBaseArithmeticGate = raw.Config.UseBaseArithmeticGate
	commonCircuitData.Config.SecurityBits = raw.Config.SecurityBits
	commonCircuitData.Config.NumChallenges = raw.Config.NumChallenges
	commonCircuitData.Config.ZeroKnowledge = raw.Config.ZeroKnowledge
	commonCircuitData.Config.MaxQuotientDegreeFactor = raw.Config.MaxQuotientDegreeFactor

	commonCircuitData.Config.FriConfig.RateBits = raw.Config.FriConfig.RateBits
	commonCircuitData.Config.FriConfig.CapHeight = raw.Config.FriConfig.CapHeight
	commonCircuitData.Config.FriConfig.ProofOfWorkBits = raw.Config.FriConfig.ProofOfWorkBits
	commonCircuitData.Config.FriConfig.NumQueryRounds = raw.Config.FriConfig.NumQueryRounds

	commonCircuitData.FriParams.DegreeBits = raw.FriParams.DegreeBits
	commonCircuitData.DegreeBits = raw.FriParams.DegreeBits
	commonCircuitData.FriParams.Config.RateBits = raw.FriParams.Config.RateBits
	commonCircuitData.FriParams.Config.CapHeight = raw.FriParams.Config.CapHeight
	commonCircuitData.FriParams.Config.ProofOfWorkBits = raw.FriParams.Config.ProofOfWorkBits
	commonCircuitData.FriParams.Config.NumQueryRounds = raw.FriParams.Config.NumQueryRounds
	commonCircuitData.FriParams.ReductionArityBits = raw.FriParams.ReductionArityBits

	commonCircuitData.GateIds = raw.Gates

	selectorGroupStart := []uint64{}
	selectorGroupEnd := []uint64{}
	for _, group := range raw.SelectorsInfo.Groups {
		selectorGroupStart = append(selectorGroupStart, group.Start)
		selectorGroupEnd = append(selectorGroupEnd, group.End)
	}

	commonCircuitData.SelectorsInfo = *gates.NewSelectorsInfo(
		raw.SelectorsInfo.SelectorIndices,
		selectorGroupStart,
		selectorGroupEnd,
	)

	commonCircuitData.QuotientDegreeFactor = raw.QuotientDegreeFactor
	commonCircuitData.NumGateConstraints = raw.NumGateConstraints
	commonCircuitData.NumConstants = raw.NumConstants
	commonCircuitData.NumPublicInputs = raw.NumPublicInputs
	commonCircuitData.KIs = raw.KIs
	commonCircuitData.NumPartialProducts = raw.NumPartialProducts

	// Don't support circuits that have hiding enabled
	if raw.FriParams.Hiding {
		return commonCircuitData, fmt.Errorf("Circuit has hiding enabled, which is not supported")
	}

	return commonCircuitData, nil
}

func ReadVerifierOnlyCircuitDataRaw(circuit_data_str string) (types.VerifierOnlyCircuitDataRaw, error) {
	var raw types.VerifierOnlyCircuitDataRaw
	if err := json.Unmarshal([]byte(circuit_data_str), &raw); err != nil {
		return raw, fmt.Errorf("Failed to unmarshal proof with public inputs: %v", err)
	}

	return raw, nil
}

func ReadProofWithPublicInputsRaw(proof_with_public_inputs_str string) (types.ProofWithPublicInputsRaw, error) {

	var raw types.ProofWithPublicInputsRaw
	if err := json.Unmarshal([]byte(proof_with_public_inputs_str), &raw); err != nil {
		return raw, fmt.Errorf("Failed to unmarshal proof with public inputs: %v", err)
	}

	return raw, nil
}

func CheckKeysExist(path string) bool {
	files := []string{
		CIRCUIT_PATH,
		VK_PATH,
		PK_PATH,
	}

	for _, file := range files {
		path := filepath.Join(path, file)
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return false
			} else {
				return false
			}
		}
	}

	return true
}

func WriteProvingKey(pk groth16.ProvingKey, path string) error {
	if pk == nil {
		return fmt.Errorf("pk is not initialized")
	}

	pkFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer pkFile.Close()

	if _, err := pk.WriteRawTo(pkFile); err != nil {
		return fmt.Errorf("failed to write pk to file: %w", err)
	}

	return nil
}

func ReadProvingKey(CURVE_ID ecc.ID, path string) (groth16.ProvingKey, error) {
	pk := groth16.NewProvingKey(CURVE_ID)
	pkFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open pk file: %w", err)
	}
	defer pkFile.Close()

	_, err = pk.ReadFrom(pkFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read pk: %w", err)
	}

	return pk, nil
}

func WriteVerifyingKey(vk groth16.VerifyingKey, path string) error {
	if vk == nil {
		return fmt.Errorf("vk is not initialized")
	}

	vkFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer vkFile.Close()

	if _, err := vk.WriteTo(vkFile); err != nil {
		return fmt.Errorf("failed to write vk to file: %w", err)
	}

	return nil
}

func ReadVerifyingKey(CURVE_ID ecc.ID, path string) (groth16.VerifyingKey, error) {
	vk := groth16.NewVerifyingKey(CURVE_ID)
	vkFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open proof file: %w", err)
	}
	defer vkFile.Close()

	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read vk: %w", err)
	}

	return vk, nil
}

func ReadCircuit(CURVE_ID ecc.ID, path string) (constraint.ConstraintSystem, error) {
	r1cs := groth16.NewCS(CURVE_ID)
	if r1cs == nil {
		return nil, fmt.Errorf("r1cs is not initialized")
	}

	circuitFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open circuit file: %w", err)
	}
	defer circuitFile.Close()

	_, err = r1cs.ReadFrom(circuitFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read circuit: %w", err)
	}

	return r1cs, nil
}

func WriteCircuit(r1cs constraint.ConstraintSystem, path string) error {
	if r1cs == nil {
		return fmt.Errorf("r1cs is not initialized")
	}

	circuitFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to circuit file: %w", err)
	}
	defer circuitFile.Close()

	if _, err := r1cs.WriteTo(circuitFile); err != nil {
		return fmt.Errorf("failed to write circuit to file: %w", err)
	}

	return nil
}

type CRVerifierCircuit struct {
	PublicInputs            []frontend.Variable               `gnark:",public"`
	Proof                   variables.Proof                   `gnark:"-"`
	VerifierOnlyCircuitData variables.VerifierOnlyCircuitData `gnark:"-"`

	OriginalPublicInputs []gl.Variable `gnark:"_"`

	// This is configuration for the circuit, it is a constant not a variable
	CommonCircuitData types.CommonCircuitData
}

func (c *CRVerifierCircuit) Define(api frontend.API) error {
	verifierChip := verifier.NewVerifierChip(api, c.CommonCircuitData)
	if len(c.PublicInputs) != 2 {
		panic("invalid public inputs, should contain 2 BLS12_381 elements")
	}
	if len(c.OriginalPublicInputs) != 512 {
		panic("invalid original public inputs, should contain 512 goldilocks elements")
	}

	two := big.NewInt(2)

	blockStateHashAcc := frontend.Variable(0)
	sighashAcc := frontend.Variable(0)
	for i := 255; i >= 0; i-- {
		blockStateHashAcc = api.MulAcc(c.OriginalPublicInputs[i].Limb, blockStateHashAcc, two)
	}
	for i := 511; i >= 256; i-- {
		sighashAcc = api.MulAcc(c.OriginalPublicInputs[i].Limb, sighashAcc, two)
	}

	api.AssertIsEqual(c.PublicInputs[0], blockStateHashAcc)
	api.AssertIsEqual(c.PublicInputs[1], sighashAcc)

	verifierChip.Verify(c.Proof, c.OriginalPublicInputs, c.VerifierOnlyCircuitData)

	return nil
}

func ReadPlonky2Data(path string) (string, string, string) {
	jsonFile, err := os.Open(filepath.Join(path, "common_circuit_data.json"))
	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	rawBytes, _ := io.ReadAll(jsonFile)

	comm_data_str := string(rawBytes)

	jsonFile, err = os.Open(filepath.Join(path, "proof_with_public_inputs.json"))
	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	rawBytes, _ = io.ReadAll(jsonFile)

	proof_str := string(rawBytes)

	jsonFile, err = os.Open(filepath.Join(path, "verifier_only_circuit_data.json"))
	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	rawBytes, _ = io.ReadAll(jsonFile)

	verify_str := string(rawBytes)

	return comm_data_str, proof_str, verify_str
}

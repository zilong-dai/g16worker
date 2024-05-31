package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/g16worker/serialize"
	"github.com/zilong-dai/g16worker/utils"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"

	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/frontend"
)

func (w *G16Worker) Initialize(keystore_path string) {
	fmt.Println("Initializing...", time.Now().Format(time.RFC3339))

	var err error
	if serialize.CheckKeyFilesIsExist(keystore_path) {
		w.CCS, err = serialize.ReadCircuit(ecc.BLS12_381, filepath.Join(keystore_path, CIRCUIT_PATH))
		if err != nil {
			panic(err)
		}
		w.VK, err = serialize.ReadVerifyingKey(ecc.BLS12_381, filepath.Join(keystore_path, VK_PATH))
		if err != nil {
			panic(err)
		}
		w.PK, err = serialize.ReadProvingKey(ecc.BLS12_381, filepath.Join(keystore_path, PK_PATH))
		if err != nil {
			panic(err)
		}
	} else {
		panic("key files not found, you should download keys or run setup first")
	}
	fmt.Println("Initializing End...", time.Now().Format(time.RFC3339))
}

func (w *G16Worker) SetUp(plonky2_file_path string) error {
	fmt.Println("Setup...", time.Now().Format(time.RFC3339))

	plonky2Strings, err := serialize.ReadPlonky2Data(plonky2_file_path)
	if err != nil {
		return fmt.Errorf("failed to read plonky2 data: %w", err)
	}

	circuit, err := utils.ReadCRVerifierCircuit(plonky2Strings[0], plonky2Strings[1], plonky2Strings[2])
	if err != nil {
		return fmt.Errorf("failed to read plonky2 verify circuit: %w", err)
	}

	w.CCS, err = frontend.Compile(CURVE_ID.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return fmt.Errorf("failed to compile r1cs: %v", err)
	}

	w.PK, w.VK, err = groth16.Setup(w.CCS)
	if err != nil {
		return fmt.Errorf("failed to perform trusted setup: %v", err)
	}

	if err := serialize.WriteCircuit(w.CCS, filepath.Join(KEY_STORE_PATH, CIRCUIT_PATH)); err != nil {
		return fmt.Errorf("failed to write r1cs to %s: %v", KEY_STORE_PATH, err)
	}

	if err := serialize.WriteVerifyingKey(w.VK, filepath.Join(KEY_STORE_PATH, VK_PATH)); err != nil {
		return fmt.Errorf("failed to write verifier key to %s: %v", KEY_STORE_PATH, err)
	}

	if err := serialize.WriteProvingKey(w.PK, filepath.Join(KEY_STORE_PATH, PK_PATH)); err != nil {
		return fmt.Errorf("failed to write proving key to %s: %v", KEY_STORE_PATH, err)
	}

	fmt.Println("Setup End...", time.Now().Format(time.RFC3339))
	return nil
}

func (w *G16Worker) GenerateProof(common_circuit_data string, proof_with_public_inputs string, verifier_only_circuit_data string) error {

	if w.PK == nil || w.VK == nil || w.CCS == nil {
		return errors.New("please generate keys first")
	}

	circuit, err := utils.ReadCRVerifierCircuit(common_circuit_data, proof_with_public_inputs, verifier_only_circuit_data)
	if err != nil {
		return fmt.Errorf("failed to read plonky2 verify circuit: %w", err)
	}

	assignment := utils.CRVerifierCircuit{
		PublicInputs:            circuit.PublicInputs,
		Proof:                   circuit.Proof,
		OriginalPublicInputs:    circuit.OriginalPublicInputs,
		VerifierOnlyCircuitData: circuit.VerifierOnlyCircuitData,
	}

	// NewWitness() must be called before Compile() to avoid gnark panicking.
	// This method don't need compile r1cs instead of reading r1cs from file
	// ref: https://github.com/zilong-dai/gnark/issues/1038
	witness, err := frontend.NewWitness(&assignment, CURVE_ID.ScalarField())
	if err != nil {
		return fmt.Errorf("failed to create witness: %w", err)
	}

	proof, err := groth16.Prove(w.CCS, w.PK, witness)
	if err != nil {
		return fmt.Errorf("failed to create proof: %w", err)
	}
	w.Proof = proof

	publicWitness, err := witness.Public()
	if err != nil {
		return fmt.Errorf("failed to get public witness: %w", err)
	}
	w.PublicInputs = publicWitness

	err = groth16.Verify(proof, w.VK, publicWitness)
	if err != nil {
		return fmt.Errorf("failed to verify proof: %w", err)
	}

	return nil
}

func (w *G16Worker) VerifyProof(proofString string, serializeMode serialize.MODE) error {
	g16ProofWithPublicInputs := NewG16ProofWithPublicInputs()
	switch serializeMode {
	case serialize.GNARK:
		if err := json.Unmarshal([]byte(proofString), g16ProofWithPublicInputs); err != nil {
			return fmt.Errorf("failed to unmarshal proof: %w", err)
		}
	case serialize.ARK:
		return fmt.Errorf("ARK is not supported yet")
	case serialize.MCL:
		return fmt.Errorf("MCL is not supported yet")
	default:
		return fmt.Errorf("unknown serialize mode: %d", serializeMode)
	}

	return groth16.Verify(g16ProofWithPublicInputs.Proof, w.VK, g16ProofWithPublicInputs.PublicInputs)
}

package worker

import (
	"fmt"

	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/backend/witness"
	"github.com/zilong-dai/gnark/constraint"
)

type G16Worker struct {
	PK           groth16.ProvingKey
	VK           groth16.VerifyingKey
	CCS         constraint.ConstraintSystem
	Proof        groth16.Proof
	PublicInputs witness.Witness
	// IsSetup bool
}

func NewG16Worker() (*G16Worker, error) {

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

	w := G16Worker{
		PK:           pk,
		VK:           vk,
		CCS:         r1cs,
		Proof:        proof,
		PublicInputs: witness,
	}
	return &w, nil
}


type G16ProofWithPublicInputs struct {
	Proof        groth16.Proof
	PublicInputs witness.Witness
}

func NewG16ProofWithPublicInputs() *G16ProofWithPublicInputs {
	proof := groth16.NewProof(CURVE_ID)

	publicInputs, err := witness.New(CURVE_ID.ScalarField())
	if err != nil {
		panic(err)
	}

	return &G16ProofWithPublicInputs{
		Proof:        proof,
		PublicInputs: publicInputs,
	}

}

type G16VerifyingKey struct {
	VK groth16.VerifyingKey
}

func NewG16VerifyingKey() *G16VerifyingKey {
	vk := groth16.NewVerifyingKey(CURVE_ID)
	return &G16VerifyingKey{
		VK: vk,
	}
}
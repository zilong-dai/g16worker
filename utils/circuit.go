package utils

import (
	"encoding/json"
	"fmt"
	"math/big"

	gl "github.com/zilong-dai/gnark-plonky2-verifier/goldilocks"
	"github.com/zilong-dai/gnark-plonky2-verifier/plonk/gates"
	"github.com/zilong-dai/gnark-plonky2-verifier/types"
	"github.com/zilong-dai/gnark-plonky2-verifier/variables"
	"github.com/zilong-dai/gnark-plonky2-verifier/verifier"
	"github.com/zilong-dai/gnark/frontend"
)

type CRVerifierCircuit struct {
	PublicInputs            []frontend.Variable               `gnark:",public"`
	Proof                   variables.Proof                   `gnark:"witness"`
	VerifierOnlyCircuitData variables.VerifierOnlyCircuitData `gnark:"-"`

	OriginalPublicInputs []gl.Variable `gnark:"witness"`

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

func ReadCRVerifierCircuit(common_circuit_data string, proof_with_public_inputs string, verifier_only_circuit_data string) (*CRVerifierCircuit, error) {

	commonCircuitData, err := ReadCommonCircuitDataRaw(common_circuit_data)
	if err != nil {
		return nil, fmt.Errorf("failed to read common circuit data: %w", err)
	}

	circuitDataRaw, err := ReadVerifierOnlyCircuitDataRaw(verifier_only_circuit_data)
	if err != nil {
		return nil, fmt.Errorf("failed to read verifier only circuit data: %w", err)
	}

	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(circuitDataRaw)
	rawProofWithPis, err := ReadProofWithPublicInputsRaw(proof_with_public_inputs)
	if err != nil {
		return nil, fmt.Errorf("failed to read proof with public inputs: %w", err)
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

	return &CRVerifierCircuit{
		PublicInputs:            []frontend.Variable{blockStateHash, sighash},
		Proof:                   proofWithPis.Proof,
		OriginalPublicInputs:    proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}, nil
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

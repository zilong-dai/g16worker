package worker

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381_fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/zilong-dai/g16worker/serialize"
	"github.com/zilong-dai/gnark/backend/groth16"
	bls12381 "github.com/zilong-dai/gnark/backend/groth16/bls12-381"
)

func (p G16ProofWithPublicInputs) MarshalJSON() ([]byte, error) {

	proof := p.Proof.(*bls12381.Proof)

	pi_a_arr := serialize.SerializeG1(&proof.Ar)
	pi_b_arr := serialize.SerializeG2(&proof.Bs)
	pi_c_arr := serialize.SerializeG1(&proof.Krs)

	piVectors := p.PublicInputs.Vector().(bls12381_fr.Vector)
	public_inputs_arr := make([]string, len(piVectors))
	for i, piVec := range piVectors {
		public_inputs_arr[i] = serialize.SerializeFr(&piVec)
	}

	commitments_arr := make([]serialize.ArkProofG1, len(proof.Commitments))
	for i, commitment := range proof.Commitments {
		commitments_arr[i] = *serialize.SerializeG1(&commitment)
	}

	commitmentPok_arr := *serialize.SerializeG1(&proof.CommitmentPok)

	proofMap := serialize.GnarkHex2Proof{
		Ar:            *pi_a_arr,
		Bs:            *pi_b_arr,
		Krs:           *pi_c_arr,
		Commitments:   commitments_arr,
		CommitmentPok: commitmentPok_arr,
		Witness:       public_inputs_arr,
	}
	// proofMap := map[string]interface{}{
	// 	"pi_a":          pi_a_arr,
	// 	"pi_b":          pi_b_arr,
	// 	"pi_c":          pi_c_arr,
	// 	"Commitments":   commitments_arr,
	// 	"CommitmentPok": commitmentPok_arr,
	// 	"public_inputs": public_inputs_arr,
	// }
	return json.Marshal(proofMap)

}

func (p *G16ProofWithPublicInputs) UnmarshalJSON(data []byte) error {
	proof := p.Proof.(*bls12381.Proof)

	var gnarkHex2Proof serialize.GnarkHex2Proof

	err := json.Unmarshal(data, &gnarkHex2Proof)
	if err != nil {
		return err
	}

	if Ar, err := serialize.DeSerializeG1(&gnarkHex2Proof.Ar); err != nil {
		return fmt.Errorf("failed to unmarshal Ar: %w", err)
	} else {
		proof.Ar = *Ar
	}

	if Bs, err := serialize.DeSerializeG2(&gnarkHex2Proof.Bs); err != nil {
		return fmt.Errorf("failed to unmarshal Bs: %w", err)
	} else {
		proof.Bs = *Bs
	}

	if Krs, err := serialize.DeSerializeG1(&gnarkHex2Proof.Krs); err != nil {
		return fmt.Errorf("failed to unmarshal Krs: %w", err)
	} else {
		proof.Krs = *Krs
	}

	proof.Commitments = make([]curve.G1Affine, len(gnarkHex2Proof.Commitments))
	for i, gCommitment := range gnarkHex2Proof.Commitments {
		if Commitment, err := serialize.DeSerializeG1(&gCommitment); err != nil {
			return fmt.Errorf("failed to unmarshal Commitments: %w", err)
		} else {
			proof.Commitments[i] = *Commitment
		}
	}

	if CommitmentPok, err := serialize.DeSerializeG1(&gnarkHex2Proof.CommitmentPok); err != nil {
		return fmt.Errorf("failed to unmarshal CommitmentPok: %w", err)
	} else {
		proof.CommitmentPok = *CommitmentPok
	}

	// public inputs num n, witness inputs num 0, vector length n

	// publicinputs_bytes, err := hex.DecodeString("000000020000000000000002" + ProofString.PublicInputs[0] + ProofString.PublicInputs[1])
	// if err != nil {
	// 	return err
	// }
	// bytesBuffer := bytes.NewBuffer([]byte{})
	// publicInputsLen := uint32(len(gnarkHex2Proof.Witness))
	// binary.Write(bytesBuffer, binary.BigEndian, publicInputsLen)
	// binary.Write(bytesBuffer, binary.BigEndian, uint32(0))
	// binary.Write(bytesBuffer, binary.BigEndian, publicInputsLen)
	// for _, publicInput := range gnarkHex2Proof.Witness {
	// 	publicInputBytes, err := hex.DecodeString(publicInput)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to unmarshal public inputs: %w", err)
	// 	}
	// 	if _, err := bytesBuffer.Write(publicInputBytes); err != nil {
	// 		return fmt.Errorf("failed to unmarshal public inputs: %w", err)
	// 	}
	// }

	// if _, err = p.PublicInputs.ReadFrom(bytesBuffer); err != nil {
	// 	return fmt.Errorf("failed to unmarshal public inputs: %w", err)
	// }
	if p.PublicInputs, err = serialize.DeSerializeWitness(gnarkHex2Proof.Witness); err != nil {
		return fmt.Errorf("failed to unmarshal public inputs: %w", err)
	}

	return nil
}

func (gvk G16VerifyingKey) MarshalJSON() ([]byte, error) {
	vk := gvk.VK.(*bls12381.VerifyingKey)

	gamma_abc_g1_arr := make([]serialize.ArkProofG1, len(vk.G1.K))
	for i, kG1 := range vk.G1.K {
		gamma_abc_g1_arr[i] = *serialize.SerializeG1(&kG1)
	}

	alpha_g1_arr := serialize.SerializeG1(&vk.G1.Alpha)
	beta_g2_arr := serialize.SerializeG2(&vk.G2.Beta)
	gamma_g2_arr := serialize.SerializeG2(&vk.G2.Gamma)
	delta_g2_arr := serialize.SerializeG2(&vk.G2.Delta)

	var commitmentKeyBuffer bytes.Buffer
	if _, err := vk.CommitmentKey.WriteTo(&commitmentKeyBuffer); err != nil {
		return nil, fmt.Errorf("failed to write commitment key: %w", err)
	}
	commitment_key_arr := hex.EncodeToString(commitmentKeyBuffer.Bytes())

	vkMap := serialize.GnarkHex2VK{
		AlphaG1:                      *alpha_g1_arr,
		BetaG2:                       *beta_g2_arr,
		GammaG2:                      *gamma_g2_arr,
		DeltaG2:                      *delta_g2_arr,
		G1K:                          gamma_abc_g1_arr,
		CommitmentKey:                commitment_key_arr,
		PublicAndCommitmentCommitted: vk.PublicAndCommitmentCommitted,
	}

	return json.Marshal(vkMap)
}

func (gvk *G16VerifyingKey) UnmarshalJSON(data []byte) error {
	vk := gvk.VK.(*bls12381.VerifyingKey)
	var gnarkHex2VK serialize.GnarkHex2VK

	err := json.Unmarshal(data, &gnarkHex2VK)
	if err != nil {
		return err
	}

	if alphaG1, err := serialize.DeSerializeG1(&gnarkHex2VK.AlphaG1); err != nil {
		return fmt.Errorf("failed to unmarshal Alpha: %w", err)
	} else {
		vk.G1.Alpha = *alphaG1
	}

	if betaG2, err := serialize.DeSerializeG2(&gnarkHex2VK.BetaG2); err != nil {
		return fmt.Errorf("failed to unmarshal Beta: %w", err)
	} else {
		vk.G2.Beta = *betaG2
	}

	if gammaG2, err := serialize.DeSerializeG2(&gnarkHex2VK.GammaG2); err != nil {
		return fmt.Errorf("failed to unmarshal Gamma: %w", err)
	} else {
		vk.G2.Gamma = *gammaG2
	}

	if deltaG2, err := serialize.DeSerializeG2(&gnarkHex2VK.DeltaG2); err != nil {
		return fmt.Errorf("failed to unmarshal Delta: %w", err)
	} else {
		vk.G2.Delta = *deltaG2
	}

	vk.G1.K = make([]curve.G1Affine, len(gnarkHex2VK.G1K))
	for i, gKG1 := range gnarkHex2VK.G1K {
		if kG1, err := serialize.DeSerializeG1(&gKG1); err != nil {
			return fmt.Errorf("failed to unmarshal K: %w", err)
		} else {
			vk.G1.K[i] = *kG1
		}

	}

	comkey_bytes, err := hex.DecodeString(gnarkHex2VK.CommitmentKey)
	if err != nil {
		return err
	}
	_, err = vk.CommitmentKey.ReadFrom(bytes.NewReader(comkey_bytes))
	if err != nil {
		return err
	}

	vk.PublicAndCommitmentCommitted = gnarkHex2VK.PublicAndCommitmentCommitted

	if err := vk.Precompute(); err != nil {
		return fmt.Errorf("failed to precompute: %w", err)
	}

	return nil
}

func ToG16CompressProof(p *G16ProofWithPublicInputs) (*serialize.G16CompressProof, error) {
	proof := p.Proof.(*bls12381.Proof)
	return &serialize.G16CompressProof{
		PiA:          serialize.SerializeG1Compress(&proof.Ar),
		PiB:          serialize.SerializeG2Compress(&proof.Bs),
		PiC:          serialize.SerializeG1Compress(&proof.Krs),
		PublicInputs: serialize.SerializeWitness(p.PublicInputs),
	}, nil
}

func FromG16CompressProof(g16CProof *serialize.G16CompressProof) (*G16ProofWithPublicInputs, error) {
	p := NewG16ProofWithPublicInputs()
	proof := p.Proof.(*bls12381.Proof)

	if Ar, err := serialize.DeSerializeG1Compress(g16CProof.PiA); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Ar: %w", err)
	} else {
		proof.Ar = *Ar
	}

	if Bs, err := serialize.DeSerializeG2Compress(g16CProof.PiB); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Bs: %w", err)
	} else {
		proof.Bs = *Bs
	}

	if Krs, err := serialize.DeSerializeG1Compress(g16CProof.PiC); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Krs: %w", err)
	} else {
		proof.Krs = *Krs
	}

	if pi, err := serialize.DeSerializeWitness(g16CProof.PublicInputs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PublicInputs: %w", err)
	} else {
		p.PublicInputs = pi
	}

	return p, nil
}

func ToG16CompressVK(Vk groth16.VerifyingKey) (*serialize.G16CompressVK, error) {
	vk := Vk.(*bls12381.VerifyingKey)

	gamma_abc_g1_arr := make([]string, len(vk.G1.K))
	for i, kG1 := range vk.G1.K {
		gamma_abc_g1_arr[i] = serialize.SerializeG1Compress(&kG1)
	}

	return &serialize.G16CompressVK{
		AlphaG1: serialize.SerializeG1Compress(&vk.G1.Alpha),
		BetaG2:  serialize.SerializeG2Compress(&vk.G2.Beta),
		GammaG2: serialize.SerializeG2Compress(&vk.G2.Gamma),
		DeltaG2: serialize.SerializeG2Compress(&vk.G2.Delta),
		G1K:     gamma_abc_g1_arr,
	}, nil
}

func FromG16CompressVK(g16CVK *serialize.G16CompressVK) (groth16.VerifyingKey, error) {
	VK := groth16.NewVerifyingKey(CURVE_ID)
	vk := VK.(*bls12381.VerifyingKey)

	if AlphaG1, err := serialize.DeSerializeG1Compress(g16CVK.AlphaG1); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Alpha: %w", err)
	} else {
		vk.G1.Alpha = *AlphaG1
	}

	if BetaG2, err := serialize.DeSerializeG2Compress(g16CVK.BetaG2); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Beta: %w", err)
	} else {
		vk.G2.Beta = *BetaG2
	}

	if GammaG2, err := serialize.DeSerializeG2Compress(g16CVK.GammaG2); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Gamma: %w", err)
	} else {
		vk.G2.Gamma = *GammaG2
	}

	if DeltaG2, err := serialize.DeSerializeG2Compress(g16CVK.DeltaG2); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Delta: %w", err)
	} else {
		vk.G2.Delta = *DeltaG2
	}

	vk.G1.K = make([]curve.G1Affine, len(g16CVK.G1K))
	for i, kG1 := range g16CVK.G1K {
		if g1, err := serialize.DeSerializeG1Compress(kG1); err != nil {
			return nil, fmt.Errorf("failed to unmarshal G1K[%d]: %w", i, err)
		} else {
			vk.G1.K[i] = *g1
		}
	}

	if err := vk.Precompute(); err != nil {
		return nil, fmt.Errorf("failed to precompute: %w", err)
	}

	return VK, nil
}

func ToCityG16Proof(p *G16ProofWithPublicInputs) (*serialize.CityG16Proof, error) {
	proof := p.Proof.(*bls12381.Proof)

	PiBStr := serialize.SerializeMCLG2Compress(&proof.Bs)

	return &serialize.CityG16Proof{
		PiA:          serialize.SerializeMCLG1Compress(&proof.Ar),
		PiBA0:        PiBStr[:len(PiBStr)/2],
		PiBA1:        PiBStr[len(PiBStr)/2:],
		PiC:          serialize.SerializeMCLG1Compress(&proof.Krs),
		PublicInput0: serialize.SerializeWitness(p.PublicInputs)[0],
		PublicInput1: serialize.SerializeWitness(p.PublicInputs)[1],
	}, nil
}

func FromGCityG16Proof(g16CProof *serialize.CityG16Proof) (*G16ProofWithPublicInputs, error) {
	p := NewG16ProofWithPublicInputs()
	proof := p.Proof.(*bls12381.Proof)

	if Ar, err := serialize.DeSerializeMCLG1Compress(g16CProof.PiA); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Ar: %w", err)
	} else {
		proof.Ar = *Ar
	}

	if Bs, err := serialize.DeSerializeMCLG2Compress(g16CProof.PiBA0 + g16CProof.PiBA1); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Bs: %w", err)
	} else {
		proof.Bs = *Bs
	}

	if Krs, err := serialize.DeSerializeMCLG1Compress(g16CProof.PiC); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Krs: %w", err)
	} else {
		proof.Krs = *Krs
	}

	if pi, err := serialize.DeSerializeWitness([]string{g16CProof.PublicInput0, g16CProof.PublicInput1}); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PublicInputs: %w", err)
	} else {
		p.PublicInputs = pi
	}

	return p, nil
}

func ToCityG16VK(Vk groth16.VerifyingKey) (*serialize.CityG16VK, error) {
	vk := Vk.(*bls12381.VerifyingKey)

	gamma_abc_g1_arr := make([]string, len(vk.G1.K))
	for i, kG1 := range vk.G1.K {
		gamma_abc_g1_arr[i] = serialize.SerializeMCLG1Compress(&kG1)
	}

	return &serialize.CityG16VK{
		AlphaG1: serialize.SerializeMCLG1Compress(&vk.G1.Alpha),
		BetaG2:  serialize.SerializeMCLG2Compress(&vk.G2.Beta),
		GammaG2: serialize.SerializeMCLG2Compress(&vk.G2.Gamma),
		DeltaG2: serialize.SerializeMCLG2Compress(&vk.G2.Delta),
		G1K:     gamma_abc_g1_arr,
	}, nil
}

func FromCityG16VK(g16CVK *serialize.CityG16VK) (groth16.VerifyingKey, error) {
	VK := groth16.NewVerifyingKey(CURVE_ID)
	vk := VK.(*bls12381.VerifyingKey)

	if AlphaG1, err := serialize.DeSerializeMCLG1Compress(g16CVK.AlphaG1); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Alpha: %w", err)
	} else {
		vk.G1.Alpha = *AlphaG1
	}

	if BetaG2, err := serialize.DeSerializeMCLG2Compress(g16CVK.BetaG2); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Beta: %w", err)
	} else {
		vk.G2.Beta = *BetaG2
	}

	if GammaG2, err := serialize.DeSerializeMCLG2Compress(g16CVK.GammaG2); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Gamma: %w", err)
	} else {
		vk.G2.Gamma = *GammaG2
	}

	if DeltaG2, err := serialize.DeSerializeMCLG2Compress(g16CVK.DeltaG2); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Delta: %w", err)
	} else {
		vk.G2.Delta = *DeltaG2
	}

	vk.G1.K = make([]curve.G1Affine, len(g16CVK.G1K))
	for i, kG1 := range g16CVK.G1K {
		if g1, err := serialize.DeSerializeMCLG1Compress(kG1); err != nil {
			return nil, fmt.Errorf("failed to unmarshal G1K[%d]: %w", i, err)
		} else {
			vk.G1.K[i] = *g1
		}
	}

	if err := vk.Precompute(); err != nil {
		return nil, fmt.Errorf("failed to precompute: %w", err)
	}

	return VK, nil
}

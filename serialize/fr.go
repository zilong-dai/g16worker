package serialize

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/zilong-dai/gnark/backend/witness"
)

func SerializeFr(fr *fr.Element) string {
	frBytes := fr.Bytes()
	return hex.EncodeToString(frBytes[:])
}

func DeSerializeFr(frs string) (*fr.Element, error) {
	frp := new (fr.Element)
	frBytes, err := hex.DecodeString(frs)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}
	frp.SetBytes(frBytes)
	return frp, nil
}

func SerializeWitness(publicInputs witness.Witness) []string {
	piVectors := publicInputs.Vector().(fr.Vector)
	public_inputs_arr := make([]string, len(piVectors))
	for i, piVec := range piVectors {
		public_inputs_arr[i] = SerializeFr(&piVec)
	}
	return public_inputs_arr
}

func DeSerializeWitness(publicInputsString []string) (witness.Witness, error) {
	publicInputs, err := witness.New(CURVE_ID.ScalarField())
	if err!= nil {
		panic(err)
	}
	bytesBuffer := bytes.NewBuffer([]byte{})
	publicInputsLen := uint32(len(publicInputsString))
	binary.Write(bytesBuffer, binary.BigEndian, publicInputsLen)
	binary.Write(bytesBuffer, binary.BigEndian, uint32(0))
	binary.Write(bytesBuffer, binary.BigEndian, publicInputsLen)
	for _, publicInput := range publicInputsString {
		publicInputBytes, err := hex.DecodeString(publicInput)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal public inputs: %w", err)
		}
		if _, err := bytesBuffer.Write(publicInputBytes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal public inputs: %w", err)
		}
	}

	if _, err = publicInputs.ReadFrom(bytesBuffer); err != nil {
		return nil, fmt.Errorf("failed to unmarshal public inputs: %w", err)
	}
	return publicInputs, nil
}
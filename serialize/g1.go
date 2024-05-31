package serialize

import (
	"encoding/hex"
	"errors"
	"fmt"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

func SerializeG1(g1 *curve.G1Affine) *ArkProofG1 {
	xBytes := g1.X.Bytes()
	yBytes := g1.Y.Bytes()
	return &ArkProofG1{X: hex.EncodeToString(xBytes[:]), Y: hex.EncodeToString(yBytes[:])}
}

func DeSerializeG1(g1 *ArkProofG1) (*curve.G1Affine, error) {
	g1Point := new(curve.G1Affine)
	if xBytes, err := hex.DecodeString(g1.X); err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	} else {

		g1Point.X.SetBytes(xBytes)
	}

	if yBytes, err := hex.DecodeString(g1.Y); err != nil {
		return nil, fmt.Errorf("failed to decode y: %w", err)
	} else {
		g1Point.Y.SetBytes(yBytes)
	}

	return g1Point, nil
}

func SerializeG1Compress(g1 *curve.G1Affine) string {
	g1Bytes := g1.Bytes()
	return hex.EncodeToString(g1Bytes[:])
}

func DeSerializeG1Compress(g1s string) (*curve.G1Affine, error) {
	g1 := new(curve.G1Affine)
	g1Bytes, err := hex.DecodeString(g1s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}
	g1.SetBytes(g1Bytes)
	return g1, nil
}

func SerializeMCLG1Compress(g1 *curve.G1Affine) string {
	xBytes := g1.X.Bytes()
	if IsOddFp(&g1.Y) {
		// xBytes[0] |= 0x80
		AddOddFlag(&xBytes[0])
	}
	return ReverseHexString(hex.EncodeToString(xBytes[:]))
}

func DeSerializeMCLG1Compress(g1s string) (*curve.G1Affine, error) {
	g1 := new(curve.G1Affine)
	g1xBytes, err := hex.DecodeString(ReverseHexString(g1s))
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}

	oddFlag := false
	if g1xBytes[0]&0x80 == 0x80 {
		oddFlag = true
		// g1xBytes[0] &= 0x7f
		RemoveOddFlag(&g1xBytes[0])
	}
	g1.X.SetBytes(g1xBytes[:])

	var YSquared, Y, bCurveCoeff fp.Element

	bCurveCoeff.SetUint64(4)
	YSquared.Square(&g1.X).Mul(&YSquared, &g1.X)
	YSquared.Add(&YSquared, &bCurveCoeff)
	if Y.Sqrt(&YSquared) == nil {
		return nil, errors.New("invalid compressed coordinate: square root doesn't exist")
	}

	if oddFlag != IsOddFp(&Y) {
		Y.Neg(&Y)
	}

	g1.Y = Y

	return g1, nil
}

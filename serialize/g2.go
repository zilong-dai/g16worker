package serialize

import (
	"encoding/hex"
	"errors"
	"fmt"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

func SerializeG2(g2 *curve.G2Affine) *ArkProofG2 {
	xBytes1 := g2.X.A1.Bytes()
	xBytes0 := g2.X.A0.Bytes()
	yBytes1 := g2.Y.A1.Bytes()
	yBytes0 := g2.Y.A0.Bytes()

	return &ArkProofG2{X: ArkProofE2{A0: hex.EncodeToString(xBytes0[:]), A1: hex.EncodeToString(xBytes1[:])}, Y: ArkProofE2{A0: hex.EncodeToString(yBytes0[:]), A1: hex.EncodeToString(yBytes1[:])}}
}

func DeSerializeG2(g2 *ArkProofG2) (*curve.G2Affine, error) {
	g2Point := new(curve.G2Affine)

	if xA0Bytes, err := hex.DecodeString(g2.X.A0); err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	} else {
		g2Point.X.A0.SetBytes(xA0Bytes)
	}

	if xA1Bytes, err := hex.DecodeString(g2.X.A1); err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	} else {
		g2Point.X.A1.SetBytes(xA1Bytes)
	}

	if yA0Bytes, err := hex.DecodeString(g2.Y.A0); err != nil {
		return nil, fmt.Errorf("failed to decode y: %w", err)
	} else {
		g2Point.Y.A0.SetBytes(yA0Bytes)
	}

	if yA1Bytes, err := hex.DecodeString(g2.Y.A1); err != nil {
		return nil, fmt.Errorf("failed to decode y: %w", err)
	} else {
		g2Point.Y.A1.SetBytes(yA1Bytes)
	}

	return g2Point, nil
}
func SerializeG2Compress(g2 *curve.G2Affine) string {
	g2Bytes := g2.Bytes()
	return hex.EncodeToString(g2Bytes[:])
}

func DeSerializeG2Compress(g2s string) (*curve.G2Affine, error) {
	g2 := new(curve.G2Affine)
	g2Bytes, err := hex.DecodeString(g2s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}
	g2.SetBytes(g2Bytes)
	return g2, nil
}

func SerializeMCLG2Compress(g2 *curve.G2Affine) string {
	xA0Bytes := g2.X.A0.Bytes()
	xA1Bytes := g2.X.A1.Bytes()
	if IsOddFp(&g2.Y.A0) {
		// xBytes[0] |= 0x80
		AddOddFlag(&xA1Bytes[0])
	}
	return ReverseHexString(hex.EncodeToString(xA0Bytes[:])) + ReverseHexString(hex.EncodeToString(xA1Bytes[:]))
}

func DeSerializeMCLG2Compress(g2s string) (*curve.G2Affine, error) {
	if len(g2s)%2 != 0 {
		panic("G2 MCL compressed string must be of even length")
	}

	g2a0, g2a1 := g2s[0:len(g2s)/2], g2s[len(g2s)/2:]
	xA0Bytes, err := hex.DecodeString(ReverseHexString(g2a0))
	if err != nil {
		return nil, fmt.Errorf("failed to decode g2 hex string: %w", err)
	}
	xA1Bytes, err := hex.DecodeString(ReverseHexString(g2a1))
	if err != nil {
		return nil, fmt.Errorf("failed to decode g2 hex string: %w", err)
	}

	oddFlag := false
	if xA1Bytes[0]&0x80 == 0x80 {
		oddFlag = true
		RemoveOddFlag(&xA1Bytes[0])
	}

	g2 := new(curve.G2Affine)
	g2.X.A0.SetBytes(xA0Bytes)
	g2.X.A1.SetBytes(xA1Bytes)

	var YSquared, Y, bTwistCurveCoeff curve.E2
	var bCurveCoeff fp.Element
	var twist curve.E2

	bCurveCoeff.SetUint64(4)
	twist.A0.SetUint64(1)
	twist.A1.SetUint64(1)
	bTwistCurveCoeff.MulByElement(&twist, &bCurveCoeff)

	YSquared.Square(&g2.X).Mul(&YSquared, &g2.X)
	YSquared.Add(&YSquared, &bTwistCurveCoeff)
	if YSquared.Legendre() == -1 {
		return nil, errors.New("invalid compressed coordinate: square root doesn't exist")
	}
	Y.Sqrt(&YSquared)

	if oddFlag != IsOddFp(&Y.A0) {
		Y.Neg(&Y)
	}
	g2.Y = Y

	return g2, nil
}

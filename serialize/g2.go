package serialize

import (
	"encoding/hex"
	"fmt"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
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

	if xA0Bytes, err:= hex.DecodeString(g2.X.A0); err!=nil{
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}else {
		g2Point.X.A0.SetBytes(xA0Bytes)
	}

	if xA1Bytes, err:= hex.DecodeString(g2.X.A1); err!=nil{
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}else {
		g2Point.X.A1.SetBytes(xA1Bytes)
	}

	if yA0Bytes, err:= hex.DecodeString(g2.Y.A0); err!=nil{
		return nil, fmt.Errorf("failed to decode y: %w", err)
	}else {
		g2Point.Y.A0.SetBytes(yA0Bytes)
	}

	if yA1Bytes, err:= hex.DecodeString(g2.Y.A1); err!=nil{
		return nil, fmt.Errorf("failed to decode y: %w", err)
	}else {
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
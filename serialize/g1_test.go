package serialize_test

import (
	"math/big"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381_fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/zilong-dai/g16worker/serialize"
	"golang.org/x/exp/rand"
)

func TestG1Serialize(t *testing.T) {
	var g1Gen curve.G1Jac
	var g1GenAff curve.G1Affine

	for i := 0; i < 1<<16; i++ {
		g1Gen.X.SetString("3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507")
		g1Gen.Y.SetString("1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569")
		g1Gen.Z.SetOne()

		g1GenAff.FromJacobian(&g1Gen)

		randScalar := rand.Uint64()

		randScalarFr := new(bls12381_fr.Element).SetUint64(randScalar)

		randAffine := g1GenAff.ScalarMultiplication(&g1GenAff, randScalarFr.BigInt(big.NewInt(0)))

		if !randAffine.IsOnCurve() {
			panic("not on curve")
		}

		randAffineString := serialize.SerializeG12(randAffine)

		randAffine2, err := serialize.DeSerializeG12(randAffineString)
		if err != nil {
			panic(err)
		}
		if !randAffine2.IsOnCurve() {
			panic("not on curve")
		}
		if randAffine.X.Cmp(&randAffine2.X) != 0 || randAffine.Y.Cmp(&randAffine2.Y) != 0 {
			panic("not equal")
		}
	}
}

package serialize_test

import (
	"math/big"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381_fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/zilong-dai/g16worker/serialize"
	"golang.org/x/exp/rand"
)

func TestG2Serialize(t *testing.T) {
	var g2Gen curve.G2Jac
	var g2GenAff curve.G2Affine

	for i := 0; i < 1<<16; i++ {
		g2Gen.X.SetString("352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160",
			"3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758")
		g2Gen.Y.SetString("1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905",
			"927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582")
		g2Gen.Z.SetString("1",
			"0")

		g2GenAff.FromJacobian(&g2Gen)

		randScalar := rand.Uint64()

		randScalarFr := new(bls12381_fr.Element).SetUint64(randScalar)

		randAffine := g2GenAff.ScalarMultiplication(&g2GenAff, randScalarFr.BigInt(big.NewInt(0)))

		if !randAffine.IsOnCurve() {
			panic("not on curve")
		}

		randAffineString := serialize.SerializeG22(randAffine)

		randAffine2, err := serialize.DeSerializeG22(randAffineString)
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

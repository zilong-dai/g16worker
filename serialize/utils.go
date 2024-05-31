package serialize

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

func IsOddFp(x *fp.Element) bool {
	return x.BigInt(big.NewInt(0)).Bit(0) == 1
}

func ReverseHexString(hexStr string) string {
	if len(hexStr)%2 != 0 {
		panic("hexStr must be of even length")
	}
	reversed := make([]byte, len(hexStr))
	for i := 0; i < len(hexStr); i += 2 {
		reversed[i] = hexStr[len(hexStr)-i-2]
		reversed[i+1] = hexStr[len(hexStr)-i-1]
	}
	return string(reversed)
}

func AddOddFlag(b *byte) {
	*b |= 0x80
}

func RemoveOddFlag(b *byte) {
	*b &= 0x7f
}

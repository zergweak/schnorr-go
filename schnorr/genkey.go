package schnorr

import (
	"crypto/rand"
	"math/big"
)

func GenKey()([32]byte, [33]byte) {
	var privateKey [32]byte
	var publicKey [33]byte
	d := new(big.Int)
	for {
		rand.Read(privateKey[:])
		d.SetBytes(privateKey[:])
		d.Mod(d, Curve.N)
		if d.Cmp(Zero) != 0{
			break
		}
	}

	Px, Py := Curve.ScalarBaseMult(d.Bytes())
	P := Marshal(Curve, Px, Py)
	copy(publicKey[:], P)

	return privateKey, publicKey
}

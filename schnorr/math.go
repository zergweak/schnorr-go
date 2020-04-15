package schnorr

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
)

func IntToByte(i *big.Int) []byte {
	b1, b2 := [32]byte{}, i.Bytes()
	copy(b1[32-len(b2):], b2)
	return b1[:]
}

func getE(Px, Py *big.Int, rX []byte, m []byte) *big.Int {
	r := append(rX, Marshal(Curve, Px, Py)...)
	r = append(r, m[:]...)
	h := sha256.Sum256(r)
	i := new(big.Int).SetBytes(h[:])
	return i.Mod(i, Curve.N)
}

func getK(Ry, k0 *big.Int) *big.Int {
	if big.Jacobi(Ry, Curve.P) == 1 {
		return k0
	}
	return k0.Sub(Curve.N, k0)
}

func aggregationPublicKey(publicKeys []*PublicKey) *PublicKey {
	if(len(publicKeys) == 0) {
		return nil
	}

	resultRx, resultRy := Unmarshal(Curve, publicKeys[0].R[:])
	resultPx, resultPy := Unmarshal(Curve, publicKeys[0].P[:])
	for i := 1; i < len(publicKeys); i++ {
		childRx, childRy := Unmarshal(Curve, publicKeys[i].R[:])
		Px, Py := Unmarshal(Curve, publicKeys[i].P[:])
		resultRx, resultRy = Curve.Add(resultRx, resultRy, childRx, childRy)
		resultPx, resultPy = Curve.Add(resultPx, resultPy, Px, Py)
	}
	resultR := Marshal(Curve, resultRx, resultRy)
	resultP := Marshal(Curve, resultPx, resultPy)
	var result PublicKey
	copy(result.R[:], resultR)
	copy(result.P[:], resultP)
	return &result
}

func aggregationPubKey(publicKeys [][33]byte) (pubkey [33]byte) {
	if(len(publicKeys) == 0) {
		return pubkey
	}

	resultX, resultY := Zero, Zero
	for i := 0; i < len(publicKeys); i++ {
		x, y := Unmarshal(Curve, publicKeys[i][:])
		resultX, resultY = Curve.Add(resultX, resultY, x, y)
	}
	result := Marshal(Curve, resultX, resultY)
	copy(pubkey[:], result)

	return pubkey
}

//用P计算Rx
func GetPublicRx(P [33]byte, message []byte) [32]byte {
	Px, Py := Unmarshal(Curve, P[:])
	ilNum := computChildOffset(IntToByte(Px), IntToByte(Py), message)

	ilx, ily := Curve.ScalarBaseMult(IntToByte(ilNum))
	Rx, _ := Curve.Add(ilx, ily, Px, Py)

	var ret [32]byte
	copy(ret[:], IntToByte(Rx))
	return ret
}

//用P计算R
func GetPublicR(P [33]byte, message []byte) [33]byte {
	Px, Py := Unmarshal(Curve, P[:])
	ilNum := computChildOffset(IntToByte(Px), IntToByte(Py), message)

	ilx, ily := Curve.ScalarBaseMult(IntToByte(ilNum))
	Rx, Ry := Curve.Add(ilx, ily, Px, Py)

	R := Marshal(Curve, Rx, Ry)
	var ret [33]byte
	copy(ret[:], R)
	return ret
}

//用d计算k0
func GetPrivateK0(d [32]byte, message []byte) [32]byte {
	Px, Py := Curve.ScalarBaseMult(d[:])
	ilNum := computChildOffset(IntToByte(Px), IntToByte(Py), message)

	k0Num := new(big.Int).SetBytes(d[:])
	k0Num = k0Num.Add(k0Num, ilNum)
	k0Num = k0Num.Mod(k0Num, Curve.N)

	var k0 [32]byte
	copy(k0[:], IntToByte(k0Num))
	return k0
}

func computChildOffset(X, Y, message []byte) *big.Int  {
	hmac512 := hmac.New(sha512.New, X)
	hmac512.Write(Y)
	hmac512.Write(message)
	i := hmac512.Sum(nil)
	ilNum := new(big.Int).SetBytes(i[:32])

	return ilNum
}
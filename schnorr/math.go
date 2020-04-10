package schnorr

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
)

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

func getPublicKey(publicKeys []*PublicKey) *PublicKey {
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

//用P计算Rx
func getPublicRx(P [33]byte, message []byte) [32]byte {
	Px, Py := Unmarshal(Curve, P[:])
	ilNum := computChildOffset(Px.Bytes(), Py.Bytes(), message)

	ilx, ily := Curve.ScalarBaseMult(ilNum.Bytes())
	Rx, _ := Curve.Add(ilx, ily, Px, Py)

	var ret [32]byte
	copy(ret[:], Rx.Bytes())
	return ret
}

//用d计算k0
func getPrivateK0(d [32]byte, message []byte) [32]byte {
	Px, Py := Curve.ScalarBaseMult(d[:])
	ilNum := computChildOffset(Px.Bytes(), Py.Bytes(), message)

	k0Num := new(big.Int).SetBytes(d[:])
	k0Num = k0Num.Add(k0Num, ilNum)
	k0Num = k0Num.Mod(k0Num, Curve.N)
	//.......................TestCode
	var message32 [32]byte
	copy(message32[:], message)
	k0Num, _ = deterministicGetK0(d[:], message32)
	fmt.Printf("d = %x\n", d)

	//.......................

	var k0 [32]byte
	copy(k0[:], k0Num.Bytes())
	fmt.Printf("k0 = %x\n", k0)
	return k0
}

func deterministicGetK0(d []byte, message [32]byte) (*big.Int, error) {
	h := sha256.Sum256(append(d, message[1:]...))
	i := new(big.Int).SetBytes(h[:])
	k0 := i.Mod(i, Curve.N)
	if k0.Sign() == 0 {
		return nil, errors.New("k0 is zero")
	}

	return k0, nil
}

func computChildOffset(X, Y, message []byte) *big.Int  {
	hmac512 := hmac.New(sha512.New, X)
	hmac512.Write(Y)
	hmac512.Write(message)
	i := hmac512.Sum(nil)
	ilNum := new(big.Int).SetBytes(i[:32])

	return ilNum
}
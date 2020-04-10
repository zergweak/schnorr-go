package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"schnorr/schnorr-go/schnorr"
)

func getK(Ry, k0 *big.Int) *big.Int {
	if big.Jacobi(Ry, schnorr.Curve.P) == 1 {
		return k0
	}
	return k0.Sub(schnorr.Curve.N, k0)
}
func intToByte(i *big.Int) []byte {
	b1, b2 := [32]byte{}, i.Bytes()
	copy(b1[32-len(b2):], b2)
	return b1[:]
}
func main()  {
	//var prikey [32]byte
	//i, err := rand.Read(prikey[:])
	//if err != nil {
	//	panic(i)
	//}
	prikey,_ := hex.DecodeString("58e8f2a1f78f0a591feb75aebecaaa81076e4290894b1c445cc32953604db089")
	k0 := new(big.Int).SetBytes(prikey[:])
	k0 = k0.Mod(k0, schnorr.Curve.N)
	fmt.Printf("k0 = %x\n", k0.Bytes())
	X, Y := schnorr.Curve.ScalarBaseMult(intToByte(k0))
	k := getK(Y, k0)

	fmt.Printf("X = %x\n", X.Bytes())
	fmt.Printf("Y = %x\n", Y.Bytes())
	fmt.Printf("k = %x\n", k.Bytes())


	K := new(big.Int).SetInt64(0)
	K = K.Add(K, k)


		prikey,_ = hex.DecodeString("94aaa4de07e1b8c060e951408cfcfb4e2ebaa971e10dd36a84cfc77cde538154")
		k0 = new(big.Int).SetBytes(prikey[:])
		k0 = k0.Mod(k0, schnorr.Curve.N)
		fmt.Printf("k0 = %x\n", k0.Bytes())
		x, y := schnorr.Curve.ScalarBaseMult(intToByte(k0))
		X, Y = schnorr.Curve.Add(X, Y, x, y)
		k = getK(y, k0)
	fmt.Printf("x = %x\n", x.Bytes())
	fmt.Printf("y = %x\n", y.Bytes())
	fmt.Printf("X = %x\n", X.Bytes())
	fmt.Printf("Y = %x\n", Y.Bytes())
	fmt.Printf("k = %x\n", k.Bytes())


		K = K.Add(K, k)


	Xx, Yy := schnorr.Curve.ScalarBaseMult(K.Bytes())
	fmt.Printf("Xx = %x\n", Xx.Bytes())
	fmt.Printf("Yy = %x\n", Yy.Bytes())

}

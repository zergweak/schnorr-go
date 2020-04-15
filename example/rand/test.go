package main

import (
	"math/big"
	"schnorr/schnorr-go/multisign"
	"schnorr/schnorr-go/schnorr"
)

func main()  {
	// 用于固定的多个用户，分别签名，最后聚合
	message := []byte("test msg")
	var privateKeys [][32]byte
	var publicKeys [][33]byte
	Rx, Ry := big.NewInt(0), big.NewInt(0)
	for i := 0; i < 10; i++{
		privateKey, publicKey := schnorr.GenKey()
		privateKeys = append(privateKeys, privateKey)
		publicKeys = append(publicKeys, publicKey)
		pubR := schnorr.GetPublicR(publicKey, message)
		RIx, RIy := schnorr.Unmarshal(schnorr.Curve, pubR[:])
		Rx, Ry = schnorr.Curve.Add(Rx, Ry, RIx, RIy)
	}

	// 开始每个用户依次签名，注意每个用户可以拿到所有人的私钥，但是只持有自己的私钥
	var err error
	var ret bool
	s := big.NewInt(0)
	for i, privateKey := range privateKeys  {
		signI, err := multisign.Sign(message, privateKey, publicKeys)
		if err != nil {
			panic(err)
		}
		ret, err = multisign.VerifySignInput(publicKeys[i:i+1], publicKeys, message, signI)
		if err != nil {
			panic(err)
		}
		if !ret {
			panic("验证签名失败")
		}
		s = new(big.Int).Add(new(big.Int).SetBytes(signI[32:]), s)
		s = s.Mod(s, schnorr.Curve.N)
	}

	var sign [64]byte
	copy(sign[:32], schnorr.IntToByte(Rx))
	copy(sign[32:], schnorr.IntToByte(s))

	//所有人都签名完了，验证签名
	ret, err = multisign.MultiVerify(publicKeys, message, sign)
	if err != nil {
		panic(err)
	}
	if !ret {
		panic("验证签名失败")
	}
}

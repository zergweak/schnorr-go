package main

import (
	"schnorr/schnorr-go/multisign"
	"schnorr/schnorr-go/schnorr"
)

func main()  {
	// 用于固定的多个用户，固定的顺序进行测试
	var privateKeys [][32]byte
	var publicKeys [][33]byte

	for i := 0; i < 10; i++{
		privateKey, publicKey := schnorr.GenKey()
		privateKeys = append(privateKeys, privateKey)
		publicKeys = append(publicKeys, publicKey)
	}

	// 开始每个用户依次签名，注意每个用户可以拿到所有人的私钥，但是只持有自己的私钥
	message := []byte("test msg")
	var sign [64]byte
	var err error
	var ret bool
	for i, privateKey := range privateKeys  {
		ret, err = multisign.VerifySignInput(publicKeys[:i], publicKeys, message, sign)
		if err != nil {
			panic(err)
		}
		if !ret {
			panic("验证前置签名失败")
		}
		sign, err = multisign.AppendSignature(sign, message, privateKey, publicKeys, i)
		if err != nil {
			panic(err)
		}
		ret, err = multisign.VerifySignInput(publicKeys[:i+1], publicKeys, message, sign)
		if err != nil {
			panic(err)
		}
		if !ret {
			panic("验证签名失败")
		}
	}

	//所有人都签名完了，验证签名
	ret, err = multisign.MultiVerify(publicKeys, message, sign)
	if err != nil {
		panic(err)
	}
	if !ret {
		panic("验证签名失败")
	}
}

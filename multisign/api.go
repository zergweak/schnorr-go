package multisign

import (
	"errors"
	"schnorr/schnorr-go/schnorr"
)

// AppendSignature 实现一个聚合签名，可以在一个签名的基础上追加一个签名
// signInput 是上一个参与者的签名结果，如果本次为第一个，则为空
// privateKey是私钥，
// message是签名消息
// publicKeys 是公钥的集合，按照签名顺序排序
// index 当前签名的序号，小于index的已经签完
func AppendSignature(signInput [64]byte, message []byte, privateKey [32]byte, publicKeys [][33]byte, index int) (signOutput [64]byte, err error){
	k0 := schnorr.GetPrivateK0(privateKey, message)
	privKey := &schnorr.PrivateKey{D:privateKey, K0:k0}

	if len(publicKeys) == 0 {
		return signOutput, errors.New("invalid publicKeys")
	}
	var pubKeys []*schnorr.PublicKey
	for _, publicKey := range publicKeys {
		R := schnorr.GetPublicR(publicKey, message)
		pubKey := &schnorr.PublicKey{P:publicKey, R:R}
		pubKeys = append(pubKeys, pubKey)
	}
	return schnorr.AppendSignature(signInput, message, privKey, pubKeys, index)
}

//Verify
func Verify(publicKey [33]byte, message []byte, signature [64]byte) (bool, error) {
	return schnorr.Verify(publicKey, message, signature)
}

//MultiVerify
func MultiVerify(publicKey [][33]byte, message []byte, signature [64]byte) (bool, error) {
	return schnorr.MultiVerify(publicKey, message, signature)
}

//VerifySignInput 验证签名的中间过程
//publicKeysSigned 已经参与的签名公钥
//publicKeys	所有参与签名的公钥
//message		签名消息
//signInput		签名中间结果
func VerifySignInput(publicKeysSigned [][33]byte, publicKeys [][33]byte, message []byte, signInput [64]byte) (bool, error) {
	if len(publicKeysSigned) == 0 {
		return true, nil //没有签过
	}

	if len(publicKeys) == 0 {
		return false, errors.New("invalid publicKeys")
	}

	if len(publicKeys) < len(publicKeysSigned) {
		return false, errors.New("publicKeysSigned size bigger than publicKeys")
	}

	var signedPubKeys []*schnorr.PublicKey
	for _, publicKey := range publicKeysSigned {
		R := schnorr.GetPublicR(publicKey, message)
		pubKey := &schnorr.PublicKey{P:publicKey, R:R}
		signedPubKeys = append(signedPubKeys, pubKey)
	}

	var pubKeys []*schnorr.PublicKey
	for _, publicKey := range publicKeys {
		R := schnorr.GetPublicR(publicKey, message)
		pubKey := &schnorr.PublicKey{P:publicKey, R:R}
		pubKeys = append(pubKeys, pubKey)
	}

	return schnorr.VerifySignInput(signedPubKeys, pubKeys, message, signInput)
}

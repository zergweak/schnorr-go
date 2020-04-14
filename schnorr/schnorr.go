package schnorr

import (
	"errors"
	"math/big"
)

//PrivateKey 私钥
type PrivateKey struct {
	D [32]byte     //签名私钥
	K0 [32]byte	   //随机数
}

//PublicKey 公钥
type PublicKey struct {
	P [33]byte	   //签名公钥
	R [33]byte	   //k0*G
}

// AppendSignature 实现一个聚合签名，可以在一个签名的基础上追加一个签名
// signInput 是上一个参与者的签名结果，如果本次为第一个，则为nil
// privateKey是私钥，
// message是签名消息
// publicKeys 是公钥的集合，按照签名顺序排序
// index 当前签名的序号，小于index的已经签完
func AppendSignature(signInput [64]byte, message []byte, privateKey *PrivateKey, publicKeys []*PublicKey, index int) (signOutput [64]byte, err error) {
	//校验privateKey
	if index >= len(publicKeys) || index < 0{
		return signOutput, errors.New("invalid index")
	}

	RxSigned, RySigned := Zero, Zero
	if index > 0 {
		ret, err := VerifySignInput(publicKeys[:index], publicKeys, message, signInput)
		if err != nil {
			return signOutput, err
		}
		if !ret {
			return signOutput, errors.New("signature verification failed")
		}
		pubSigned := aggregationPublicKey(publicKeys[:index])
		RxSigned, RySigned = Unmarshal(Curve, pubSigned.R[:])
	}

	Rix, Riy, s, err := Sign(message, privateKey, publicKeys)
	if index > 0 {
		Rix, Riy = Curve.Add(RxSigned, RySigned, Rix, Riy)
		sSigned := new(big.Int).SetBytes(signInput[32:])
		s = s.Add(s, sSigned)
		s = s.Mod(s, Curve.N)
	}
	copy(signOutput[:32], intToByte(Rix))
	copy(signOutput[32:], intToByte(s))
	return  signOutput, nil
}

// Sign 一个参与者签名
// privateKey是私钥
// publicKey是公钥
// message是签名消息
// publicKeys 是公钥的集合
func Sign(message []byte, privateKey *PrivateKey, publicKeys []*PublicKey) (RIx, RIy, s *big.Int, err error){
	//校验privateKey 在publicKeys里
	if !checkPublicInArray(privateKey, publicKeys) {
		return nil,nil, nil, errors.New("privateKey is not in array")
	}

	// 求聚合公钥
	pub := aggregationPublicKey(publicKeys)
	Px, Py := Unmarshal(Curve, pub.P[:])
	Rx, Ry := Unmarshal(Curve, pub.R[:])
	//Bip32分散k0
	RIx, RIy = Curve.ScalarBaseMult(privateKey.K0[:])

	k0 := new(big.Int).SetBytes(privateKey.K0[:])
	k := getK(Ry, k0)

	rX := intToByte(Rx)
	e := getE(Px, Py, rX, message)
	// s = k + de
	priKey := new(big.Int).SetBytes(privateKey.D[:])
	e.Mul(e, priKey)
	k.Add(k, e)
	k.Mod(k, Curve.N)

	return RIx, RIy, k,nil
}

//Verify
func Verify(publicKey [33]byte, message []byte, signature [64]byte) (bool, error) {
	Px, Py := Unmarshal(Curve, publicKey[:])

	if Px == nil || Py == nil || !Curve.IsOnCurve(Px, Py) {
		return false, errors.New("signature verification failed")
	}
	r := new(big.Int).SetBytes(signature[:32])
	if r.Cmp(Curve.P) >= 0 {
		return false, errors.New("r is larger than or equal to field size")
	}
	s := new(big.Int).SetBytes(signature[32:])
	if s.Cmp(Curve.N) >= 0 {
		return false, errors.New("s is larger than or equal to curve order")
	}

	e := getE(Px, Py, intToByte(r), message)
	sGx, sGy := Curve.ScalarBaseMult(intToByte(s))
	// e.Sub(Curve.N, e)
	ePx, ePy := Curve.ScalarMult(Px, Py, intToByte(e))
	ePy.Sub(Curve.P, ePy)
	Rx, Ry := Curve.Add(sGx, sGy, ePx, ePy)

	if (Rx.Sign() == 0 && Ry.Sign() == 0) || big.Jacobi(Ry, Curve.P) != 1 || Rx.Cmp(r) != 0 {
		return false, errors.New("signature verification failed")
	}
	return true, nil
}

//MultiVerify
func MultiVerify(publicKey [][33]byte, message []byte, signature [64]byte) (bool, error) {
	pubKey := aggregationPubKey(publicKey)
	return Verify(pubKey, message, signature)
}

//VerifySignInput 验证签名的中间过程
//publicKeysSigned 已经参与的签名公钥
//publicKeys	所有参与签名的公钥
//message		签名消息
//signInput		签名中间结果
func VerifySignInput(publicKeysSigned []*PublicKey, publicKeys []*PublicKey, message []byte, signInput [64]byte) (bool, error) {
	pub := aggregationPublicKey(publicKeys)
	Px, Py := Unmarshal(Curve, pub.P[:])
	Rx, Ry := Unmarshal(Curve, pub.R[:])

	pubSigned := aggregationPublicKey(publicKeysSigned)
	pubSignedPx, pubSignedPy := Unmarshal(Curve, pubSigned.P[:])
	pubSignedRx, pubSignedRy := Unmarshal(Curve, pubSigned.R[:])

	r := new(big.Int).SetBytes(signInput[:32])
	if r.Cmp(Curve.P) >= 0 {
		return false, errors.New("r is larger than or equal to field size")
	}
	s := new(big.Int).SetBytes(signInput[32:])
	if s.Cmp(Curve.N) >= 0 {
		return false, errors.New("s is larger than or equal to curve order")
	}

	rX := intToByte(Rx)
	e := getE(Px, Py, rX, message)
	sGx, sGy := Curve.ScalarBaseMult(intToByte(s))
	// e.Sub(Curve.N, e)
	ePx, ePy := Curve.ScalarMult(pubSignedPx, pubSignedPy, intToByte(e))
	ePy.Sub(Curve.P, ePy)
	Rx1, Ry1 := Curve.Add(sGx, sGy, ePx, ePy)
	if Rx1.Sign() == 0 && Ry1.Sign() == 0 {
		return false, errors.New("signature verification failed : Rx1, Rx1 are zero")
	}
	if pubSignedRx.Cmp(r) != 0 {
		return false, errors.New("signature verification failed : pubSignedRx is not equal r")
	}
	if Rx1.Cmp(r) != 0 {
		return false, errors.New("signature verification failed : Rx1 is not equal r")
	}
	// 所有的k都根据Ry是否jacobi做过调整, 因此通过s计算出的Ry1也是做过调整的。
	// big.Jacobi(Ry, Curve.P) != 1 成立是，Ry1 和 pubSignedRy 是反的。
	if big.Jacobi(Ry, Curve.P) != 1 {
		Ry1 = new(big.Int).Sub(Curve.P, Ry1)
	}
	if Ry1.Cmp(pubSignedRy) != 0 {
		return false, errors.New("signature verification failed : Ry1 is not equal pubSignedRy")
	}
	return true, nil
}
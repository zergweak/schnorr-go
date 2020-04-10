package schnorr

import (
	"errors"
	"fmt"
	"math/big"
)

//PrivateKey 私钥
type PrivateKey struct {
	d [32]byte     //签名私钥
	k0 [32]byte	   //随机数
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
	if index >= len(publicKeys) {
		return signOutput, errors.New("invalid index")
	}

	PIx, PIy := Curve.ScalarBaseMult(privateKey.d[:])
	RIx, RIy := Curve.ScalarBaseMult(privateKey.k0[:])
	fmt.Printf("privateKey.k0 = %x\n", privateKey.k0)
	Px, Py := Unmarshal(Curve, publicKeys[index].P[:])
	Rx, Ry := Unmarshal(Curve, publicKeys[index].R[:])
	if Px.Cmp(PIx) != 0 || Py.Cmp(PIy) != 0 || Rx.Cmp(RIx) != 0 || Ry.Cmp(RIy) != 0{
		return signOutput, errors.New("invalid private key")
	}

	RxSigned, RySigned := new(big.Int).SetInt64(0), new(big.Int).SetInt64(0)
	if index > 0 {
		RxSigned, RySigned, err = VerifySignInput(publicKeys[:index], publicKeys, message, signInput)
		if err != nil {
			return signOutput, err
		}
	}
	fmt.Printf("privateKey.ddddd = %x\n", privateKey.d)
	Rix, Riy, s, err := Sign(message, privateKey, publicKeys)
	fmt.Printf("privateKey.k0 = %x\n", privateKey.k0)
	fmt.Printf("Rix = %x\n", Rix.Bytes())
	fmt.Printf("Riy = %x\n", Riy.Bytes())
	fmt.Printf("si = %x\n", s.Bytes())
	if index > 0 {
		//不对
		Rix, Riy = Curve.Add(RxSigned, RySigned, Rix, Riy)
		sSigned := new(big.Int).SetBytes(signInput[32:])
		s = s.Add(s, sSigned)
		s = s.Mod(s, Curve.N)
		fmt.Printf("s = %x\n", s.Bytes())
	}
	copy(signOutput[:32], Rix.Bytes())
	copy(signOutput[32:], s.Bytes())
	return  signOutput, nil
}

// Sign 一个参与者签名
// privateKey是私钥
// publicKey是公钥
// message是签名消息
// publicKeys 是公钥的集合
func Sign(message []byte, privateKey *PrivateKey, publicKeys []*PublicKey) (RIx, RIy, s *big.Int, err error){
	fmt.Printf("privateKey.d = %x\n", privateKey.d)
	//校验privateKey 在publicKeys里
	if !checkPublicInArray(privateKey, publicKeys) {
		return nil,nil, nil, errors.New("privateKey is not in array")
	}

	// 求聚合公钥
	pub := getPublicKey(publicKeys)
	Px, Py := Unmarshal(Curve, pub.P[:])
	Rx, Ry := Unmarshal(Curve, pub.R[:])
	//Bip32分散k0
	RIx, RIy = Curve.ScalarBaseMult(privateKey.k0[:])

	k0 := new(big.Int).SetBytes(privateKey.k0[:])
	fmt.Printf("privateKey.k0 = %x\n", privateKey.k0)
	fmt.Printf("privateKey.d = %x\n", privateKey.d)
	fmt.Printf("K0 = %x\n", k0.Bytes())
	k := getK(Ry, k0)
	fmt.Printf("Ry = %x\n", Ry.Bytes())
	fmt.Printf("ki = %x\n", k.Bytes())

	rX := intToByte(Rx)
	e := getE(Px, Py, rX, message)
	fmt.Printf("e = %x\n", e.Bytes())
	// s = k + de
	fmt.Printf("privateKey.d = %x\n", privateKey.d)
	priKey := new(big.Int).SetBytes(privateKey.d[:])
	fmt.Printf("priKey = %x\n", priKey.Bytes())
	fmt.Printf("k = %x\n", k.Bytes())
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

//VerifySignInput 验证签名的中间过程
//publicKeysSigned 已经参与的签名公钥
//publicKeys	所有参与签名的公钥
//message		签名消息
//signInput		签名中间结果
func VerifySignInput(publicKeysSigned []*PublicKey, publicKeys []*PublicKey, message []byte, signInput [64]byte) (x, y *big.Int, err error) {
	pub := getPublicKey(publicKeys)
	Px, Py := Unmarshal(Curve, pub.P[:])
	Rx, _ := Unmarshal(Curve, pub.R[:])

	pubSigned := getPublicKey(publicKeysSigned)
	pubSignedPx, pubSignedPy := Unmarshal(Curve, pubSigned.P[:])


	if Px == nil || Py == nil || !Curve.IsOnCurve(Px, Py) {
		return nil, nil, errors.New("signature verification failed")
	}
	r := new(big.Int).SetBytes(signInput[:32])
	if r.Cmp(Curve.P) >= 0 {
		return nil, nil, errors.New("r is larger than or equal to field size")
	}
	s := new(big.Int).SetBytes(signInput[32:])
	if s.Cmp(Curve.N) >= 0 {
		return nil, nil, errors.New("s is larger than or equal to curve order")
	}

	rX := intToByte(Rx)
	e := getE(Px, Py, rX, message)
	sGx, sGy := Curve.ScalarBaseMult(intToByte(s))
	// e.Sub(Curve.N, e)
	ePx, ePy := Curve.ScalarMult(pubSignedPx, pubSignedPy, intToByte(e))
	ePy.Sub(Curve.P, ePy)
	Rx1, Ry1 := Curve.Add(sGx, sGy, ePx, ePy)

	if (Rx1.Sign() == 0 && Ry1.Sign() == 0) /*|| big.Jacobi(Ry1, Curve.P) != 1*/ || Rx1.Cmp(r) != 0 {
		return nil, nil, errors.New("signature verification failed")
	}
	return Rx1, Ry1, nil
}
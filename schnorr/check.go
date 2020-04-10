package schnorr

func checkPublicInArray(privateKey *PrivateKey, publicKeys []*PublicKey) bool{
	PIx, PIy := Curve.ScalarBaseMult(privateKey.D[:])
	RIx, RIy := Curve.ScalarBaseMult(privateKey.K0[:])

	for _, publicKey := range publicKeys {
		Px, Py := Unmarshal(Curve, publicKey.P[:])
		Rx, Ry := Unmarshal(Curve, publicKey.R[:])
		if Px.Cmp(PIx) == 0 && Py.Cmp(PIy) == 0 && Rx.Cmp(RIx) == 0 && Ry.Cmp(RIy) == 0{
			return true
		}
	}
	return false
}

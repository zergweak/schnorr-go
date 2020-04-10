package schnorr

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestGetK0(t *testing.T)  {
	message, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	d, _ := hex.DecodeString("b2b084220e17de5bb85c6b33fe4630dc0cc3a0382c49509461a26341bc3c27e4")
	P, _ := hex.DecodeString("021b34e02fbfab6153513c7578de070e1c9f2654b88109fb3906bb7f63dffd957d")

	var d32 [32]byte
	var P33 [33]byte

	copy(d32[:], d)
	copy(P33[:], P)

	k0 := getPrivateK0(d32, message)
	Rx := getPublicRx(P33, message)

	Rx1, _ := Curve.ScalarBaseMult(k0[:])

	if !bytes.Equal(Rx[:], Rx1.Bytes()) {
		panic("R 不相等")
	}
}


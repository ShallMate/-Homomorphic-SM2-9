// Copyright 2020 cetc-30. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sm9

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math"
	"math/big"

	"github.com/pkg/errors"
	"github.com/xlcetc/cryptogm/elliptic/sm9curve"
	"github.com/xlcetc/cryptogm/sm/sm2"
	"github.com/xlcetc/cryptogm/sm/sm3"
)

type hashMode int

const (
	H1 hashMode = iota
	H2
)

//MasterKey contains a master secret key and a master public key.
type MasterKey struct {
	Msk *big.Int
	MasterPubKey
}

type MasterPubKey struct {
	Mpk *sm9curve.G2
}

//UserKey contains a secret key.
type UserKey struct {
	Sk *sm9curve.G1
}

//Sm9Sig contains a big number and an element in G1.
type Sm9Sig struct {
	H *big.Int
	S *sm9curve.G1
}

var T2 = make([]*sm9curve.GT, 256)
var T1 = make(map[[8]byte]int64, 16777216)

var Mk *MasterKey
var Hid byte = 1
var Uid = []byte("Alice")
var Uk *UserKey

//hash implements H1(Z,n) or H2(Z,n) in sm9 algorithm.
func hash(z []byte, n *big.Int, h hashMode) *big.Int {
	//counter
	ct := 1

	hlen := 8 * int(math.Ceil(float64(5*n.BitLen()/32)))

	var ha []byte
	for i := 0; i < int(math.Ceil(float64(hlen/256))); i++ {
		msg := append([]byte{byte(h)}, z...)
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(ct))
		msg = append(msg, buf...)
		hai := sm3.SumSM3(msg)
		ct++
		if float64(hlen)/256 == float64(int64(hlen/256)) && i == int(math.Ceil(float64(hlen/256)))-1 {
			ha = append(ha, hai[:(hlen-256*int(math.Floor(float64(hlen/256))))/32]...)
		} else {
			ha = append(ha, hai[:]...)
		}
	}

	bn := new(big.Int).SetBytes(ha)
	one := big.NewInt(1)
	nMinus1 := new(big.Int).Sub(n, one)
	bn.Mod(bn, nMinus1)
	bn.Add(bn, one)

	return bn
}

//generate rand numbers in [1,n-1].
func randFieldElement(rand io.Reader, n *big.Int) (k *big.Int, err error) {
	one := big.NewInt(1)
	b := make([]byte, 256/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	nMinus1 := new(big.Int).Sub(n, one)
	k.Mod(k, nMinus1)
	return
}

//generate master key for KGC(Key Generate Center).
func MasterKeyGen(rand io.Reader) (mk *MasterKey, err error) {
	s, err := randFieldElement(rand, sm9curve.Order)
	if err != nil {
		return nil, errors.Errorf("gen rand num err:%s", err)
	}

	mk = new(MasterKey)
	mk.Msk = new(big.Int).Set(s)

	mk.Mpk = new(sm9curve.G2).ScalarBaseMult(s)

	return
}

//generate user's secret key.
func UserKeyGen(mk *MasterKey, id []byte, hid byte) (uk *UserKey, err error) {
	id = append(id, hid)
	n := sm9curve.Order
	t1 := hash(id, n, H1)
	t1.Add(t1, mk.Msk)

	//if t1 = 0, we need to regenerate the master key.
	if t1.BitLen() == 0 || t1.Cmp(n) == 0 {
		return nil, errors.New("need to regen mk!")
	}

	t1.ModInverse(t1, n)

	//t2 = s*t1^-1
	t2 := new(big.Int).Mul(mk.Msk, t1)

	uk = new(UserKey)
	uk.Sk = new(sm9curve.G1).ScalarBaseMult(t2)
	return
}

//sm9 sign algorithm:
//A1:compute g = e(P1,Ppub);
//A2:choose random num r in [1,n-1];
//A3:compute w = g^r;
//A4:compute h = H2(M||w,n);
//A5:compute l = (r-h) mod n, if l = 0 goto A2;
//A6:compute S = l·sk.
func Sign(uk *UserKey, mpk *MasterPubKey, msg []byte) (sig *Sm9Sig, err error) {
	sig = new(Sm9Sig)
	n := sm9curve.Order
	g := sm9curve.Pair(sm9curve.Gen1, mpk.Mpk)

regen:
	r, err := randFieldElement(rand.Reader, n)
	if err != nil {
		return nil, errors.Errorf("gen rand num failed:%s", err)
	}

	w := new(sm9curve.GT).ScalarMult(g, r)

	wBytes := w.Marshal()

	msg = append(msg, wBytes...)

	h := hash(msg, n, H2)

	sig.H = new(big.Int).Set(h)

	l := new(big.Int).Sub(r, h)
	l.Mod(l, n)

	if l.BitLen() == 0 {
		goto regen
	}

	sig.S = new(sm9curve.G1).ScalarMult(uk.Sk, l)

	return
}

//sm9 verify algorithm(given sig (h',S'), message M' and user's id):
//B1:compute g = e(P1,Ppub);
//B2:compute t = g^h';
//B3:compute h1 = H1(id||hid,n);
//B4:compute P = h1·P2+Ppub;
//B5:compute u = e(S',P);
//B6:compute w' = u·t;
//B7:compute h2 = H2(M'||w',n), check if h2 = h'.
func Verify(sig *Sm9Sig, msg []byte, id []byte, hid byte, mpk *MasterPubKey) bool {
	n := sm9curve.Order
	g := sm9curve.Pair(sm9curve.Gen1, mpk.Mpk)

	t := new(sm9curve.GT).ScalarMult(g, sig.H)

	id = append(id, hid)

	h1 := hash(id, n, H1)

	P := new(sm9curve.G2).ScalarBaseMult(h1)

	P.Add(P, mpk.Mpk)

	u := sm9curve.Pair(sig.S, P)

	w := new(sm9curve.GT).Add(u, t)

	wBytes := w.Marshal()

	msg = append(msg, wBytes...)

	h2 := hash(msg, n, H2)

	if h2.Cmp(sig.H) != 0 {
		return false
	}

	return true
}

func LgwEnc(m []byte, mpk *MasterPubKey, id []byte, hid byte) (*sm9curve.G2, []byte) {
	n := sm9curve.Order
	idhid := append(id, hid)
	// h1 = H1(id||hid,n)
	h1 := hash(idhid, n, H1)
	h1P1 := new(sm9curve.G2).ScalarBaseMult(h1)
	QB := new(sm9curve.G2).Add(h1P1, mpk.Mpk)
	r, _ := randFieldElement(rand.Reader, n)
	//c1 = [r]QB
	C1 := new(sm9curve.G2).ScalarMult(QB, r)
	//g = r(mpk,p2)
	g := sm9curve.Pair(sm9curve.Gen1, mpk.Mpk)
	w := new(sm9curve.GT).ScalarMult(g, r)
	c1byte := C1.Marshal()
	wbyte := w.Marshal()
	//fmt.Println(wbyte)
	c1w := append(c1byte, wbyte...)
	c1wid := append(c1w, id...)
	t := sm2.KeyDerivation(c1wid, len(m)*8)
	for i := 0; i < len(m); i++ {
		m[i] = m[i] ^ t[i]
	}
	return C1, m
}

func LgwDec(c1 *sm9curve.G2, c2 []byte, id []byte, uk *UserKey) []byte {
	//w= e(c1,skid)
	w := sm9curve.Pair(uk.Sk, c1)
	wbyte := w.Marshal()
	c1byte := c1.Marshal()
	c1w := append(c1byte, wbyte...)
	c1wid := append(c1w, id...)
	t := sm2.KeyDerivation(c1wid, len(c2)*8)
	for i := 0; i < len(c2); i++ {
		c2[i] = c2[i] ^ t[i]
	}
	return c2
}

func LgwHEnc(m *big.Int, mpk *MasterPubKey, id []byte, hid byte) (*sm9curve.G2, *sm9curve.GT) {
	n := sm9curve.Order
	id = append(id, hid)
	// h1 = H1(id||hid,n)
	h1 := hash(id, n, H1)
	h1P1 := new(sm9curve.G2).ScalarBaseMult(h1)
	QB := new(sm9curve.G2).Add(h1P1, mpk.Mpk)
	r, _ := randFieldElement(rand.Reader, n)
	//c1 = [r]QB
	C1 := new(sm9curve.G2).ScalarMult(QB, r)
	//g = r(mpk,p2)
	g := sm9curve.Pair(sm9curve.Gen1, mpk.Mpk)
	w := new(sm9curve.GT).ScalarMult(g, r)
	gm := new(sm9curve.GT).ScalarMult(g, m)
	//c2=g^m * w
	C2 := new(sm9curve.GT).Add(gm, w)
	return C1, C2
}

func LgwHDec(c1 *sm9curve.G2, c2 *sm9curve.GT, uk *UserKey) int {
	//w= e(c1,skid)
	m := -1
	w := sm9curve.Pair(uk.Sk, c1)
	//w^-1
	inv_w := new(sm9curve.GT).Neg(w)
	//gm = c2*w^-1
	gm := new(sm9curve.GT).Add(c2, inv_w)
	//fmt.Println(gm.Marshal())
	j := 0
	for ; j < 256; j++ {
		if j == 0 {
			sum := sha256.Sum256(gm.Marshal())
			var sum64 [8]byte
			copy(sum64[:], sum[:8])
			i, ok := T1[sum64]
			if ok {
				m = int(i)
				break
			}
		}
		x3 := new(sm9curve.GT).Add(gm, T2[j])
		sum := sha256.Sum256(x3.Marshal())
		var sum64 [8]byte
		copy(sum64[:], sum[:8])
		if i, ok := T1[sum64]; ok {
			m = j*16777216 + int(i)
			break
		}
	}
	return m
}

/*
func init() {
	Mk, _ = MasterKeyGen(rand.Reader)
	Uk, _ = UserKeyGen(Mk, Uid, Hid)
	g := sm9curve.Pair(sm9curve.Gen1, Mk.Mpk)
	var i int64 = 2
	var j int64 = 0
	temp := new(sm9curve.GT).Set(g)
	sum := sha256.Sum256(g.Marshal())
	var sum64 [8]byte
	copy(sum64[:], sum[:8])
	T1[sum64] = 1
	for ; i <= 16777216; i++ {
		fmt.Println(i)
		t1key := new(sm9curve.GT).Add(temp, g)
		temp.Set(t1key)
		sum := sha256.Sum256(t1key.Marshal())
		var sum64 [8]byte
		copy(sum64[:], sum[:8])
		T1[sum64] = i
	}
	//t2temp := new(sm9curve.GT).Set(temp)
	for ; j < 256; j++ {
		fmt.Println(j)
		jbigint := big.NewInt(j * 16777216)
		t2 := new(sm9curve.GT).ScalarMult(g, jbigint)
		t2 = t2.Neg(t2)
		T2[j] = t2
	}
}
*/

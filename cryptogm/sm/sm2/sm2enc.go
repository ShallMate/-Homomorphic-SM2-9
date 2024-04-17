// Copyright 2020 cetc-30. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"

	"github.com/xlcetc/cryptogm/elliptic/sm2curve"
	"github.com/xlcetc/cryptogm/sm/sm3"
)

var EncryptionErr = errors.New("sm2: encryption error")
var DecryptionErr = errors.New("sm2: decryption error")

var T2x = make([]*big.Int, 256)
var T2y = make([]*big.Int, 256)
var T1 = make(map[string]int64, 16777216)

func keyDerivation(Z []byte, klen int) []byte {
	var ct = 1
	if klen%8 != 0 {
		return nil
	}

	K := make([]byte, int(math.Ceil(float64(klen)/(sm3.Size*8))*sm3.Size))
	v := sm3.Size * 8

	l := int(math.Ceil(float64(klen) / float64(v)))

	var m = make([]byte, len(Z)+4)
	var vBytes = make([]byte, 4)
	copy(m, Z)

	for ; ct <= l; ct++ {
		binary.BigEndian.PutUint32(vBytes, uint32(ct))
		copy(m[len(Z):], vBytes)

		hash := sm3.SumSM3(m)
		copy(K[(ct-1)*sm3.Size:], hash[:])
	}
	return K[:klen/8]
}

func KeyDerivation(Z []byte, klen int) []byte {
	var ct = 1
	if klen%8 != 0 {
		return nil
	}

	K := make([]byte, int(math.Ceil(float64(klen)/(sm3.Size*8))*sm3.Size))
	v := sm3.Size * 8

	l := int(math.Ceil(float64(klen) / float64(v)))

	var m = make([]byte, len(Z)+4)
	var vBytes = make([]byte, 4)
	copy(m, Z)

	for ; ct <= l; ct++ {
		binary.BigEndian.PutUint32(vBytes, uint32(ct))
		copy(m[len(Z):], vBytes)

		hash := sm3.SumSM3(m)
		copy(K[(ct-1)*sm3.Size:], hash[:])
	}
	return K[:klen/8]
}

func LgwEnc(rand io.Reader, key *PublicKey, msg []byte) (x, y *big.Int, c2, c3 []byte, err error) {
	k := generateRandK(rand, key.Curve)
	// C1 = k[G]
regen:
	x1, y1 := key.Curve.ScalarBaseMult(k.Bytes())
	var x2, y2 *big.Int
	// [k]PK
	x2, y2 = key.Curve.ScalarMult(key.X, key.Y, k.Bytes())
	//t=KDF(x2||m||y2,klen)
	xBuf := x2.Bytes()
	yBuf := y2.Bytes()
	xPadding := make([]byte, 32)
	yPadding := make([]byte, 32)
	if n := len(xBuf); n < 32 {
		xBuf = append(xPadding[:32-n], xBuf...)
	}
	if n := len(yBuf); n < 32 {
		yBuf = append(yPadding[:32-n], yBuf...)
	}
	//z=x2||y2
	Z := make([]byte, 64)
	copy(Z, xBuf)
	copy(Z[32:], yBuf)
	t := keyDerivation(Z, len(msg)*8)
	if t == nil {
		return nil, nil, nil, nil, EncryptionErr
	}
	for i, v := range t {
		if v != 0 {
			break
		}
		if i == len(t)-1 {
			goto regen
		}
	}
	//M^t
	for i, v := range t {
		t[i] = v ^ msg[i]
	}
	m3 := make([]byte, 64+len(msg))
	copy(m3, xBuf)
	copy(m3[32:], msg)
	copy(m3[32+len(msg):], yBuf)
	h := sm3.SumSM3(m3)
	c3 = h[:]
	return x1, y1, t, c3, nil
}

func LgwHEnc(rand io.Reader, key *PublicKey, m *big.Int) (x1, y1, c2x, c2y *big.Int) {
	k := generateRandK(rand, key.Curve)
	// C1 = k[G]
	x1, y1 = key.Curve.ScalarBaseMult(k.Bytes())
	var x2, y2 *big.Int
	// [k]PK
	x2, y2 = key.Curve.ScalarMult(key.X, key.Y, k.Bytes())
	mGx, mGy := key.Curve.ScalarBaseMult(m.Bytes())
	c2x = new(big.Int)
	c2y = new(big.Int)
	c2x, c2y = key.Curve.Add(mGx, mGy, x2, y2)
	return x1, y1, c2x, c2y
}

func LgwHDec(key *PrivateKey, c1x, c1y, c2x, c2y *big.Int) (int, error) {
	var m int = -1
	x2, y2 := key.Curve.ScalarMult(c1x, c1y, key.D.Bytes())
	inv_y2 := new(big.Int)
	inv_y2.Add(key.Curve.Params().P, inv_y2)
	inv_y2.Sub(inv_y2, y2)
	mGx, mGy := key.Curve.Add(c2x, c2y, x2, inv_y2)
	if c2x.Cmp(x2) == 0 {
		return 0, nil
	}
	j := 0
	for ; j < 256; j++ {
		if j == 0 {
			i, ok := T1[mGx.String()]
			if ok {
				m = int(i)
				break
			}
		}
		x3, _ := key.Curve.Add(mGx, mGy, T2x[j], T2y[j])
		if i, ok := T1[x3.String()]; ok {
			m = j*16777216 + int(i)
			break
		}
	}
	return m, nil
}

func Encrypt(rand io.Reader, key *PublicKey, msg []byte) (cipher []byte, err error) {
	x, y, c2, c3, err := doEncrypt(rand, key, msg)
	if err != nil {
		return nil, err
	}

	c1 := pointToBytes(x, y)

	//c = c1||c2||c3,len(c1)=65,len(c3)=32
	cipher = append(c1, c2...)
	cipher = append(cipher, c3...)

	return
}

func doEncrypt(rand io.Reader, key *PublicKey, msg []byte) (x, y *big.Int, c2, c3 []byte, err error) {
	k := generateRandK(rand, key.Curve)

regen:
	x1, y1 := key.Curve.ScalarBaseMult(k.Bytes())

	var x2, y2 *big.Int
	if opt, ok := key.Curve.(optMethod); ok && (key.PreComputed != nil) {
		x2, y2 = opt.PreScalarMult(key.PreComputed, k.Bytes())
	} else {
		x2, y2 = key.Curve.ScalarMult(key.X, key.Y, k.Bytes())
	}

	xBuf := x2.Bytes()
	yBuf := y2.Bytes()

	xPadding := make([]byte, 32)
	yPadding := make([]byte, 32)
	if n := len(xBuf); n < 32 {
		xBuf = append(xPadding[:32-n], xBuf...)
	}

	if n := len(yBuf); n < 32 {
		yBuf = append(yPadding[:32-n], yBuf...)
	}

	//z=x2||y2
	Z := make([]byte, 64)
	copy(Z, xBuf)
	copy(Z[32:], yBuf)

	t := keyDerivation(Z, len(msg)*8)
	if t == nil {
		return nil, nil, nil, nil, EncryptionErr
	}
	for i, v := range t {
		if v != 0 {
			break
		}
		if i == len(t)-1 {
			goto regen
		}
	}

	//M^t
	for i, v := range t {
		t[i] = v ^ msg[i]
	}

	m3 := make([]byte, 64+len(msg))
	copy(m3, xBuf)
	copy(m3[32:], msg)
	copy(m3[32+len(msg):], yBuf)
	h := sm3.SumSM3(m3)
	c3 = h[:]

	return x1, y1, t, c3, nil
}

func LgwDec(x1, y1 *big.Int, c2, c3 []byte, key *PrivateKey) ([]byte, error) {
	//dB*C1
	x2, y2 := key.Curve.ScalarMult(x1, y1, key.D.Bytes())

	xBuf := x2.Bytes()
	yBuf := y2.Bytes()

	xPadding := make([]byte, 32)
	yPadding := make([]byte, 32)
	if n := len(xBuf); n < 32 {
		xBuf = append(xPadding[:32-n], xBuf...)
	}

	if n := len(yBuf); n < 32 {
		yBuf = append(yPadding[:32-n], yBuf...)
	}

	//z=x2||y2
	Z := make([]byte, 64)
	copy(Z, xBuf)
	copy(Z[32:], yBuf)

	t := keyDerivation(Z, len(c2)*8)
	if t == nil {
		return nil, DecryptionErr
	}
	for i, v := range t {
		if v != 0 {
			break
		}
		if i == len(t)-1 {
			return nil, DecryptionErr
		}
	}

	// m` = c2 ^ t
	for i, v := range t {
		t[i] = v ^ c2[i]
	}

	//validate
	_u := make([]byte, 64+len(t))
	copy(_u, xBuf)
	copy(_u[32:], t)
	copy(_u[32+len(t):], yBuf)
	u := sm3.SumSM3(_u)
	if !bytes.Equal(u[:], c3) {
		return nil, DecryptionErr
	}

	return t, nil
}

func Decrypt(c []byte, key *PrivateKey) ([]byte, error) {
	x1, y1 := pointFromBytes(c[:65])

	//dB*C1
	x2, y2 := key.Curve.ScalarMult(x1, y1, key.D.Bytes())

	xBuf := x2.Bytes()
	yBuf := y2.Bytes()

	xPadding := make([]byte, 32)
	yPadding := make([]byte, 32)
	if n := len(xBuf); n < 32 {
		xBuf = append(xPadding[:32-n], xBuf...)
	}

	if n := len(yBuf); n < 32 {
		yBuf = append(yPadding[:32-n], yBuf...)
	}

	//z=x2||y2
	Z := make([]byte, 64)
	copy(Z, xBuf)
	copy(Z[32:], yBuf)

	t := keyDerivation(Z, (len(c)-97)*8)
	if t == nil {
		return nil, DecryptionErr
	}
	for i, v := range t {
		if v != 0 {
			break
		}
		if i == len(t)-1 {
			return nil, DecryptionErr
		}
	}
	// m` = c2 ^ t
	c2 := c[65:(len(c) - 32)]
	for i, v := range t {
		t[i] = v ^ c2[i]
	}
	//validate
	_u := make([]byte, 64+len(t))
	copy(_u, xBuf)
	copy(_u[32:], t)
	copy(_u[32+len(t):], yBuf)
	u := sm3.SumSM3(_u)
	if !bytes.Equal(u[:], c[65+len(c2):]) {
		return nil, DecryptionErr
	}
	return t, nil
}

// uncompressed form, s=04||x||y
func pointToBytes(x, y *big.Int) []byte {
	buf := []byte{}

	xBuf := x.Bytes()
	yBuf := y.Bytes()

	xPadding := make([]byte, 32)
	yPadding := make([]byte, 32)
	if n := len(xBuf); n < 32 {
		xBuf = append(xPadding[:32-n], xBuf...)
	}

	if n := len(yBuf); n < 32 {
		yBuf = append(yPadding[:32-n], yBuf...)
	}

	//s = 04||x||y
	buf = append(buf, 0x4)
	buf = append(buf, xBuf...)
	buf = append(buf, yBuf...)

	return buf
}

func pointFromBytes(buf []byte) (x, y *big.Int) {
	if len(buf) != 65 || buf[0] != 0x4 {
		return nil, nil
	}

	x = new(big.Int).SetBytes(buf[1:33])
	y = new(big.Int).SetBytes(buf[33:])

	return
}

func init() {
	c := sm2curve.P256()
	var i int64 = 2
	//var k int64 = 1
	//16777216,4096
	x := big.NewInt(0)
	x.Add(c.Params().Gx, x)
	y := big.NewInt(0)
	y.Add(c.Params().Gy, y)

	T1[c.Params().Gx.String()] = 1
	for ; i <= 16777216; i++ {
		fmt.Printf("%d\n", i)
		x, y = c.Add(x, y, c.Params().Gx, c.Params().Gy)
		T1[x.String()] = i
	}
	var j int64 = 0
	//t1lastx, t1lasty := c.ScalarMult(c.Gx, c.Gy, big.NewInt(4096).Bytes())
	t1lastx, t1lasty := c.ScalarMult(c.Params().Gx, c.Params().Gy, big.NewInt(16777216).Bytes())
	for ; j < 256; j++ {
		//fmt.Printf("%d\n", j)
		jbigint := big.NewInt(j)
		t2x, t2y := c.ScalarMult(t1lastx, t1lasty, jbigint.Bytes())
		inv_t2y := new(big.Int)
		inv_t2y.Add(c.Params().P, inv_t2y)
		//fmt.Println(c.Params().P)
		inv_t2y.Sub(inv_t2y, t2y)
		T2x[j] = t2x
		T2y[j] = inv_t2y
		//fmt.Println(T2x[j])
		//fmt.Println(T2y[j])
	}
}

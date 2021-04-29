package main

import (
	"bytes"
	"crypto/rand"

	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/salviati/cuckoo"
	"github.com/xlcetc/cryptogm/elliptic/sm9curve"
	"github.com/xlcetc/cryptogm/sm/sm2"
	"github.com/xlcetc/cryptogm/sm/sm9"

	paillier "github.com/roasbeef/go-go-gadget-paillier"
)

var ecctimeall time.Duration = 0
var eccenall time.Duration = 0
var eccdeall time.Duration = 0
var hsm2enall time.Duration = 0
var hsm2deall time.Duration = 0
var sm2enall time.Duration = 0
var sm2deall time.Duration = 0
var hsm9enall time.Duration = 0
var hsm9deall time.Duration = 0
var sm9enall time.Duration = 0
var sm9deall time.Duration = 0
var pailliertimeall time.Duration = 0
var paillierenall time.Duration = 0
var paillierdeall time.Duration = 0
var fieldadd time.Duration = 0
var pillieradd time.Duration = 0
var pilliermul time.Duration = 0
var sha256all time.Duration = 0
var ecchadd time.Duration = 0
var ecchmul time.Duration = 0
var sm2hadd time.Duration = 0
var sm2hmul time.Duration = 0
var sm9hadd time.Duration = 0
var sm9hmul time.Duration = 0

func testbtcecc(message *big.Int) {
	pubKeyBytes, err := hex.DecodeString("04115c42e757b2efb7671c578530ec191a1" +
		"359381e6a71127a9d37c486fd30dae57e76dc58f693bd7e7010358ce6b165e483a29" +
		"21010db67ac11b1b51b651953d2") // uncompressed pubkey
	if err != nil {
		fmt.Println(err)
		return
	}
	pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
	if err != nil {
		fmt.Println(err)
		return
	}
	// Decode the hex-encoded private key.
	pkBytes, _ := hex.DecodeString("a11b0a4e1a132305652ee7a8eb7848f6ad" +
		"5ea381e3ce20a2c086a2e388230811")
	// note that we already have corresponding pubKey
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), pkBytes)
	// Encrypt a message decryptable by the private key corresponding to pubKey
	//msg := "29"
	start1 := time.Now()
	c1x, c1y, c2x, c2y := btcec.Encrypt(pubKey, message.Bytes())
	cost1 := time.Since(start1)
	fmt.Printf("btcecc encrypt cost=[%s]\n", cost1)
	start2 := time.Now()
	// Try decrypting and verify if it's the same message.
	plaintext, err := btcec.Decrypt(privKey, c1x, c1y, c2x, c2y)
	cost2 := time.Since(start2)
	fmt.Printf("btcecc decrypt cost=[%s]\n", cost2)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("hecc Decryption Result : ", plaintext)
	cost3 := cost1 + cost2
	fmt.Printf("btcecc all cost=[%s]\n", cost3)
	eccenall = eccenall + cost1
	eccdeall = eccdeall + cost2
}

func testhbtcecc(message1 *big.Int, message2 *big.Int) {
	pubKeyBytes, err := hex.DecodeString("04115c42e757b2efb7671c578530ec191a1" +
		"359381e6a71127a9d37c486fd30dae57e76dc58f693bd7e7010358ce6b165e483a29" +
		"21010db67ac11b1b51b651953d2") // uncompressed pubkey
	if err != nil {
		fmt.Println(err)
		return
	}
	pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
	if err != nil {
		fmt.Println(err)
		return
	}
	// Decode the hex-encoded private key.
	pkBytes, _ := hex.DecodeString("a11b0a4e1a132305652ee7a8eb7848f6ad" +
		"5ea381e3ce20a2c086a2e388230811")
	// note that we already have corresponding pubKey
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), pkBytes)
	// Encrypt a message decryptable by the private key corresponding to pubKey
	//msg := "29"
	c := btcec.S256()
	start1 := time.Now()
	c1x1, c1y1, c2x1, c2y1 := btcec.Encrypt(pubKey, message1.Bytes())
	c1x2, c1y2, c2x2, c2y2 := btcec.Encrypt(pubKey, message2.Bytes())
	c1x, c1y := c.Add(c1x1, c1y1, c1x2, c1y2)
	c2x, c2y := c.Add(c2x1, c2y1, c2x2, c2y2)
	cost1 := time.Since(start1)
	fmt.Printf("btcecc encrypt cost=[%s]\n", cost1)
	start2 := time.Now()
	// Try decrypting and verify if it's the same message.
	plaintext, err := btcec.Decrypt(privKey, c1x, c1y, c2x, c2y)
	cost2 := time.Since(start2)
	fmt.Printf("btcecc decrypt cost=[%s]\n", cost2)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("hecc Decryption Result : ", plaintext)
	cost3 := cost1 + cost2
	fmt.Printf("btcecc all cost=[%s]\n", cost3)
	eccenall = eccenall + cost1
	eccdeall = eccdeall + cost2
}

func testecchadd(m1 *big.Int, m2 *big.Int) {
	pubKeyBytes, err := hex.DecodeString("04115c42e757b2efb7671c578530ec191a1" +
		"359381e6a71127a9d37c486fd30dae57e76dc58f693bd7e7010358ce6b165e483a29" +
		"21010db67ac11b1b51b651953d2") // uncompressed pubkey
	if err != nil {
		fmt.Println(err)
		return
	}
	pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
	if err != nil {
		fmt.Println(err)
		return
	}

	// Encrypt a message decryptable by the private key corresponding to pubKey
	//msg := "29"
	c := btcec.S256()
	c1x1, c1y1, c2x1, c2y1 := btcec.Encrypt(pubKey, m1.Bytes())
	c1x2, c1y2, c2x2, c2y2 := btcec.Encrypt(pubKey, m2.Bytes())
	start2 := time.Now()
	_, _ = c.Add(c1x1, c1y1, c1x2, c1y2)
	_, _ = c.Add(c2x1, c2y1, c2x2, c2y2)
	cost2 := time.Since(start2)
	ecchadd = ecchadd + cost2
}

func testecchmul(m1 *big.Int, p *big.Int) {
	pubKeyBytes, err := hex.DecodeString("04115c42e757b2efb7671c578530ec191a1" +
		"359381e6a71127a9d37c486fd30dae57e76dc58f693bd7e7010358ce6b165e483a29" +
		"21010db67ac11b1b51b651953d2") // uncompressed pubkey
	if err != nil {
		fmt.Println(err)
		return
	}
	pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
	if err != nil {
		fmt.Println(err)
		return
	}

	// Encrypt a message decryptable by the private key corresponding to pubKey
	//msg := "29"
	c := btcec.S256()
	c1x1, c1y1, c2x1, c2y1 := btcec.Encrypt(pubKey, m1.Bytes())
	start2 := time.Now()
	_, _ = c.ScalarMult(c1x1, c1y1, p.Bytes())
	_, _ = c.ScalarMult(c2x1, c2y1, p.Bytes())
	cost2 := time.Since(start2)
	ecchmul = ecchmul + cost2
}

func testsm2hadd(m1 *big.Int, m2 *big.Int) {
	sk, _ := sm2.GenerateKey(rand.Reader)
	pk := sk.PublicKey
	//fmt.Println(messages[0].String())
	//test encryption

	c1x, c1y, c2x, c2y := sm2.LgwHEnc(rand.Reader, &pk, m1)
	c1x2, c1y2, c2x2, c2y2 := sm2.LgwHEnc(rand.Reader, &pk, m1)
	start1 := time.Now()
	_, _ = pk.Curve.Add(c1x, c1y, c1x2, c1y2)
	_, _ = pk.Curve.Add(c2x, c2y, c2x2, c2y2)
	cost1 := time.Since(start1)
	sm2hadd = sm2hadd + cost1
}

func testsm2hmul(m1 *big.Int, p *big.Int) {
	sk, _ := sm2.GenerateKey(rand.Reader)
	pk := sk.PublicKey
	//fmt.Println(messages[0].String())
	//test encryption

	c1x, c1y, c2x, c2y := sm2.LgwHEnc(rand.Reader, &pk, m1)
	start1 := time.Now()
	_, _ = pk.Curve.ScalarMult(c1x, c1y, p.Bytes())
	_, _ = pk.Curve.ScalarMult(c2x, c2y, p.Bytes())
	cost1 := time.Since(start1)
	sm2hmul = sm2hmul + cost1
}

func testsm9hadd(m1 *big.Int, m2 *big.Int) {
	mk, _ := sm9.MasterKeyGen(rand.Reader)
	var hid byte = 1
	var uid = []byte("Alice")

	C1, C2 := sm9.LgwHEnc(m1, &mk.MasterPubKey, uid, hid)
	C3, C4 := sm9.LgwHEnc(m2, &mk.MasterPubKey, uid, hid)
	start1 := time.Now()
	_ = new(sm9curve.G2).Add(C1, C3)
	_ = new(sm9curve.GT).Add(C2, C4)
	cost1 := time.Since(start1)
	sm9hadd = sm9hadd + cost1
}

func testsm9hmul(m1 *big.Int, p *big.Int) {
	mk, _ := sm9.MasterKeyGen(rand.Reader)
	var hid byte = 1
	var uid = []byte("Alice")

	C1, C2 := sm9.LgwHEnc(m1, &mk.MasterPubKey, uid, hid)
	start1 := time.Now()
	_ = new(sm9curve.G2).ScalarMult(C1, p)
	_ = new(sm9curve.GT).ScalarMult(C2, p)
	cost1 := time.Since(start1)
	sm9hmul = sm9hmul + cost1
}

func testpaillier(m15 *big.Int) {
	privKey, _ := paillier.GenerateKey(rand.Reader, 3072)
	// Encrypt the number "15".
	start1 := time.Now()
	c15, _ := paillier.Encrypt(&privKey.PublicKey, m15.Bytes())
	cost1 := time.Since(start1)
	fmt.Printf("paillier encrypto cost=[%s]\n", cost1)
	start2 := time.Now()
	d, _ := paillier.Decrypt(privKey, c15)
	cost2 := time.Since(start2)
	fmt.Printf("paillier decrypto cost=[%s]\n", cost2)
	plainText := new(big.Int).SetBytes(d)
	fmt.Println("paillier Decryption Result : ", plainText.String())
	cost3 := cost1 + cost2
	fmt.Printf("paillier all cost=[%s]\n", cost3)
	paillierenall = paillierenall + cost1
	paillierdeall = paillierdeall + cost2
}

func testsomepaillier(m15 [1000]*big.Int) {
	privKey, _ := paillier.GenerateKey(rand.Reader, 3072)
	for i := 0; i < 1000; i++ {
		start1 := time.Now()
		c15, _ := paillier.Encrypt(&privKey.PublicKey, m15[i].Bytes())
		cost1 := time.Since(start1)
		fmt.Printf("paillier encrypto cost=[%s]\n", cost1)
		start2 := time.Now()
		d, _ := paillier.Decrypt(privKey, c15)
		cost2 := time.Since(start2)
		fmt.Printf("paillier decrypto cost=[%s]\n", cost2)
		plainText := new(big.Int).SetBytes(d)
		fmt.Println("paillier Decryption Result : ", plainText.String())
		cost3 := cost1 + cost2
		fmt.Printf("paillier all cost=[%s]\n", cost3)
		paillierenall = paillierenall + cost1
		paillierdeall = paillierdeall + cost2
	}
}
func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

var T = make(map[[8]byte]uint32)

var (
	//mbench map[Key]Value
	cbench *cuckoo.Cuckoo
)

func main() {

	msgmax := big.NewInt(4294967296)
	var messages [1000]*big.Int

	for i := 0; i < 1000; i++ {
		messages[i], _ = rand.Int(rand.Reader, msgmax)
	}
	/*
		testsomepaillier(messages)
		fmt.Printf("1000 times 32 bit paillier encrypto cost=[%s]\n", paillierenall)
		fmt.Printf("1000 times 32 bit paillier decrypto cost=[%s]\n", paillierdeall)
	*/

	/*
		sk, _ := sm2.GenerateKey(rand.Reader)
		pk := sk.PublicKey
		for i := 0; i < 1000; i++ {
			start1 := time.Now()
			cipher, _ := sm2.Encrypt(rand.Reader, &pk, []byte(messages[0].String()))
			cost1 := time.Since(start1)
			sm2enall = sm2enall + cost1
			fmt.Printf("standard sm2 encrypto cost=[%s]\n", cost1)
			//test decryption
			start2 := time.Now()
			plain, _ := sm2.Decrypt(cipher, sk)
			cost2 := time.Since(start2)
			sm2deall = sm2deall + cost2
			fmt.Printf("standard sm2 decrypto cost=[%s]\n", cost2)
			fmt.Println(string(plain))
		}
		fmt.Printf("1000 times 32 bit standard sm2 encrypto cost=[%s]\n", sm2enall)
		fmt.Printf("1000 times 32 bit standard sm2 decrypto cost=[%s]\n", sm2deall)
	*/

	/*
		sk, _ := sm2.GenerateKey(rand.Reader)
		pk := sk.PublicKey
		//fmt.Println(messages[0].String())
		//test encryption
		for i := 0; i < 1000; i++ {
			start1 := time.Now()
			c1x, c1y, c2x, c2y := sm2.LgwHEnc(rand.Reader, &pk, messages[i])
			cost1 := time.Since(start1)
			fmt.Printf("sm2 encrypto cost=[%s]\n", cost1)
			hsm2enall = hsm2enall + cost1
			//test decryption
			start2 := time.Now()
			plain, _ := sm2.LgwHDec(sk, c1x, c1y, c2x, c2y)
			cost2 := time.Since(start2)
			fmt.Printf("sm2 decrypto cost=[%s]\n", cost2)
			hsm2deall = hsm2deall + cost2
			fmt.Println(plain)
		}
		fmt.Printf("1000 times 32 bit homomorphic sm2 encrypto cost=[%s]\n", hsm2enall)
		fmt.Printf("1000 times 32 bit homomorphic sm2 decrypto cost=[%s]\n", hsm2deall)
	*/

	/*
		mk, _ := sm9.MasterKeyGen(rand.Reader)
		var hid byte = 1
		var uid = []byte("Alice")
		uk, _ := sm9.UserKeyGen(mk, uid, hid)
		for i := 0; i < 1000; i++ {
			start3 := time.Now()
			c1, c2 := sm9.LgwEnc([]byte(messages[i].String()), &mk.MasterPubKey, uid, hid)
			cost3 := time.Since(start3)
			sm9enall = sm9enall + cost3
			fmt.Printf("standard sm9 encrypto cost=[%s]\n", cost3)
			start4 := time.Now()
			m := sm9.LgwDec(c1, c2, uid, uk)
			cost4 := time.Since(start4)
			sm9deall = sm9deall + cost4
			fmt.Printf("standard sm9 decrypto cost=[%s]\n", cost4)
			fmt.Println(string(m))
		}
		fmt.Printf("1000 times 32 bit standard sm9 encrypto cost=[%s]\n", sm9enall)
		fmt.Printf("1000 times 32 bit standard sm9 decrypto cost=[%s]\n", sm9deall)
	*/

	/*
		for i := 0; i < 1000; i++ {
			start3 := time.Now()
			C1, C2 := sm9.LgwHEnc(messages[i], &sm9.Mk.MasterPubKey, sm9.Uid, sm9.Hid)
			cost3 := time.Since(start3)
			fmt.Printf("sm9 encrypto cost=[%s]\n", cost3)
			hsm9enall = hsm9enall + cost3
			start4 := time.Now()
			sm9plain := sm9.LgwHDec(C1, C2, sm9.Uk)
			cost4 := time.Since(start4)
			fmt.Printf("sm9 decrypto cost=[%s]\n", cost4)
			fmt.Println(sm9plain)
			hsm9deall = hsm9deall + cost4
			fmt.Println(sm9plain)
		}
		fmt.Printf("1000 times 32 bit homomorphic sm9 encrypto cost=[%s]\n", hsm9enall)
		fmt.Printf("1000 times 32 bit homomorphic sm9 decrypto cost=[%s]\n", hsm9deall)
	*/

	/*
		for i := 0; i < 1000; i++ {
			testbtcecc(messages[i])

		}
		fmt.Printf("1000 times 32 bit homomorphic elgamal encrypto cost=[%s]\n", eccenall)
		fmt.Printf("1000 times 32 bit homomorphic elgamal decrypto cost=[%s]\n", eccdeall)
	*/

	/*
		for i := 0; i < 1000; i++ {
			fmt.Println(i)
			testecchadd(messages[i], messages[999-i])
		}
		fmt.Printf("1000 times 32 bit homomorphic elgamal h-add cost=[%s]\n", ecchadd)
	*/

	/*
		for i := 0; i < 1000; i++ {
			fmt.Println(i)
			testecchmul(messages[i], messages[999-i])
		}
		fmt.Printf("1000 times 32 bit homomorphic elgamal h-mul cost=[%s]\n", ecchmul)
	*/

	/*
		for i := 0; i < 1000; i++ {
			fmt.Println(i)
			testsm2hadd(messages[i], messages[999-i])
		}
		fmt.Printf("1000 times 32 bit homomorphic sm2 h-add cost=[%s]\n", sm2hadd)
	*/

	/*
		for i := 0; i < 1000; i++ {
			fmt.Println(i)
			testsm2hmul(messages[i], messages[999-i])
		}
		fmt.Printf("1000 times 32 bit homomorphic sm2 h-mul cost=[%s]\n", sm2hmul)
	*/

	/*
		for i := 0; i < 1000; i++ {
			fmt.Println(i)
			testsm9hadd(messages[i], messages[999-i])
		}
		fmt.Printf("1000 times 32 bit homomorphic sm9 h-add cost=[%s]\n", sm9hadd)
	*/

	for i := 0; i < 1000; i++ {
		fmt.Println(i)
		testsm9hmul(messages[i], messages[999-i])
	}
	fmt.Printf("1000 times 32 bit homomorphic sm9 h-mul cost=[%s]\n", sm9hmul)
}

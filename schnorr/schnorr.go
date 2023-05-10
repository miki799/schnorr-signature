package schnorr

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type SignatureKey struct {
	p *big.Int // group order (large prime number)
	g *big.Int // generator
	x *big.Int // private key
}

type PublicKey struct {
	p *big.Int // group order (large prime number)
	g *big.Int // generator
	X *big.Int // public key, X = x * g
}

type Signature struct {
	R *big.Int // R = r * g
	s *big.Int // (r + H(R||m)x)modp
}

func (S Signature) String() string {
	return fmt.Sprintf("(r=%s, s=%s)", S.R, S.s)
}

/*
Generate signature key and public key of the signer.
*/
func GenerateKeys() (*SignatureKey, *PublicKey) {
	// prime number p (group order), generator g
	p, g := generateMultiplicativeGroup(256)

	// Generate random number x which belongs to generated group
	// it will be a private signing key
	x, err := rand.Int(rand.Reader, p)
	if err != nil {
		panic(err)
	}

	// public key, X = x * g
	X := new(big.Int).Mul(x, g)

	return &SignatureKey{p, g, x}, &PublicKey{p, g, X}
}

/*
Applies Schnorr signature to the given message
*/
func Sign(m string, sk *SignatureKey) *Signature {
	// Generate random number x which belongs to generated group
	r, err := rand.Int(rand.Reader, sk.p)
	if err != nil {
		panic(err)
	}

	// R = r * g
	R := new(big.Int).Mul(r, sk.g)

	// Apply SHA256 hasing function to R and m concatenation H(R||m)
	c := hash(R.String() + m)
	cInt := new(big.Int).SetBytes(c[:])

	// Create signature s = (r + cx)modp
	s := new(big.Int).Mul(cInt, sk.x)
	s.Add(r, s)
	s.Mod(s, sk.p)

	return &Signature{R, s}
}

/*
Use to verify signature correctness. Following condition needs to be checked:
sg = R + cX
where:
s - signature
g - group generator
R - r * g
c - H(R||m) - SHA256 checksum of R||m
X - public key
*/
func VerifySignature(message string, signature *Signature, publicKey *PublicKey) bool {
	/*
		left side
	*/
	sg := new(big.Int).Mul(signature.s, publicKey.g)
	sg.Mod(sg, publicKey.p)

	/*
		right side
	*/

	// Apply SHA256 hasing function to R and m concatenation H(R||m)
	c := hash(signature.R.String() + message)
	cInt := new(big.Int).SetBytes(c[:])

	cx := new(big.Int).Mul(cInt, publicKey.X)
	rcx := new(big.Int).Add(signature.R, cx)
	rcx.Mod(rcx, publicKey.p)

	// verify
	return sg.Cmp(rcx) == 0
}

/*
Shortened Blind Schnorr signature process

Step 1

	Signer generates R and sends it to the User

Step 2

	User generates a (alfa) and b (beta), which belongs to the generated group
	User calculates:
		R' = R + ag + bX
		c' = H(R'||m)
		c = (c' + b)modp
	User sends c to the Signer

Step 3

	Signer receives c from the User and sends back signature s = (r + cx)modp

Step 4

	User receives signature s from the Signer and checks this condition: sg == R + cX.
	If it is true, he can proceed with creating his own signature {R', s'}, where s' = (s + a)modp
*/
func BlindSignatureProcess(message string, signerSignatureKey *SignatureKey, publicKey *PublicKey) {
	fmt.Println("### Blind Schnorr Signature ###")

	/*
		Step 1
	*/

	r, err := rand.Int(rand.Reader, publicKey.p)
	if err != nil {
		panic(err)
	}
	R := new(big.Int).Mul(r, publicKey.g)

	/*
		Step 2
	*/

	a, err := rand.Int(rand.Reader, publicKey.p)
	if err != nil {
		panic(err)
	}

	b, err := rand.Int(rand.Reader, publicKey.p)
	if err != nil {
		panic(err)
	}

	// R' = R + ag + bX
	RP := new(big.Int).Add(R, new(big.Int).Mul(a, publicKey.g))
	RP.Add(RP, new(big.Int).Mul(b, publicKey.X))

	// c' = H(R'||m)
	cp := hash(RP.String() + message)
	cpInt := new(big.Int).SetBytes(cp[:])

	// c = (c' + b)modp
	c := new(big.Int).Add(cpInt, b)
	c.Mod(c, publicKey.p)

	/*
		Step 3
	*/

	// s = (r + cx)modp
	s := new(big.Int).Mul(c, signerSignatureKey.x)
	s.Add(s, r)
	s.Mod(s, signerSignatureKey.p)

	/*
		Step 4
	*/

	sg := new(big.Int).Mul(s, publicKey.g)
	sg.Mod(sg, publicKey.p)

	cx := new(big.Int).Mul(c, publicKey.X)
	rcx := new(big.Int).Add(R, cx)
	rcx.Mod(rcx, publicKey.p)

	// sg == R + cX
	if sg.Cmp(rcx) == 0 {
		fmt.Println("Signature received from Signer by User is valid!")
	} else {
		fmt.Println("Signature received from Signer by User is invalid!")
		return
	}

	// s' = (s + a)modp
	sp := new(big.Int).Add(s, a)
	sp.Mod(sp, publicKey.p)

	// User signature {R', s'}
	userSignature := &Signature{RP, sp}

	if VerifySignature(message, userSignature, publicKey) {
		fmt.Println("Signature created by User is valid!")
	} else {
		fmt.Println("Signature created by User is invalid!")
	}
}

/*
Return the SHA256 checksum of the given string
*/
func hash(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}

/*
Generate multipliactive group G of order p with generator g.
Definitely could be done better.
*/
func generateMultiplicativeGroup(bits int) (*big.Int, *big.Int) {
	// Generate random 256bit prime number p
	p, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		panic(err)
	}

	// Select group generator
	g := big.NewInt(2)
	for {
		if g.Exp(g, p, p).Cmp(g) == 0 {
			break
		}
		g.Add(g, big.NewInt(1))
	}

	return p, g
}

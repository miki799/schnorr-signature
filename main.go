package main

import (
	"fmt"

	"github.com/miki799/schnorr-signature/schnorr"
)

func main() {

	/*
		Schnorr signature
	*/

	fmt.Println("### Schnorr signature ###")

	message := "hello"
	fmt.Println("Message to sign: ", message)

	signatureKey, publicKey := schnorr.GenerateKeys()
	signature := schnorr.Sign(message, signatureKey)

	fmt.Println("Created signature:", signature.String())

	isSignatureValid := schnorr.VerifySignature(message, signature, publicKey)

	if isSignatureValid {
		fmt.Println("Signature is valid. Schnorr signature alghoritm is working!")
	} else {
		fmt.Println("Signature is invalid. Schnorr singature alghoritm is not working!")
		return
	}

	/*
		Schnorr blind signature
	*/

	schnorr.BlindSignatureProcess(message, signatureKey, publicKey)
}

package cryptogen

import (
	"fmt"
	"crypto/x509"
	"encoding/pem"
	"encoding/base64"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto"
	"io/ioutil"
	"os"
)

func LoadKeyFile(keyFile string) *rsa.PrivateKey {
	fileKey, err := ioutil.ReadFile(keyFile)
	if err != nil {
					fmt.Fprintf(os.Stderr, "Error from reading: %s\n", err)
	}

	pemBlock, rest := pem.Decode(fileKey)
	if rest != nil {
			fmt.Println(rest)
	}

	rsaKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
			fmt.Println(err)
	}

	return rsaKey
}

func LoadKeyFile2(keyFile string) *rsa.PublicKey {
	fileKey, err := ioutil.ReadFile(keyFile)
	if err != nil {
					fmt.Fprintf(os.Stderr, "Error from reading: %s\n", err)
	}

	pemBlock, rest := pem.Decode(fileKey)
	if rest != nil {
			fmt.Println(rest)
	}

	rsaKey, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
			fmt.Println(err)
	}

	return rsaKey
}



func SignMessage(message string, rsaKey *rsa.PrivateKey) string {

// ServerNonce + (CientNonce in base64)

	rng := rand.Reader
	hashed := sha256.Sum256([]byte(message))

	signature, err := rsa.SignPKCS1v15(rng, rsaKey, crypto.SHA256, hashed[:])

	if err != nil {
					fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
	}

	fmt.Printf("Signature: %x\n", signature)
	return string(signature)
}

func ClientNonce(size int) []byte {
	nonce := make([]byte, size)
	_, err := rand.Read(nonce)
	if err != nil {
					fmt.Fprintf(os.Stderr, "Error from nonce: %s\n", err)
	}
	return nonce
}

func EncodeB64(bytes []byte) string {
	b64encoding := base64.StdEncoding.EncodeToString(bytes)

	return b64encoding
}

func DecodeB64(str string) string {
	b64decoding, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		fmt.Println("decode error:", err)
	}	
	return string(b64decoding)
}
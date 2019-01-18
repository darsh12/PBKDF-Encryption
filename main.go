package main

import (
	"CSS577/functions"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

var HASHALGORITHM = sha256.New

//16=aes128; 24=aes192; 32=aes256
const KEYLENGTH = 32

func main() {
	//fmt.Print("hello world")
	_, encryptionKey, hmacKey := helper.Pbkdf([]byte("hey"), []byte("yeh"), 1000000, KEYLENGTH, HASHALGORITHM)

	//fmt.Printf("%x\n%x\n%x\n", masterKey, encryptionKey, hmacKey)

	plainText := "exampleplaintext"

	cipherText, hmacSum := helper.Encryption(plainText, encryptionKey, hmacKey, HASHALGORITHM)

	//Create a hmac block
	decryptHmacBlock := hmac.New(HASHALGORITHM, hmacKey)
	//Write the ciphertext to the block
	decryptHmacBlock.Write(cipherText)
	//Get the actual hmac hash
	decryptHmacExpcted := decryptHmacBlock.Sum(nil)

	//Check whether the received hmac and the calclated hmac are the same
	eq := hmac.Equal(hmacSum, decryptHmacExpcted)

	//If hmac is not the same panic and get out
	if !eq {
		panic("Houston, someone tampered with the message")
	}

	//Create a block for cipher text
	decryptBlock, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err)
	}

	//Check if cipher text is less than the block size
	if len(cipherText) < aes.BlockSize {
		panic("Ciphertext too short")
	}

	//Get the iv from the cipher text
	decryptIV := cipherText[:aes.BlockSize]

	//Get the actual cipher text
	decryptText := cipherText[aes.BlockSize:]

	//Check if the cipher text is a multiple of the block size
	if len(decryptText)%aes.BlockSize != 0 {
		panic("Decrypt text not a multiple")
	}

	//Get the cbc decryption mode
	decryptMode := cipher.NewCBCDecrypter(decryptBlock, decryptIV)
	//Decrypt the cipher text
	decryptMode.CryptBlocks(decryptText, decryptText)

	fmt.Printf("Decrypted Text:%s\n", decryptText)

	fmt.Printf("HMAC equal: %t\n", eq)

}

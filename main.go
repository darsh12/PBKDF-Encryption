package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
)

var HASHALGORITHM = sha256.New

//16=aes128; 24=aes192; 32=aes256
const KEYLENGTH = 32

func main() {
	//fmt.Print("hello world")
	masterKey := pbkdf2.Key([]byte("hey"), []byte("yeh"), 1000000, KEYLENGTH, HASHALGORITHM)

	encryptionKey := pbkdf2.Key(masterKey, []byte("encryption"), 1, KEYLENGTH, HASHALGORITHM)

	hmacKey := pbkdf2.Key(encryptionKey, []byte("hmac"), 1, KEYLENGTH, HASHALGORITHM)

	//fmt.Printf("%x\n%x\n%x\n", masterKey, encryptionKey, hmacKey)

	plainText := []byte("exampleplaintext")

	//Assume the plainText is a multiple if a block size
	if len(plainText)%aes.BlockSize != 0 {
		panic("Not a multiple")
	}

	//Create a new block
	block, err := aes.NewCipher(encryptionKey)

	if err != nil {
		panic(err)
	}

	//Create a random iv and attach it at the start of the cipherText

	cipherText := make([]byte, aes.BlockSize+len(plainText))

	//Create a byte array of the block size
	iv := cipherText[:aes.BlockSize]

	//Use the readfull func to copy exact bytes to the buffer
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	//Use the cbc mode, and start appending the encryptedtext at the end of cipherText
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	//Create a new hmac block
	hmacBlock := hmac.New(HASHALGORITHM, hmacKey)
	//Write data to the block
	hmacBlock.Write(cipherText)

	//Get the actual hash of the cipherText
	hmacSum := hmacBlock.Sum(nil)

	fmt.Printf("Cipher Text: %x\n", cipherText)
	fmt.Printf("HMAC Hash: %x\n", hmacSum)

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

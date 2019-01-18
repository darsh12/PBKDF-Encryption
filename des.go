package main

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
)

func main() {
	masterKey := pbkdf2.Key([]byte("hey"), []byte("yeh"), 1000000, 32, sha256.New)

	encryptionKey := pbkdf2.Key(masterKey, []byte("encryption"), 1, 24, sha256.New)

	hmacKey := pbkdf2.Key(encryptionKey, []byte("hmac"), 1, 32, sha256.New)

	fmt.Printf(" Master Key: %x\n Encryption Key: %x\n HMAC Key: %x\n", masterKey, encryptionKey, hmacKey)

	plainText := []byte("exampleplaintext")

	//Assume the plainText is a multiple if a block size
	if len(plainText)%des.BlockSize != 0 {
		panic("Not a multiple")
	}

	//Create a new block
	block, err := des.NewTripleDESCipher(encryptionKey)

	if err != nil {
		panic(err)
	}

	//Create a random iv and attach it at the start of the cipherText

	cipherText := make([]byte, des.BlockSize+len(plainText))

	//Create a byte array of the block size
	iv := cipherText[:des.BlockSize]

	//Use the readfull func to copy exact bytes to the buffer
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	//Use the cbc mode, and start appending the encryptedtext at the end of cipherText
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[des.BlockSize:], plainText)

	fmt.Printf(" IV: %x\n", iv)
	fmt.Printf(" Cipher Text: %x\n", cipherText)

	decryptBlock, err := des.NewTripleDESCipher(encryptionKey)
	if err != nil {
		panic(err)
	}

	if len(cipherText) < des.BlockSize {
		panic("Ciphertext too short")
	}

	decryptIV := cipherText[:des.BlockSize]
	decryptText := cipherText[des.BlockSize:]

	if len(decryptText)%des.BlockSize != 0 {
		panic("Decrypt text not a multiple")
	}

	decryptMode := cipher.NewCBCDecrypter(decryptBlock, decryptIV)
	decryptMode.CryptBlocks(decryptText, decryptText)

	fmt.Printf("Decrypted Text:%s\n", decryptText)

}

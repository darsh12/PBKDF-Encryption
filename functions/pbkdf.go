package helper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"io"
)

func Pbkdf(password []byte, salt []byte, iter int, keyLen int, hashType func() hash.Hash) (masterKey []byte, encryptionKey []byte, hmacKey []byte) {

	masterKey = pbkdf2.Key(password, salt, iter, keyLen, hashType)
	encryptionKey = pbkdf2.Key(masterKey, salt, 1, keyLen, hashType)
	hmacKey = pbkdf2.Key(masterKey, salt, 1, keyLen, hashType)

	return masterKey, encryptionKey, hmacKey
}

func Encryption(plainText string, encryptionKey []byte, hmacKey []byte, hashType func() hash.Hash) (cipherText []byte, hmacSum []byte) {
	text := []byte(plainText)

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

	cipherText = make([]byte, aes.BlockSize+len(plainText))

	//Create a byte array of the block size
	iv := cipherText[:aes.BlockSize]

	//Use the readfull func to copy exact bytes to the buffer
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	//Use the cbc mode, and start appending the encryptedtext at the end of cipherText
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], text)

	//Create a new hmac block
	hmacBlock := hmac.New(hashType, hmacKey)
	//Write data to the block
	hmacBlock.Write(cipherText)

	//Get the actual hash of the cipherText
	hmacSum = hmacBlock.Sum(nil)

	return cipherText, hmacSum

}

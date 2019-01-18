package helper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"io"
)

func Pbkdf(password []byte, salt []byte, iter int, keyLen int, hashType func() hash.Hash) (masterKey []byte, encryptionKey []byte, hmacKey []byte) {

	masterKey = pbkdf2.Key(password, salt, iter, keyLen, hashType)
	encryptionKey = pbkdf2.Key(masterKey, []byte("Salt1"), 1, keyLen, hashType)
	hmacKey = pbkdf2.Key(masterKey, []byte("Salt2"), 1, keyLen, hashType)

	return masterKey, encryptionKey, hmacKey
}

func Encryption(plainText []byte, encryptionKey []byte, hmacKey []byte, hashType func() hash.Hash) (cipherText []byte, hmacSum []byte, err error) {

	//Assume the plainText is a multiple if a block size
	//TODO: Pad the plaintext
	if len(plainText)%aes.BlockSize != 0 {
		panic("Not a multiple")
	}

	//Create a new block
	block, err := aes.NewCipher(encryptionKey)

	if err != nil {
		err = errors.New("error generation encryption block")
	}

	//Create a random iv and attach it at the start of the cipherText

	cipherText = make([]byte, aes.BlockSize+len(plainText))

	//Create a byte array of the block size
	iv := cipherText[:aes.BlockSize]

	//Use the readfull func to copy exact bytes to the buffer
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		err = errors.New("error generation a random IV")
	}
	//Use the cbc mode, and start appending the encrypted text at the end of cipherText
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	//Create a new hmac block
	hmacBlock := hmac.New(hashType, hmacKey)
	//Write data to the block
	hmacBlock.Write(cipherText)

	//Get the actual hash of the cipherText
	hmacSum = hmacBlock.Sum(nil)

	return cipherText, hmacSum, err

}

func Decryption(cipherText string, encryptionKey []byte, hmacKey []byte, hashType func() hash.Hash, hmacSum string) (plainText []byte, hmacEqual bool, err error) {

	//Decode the cipher text and hmacSum
	decodeCipherText, _ := hex.DecodeString(cipherText)
	decodeHmacSum, _ := hex.DecodeString(hmacSum)
	//Create a new hmac block
	hmacBlock := hmac.New(hashType, hmacKey)

	//Write to hmac block
	hmacBlock.Write(decodeCipherText)

	//Get the hash
	hmacCalculated := hmacBlock.Sum(nil)

	//Check if the hmac's are equal
	hmacEqual = hmac.Equal(hmacCalculated, decodeHmacSum)

	//If the hmac are not equal throw an error
	if !hmacEqual {
		err = errors.New("HMAC could not be verified")
	}

	//Create a block
	block, err := aes.NewCipher(encryptionKey)

	if err != nil {
		err = errors.New("error generating decryption block")
	}

	//Check if the cipher text is less than the block size
	if len(cipherText) < aes.BlockSize {
		err = errors.New("cipher text too short")

	}

	//Get the iv from the cipher text
	iv := decodeCipherText[:aes.BlockSize]

	//Get the actual cipher text
	plainText = decodeCipherText[aes.BlockSize:]

	//Check if the cipher text is a multiple of the block size
	//TODO: Unpad the cipher text
	if len(plainText)%aes.BlockSize != 0 {
		err = errors.New("decrypt text is not a multiple of block")
	}

	//Get the cbc decryption mode
	mode := cipher.NewCBCDecrypter(block, iv)

	//Decrypt the cipher text
	mode.CryptBlocks(plainText, plainText)

	return plainText, hmacEqual, err
}

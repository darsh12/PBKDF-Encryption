package helper

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
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

	// Pad the plaintext
	paddedText := Pad(plainText)

	//Create a new block
	block, err := aes.NewCipher(encryptionKey)

	if err != nil {
		err = errors.New("error generation encryption block")
	}

	//Create a random iv and attach it at the start of the cipherText

	cipherText = make([]byte, aes.BlockSize+len(paddedText))

	//Create a byte array of the block size
	iv := cipherText[:aes.BlockSize]

	//Use the readfull func to copy exact bytes to the buffer
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		err = errors.New("error generation a random IV")
	}
	//Use the cbc mode, and start appending the encrypted text at the end of cipherText
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], paddedText)

	//Create a new hmac block
	hmacBlock := hmac.New(hashType, hmacKey)
	//Write data to the block
	hmacBlock.Write(cipherText)

	//Get the actual hash of the cipherText
	hmacSum = hmacBlock.Sum(nil)

	return cipherText, hmacSum, err

}

func Decryption(cipherText []byte, encryptionKey []byte, hmacKey []byte, hashType func() hash.Hash, hmacSum []byte) (plainText []byte, hmacEqual bool, err error) {

	//Create a new hmac block
	hmacBlock := hmac.New(hashType, hmacKey)

	//Write to hmac block
	hmacBlock.Write(cipherText)

	//Get the hash
	hmacCalculated := hmacBlock.Sum(nil)

	//Check if the hmac's are equal
	hmacEqual = hmac.Equal(hmacCalculated, hmacSum)

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
	iv := cipherText[:aes.BlockSize]

	//Get the actual cipher text
	plainText = cipherText[aes.BlockSize:]

	//Get the cbc decryption mode
	mode := cipher.NewCBCDecrypter(block, iv)

	//Decrypt the cipher text
	mode.CryptBlocks(plainText, plainText)

	//Unpad the plain text
	unpadText, err := Unpad(plainText)
	if err != nil {
		err = errors.New("unable to unpad plain text")
	}

	return unpadText, hmacEqual, err
}

//Code snippet from https://gist.github.com/stupidbodo/601b68bfef3449d1b8d9
func Pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func Unpad(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length {
		return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
	}

	return src[:(length - unpadding)], nil
}

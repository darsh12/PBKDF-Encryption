package helper

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"github.com/pkg/xattr"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"io"
	"io/ioutil"
	"os"
)

func Pbkdf(password []byte, salt []byte, iter int, keyLen int, hashType func() hash.Hash) (masterKey []byte, encryptionKey []byte, hmacKey []byte) {

	masterKey = pbkdf2.Key(password, salt, iter, keyLen, hashType)
	encryptionKey = pbkdf2.Key(masterKey, []byte("Salt1"), 1, keyLen, hashType)
	hmacKey = pbkdf2.Key(masterKey, []byte("Salt2"), 1, keyLen, hashType)

	return masterKey, encryptionKey, hmacKey
}

func Encryption(password string, plainText string, hashAlgorithm string, blockType string, keyLength int) (err error) {

	//Initialise variables
	var block cipher.Block
	var blockSize int
	salt := make([]byte, 32)

	//Generate a random salt value
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		CheckError(err)
	}

	//Default to sha256
	hashType := sha256.New

	//If specified used sha512
	if hashAlgorithm == "sha512" {
		hashType = sha512.New
	}

	//Generate the keys from the password
	_, encryptionKey, hmacKey := Pbkdf([]byte(password), salt, 5000000, keyLength, hashType)

	// Pad the plaintext
	paddedText := Pad([]byte(plainText))

	// assign appropriate block and blocksize depending on the encryption type
	if (blockType == "aes128") || blockType == "aes256" {
		block, err = aes.NewCipher(encryptionKey)
		blockSize = aes.BlockSize
		CheckError(err)

	} else if blockType == "3des" {
		block, err = des.NewTripleDESCipher(encryptionKey)
		blockSize = des.BlockSize
		CheckError(err)
	} else {
		err = errors.New("invalid encryption choice")
		CheckError(err)
	}

	//Create a random iv and attach it at the start of the cipherText

	cipherText := make([]byte, blockSize+len(paddedText))

	//Create a byte array of the block size
	iv := cipherText[:blockSize]

	//Use the readfull func to copy exact bytes to the buffer
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		CheckError(err)
	}
	//Use the cbc mode, and start appending the encrypted text at the end of cipherText
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[blockSize:], paddedText)

	//Create a new hmac block
	hmacBlock := hmac.New(hashType, hmacKey)
	//Write data to the block
	hmacBlock.Write(cipherText)

	//Get the actual hashAlgorithm of the cipherText
	hmacSum := hmacBlock.Sum(nil)

	/*
		WRITE CIPHER TEXT AND ACCOMPANYING XATTR TO FILE
	*/

	//Create a new file
	f, err := os.Create("encrypted.aes")

	CheckError(err)

	//Write cipher text to file. We dont care about the total bytes written
	_, err = f.Write(cipherText)

	CheckError(err)

	//Write the xattr (metadata) to the file
	err = xattr.FSet(f, "HMAC", hmacSum)
	CheckError(err)

	err = xattr.FSet(f, "HASH", []byte(hashAlgorithm))
	CheckError(err)

	err = xattr.FSet(f, "ALGORITHM", []byte(blockType))
	CheckError(err)

	err = xattr.FSet(f, "SALT", salt)
	CheckError(err)

	return err

}

func Decryption(name string, password string) (text string, err error) {

	var keyLength int

	//Read the file contents
	cipherText, err := ioutil.ReadFile(name)
	CheckError(err)

	//Open the file to get the xattr
	f, err := os.Open(name)
	CheckError(err)

	// Read the xattr from the file
	hmacSum, err := xattr.FGet(f, "HMAC")
	CheckError(err)

	hashAlgorithm, err := xattr.FGet(f, "HASH")
	CheckError(err)

	blockType, err := xattr.FGet(f, "ALGORITHM")
	CheckError(err)

	salt, err := xattr.FGet(f, "SALT")
	CheckError(err)

	//Default to sha256
	hashType := sha256.New

	//If specified used sha512
	if string(hashAlgorithm) == "sha512" {
		hashType = sha512.New
	}

	// assign appropriate keylength depending on encryption algorithm
	if string(blockType) == "aes128" {
		keyLength = 16
	} else if string(blockType) == "aes256" {
		keyLength = 32
	} else if string(blockType) == "3des" {
		keyLength = 24

	}

	//Generate the keys from the password
	_, encryptionKey, hmacKey := Pbkdf([]byte(password), salt, 5000000, keyLength, hashType)

	//Initialise variables
	var block cipher.Block
	var blockSize int

	// assign appropriate block and blocksize depending on the encryption type
	if (string(blockType) == "aes128") || string(blockType) == "aes256" {
		block, err = aes.NewCipher(encryptionKey)
		blockSize = aes.BlockSize
		CheckError(err)

	} else if string(blockType) == "3des" {
		block, err = des.NewTripleDESCipher(encryptionKey)
		blockSize = des.BlockSize
		CheckError(err)
	} else {
		err = errors.New("invalid encryption choice")
		CheckError(err)
	}

	//Create a new hmac block
	hmacBlock := hmac.New(hashType, hmacKey)

	//Write to hmac block
	hmacBlock.Write(cipherText)

	//Get the hash
	hmacCalculated := hmacBlock.Sum(nil)

	//Check if the hmac's are equal
	hmacEqual := hmac.Equal(hmacCalculated, hmacSum)

	//If the hmac are not equal throw an error
	if !hmacEqual {
		err = errors.New("HMAC could not be verified")
		CheckError(err)
	}

	//Check if the cipher text is less than the block size
	if len(cipherText) < blockSize {
		CheckError(err)
	}

	//Get the iv from the cipher text
	iv := cipherText[:blockSize]

	//Get the actual cipher text
	plainText := cipherText[blockSize:]

	//Get the cbc decryption mode
	mode := cipher.NewCBCDecrypter(block, iv)

	//Decrypt the cipher text
	mode.CryptBlocks(plainText, plainText)

	//Unpad the plain text
	unpadText, err := Unpad(plainText)
	CheckError(err)

	return string(unpadText), err
}

//Function to check errors
func CheckError(err error) {
	if err != nil {
		//log.Fatal(err)
		panic(err)
	}
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

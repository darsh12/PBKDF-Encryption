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
	"fmt"
	"github.com/pkg/xattr"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"os"
)

//Struct to store the different types of keys
type PbkdfKeys struct {
	masterKey     []byte
	encryptionKey []byte
	hmacKey       []byte
}

//Struct to store parameters that help in encryption and decryption
type Parameters struct {
	encryptionBlock     cipher.Block
	encryptionBlockSize int
	hashAlgorithm       func() hash.Hash
}

//Struct to store values to be written in metadata during the encryption process
type Metadata struct {
	hash      []byte
	algorithm []byte
}

//This function will create three keys, store the keys in the PbkdfKeys struct and return the struct
func Pbkdf(password []byte, salt []byte, iter int, keyLen int, hashType func() hash.Hash) (key PbkdfKeys) {

	key.masterKey = pbkdf2.Key(password, salt, iter, keyLen, hashType)
	key.encryptionKey = pbkdf2.Key(key.masterKey, []byte("Salt1"), 1, keyLen, hashType)
	key.hmacKey = pbkdf2.Key(key.masterKey, []byte("Salt2"), 1, keyLen, hashType)

	return key
}

/*
This function will take in a password, plain text, the type of encryption and hash algorithm that will be used, from the user.
It will then encrypt and the cipher text along with the metadata.
It will return an error if there are any.
*/
func Encryption(password string, plainText string, cli Parameters, meta Metadata) (err error) {

	//Initialise variable
	salt := make([]byte, 32)

	//Initialise struct
	var key PbkdfKeys

	//Generate a random salt value
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		CheckError(err)
	}

	//Generate the keys from the password
	key = Pbkdf([]byte(password), salt, 5000000, cli.encryptionBlockSize, cli.hashAlgorithm)

	// Pad the plaintext
	paddedText := Pad([]byte(plainText), string(meta.algorithm))

	// assign appropriate block and blocksize depending on the encryption type
	if (string(meta.algorithm) == "aes128") || (string(meta.algorithm) == "aes256") {
		cli.encryptionBlock, err = aes.NewCipher(key.encryptionKey)
		cli.encryptionBlockSize = aes.BlockSize
		CheckError(err)

	} else if string(meta.algorithm) == "3des" {
		cli.encryptionBlock, err = des.NewTripleDESCipher(key.encryptionKey)
		cli.encryptionBlockSize = des.BlockSize
		CheckError(err)
	} else {
		err = errors.New("invalid encryption choice")
		CheckError(err)
	}

	//Create a byte array of the length of the block size + length of the text
	cipherText := make([]byte, cli.encryptionBlockSize+len(paddedText))

	//Create a random iv and attach it at the start of the cipherText
	//Create a byte array of the block size
	iv := cipherText[:cli.encryptionBlockSize]

	//Use the readfull func to copy exact bytes to the buffer
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		CheckError(err)
	}
	//Use the cbc mode, and start appending the encrypted text at the end of cipherText
	mode := cipher.NewCBCEncrypter(cli.encryptionBlock, iv)
	mode.CryptBlocks(cipherText[cli.encryptionBlockSize:], paddedText)

	//Create a new hmac block
	hmacBlock := hmac.New(cli.hashAlgorithm, key.hmacKey)
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

	err = xattr.FSet(f, "HASH", meta.hash)
	CheckError(err)

	err = xattr.FSet(f, "ALGORITHM", meta.algorithm)
	CheckError(err)

	err = xattr.FSet(f, "SALT", salt)
	CheckError(err)

	fmt.Println("Cipher text written to encrypted.aes")
	return err

}

/*
This function will take in the encrypted file path and the password from the user.
The rest of the parameters required for decryptio, will be extracted from the metadata, written during the encryption process
It will return the plaintext if successful, else return an error if something goes wrong.
*/
func Decryption(file string, password string) (text string, err error) {

	//Initialise structs
	var par Parameters
	var key PbkdfKeys

	//Read the file contents
	cipherText, err := ioutil.ReadFile(file)
	CheckError(err)

	//Open the file to get the xattr
	f, err := os.Open(file)
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

	//Figure out which hash algorithm was used
	if string(hashAlgorithm) == "sha256" {
		par.hashAlgorithm = sha256.New
	} else if string(hashAlgorithm) == "sha512" {
		par.hashAlgorithm = sha512.New
	} else {
		err = errors.New("invalid hash algorithm")
		CheckError(err)
	}

	// assign appropriate key length depending on encryption algorithm
	if string(blockType) == "aes128" {
		par.encryptionBlockSize = 16
	} else if string(blockType) == "aes256" {
		par.encryptionBlockSize = 32
	} else if string(blockType) == "3des" {
		par.encryptionBlockSize = 24
	} else {
		err = errors.New("invalid hash algorithm")
		CheckError(err)
	}

	//Generate the keys from the password
	key = Pbkdf([]byte(password), salt, 5000000, par.encryptionBlockSize, par.hashAlgorithm)

	// assign appropriate block and blocksize depending on the encryption type
	if (string(blockType) == "aes128") || string(blockType) == "aes256" {
		par.encryptionBlock, err = aes.NewCipher(key.encryptionKey)
		par.encryptionBlockSize = aes.BlockSize
		CheckError(err)

	} else if string(blockType) == "3des" {
		par.encryptionBlock, err = des.NewTripleDESCipher(key.encryptionKey)
		par.encryptionBlockSize = des.BlockSize
		CheckError(err)
	} else {
		err = errors.New("invalid encryption choice")
		CheckError(err)
	}

	//Create a new hmac block
	hmacBlock := hmac.New(par.hashAlgorithm, key.hmacKey)

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
	if len(cipherText) < par.encryptionBlockSize {
		CheckError(err)
	}

	//Get the iv from the cipher text
	iv := cipherText[:par.encryptionBlockSize]

	//Get the actual cipher text
	plainText := cipherText[par.encryptionBlockSize:]

	//Get the cbc decryption mode
	mode := cipher.NewCBCDecrypter(par.encryptionBlock, iv)

	//Decrypt the cipher text
	mode.CryptBlocks(plainText, plainText)

	//Unpad the plain text
	unpadText, err := Unpad(plainText)
	CheckError(err)

	return string(unpadText), err
}

//Function to check errors, to prevent a lot if statements in-code
func CheckError(err error) {
	if err != nil {
		log.Fatal(err)
		//panic(err)
	}
}

//Function to pad the data and figure out the block size by repeating the bytes
func Pad(src []byte, algorithm string) []byte {
	var padding int

	if (algorithm == "aes128") || algorithm == "aes256" {
		padding = aes.BlockSize - len(src)%aes.BlockSize
	} else if algorithm == "3des" {
		padding = des.BlockSize - len(src)%des.BlockSize
	} else {
		err := errors.New("invalid encryption choice")
		CheckError(err)
	}

	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

//Function to unpad the data
func Unpad(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length {
		return nil, errors.New("un-padding error. ")
	}

	return src[:(length - unpadding)], nil
}

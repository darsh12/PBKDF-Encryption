package main

import (
	"CSS577/functions"
	"crypto/sha512"
)

var HASHALGORITHM = sha512.New

//16=aes128; 24=aes192; 32=aes256
const KEYLENGTH = 16

func main() {
	_, encryptionKey, hmacKey := helper.Pbkdf([]byte("password"), []byte("salt"), 1, KEYLENGTH, HASHALGORITHM)

	text := []byte("1111111111111111")

	cipherText, hmacSum, err := helper.Encryption(text, encryptionKey, hmacKey, HASHALGORITHM)

	if err != nil {
		panic(err)
	}

	//fmt.Printf("cipher: %x\n"+
	//	"encryption: %x\n"+
	//	"hmac: %x\n"+
	//	"sum: %x\n",
	//	cipherText, encryptionKey, hmacKey, hmacSum)

	err = helper.WriteToFile("test.aes", cipherText, hmacSum, []byte("sha512"), []byte("aes128"))

	if err != nil {
		panic(err)
	}

	//plainText, equal, err := helper.Decryption(
	//	"dd22148d908d84e069a647ed9a231155cc33b5ea38d255203fc911c69d992958",
	//	encryptionKey,
	//	hmacKey,
	//	HASHALGORITHM,
	//	"7f95fc765db4ade42f744dd1fd0c6d34d7952845d9d5f9042f62fda304c6bbd1")
	//
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Printf("Plain Text: %s\n HMAC eqaul: %t\n", plainText, equal)
}

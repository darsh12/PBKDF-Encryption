package main

import (
	"CSS577/functions"
	"bufio"
	"crypto/sha512"
	"fmt"
	"os"
)

var HASHALGORITHM = sha512.New

//16=aes128; 24=aes192; 32=aes256
const KEYLENGTH = 16

func main() {

	//Create a reader object
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter your password: ")

	//Get the password from the user
	password, err := reader.ReadString('\n')

	if err != nil {
		panic(err)
	}

	//Get user text encrypt
	fmt.Print("Input your string: ")
	inputText, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}

	//Calculate the keys based on the password
	_, encryptionKey, hmacKey := helper.Pbkdf([]byte(password), []byte("salt"), 5, KEYLENGTH, HASHALGORITHM)

	//Encrpyt the text
	cipherText, hmacSum, err := helper.Encryption([]byte(inputText), encryptionKey, hmacKey, HASHALGORITHM)

	if err != nil {
		panic(err)
	}

	//Write the encrypted text to the file
	err = helper.WriteToFile("test.aes", cipherText, hmacSum, []byte("sha512"), []byte("aes128"))

	if err != nil {
		panic(err)
	}

	//Read cipher text from the file
	cipherTextDec, hmacSumDec, _, _, err := helper.ReadFromFile("test.aes")

	if err != nil {
		panic(err)
	}

	//Decrypt the cipher text
	plainTextDecrypted, hmacDecrypted, err := helper.Decryption(cipherTextDec, encryptionKey, hmacKey, HASHALGORITHM, hmacSumDec)
	fmt.Printf("%s%t", plainTextDecrypted, hmacDecrypted)

}

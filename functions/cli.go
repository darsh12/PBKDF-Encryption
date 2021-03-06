package helper

import (
	"bufio"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"os"
)

//Function to create a user option interface for encryption purposes
func Ui() (encryption Parameters, meta Metadata) {

	in := bufio.NewScanner(os.Stdin)

	var encryptionType, hashType string

	fmt.Println("Choose Encryption Algorithm: ")
	fmt.Print("1: AES128, 2: AES256, 3: 3DES: ")

	//Read encryption algorithm
	in.Scan()
	encryptionType = in.Text()

	switch encryptionType {
	case "1":
		encryption.encryptionKeyLength = 16
		meta.algorithm = "aes128"
		break
	case "2":
		encryption.encryptionKeyLength = 32
		meta.algorithm = "aes256"
		break
	case "3":
		encryption.encryptionKeyLength = 24
		meta.algorithm = "3des"
	default:
		fmt.Println("Invalid choice")
		os.Exit(1)
	}

	fmt.Println("Choose Hash Algorithm: ")
	fmt.Print("1: SHA256, 2: SHA512: ")

	//Read hash algorithm
	in.Scan()
	hashType = in.Text()

	switch hashType {
	case "1":
		meta.hash = "sha256"
		encryption.hashAlgorithm = sha256.New
		break
	case "2":
		meta.hash = "sha512"
		encryption.hashAlgorithm = sha512.New
		break
	default:
		fmt.Println("Invalid choice")
		os.Exit(1)

	}

	return encryption, meta
}

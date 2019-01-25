package helper

import (
	"bufio"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"log"
	"os"
	"strings"
)

//Function to create a user option interface for encryption purposes
func Ui() (encryption Parameters, meta Metadata) {

	in := bufio.NewScanner(os.Stdin)

	var encryptionType, hashType string

	fmt.Println("Choose Encryption Algorithm: ")
	fmt.Println("1: AES128, 2: AES256, 3: 3DES")

	//Read encryption algorithm
	in.Scan()
	encryptionType = in.Text()

	switch encryptionType {
	case "1":
		encryption.encrpytionBlockSize = 16
		meta.algorithm = []byte("aes128")
		break
	case "2":
		encryption.encrpytionBlockSize = 32
		meta.algorithm = []byte("aes256")
		break
	case "3":
		encryption.encrpytionBlockSize = 24
		meta.algorithm = []byte("3des")
	default:
		fmt.Println("Invalid choice")
		os.Exit(1)
	}

	fmt.Println("Choose Hash Algorithm: ")
	fmt.Println("1: SHA256, 2: SHA512")

	//Read hash algorithm
	in.Scan()
	hashType = in.Text()

	switch hashType {
	case "1":
		meta.hash = []byte("sha256")
		encryption.hashAlgorithm = sha256.New
		break
	case "2":
		meta.hash = []byte("sha512")
		encryption.hashAlgorithm = sha512.New
		break
	default:
		fmt.Println("Invalid choice")
		os.Exit(1)

	}

	return encryption, meta
}

func CheckEmptyString(str string) {
	if strings.TrimSpace(str) == "" {
		log.Fatal("empty input")
		os.Exit(1)
	}
}

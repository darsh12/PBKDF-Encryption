package helper

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

//Function to create a user option interface for encryption purposes
func Ui() (b string, h string, k int) {

	in := bufio.NewScanner(os.Stdin)

	var encryptionType, blockType, hashType string
	var keyLength int

	fmt.Println("Choose Encryption Algorithm: ")
	fmt.Println("1: AES128, 2: AES256, 3: 3DES")

	//Read encryption algorithm
	in.Scan()
	encryptionType = in.Text()

	switch encryptionType {
	case "1":
		keyLength = 16
		blockType = "aes128"
		break
	case "2":
		keyLength = 32
		blockType = "aes256"
		break
	case "3":
		keyLength = 24
		blockType = "3des"
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
		hashType = "sha256"
		break
	case "2":
		hashType = "sha512"
		break
	default:
		fmt.Println("Invalid choice")
		os.Exit(1)

	}

	return blockType, hashType, keyLength
}

func CheckEmptyString(str string) {
	if strings.TrimSpace(str) == "" {
		log.Fatal("empty input")
		os.Exit(1)
	}
}

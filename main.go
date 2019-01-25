package main

import (
	"CSS577/functions"
	"bufio"
	"fmt"
	"os"
)

func main() {

	var executionType string

	in := bufio.NewScanner(os.Stdin)

	fmt.Print("1: Encryption, 2: Decryption: ")
	//Read executionType input
	in.Scan()
	executionType = in.Text()

	switch executionType {

	//ENCRYPTION OPTION
	case "1":
		var password, inputText string

		//Initialise structs
		var enc helper.Parameters
		var meta helper.Metadata

		fmt.Println("Enter Text:")
		//Read user input
		in.Scan()
		inputText = in.Text()

		//Check if input is empty
		helper.CheckEmptyString(inputText)

		fmt.Print("Enter your password: ")
		in.Scan()
		password = in.Text()

		helper.CheckEmptyString(password)

		//
		enc, meta = helper.Ui()
		err := helper.Encryption(password, inputText, enc, meta)
		helper.CheckError(err)

		break

		//DECRYPTION OPTION
	case "2":
		var file, password string

		fmt.Print("Enter full path of file: ")
		in.Scan()
		file = in.Text()

		helper.CheckEmptyString(file)

		fmt.Print("Enter the password: ")
		in.Scan()
		password = in.Text()

		helper.CheckEmptyString(password)

		plainText, err := helper.Decryption(file, password)
		helper.CheckError(err)
		fmt.Printf("The decrypted text is: \n%s\n", plainText)

		break
	default:
		fmt.Println("Invalid choice")
		os.Exit(1)
	}

}

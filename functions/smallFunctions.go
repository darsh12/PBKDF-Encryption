package helper

import (
	"bytes"
	"crypto/aes"
	"crypto/des"
	"encoding/base64"
	"errors"
	"log"
	"os"
	"strings"
)

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

func encodeBase64(input []byte) string {
	return base64.StdEncoding.EncodeToString(input)
}

func DecodeBase64(input string) []byte {
	str, err := base64.StdEncoding.DecodeString(input)
	CheckError(err)
	return str
}

func CheckEmptyString(str string) {
	if strings.TrimSpace(str) == "" {
		log.Fatal("empty input")
		os.Exit(1)
	}
}

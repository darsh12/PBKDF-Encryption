package helper

import (
	"github.com/pkg/errors"
	"github.com/pkg/xattr"
	"os"
)

func WriteToFile(name string, cipherText []byte, hmacSum []byte, hashAlgorithm []byte, algorithm []byte) (err error) {

	//Create a new file
	f, err := os.Create(name)

	if err != nil {
		err = errors.New("Unable to create file")
	}

	//Write cipher text to file. We dont care about the total bytes written
	_, err = f.Write(cipherText)

	if err != nil {
		err = errors.New("Unable to write to file")
	}

	err = xattr.FSet(f, "HMAC", hmacSum)
	if err != nil {
		err = errors.New("Unable to write to hmac xattr")
	}

	err = xattr.FSet(f, "HASH", hashAlgorithm)
	if err != nil {
		err = errors.New("Unable to write to hash xattr")
	}

	err = xattr.FSet(f, "ALGORITHM", algorithm)
	if err != nil {
		err = errors.New("Unable to write to algorithm xattr")
	}

	return err
}

package helper

import (
	"github.com/pkg/errors"
	"github.com/pkg/xattr"
	"io/ioutil"
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

	//Write the xattr (metadata) to the file
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

func ReadFromFile(name string) (cipherText []byte, hmacSum []byte, hashAlgorithm []byte, algorithm []byte, err error) {

	cipherText, err = ioutil.ReadFile(name)
	if err != nil {
		err = errors.New("unable to read from file")
		return nil, nil, nil, nil, err
	}

	//Open the file
	f, err := os.Open(name)
	if err != nil {
		err = errors.New("unable to open file")
		return nil, nil, nil, nil, err
	}

	// Read the xattr from the file
	hmacSum, err = xattr.FGet(f, "HMAC")
	if err != nil {
		err = errors.New("unable to read the hmac xattr")
		return nil, nil, nil, nil, err
	}

	hashAlgorithm, err = xattr.FGet(f, "HASH")
	if err != nil {
		err = errors.New("unable to read the hash xattr")
		return nil, nil, nil, nil, err
	}

	algorithm, err = xattr.FGet(f, "ALGORITHM")
	if err != nil {
		err = errors.New("unable to read the algorithm xattr")
		return nil, nil, nil, nil, err
	}

	return cipherText, hmacSum, hashAlgorithm, algorithm, err

}

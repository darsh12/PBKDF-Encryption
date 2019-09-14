# PBKDF-Encryption
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fdarsh12%2FPBKDF-Encryption.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fdarsh12%2FPBKDF-Encryption?ref=badge_shield)

Implement a secure way to encrypt a string using a HMAC with either a SHA256 or SHA512 hash. Use  3DES, AES128 and AES256 algorithms in CBC mode.

 
### Tech
* Go binary >= 1.11
* Go dependency manager: dep

### Installation

To run the program
```sh
$ cd PBKDF-Encryption
$ dep ensure
$ go run main.go
```

To build and then run the program
```sh
$ cd PBKDF-Encryption
$ dep ensure
$ go build main.go
$ ./main
```


## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fdarsh12%2FPBKDF-Encryption.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fdarsh12%2FPBKDF-Encryption?ref=badge_large)
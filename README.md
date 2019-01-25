# PBKDF-Encryption
Implement a secure way to encrypt a string using a HMAC with either a SHA256 or SHA512 hash. Use  3DES, AES128 and AES256 algorithms in CBC mode.

 ### Operating Systems
 The program will on run **linux** based distribution, because of how the program writes its metadata, therefore windows is **not supported**
 
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

# arcipher [![Go Reference](https://pkg.go.dev/badge/github.com/ItakawaM/arcipher.svg)](https://pkg.go.dev/github.com/ItakawaM/arcipher)

<p align="center">
  <img src="gopher.png" alt="arcipher logo" width="400"/>
</p>

A Go library and CLI tool for classical cryptography and cryptanalysis. Provides implementations of historical ciphers with file processing and concurrent operations.

## Overview

**Library**: Core cipher implementations and cryptanalysis algorithms for use in Go projects.

**CLI**: `arcipher` command-line tool for encrypting, decrypting, and analyzing text and files with support for concurrent block processing.

### Ciphers

| Cipher Name        | Cipher Type                 | Variant       |
|--------------------|-----------------------------|---------------|
| Rail Fence         | Permutation                 | —             |
| Caesar             | Substitution                | —             |
| Cardan             | Hole Permutation            | —             |
| Vigenere           | Polyalphabetic Substitution | Autokey (-a)  |
| Affine             | Polygraphic Substituion     | Hill          |

### Analyzers

| Analyzer Name                     | Ciphers              |
|-----------------------------------|----------------------|
| Frequency Analysis                | Caesar               |
| Kasiski Test & Frequency Analysis | Vigenere             |

### Padding

| Padding Scheme |
|----------------|
| ISOIEC7816     |

### Math Utilities

Matrix operations and modular arithmetic utilities for classical cipher implementations.

## Installation

### Prerequisites

- [Go](https://go.dev) 1.25.5 or later

### As a Library

```bash
go get github.com/ItakawaM/arcipher
```

### As a CLI Tool

**macOS / Linux:**

```bash
go build -o arcipher ./cmd/arcipher
```

or

```bash
make build BINARY=arcipher
```

**Windows:**

```powershell
go build -o arcipher.exe ./cmd/arcipher
```

or

```bash
make build
```

## Library Usage

```go
package main

import "github.com/ItakawaM/arcipher/ciphers"

func main() {
 // Create a new cipher
 cipher, err := ciphers.NewCaesarCipher(12)
 if err != nil {
  // Process error
 }

 // Create source and destination buffers
 src := []byte("HelloWorld")
 dst := make([]byte, len(src))

 // Perform action
 if err := cipher.EncryptBlock(dst, src); err != nil {
  // Process error
 }

 // Alternatively, you can alias buffers if the desired cipher allows it
 if cipher.IsInPlace() {
  if err := cipher.EncryptBlock(src, src); err != nil {
   // Process error
  }
 }
}

```

## CLI Usage

**Basic pattern:**

```bash
arcipher <CIPHER> <ACTION> <ARGS> [FLAGS]
```

**Getting help:**

```bash
arcipher <COMMAND> --help
```

**Verbose output:**

```bash
arcipher <COMMAND> --verbose
```

### Railfence

#### Message Encryption/Decryption with key 3

```bash
arcipher railfence encrypt 3 "helloworld" 
arcipher railfence decrypt 3 "loelwrdhol"
```

#### File Encryption/Decryption with key 10 using 4 threads and blocks of size 1024KB and verbose output

```bash
arcipher railfence encrypt 10 ./example/SunPoem ./example/SunPoem.enc --block 1024 --threads 4 -v
arcipher railfence decrypt 10 ./example/SunPoem.enc ./example/SunPoem --block 1024 --threads 4 -v
```

### Caesar

#### Message Encryption/Decryption with key 15

```bash
arcipher caesar encrypt 15 "helloworld"
arcipher caesar decrypt 15 "wtaadldgas"
```

#### Message Bruteforce and Frequency Analysis

```bash
arcipher caesar bruteforce "wtaadldgas"
arcipher caesar analyze "wtaadldgas"
```

#### File Encryption/Decryption with key 5 using 2 threads and blocks of size 256KB

```bash
arcipher caesar encrypt 5 ./example/SunPoem ./example/SunPoem.enc --block 256 --threads 2
arcipher caesar decrypt 5 ./example/SunPoem.enc ./example/SunPoem --block 256 --threads 2
```

#### File Bruteforce using 6 threads and blocks of size 2048KB and Frequency Analysis

```bash
arcipher caesar bruteforce ./example/SunPoem /example/SunPoem_Directory -t 6 -b 2048
arcipher caesar analyze ./example/SunPoem
```

### Cardan

#### Message Encryption/Decryption via interactive browser UI and key export

```bash
arcipher cardan encrypt "helloworld" --export key.json
arcipher cardan decrypt "h lowd e ol  lr "
```

#### Message Encryption/Decryption with exported/generated key

```bash
arcipher cardan encrypt ./key.json "helloworld"
arcipher cardan decrypt ./key.json "h lowd e ol  lr "
```

#### Generate a key for a 5x5 grid

```bash
arcipher cardan generate-key 5 key.json
```

#### File Encryption/Decryption with key and 4 threads

```bash
arcipher cardan encrypt key.json ./example/SunPoem ./example/SunPoem.enc --threads 4 -v
arcipher cardan decrypt key.json ./example/SunPoem.enc ./example/SunPoem --threads 4 -v
```

### Vigenere

#### Message Encryption/Decryption with key "Secret"

```bash
arcipher vigenere encrypt "Secret" "helloworld"
arcipher vigenere decrypt "Secret" "zincspgvnu"
```

#### Message Dictionary Bruteforce and Kasiski-Frequency Analysis

```bash
arcipher vigenere bruteforce ./example/dict.txt "zincspgvnu"
arcipher vigenere analyze "zincspgvnu"
```

#### File Encryption/Decryption with key "Keyword" using 4 threads and blocks of size 512KB

```bash
arcipher vigenere encrypt "Keyword" ./example/SunPoem ./example/SunPoem.enc --block 512 --threads 4
arcipher vigenere decrypt "Keyword" ./example/SunPoem.enc ./example/SunPoem --block 512 --threads 4
```

#### File Dictionary Bruteforce using 4 threads and Kasiski-Frequency Analysis

```bash
arcipher vigenere bruteforce ./example/dict.txt ./example/SunPoem /example/SunPoem_Directory --threads 4
arcipher vigenere analyze ./example/SunPoem.enc
```

#### Message Encryption/Decryption with Autokey variant using `-a` flag

```bash
arcipher vigenere encrypt "Secret" "helloworld" -a
arcipher vigenere decrypt "Secret" "zincspvvwo" -a
```

#### File Encryption/Decryption with Autokey variant using 4 threads

```bash
arcipher vigenere encrypt "Keyword" ./example/SunPoem ./example/SunPoem.enc --block 512 --threads 4 -a
arcipher vigenere decrypt "Keyword" ./example/SunPoem.enc ./example/SunPoem --block 512 --threads 4 -a
```

### Affine

#### Generate an Affine cipher key

```bash
arcipher affine generate-key 3 key.json
arcipher affine generate-key 25 key.json --template
```

#### Message Encryption/Decryption with key

```bash
arcipher affine encrypt ./key.json "HELLOWORLD"
arcipher affine decrypt ./key.json "ZICVTWQNGRZGVTWAVZHCQYGLMGJ"
```

#### File Encryption/Decryption with key and 4 threads

```bash
arcipher affine encrypt key.json ./example/input ./example/input.enc --threads 4 -v
arcipher affine decrypt key.json ./example/input.enc ./example/output --threads 4 -v
```

## Options

- `-v, --verbose` — Show performance metrics
- `-b, --block` — Block size in KB for file processing (default: 64)
- `-t, --threads` — Worker threads for file processing (default: CPU cores / 2)

## Testing

```bash
go test ./tests/...
```

or

```bash
make test
```

## License

MIT License — see [LICENSE](LICENSE)

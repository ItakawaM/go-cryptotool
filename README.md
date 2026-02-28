# go-cryptotool

A command-line tool for encrypting and decrypting data using classical cryptographic ciphers, implemented in Go with support for file processing and concurrent operations.

## Features

- **Multiple Cipher Support**
  - Rail Fence (Transposition Cipher)
  - Caesar Cipher (Substitution Cipher)

- **Dual Mode Operation**
  - Message mode: Encrypt/decrypt strings directly
  - File mode: Process large files with multi-threaded support

- **Performance Optimizations**
  - Concurrent block processing using worker goroutines
  - Configurable block sizes and thread counts
  - Performance benchmarking with memory metrics

- **Rail Fence Cipher Features**
  - Zigzag pattern visualization for text mode
  - Adjustable number of rails
  - PKCS7 padding for file operations

## Prerequisites

- [Go](https://go.dev) 1.25.5 or later

## Installation

### Build the project

```bash
go build .
```

This creates an executable `go-cryptotool` (or `go-cryptotool.exe` on Windows).

## Usage

### Rail Fence Cipher

#### Encrypt a message

```powershell
.\go-cryptotool.exe railfence encrypt 3 "Canabis"
```

#### Decrypt a message

```powershell
.\go-cryptotool.exe railfence decrypt 3 "inCasba"
```

#### Visualize the cipher pattern

```powershell
.\go-cryptotool.exe railfence encrypt 3 "Canabis" --print
```

#### Encrypt a file

```powershell
.\go-cryptotool.exe railfence encrypt 5 ./input.txt ./output.enc
```

#### Decrypt a file

```powershell
.\go-cryptotool.exe railfence decrypt 5 ./input.enc ./output.txt
```

### Caesar Cipher

#### Encrypt a message

```powershell
.\go-cryptotool.exe caesar encrypt 3 "AttackAtDawn"
```

#### Decrypt a message

```powershell
.\go-cryptotool.exe caesar decrypt 3 "DwwdfnDwGdzq"
```

#### Encrypt a file

```powershell
.\go-cryptotool.exe caesar encrypt 5 ./input.txt ./output.enc
```

#### Decrypt a file

```powershell
.\go-cryptotool.exe caesar decrypt 5 ./input.enc ./output.txt
```

## Command Options

### Global Options

- `-v, --verbose`: Display additional performance and memory information

### Rail Fence & Caesar Cipher Options

- `-p, --print`: Print zigzag visualization (Rail Fence text mode only)
- `-b, --block`: Block size in KB (default: 64) — Valid values: 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384
- `-t, --threads`: Number of threads for file processing (default: CPU cores / 2)

## Project Structure

```
.
├── main.go                    # Entry point
├── go.mod                     # Go module definition
├── cmd/                       # Command definitions
│   ├── root.go               # Root command setup
│   ├── railfence.go          # Rail Fence cipher commands
│   ├── caesar.go             # Caesar cipher commands
│   └── cmd.go                # Common command utilities
├── ciphers/                  # Cipher implementations
│   ├── ciphers.go            # BlockCipher interface
│   ├── railfence.go          # Rail Fence implementation
│   ├── caesar.go             # Caesar implementation
│   ├── railfence_test.go     # Rail Fence tests & fuzzing
│   └── padding/
│       └── pkcs7.go          # PKCS7 padding implementation
├── engine/                   # File processing engine
│   ├── fileProcessor.go      # BlockEngine for concurrent processing
│   └── worker.go             # Worker goroutines
├── benchmark/                # Performance measurement
│   └── benchmark.go          # Benchmarking utilities
└── examples/                 # Example files
    ├── SunPoem.txt           # Sample plaintext
    ├── SunPoem.enc           # Sample encrypted file
    └── generateGarbage.ps1   # Script to generate large test files
```

## Architecture

### Cipher Interface

All ciphers implement the `BlockCipher` interface:

```go
type BlockCipher interface {
    IsInPlace() bool
    EncryptBlock(dst []byte, src []byte) error
    DecryptBlock(dst []byte, src []byte) error
}
```

### File Processing

The `BlockEngine` handles concurrent file encryption/decryption:

- Splits files into configurable blocks
- Distributes blocks to worker goroutines
- Applies PKCS7 padding to the last block
- Supports both in-place and separate source/destination ciphers

### Worker Model

`Worker` goroutines process blocks concurrently:

- Read block from input file
- Apply encryption/decryption
- Write block to output file
- Report errors through a shared channel

## Testing

Run the test suite:

```bash
go test ./...
```

### Rail Fence Tests

The project includes:

- Unit tests for encryption/decryption
- Round-trip tests (encrypt → decrypt)
- Fuzz testing for robustness

## Performance Considerations

- **Block Size**: Larger blocks improve throughput but increase memory usage
- **Thread Count**: Optimal typically matches CPU core count; defaults to CPU cores / 2
- **In-Place Ciphers**: Caesar cipher is in-place (single buffer); Rail Fence uses separate buffers

Use the `--verbose` flag to see performance metrics:

```powershell
.\go-cryptotool.exe railfence encrypt 3 "LargeMessage" --verbose
```

## Limitations

- Rail Fence cipher: Keys ≥ block size result in simple reversal
- Caesar cipher: Only shifts alphabetic characters (A-Z, a-z)
- PKCS7 padding: Fixed 4-byte length field
- Single-layer encryption: No chaining modes

## Dependencies

- [Cobra](https://github.com/spf13/cobra) v1.10.2 — Command-line framework

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Author

ItakawaM

---

**Status**: Work In Progress

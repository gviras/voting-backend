package encryption

import "math/big"

// HomomorphicEncryptionScheme defines the interface for different
// homomorphic encryption implementations
type HomomorphicEncryptionScheme interface {
	// Identity information
	Name() string
	KeySize() int

	// Core operations
	Encrypt(value *big.Int) ([]byte, error)
	Decrypt(ciphertext []byte) (*big.Int, error)
	Add(ciphertext1, ciphertext2 []byte) ([]byte, error)
	Multiply(ciphertext1, ciphertext2 []byte) ([]byte, error)

	// Analysis helpers
	CiphertextSize(plaintext *big.Int) int
	EstimatedSecurityBits() int
	SupportsMultiplication() bool
}

// BenchmarkResult stores the performance metrics for a scheme
type BenchmarkResult struct {
	SchemeName         string
	KeySize            int
	SecurityBits       int
	EncryptionTime     int64 // nanoseconds
	DecryptionTime     int64 // nanoseconds
	AdditionTime       int64 // nanoseconds
	MultiplicationTime int64 // nanoseconds
	CiphertextSize     int   // bytes
	KeyGenerationTime  int64 // nanoseconds
}

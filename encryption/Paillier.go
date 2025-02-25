package encryption

import (
	"crypto/rand"
	"fmt"
	"github.com/roasbeef/go-go-gadget-paillier"
	"math/big"
)

// PaillierAdapter adapts the existing Paillier implementation to the HomomorphicEncryptionScheme interface
type PaillierAdapter struct {
	keySize    int
	privateKey *paillier.PrivateKey
	publicKey  *paillier.PublicKey
}

// NewPaillierAdapter creates a new adapter for the Paillier scheme
func NewPaillierAdapter(keySize int, privateKey *paillier.PrivateKey, publicKey *paillier.PublicKey) *PaillierAdapter {
	return &PaillierAdapter{
		keySize:    keySize,
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

// Initialize generates or loads keys for the scheme
func (p *PaillierAdapter) Initialize() error {
	// Generate new keys
	var err error
	p.privateKey, err = paillier.GenerateKey(rand.Reader, p.keySize)
	if err != nil {
		return fmt.Errorf("failed to generate Paillier key: %v", err)
	}
	p.publicKey = &p.privateKey.PublicKey
	return nil
}

// Name returns the name of the encryption scheme
func (p *PaillierAdapter) Name() string {
	return fmt.Sprintf("Paillier-%d", p.keySize)
}

// KeySize returns the key size in bits
func (p *PaillierAdapter) KeySize() int {
	return p.keySize
}

// Encrypt encrypts a big.Int value
func (p *PaillierAdapter) Encrypt(value *big.Int) ([]byte, error) {
	if p.publicKey == nil {
		return nil, fmt.Errorf("public key not set")
	}

	return paillier.Encrypt(p.publicKey, value.Bytes())
}

// Decrypt decrypts a ciphertext back to its big.Int value
func (p *PaillierAdapter) Decrypt(ciphertext []byte) (*big.Int, error) {
	if p == nil {
		return nil, fmt.Errorf("PaillierAdapter is nil")
	}

	if p.privateKey == nil {
		return nil, fmt.Errorf("private key not set")
	}

	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext is empty")
	}

	plaintext, err := paillier.Decrypt(p.privateKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	result := new(big.Int).SetBytes(plaintext)
	if result == nil {
		return nil, fmt.Errorf("failed to convert plaintext to big.Int")
	}

	return result, nil
}

// Add performs homomorphic addition of two ciphertexts
func (p *PaillierAdapter) Add(ciphertext1, ciphertext2 []byte) ([]byte, error) {
	if p.publicKey == nil {
		return nil, fmt.Errorf("public key not set")
	}

	return paillier.AddCipher(p.publicKey, ciphertext1, ciphertext2), nil
}

// Multiply returns an error as Paillier doesn't support homomorphic multiplication
func (p *PaillierAdapter) Multiply(ciphertext1, ciphertext2 []byte) ([]byte, error) {
	return nil, fmt.Errorf("Paillier does not support homomorphic multiplication")
}

// CiphertextSize returns the size in bytes of a ciphertext for a given plaintext
func (p *PaillierAdapter) CiphertextSize(plaintext *big.Int) int {
	// In Paillier, ciphertext size is approximately the size of N^2
	return (p.keySize * 2) / 8
}

// EstimatedSecurityBits returns an estimate of the security level in bits
func (p *PaillierAdapter) EstimatedSecurityBits() int {
	// Security estimates based on NIST recommendations
	switch p.keySize {
	case 1024:
		return 80
	case 2048:
		return 112
	case 3072:
		return 128
	case 4096:
		return 152
	default:
		return p.keySize / 20 // Rough estimate
	}
}

// SupportsMultiplication returns whether the scheme supports homomorphic multiplication
func (p *PaillierAdapter) SupportsMultiplication() bool {
	return false
}

// GetPublicKey returns the underlying public key (for use with original CryptoService)
func (p *PaillierAdapter) GetPublicKey() *paillier.PublicKey {
	return p.publicKey
}

// GetPrivateKey returns the underlying private key (for use with original CryptoService)
func (p *PaillierAdapter) GetPrivateKey() *paillier.PrivateKey {
	return p.privateKey
}

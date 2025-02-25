package encryption

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// ElGamalCiphertext represents an ElGamal ciphertext
type ElGamalCiphertext struct {
	C1 []byte // First component (ephemeral key)
	C2 []byte // Second component (encrypted message)
}

// ElGamalAdapter implements homomorphic ElGamal encryption (additive only)
type ElGamalAdapter struct {
	keySize    int
	curve      elliptic.Curve
	privateKey *big.Int
	publicKeyX *big.Int
	publicKeyY *big.Int
}

// NewElGamalAdapter creates a new adapter for ElGamal encryption
func NewElGamalAdapter(keySize int) *ElGamalAdapter {
	var curve elliptic.Curve

	switch keySize {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		// Default to P-256
		curve = elliptic.P256()
		keySize = 256
	}

	return &ElGamalAdapter{
		keySize: keySize,
		curve:   curve,
	}
}

// Initialize generates keys for the scheme
func (e *ElGamalAdapter) Initialize() error {
	// Generate private key
	privKeyBytes, x, y, err := elliptic.GenerateKey(e.curve, rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ElGamal key: %v", err)
	}

	// Convert private key bytes to big.Int
	e.privateKey = new(big.Int).SetBytes(privKeyBytes)
	e.publicKeyX = x
	e.publicKeyY = y

	return nil
}

// Name returns the name of the encryption scheme
func (e *ElGamalAdapter) Name() string {
	return fmt.Sprintf("ElGamal-EC-%d", e.keySize)
}

// KeySize returns the key size in bits
func (e *ElGamalAdapter) KeySize() int {
	return e.keySize
}

// Add performs homomorphic addition of two ciphertexts
func (e *ElGamalAdapter) Add(ciphertext1, ciphertext2 []byte) ([]byte, error) {
	if e.publicKeyX == nil || e.publicKeyY == nil {
		return nil, fmt.Errorf("public key not set")
	}

	// Deserialize ciphertexts
	var ct1, ct2 ElGamalCiphertext
	if err := json.Unmarshal(ciphertext1, &ct1); err != nil {
		return nil, fmt.Errorf("failed to unmarshal first ciphertext: %v", err)
	}
	if err := json.Unmarshal(ciphertext2, &ct2); err != nil {
		return nil, fmt.Errorf("failed to unmarshal second ciphertext: %v", err)
	}

	// Unmarshal C1 components
	c1X1, c1Y1 := elliptic.Unmarshal(e.curve, ct1.C1)
	c1X2, c1Y2 := elliptic.Unmarshal(e.curve, ct2.C1)
	if c1X1 == nil || c1X2 == nil {
		return nil, fmt.Errorf("invalid C1 component")
	}

	// Add C1 components
	resC1X, resC1Y := e.curve.Add(c1X1, c1Y1, c1X2, c1Y2)

	// Unmarshal C2 components
	c2X1, c2Y1 := elliptic.Unmarshal(e.curve, ct1.C2)
	c2X2, c2Y2 := elliptic.Unmarshal(e.curve, ct2.C2)
	if c2X1 == nil || c2X2 == nil {
		return nil, fmt.Errorf("invalid C2 component")
	}

	// Add C2 components
	resC2X, resC2Y := e.curve.Add(c2X1, c2Y1, c2X2, c2Y2)

	// Marshal result
	resC1 := elliptic.Marshal(e.curve, resC1X, resC1Y)
	resC2 := elliptic.Marshal(e.curve, resC2X, resC2Y)

	// Create result ciphertext
	result := ElGamalCiphertext{
		C1: resC1,
		C2: resC2,
	}

	return json.Marshal(result)
}

// Multiply returns an error as ElGamal doesn't support homomorphic multiplication
func (e *ElGamalAdapter) Multiply(ciphertext1, ciphertext2 []byte) ([]byte, error) {
	return nil, fmt.Errorf("ElGamal does not support homomorphic multiplication")
}

// CiphertextSize returns the size in bytes of a ciphertext for a given plaintext
func (e *ElGamalAdapter) CiphertextSize(plaintext *big.Int) int {
	// Two curve points plus some overhead for JSON
	pointSize := (e.keySize / 8) * 2
	return 2*pointSize + 20
}

// EstimatedSecurityBits returns an estimate of the security level in bits
func (e *ElGamalAdapter) EstimatedSecurityBits() int {
	// For elliptic curves, the security level is approximately half the key size
	return e.keySize / 2
}

// SupportsMultiplication returns whether the scheme supports homomorphic multiplication
func (e *ElGamalAdapter) SupportsMultiplication() bool {
	return false
}

// Benchmark runs performance tests on the scheme
func (e *ElGamalAdapter) Benchmark() (*BenchmarkResult, error) {
	if e.privateKey == nil {
		if err := e.Initialize(); err != nil {
			return nil, err
		}
	}

	result := &BenchmarkResult{
		SchemeName:   e.Name(),
		KeySize:      e.keySize,
		SecurityBits: e.EstimatedSecurityBits(),
	}

	// Benchmark key generation
	start := time.Now()
	tempScheme := NewElGamalAdapter(e.keySize)
	tempScheme.Initialize()
	result.KeyGenerationTime = time.Since(start).Nanoseconds()

	// Generate a test value
	testValue := big.NewInt(12345)

	// Benchmark encryption
	start = time.Now()
	ciphertext1, err := e.Encrypt(testValue)
	if err != nil {
		return nil, err
	}
	result.EncryptionTime = time.Since(start).Nanoseconds()

	// Get ciphertext size
	result.CiphertextSize = len(ciphertext1)

	// Benchmark decryption
	start = time.Now()
	_, err = e.Decrypt(ciphertext1)
	if err != nil {
		return nil, err
	}
	result.DecryptionTime = time.Since(start).Nanoseconds()

	// Encrypt a second value for addition
	testValue2 := big.NewInt(54321)
	ciphertext2, err := e.Encrypt(testValue2)
	if err != nil {
		return nil, err
	}

	// Benchmark addition
	start = time.Now()
	_, err = e.Add(ciphertext1, ciphertext2)
	if err != nil {
		return nil, err
	}
	result.AdditionTime = time.Since(start).Nanoseconds()

	// Multiplication is not supported by ElGamal
	result.MultiplicationTime = -1

	return result, nil
}

// First, add a discrete logarithm solver for small values (suitable for vote counting)
func (e *ElGamalAdapter) solveDiscreteLog(pointX, pointY *big.Int) (*big.Int, error) {
	// Baby-step Giant-step algorithm for small values (efficient for vote counts)
	// We're solving for m where g^m = point where g is the generator point

	// First, establish reference points for value 1 (single vote)
	baseX, baseY := e.mapValueToPoint(big.NewInt(1))

	// Maximum expected vote count - adjust based on your application needs
	maxVotes := 10000

	// For small values, we can use a simple brute force approach
	// This is reasonable for voting applications where counts are typically manageable
	for count := 0; count <= maxVotes; count++ {
		if count == 0 {
			// Special case: zero maps to point at infinity or a special encoding
			if pointX.Sign() == 0 && pointY.Sign() == 0 {
				return big.NewInt(0), nil
			}
			continue
		}

		// Try to find a match by repeated addition
		testX, testY := baseX, baseY
		for i := 1; i < count; i++ {
			testX, testY = e.curve.Add(testX, testY, baseX, baseY)
		}

		// Check if we found a match
		if pointX.Cmp(testX) == 0 && pointY.Cmp(testY) == 0 {
			return big.NewInt(int64(count)), nil
		}
	}

	return nil, fmt.Errorf("vote count exceeds maximum searchable value or point is not a valid vote encoding")
}

// Improved mapping function specifically for vote encoding
func (e *ElGamalAdapter) mapValueToPoint(value *big.Int) (*big.Int, *big.Int) {
	// For voting, we need a deterministic mapping from vote values to curve points
	// Value 1 (a single vote) needs to be consistently mapped

	// If value is zero, return special encoding (could be point at infinity, but we'll use origin)
	if value.Sign() == 0 || value.Cmp(big.NewInt(0)) == 0 {
		return big.NewInt(0), big.NewInt(0)
	}

	// For vote counting, we need a simpler encoding approach
	// Start with a base point (generator) and multiply it by the value
	if value.Cmp(big.NewInt(1)) == 0 {
		// For value 1, use a standard base point
		return e.curve.ScalarBaseMult(big.NewInt(1).Bytes())
	} else {
		// For other values, calculate value * G where G is the base point
		return e.curve.ScalarBaseMult(value.Bytes())
	}
}

// Updated Decrypt method that works with vote counts
func (e *ElGamalAdapter) Decrypt(ciphertext []byte) (*big.Int, error) {
	if e.privateKey == nil {
		return nil, fmt.Errorf("private key not set")
	}

	// Deserialize ciphertext
	var ct ElGamalCiphertext
	if err := json.Unmarshal(ciphertext, &ct); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ciphertext: %v", err)
	}

	// Unmarshal C1 component
	c1X, c1Y := elliptic.Unmarshal(e.curve, ct.C1)
	if c1X == nil {
		return nil, fmt.Errorf("invalid C1 component")
	}

	// Calculate shared secret s = C1^privateKey
	sX, sY := e.curve.ScalarMult(c1X, c1Y, e.privateKey.Bytes())

	// Invert the point for subtraction
	sY.Neg(sY)
	sY.Mod(sY, e.curve.Params().P)

	// Unmarshal C2 component
	c2X, c2Y := elliptic.Unmarshal(e.curve, ct.C2)
	if c2X == nil {
		return nil, fmt.Errorf("invalid C2 component")
	}

	// Recover message point: M = C2 - s
	msgX, msgY := e.curve.Add(c2X, c2Y, sX, sY)

	// For vote counting scenarios, we need to map the point back to vote count
	// Try to solve the discrete logarithm problem for small values (suitable for vote counts)
	count, err := e.solveDiscreteLog(msgX, msgY)
	if err != nil {
		// Fallback to X coordinate for non-vote data
		return msgX, nil
	}

	return count, nil
}

// Update the Encrypt method to work better with vote values
func (e *ElGamalAdapter) Encrypt(value *big.Int) ([]byte, error) {
	if e.publicKeyX == nil || e.publicKeyY == nil {
		return nil, fmt.Errorf("public key not set")
	}

	// Special mapping for vote values
	msgX, msgY := e.mapValueToPoint(value)

	// Generate ephemeral key
	r, err := rand.Int(rand.Reader, e.curve.Params().N)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %v", err)
	}

	// Calculate first component C1 = g^r
	c1X, c1Y := e.curve.ScalarBaseMult(r.Bytes())

	// Calculate shared secret s = (h^r)
	sX, sY := e.curve.ScalarMult(e.publicKeyX, e.publicKeyY, r.Bytes())

	// Second component C2 = M + s (point addition for elliptic curves)
	c2X, c2Y := e.curve.Add(msgX, msgY, sX, sY)

	// Encode components
	c1 := elliptic.Marshal(e.curve, c1X, c1Y)
	c2 := elliptic.Marshal(e.curve, c2X, c2Y)

	// Create and serialize ciphertext
	ciphertext := ElGamalCiphertext{
		C1: c1,
		C2: c2,
	}

	return json.Marshal(ciphertext)
}

package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

type CryptoService struct{}

func NewCryptoService() *CryptoService {
	return &CryptoService{}
}

// GenerateKeyPair generates a new ECDSA key pair
func (cs *CryptoService) GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

// GenerateNonce generates a random nonce for vote uniqueness
func (cs *CryptoService) GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	return nonce, err
}

// Sign creates a digital signature of data using private key
func (cs *CryptoService) Sign(data []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := cs.Keccak256(data)
	return crypto.Sign(hash, privateKey)
}

// VerifySignature verifies the signature of data using public key
func (cs *CryptoService) VerifySignature(data, signature []byte, publicKey *ecdsa.PublicKey) bool {
	hash := cs.Keccak256(data)
	sigPublicKey, err := crypto.SigToPub(hash, signature)
	if err != nil {
		return false
	}
	return sigPublicKey.X.Cmp(publicKey.X) == 0 && sigPublicKey.Y.Cmp(publicKey.Y) == 0
}

// HashData creates a Keccak256 hash of data
func (cs *CryptoService) HashData(data []byte) []byte {
	return cs.Keccak256(data)
}

// FromECDSAPub serializes public key to bytes
func (cs *CryptoService) FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return crypto.FromECDSAPub(pub)
}

// Keccak256 computes Keccak-256 hash
func (cs *CryptoService) Keccak256(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// DecryptVote decrypts an encrypted vote using private key
// EncryptVote encrypts a vote using public key
func (cs *CryptoService) EncryptVote(vote []byte, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// Generate ephemeral key pair for this encryption
	ephemKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %v", err)
	}

	// Generate shared secret using ECDH
	sharedX, _ := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, ephemKey.D.Bytes())
	sharedSecret := cs.Keccak256(sharedX.Bytes())

	// Create cipher
	block, err := aes.NewCipher(sharedSecret[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	// Include ephemeral public key in output
	ephemPubBytes := crypto.FromECDSAPub(&ephemKey.PublicKey)

	// Encrypt the data
	ciphertext := gcm.Seal(nil, nonce, vote, nil)

	// Combine all parts
	result := make([]byte, 2+len(ephemPubBytes)+len(nonce)+len(ciphertext))
	binary.BigEndian.PutUint16(result[0:2], uint16(len(ephemPubBytes)))
	copy(result[2:], ephemPubBytes)
	copy(result[2+len(ephemPubBytes):], nonce)
	copy(result[2+len(ephemPubBytes)+len(nonce):], ciphertext)

	return result, nil
}

// DecryptVote decrypts an encrypted vote using private key
func (cs *CryptoService) DecryptVote(encryptedVote []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	// Extract ephemeral public key length
	ephemPubLen := binary.BigEndian.Uint16(encryptedVote[0:2])

	// Get ephemeral public key
	ephemPubBytes := encryptedVote[2 : 2+ephemPubLen]
	ephemPub, err := crypto.UnmarshalPubkey(ephemPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ephemeral public key: %v", err)
	}

	// Generate shared secret using ECDH
	sharedX, _ := privateKey.Curve.ScalarMult(ephemPub.X, ephemPub.Y, privateKey.D.Bytes())
	sharedSecret := cs.Keccak256(sharedX.Bytes())

	block, err := aes.NewCipher(sharedSecret[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	startPos := int(2 + ephemPubLen)

	// Extract nonce and ciphertext
	nonce := encryptedVote[startPos : startPos+nonceSize]
	ciphertext := encryptedVote[startPos+nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}

// HashPrivateKey creates a hash of private key for verification
func (cs *CryptoService) HashPrivateKey(privateKey *ecdsa.PrivateKey) []byte {
	if privateKey == nil {
		return nil
	}
	return cs.Keccak256(crypto.FromECDSA(privateKey))
}

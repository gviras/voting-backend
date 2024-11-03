package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"

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

// EncryptVote encrypts a vote using public key
func (cs *CryptoService) EncryptVote(vote []byte, publicKey *ecdsa.PublicKey) ([]byte, error) {
	ephemKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	sharedSecret := cs.Keccak256(
		ephemKey.PublicKey.X.Bytes(),
		ephemKey.PublicKey.Y.Bytes(),
		publicKey.X.Bytes(),
		publicKey.Y.Bytes(),
	)

	block, err := aes.NewCipher(sharedSecret)
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

	return gcm.Seal(nonce, nonce, vote, nil), nil
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
func (cs *CryptoService) DecryptVote(encryptedVote []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if len(encryptedVote) < 24 { // Minimum length for nonce + data
		return nil, errors.New("encrypted vote too short")
	}

	sharedSecret := cs.Keccak256(
		privateKey.PublicKey.X.Bytes(),
		privateKey.PublicKey.Y.Bytes(),
	)

	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedVote) < nonceSize {
		return nil, errors.New("encrypted vote too short")
	}

	nonce, ciphertext := encryptedVote[:nonceSize], encryptedVote[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// HashPrivateKey creates a hash of private key for verification
func (cs *CryptoService) HashPrivateKey(privateKey *ecdsa.PrivateKey) []byte {
	if privateKey == nil {
		return nil
	}
	return cs.Keccak256(crypto.FromECDSA(privateKey))
}

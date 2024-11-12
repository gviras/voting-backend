package encryption

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/roasbeef/go-go-gadget-paillier" // Example library for Paillier homomorphic encryption
	"golang.org/x/crypto/sha3"
	"voting-backend/models"
)

type CryptoService struct {
	paillierPrivateKey *paillier.PrivateKey
	PaillierPublicKey  *paillier.PublicKey
}

// NewCryptoService initializes a new CryptoService with Paillier keys
func NewCryptoService() (*CryptoService, error) {
	privKey, err := paillier.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Paillier key: %v", err)
	}

	return &CryptoService{
		paillierPrivateKey: privKey,
		PaillierPublicKey:  &privKey.PublicKey, // Set the public key from the private key
	}, nil
}

// EncryptVoteData encrypts the given vote data (as int64) using the Paillier public key
func (cs *CryptoService) EncryptVoteData(votePayload models.VotePayload) ([]byte, error) {
	// Convert the vote payload to JSON
	voteDataBytes, err := json.Marshal(votePayload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize vote payload: %v", err)
	}

	// Encrypt the data
	encryptedVote, err := paillier.Encrypt(cs.PaillierPublicKey, voteDataBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt vote data: %v", err)
	}

	return encryptedVote, nil
}

// DecryptVoteData decrypts the given encrypted data and returns the original vote count as int64
func (cs *CryptoService) DecryptVoteData(encryptedData []byte) ([]byte, error) {
	decryptedData, err := paillier.Decrypt(cs.paillierPrivateKey, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt vote data: %v", err)
	}

	fmt.Printf("Decrypted data length: %d\n", len(decryptedData))
	fmt.Printf("Decrypted data content (hex): %x\n", decryptedData)

	return decryptedData, nil
}

// AddEncryptedVotes performs homomorphic addition of two encrypted votes
func (cs *CryptoService) AddEncryptedVotes(encryptedVote1, encryptedVote2 []byte) ([]byte, error) {
	// Check if inputs are valid
	if encryptedVote1 == nil || encryptedVote2 == nil {
		return nil, fmt.Errorf("encrypted votes cannot be nil")
	}

	// Use the Paillier library's method for adding ciphertexts
	sumEncryptedVote := paillier.AddCipher(cs.PaillierPublicKey, encryptedVote1, encryptedVote2)

	return sumEncryptedVote, nil
}

// GenerateKeyPair generates a new ECDSA key pair
func (cs *CryptoService) GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

// GenerateNonce generates a cryptographic random nonce
func (cs *CryptoService) GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	return nonce, err
}

func (cs *CryptoService) ValidateNonce(nonce []byte) error {
	// Change validation to accept 6-digit nonce (we'll pad it)
	if len(nonce) != 32 {
		return errors.New("nonce must be 32 bytes long")
	}
	return nil
}

// Sign creates a digital signature of data using the private key
func (cs *CryptoService) Sign(data []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := cs.Keccak256(data)
	return crypto.Sign(hash, privateKey)
}

// VerifySignature verifies the signature of data using the public key
func (cs *CryptoService) VerifySignature(data, signature []byte, publicKey *ecdsa.PublicKey) bool {
	hash := cs.Keccak256(data)
	sigPublicKey, err := crypto.SigToPub(hash, signature)
	if err != nil {
		return false
	}
	return sigPublicKey.X.Cmp(publicKey.X) == 0 && sigPublicKey.Y.Cmp(publicKey.Y) == 0
}

// HashData creates a Keccak256 hash of the provided data
func (cs *CryptoService) HashData(data []byte) []byte {
	return cs.Keccak256(data)
}

// FromECDSAPub serializes the public key to bytes
func (cs *CryptoService) FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return crypto.FromECDSAPub(pub)
}

// Keccak256 computes a Keccak-256 hash
func (cs *CryptoService) Keccak256(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

func (cs *CryptoService) PublicKeyFromBytes(pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	if len(pubKeyBytes) == 0 {
		return nil, fmt.Errorf("empty public key bytes")
	}

	// Use ethereum's crypto package to convert bytes back to public key
	pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %v", err)
	}

	return pubKey, nil
}

func (cs *CryptoService) VerifyPublicKeyHash(publicKey *ecdsa.PublicKey, expectedHash []byte) bool {
	if publicKey == nil {
		return false
	}

	pubKeyBytes := cs.FromECDSAPub(publicKey)
	actualHash := cs.Keccak256(pubKeyBytes)

	return bytes.Equal(actualHash, expectedHash)
}

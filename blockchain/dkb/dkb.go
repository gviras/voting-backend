// File: blockchain/dkb/dkb.go
package dkb

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"voting-backend/models"
	"voting-backend/storage"
)

const (
	MaxPendingVoters = 5 // Number of voters per block
)

type DKB struct {
	Chain   []models.DistributedKeyBlock
	pending []models.VoterKeyPair
	storage *storage.BlockchainStorage
}

func New(storage *storage.BlockchainStorage) *DKB {
	genesis := models.DistributedKeyBlock{
		Timestamp: time.Now().Unix(),
		PrevHash:  "0",
		VoterKeys: []models.VoterKeyPair{},
		Nonce:     0,
	}
	genesis.Hash = calculateHash(genesis)

	return &DKB{
		Chain:   []models.DistributedKeyBlock{genesis},
		storage: storage,
		pending: make([]models.VoterKeyPair, 0),
	}
}

func (dkb *DKB) GetPendingVoters() []models.VoterKeyPair {
	return dkb.pending
}

func (dkb *DKB) GetAllVoters() []models.VoterKeyPair {
	var allVoters []models.VoterKeyPair

	// Get voters from blockchain
	for _, block := range dkb.Chain {
		allVoters = append(allVoters, block.VoterKeys...)
	}

	// Add pending voters
	allVoters = append(allVoters, dkb.pending...)

	return allVoters
}

func (dkb *DKB) GenerateVoterKeyPair(voterID string) (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	// Check if the voter already exists
	for _, voter := range dkb.GetAllVoters() {
		if voter.VoterID == voterID {
			if voter.HasVoted {
				return nil, nil, errors.New("voter has already voted")
			}
			return nil, nil, errors.New("voter already registered")
		}
	}

	// Generate new key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	publicKey := &privateKey.PublicKey

	// Store public key in the chain, not the private key
	voterKey := models.VoterKeyPair{
		VoterID:   voterID,
		PublicKey: elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y),
		IssuedAt:  time.Now().Unix(),
		HasVoted:  false,
	}

	// Add to pending voters
	dkb.pending = append(dkb.pending, voterKey)

	// Create a new block if necessary
	if len(dkb.pending) >= MaxPendingVoters {
		err := dkb.createNewBlock()
		if err != nil {
			log.Printf("Warning: Failed to create new block: %v", err)
		}
	}

	return publicKey, privateKey, nil
}

func (dkb *DKB) createNewBlock() error {
	lastBlock := dkb.Chain[len(dkb.Chain)-1]

	newBlock := models.DistributedKeyBlock{
		Timestamp: time.Now().Unix(),
		PrevHash:  lastBlock.Hash,
		VoterKeys: dkb.pending,
		Nonce:     0,
	}

	newBlock.Hash = calculateHash(newBlock)
	dkb.Chain = append(dkb.Chain, newBlock)

	// Clear pending after adding to blockchain
	dkb.pending = make([]models.VoterKeyPair, 0)

	// Save the updated chain
	if err := dkb.storage.SaveDKBChain(dkb.Chain); err != nil {
		return fmt.Errorf("failed to save chain: %v", err)
	}

	return nil
}

func (dkb *DKB) MarkVoterHasVoted(voterID string) error {
	// Check pending voters
	for i := range dkb.pending {
		if dkb.pending[i].VoterID == voterID {
			dkb.pending[i].HasVoted = true
			// Save immediately if updated
			if err := dkb.storage.SaveDKBChain(dkb.Chain); err != nil {
				log.Printf("Warning: Failed to save chain: %v", err)
				return fmt.Errorf("failed to update pending voter status")
			}
			return nil
		}
	}

	// Check blockchain for already registered voters
	for i := range dkb.Chain {
		for j := range dkb.Chain[i].VoterKeys {
			if dkb.Chain[i].VoterKeys[j].VoterID == voterID {
				if dkb.Chain[i].VoterKeys[j].HasVoted {
					return errors.New("voter has already voted")
				}
				dkb.Chain[i].VoterKeys[j].HasVoted = true
				// Save immediately after updating
				if err := dkb.storage.SaveDKBChain(dkb.Chain); err != nil {
					log.Printf("Warning: Failed to save chain: %v", err)
					return fmt.Errorf("failed to save updated voter status")
				}
				return nil
			}
		}
	}

	return errors.New("voter not found")
}

func calculateHash(block models.DistributedKeyBlock) string {
	// Remove the hash field before calculating
	hashBlock := block
	hashBlock.Hash = ""

	data, err := json.Marshal(hashBlock)
	if err != nil {
		log.Printf("Warning: Failed to marshal block for hashing: %v", err)
		return ""
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Add method to validate the chain
func (dkb *DKB) ValidateChain() bool {
	for i := 1; i < len(dkb.Chain); i++ {
		currentBlock := dkb.Chain[i]
		previousBlock := dkb.Chain[i-1]

		// Verify hash linking
		if currentBlock.PrevHash != previousBlock.Hash {
			return false
		}

		// Verify block hash
		if calculateHash(currentBlock) != currentBlock.Hash {
			return false
		}
	}
	return true
}

func ValidatePublicKey(publicKey []byte) bool {
	// Unmarshal the public key
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey)
	if x == nil || y == nil {
		return false
	}

	// Verify the point lies on the curve
	return x.BitLen() > 0 && y.BitLen() > 0 &&
		elliptic.P256().IsOnCurve(x, y)
}

func (dkb *DKB) ValidateKeyPair(voterID string, privateKey *ecdsa.PrivateKey) bool {
	// Find the voter's public key
	var storedPublicKey []byte
	for _, voter := range dkb.GetAllVoters() {
		if voter.VoterID == voterID {
			storedPublicKey = voter.PublicKey
			break
		}
	}

	if storedPublicKey == nil {
		return false
	}

	// Marshal the provided private key's public component
	providedPublicKey := elliptic.Marshal(privateKey.PublicKey.Curve,
		privateKey.PublicKey.X,
		privateKey.PublicKey.Y)

	// Compare the keys
	return bytes.Equal(storedPublicKey, providedPublicKey)
}

func (dkb *DKB) GetVoter(voterID string) (*models.VoterKeyPair, error) {
	// Check pending voters first
	for _, voter := range dkb.pending {
		if voter.VoterID == voterID {
			return &voter, nil
		}
	}

	// Check blockchain
	for _, block := range dkb.Chain {
		for _, voter := range block.VoterKeys {
			if voter.VoterID == voterID {
				return &voter, nil
			}
		}
	}

	return nil, fmt.Errorf("voter not found: %s", voterID)
}

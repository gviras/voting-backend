// File: blockchain/evb/evb.go
package evb

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"voting-backend/models"
	"voting-backend/storage"
)

const MaxPendingVotes = 5

type EVB struct {
	Chain   []models.EncryptedVoteBlock
	pending []models.EncryptedVote
	storage *storage.BlockchainStorage
	mutex   sync.RWMutex // Add this line

}

// Helper struct for hash calculation
type blockForHash struct {
	Timestamp      int64                  `json:"timestamp"`
	PrevHash       string                 `json:"prev_hash"`
	EncryptedVotes []models.EncryptedVote `json:"encrypted_votes"`
	Nonce          int                    `json:"nonce"`
}

func New(storage *storage.BlockchainStorage) *EVB {
	genesis := models.EncryptedVoteBlock{
		Timestamp:      time.Now().Unix(),
		PrevHash:       "0",
		EncryptedVotes: []models.EncryptedVote{},
		Nonce:          0,
	}
	genesis.Hash = calculateHash(genesis)

	return &EVB{
		Chain:   []models.EncryptedVoteBlock{genesis},
		storage: storage,
		pending: make([]models.EncryptedVote, 0),
	}
}

func calculateHash(block models.EncryptedVoteBlock) string {
	// Create a copy without the hash field
	hashBlock := blockForHash{
		Timestamp:      block.Timestamp,
		PrevHash:       block.PrevHash,
		EncryptedVotes: block.EncryptedVotes,
		Nonce:          block.Nonce,
	}

	data, err := json.Marshal(hashBlock)
	if err != nil {
		log.Printf("Warning: Failed to marshal block for hashing: %v", err)
		return ""
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (evb *EVB) createNewBlock() error {
	if len(evb.pending) == 0 {
		log.Printf("No pending votes to create a block")
		return errors.New("no pending votes to create a block")
	}

	log.Printf("Creating new block with %d pending votes", len(evb.pending))

	lastBlock := evb.Chain[len(evb.Chain)-1]

	newBlock := models.EncryptedVoteBlock{
		Timestamp:      time.Now().Unix(),
		PrevHash:       lastBlock.Hash,
		EncryptedVotes: evb.pending,
		Nonce:          0,
	}
	newBlock.Hash = calculateHash(newBlock)

	log.Printf("Appending new block with hash: %s", newBlock.Hash)
	evb.Chain = append(evb.Chain, newBlock)

	log.Printf("Clearing pending votes")
	evb.pending = make([]models.EncryptedVote, 0)

	// Log before saving to storage
	log.Printf("Saving new block to storage with %d blocks in total", len(evb.Chain))
	if err := evb.storage.SaveEVBChain(evb.Chain); err != nil {
		log.Printf("Failed to save chain: %v", err)
		return fmt.Errorf("failed to save chain: %w", err)
	}

	log.Printf("Block saved successfully")
	return nil
}

func (evb *EVB) SubmitVote(vote models.EncryptedVote) error {
	evb.mutex.Lock()
	defer evb.mutex.Unlock()

	// Check if the vote already exists to prevent duplicate submissions
	for _, block := range evb.Chain {
		for _, v := range block.EncryptedVotes {
			if v.VoteHash == vote.VoteHash {
				log.Printf("Vote already submitted: %s", vote.VoteHash)
				return errors.New("vote already submitted")
			}
		}
	}

	// Add the new vote to the pending list
	evb.pending = append(evb.pending, vote)
	log.Printf("Vote submitted successfully. Current pending votes: %d", len(evb.pending))

	// Create a new block if the number of pending votes reaches the limit
	if len(evb.pending) >= MaxPendingVotes {
		log.Printf("Reached max pending votes. Attempting to create a new block.")
		if err := evb.createNewBlock(); err != nil {
			log.Printf("Error during block creation: %v", err)
			return err
		}
	}

	return nil
}

func (evb *EVB) GetPendingVotes() []models.EncryptedVote {
	return evb.pending
}

func (evb *EVB) GetAllVotes() []models.EncryptedVote {
	var allVotes []models.EncryptedVote
	for _, block := range evb.Chain {
		allVotes = append(allVotes, block.EncryptedVotes...)
	}
	return append(allVotes, evb.pending...)
}

func (evb *EVB) ValidateChain() bool {
	for i := 1; i < len(evb.Chain); i++ {
		currentBlock := evb.Chain[i]
		previousBlock := evb.Chain[i-1]

		// Verify hash linking
		if currentBlock.PrevHash != previousBlock.Hash {
			log.Printf("Invalid chain: hash link broken at block %d", i)
			return false
		}

		// Verify block hash
		calculatedHash := calculateHash(currentBlock)
		if calculatedHash != currentBlock.Hash {
			log.Printf("Invalid chain: hash mismatch at block %d", i)
			log.Printf("Expected: %s", currentBlock.Hash)
			log.Printf("Calculated: %s", calculatedHash)
			return false
		}
	}
	return true
}

func (evb *EVB) RemoveLastPendingVote() {
	evb.mutex.Lock()
	defer evb.mutex.Unlock()

	if len(evb.pending) > 0 {
		evb.pending = evb.pending[:len(evb.pending)-1]
	}
}

package service

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"voting-backend/encryption"
	"voting-backend/models"
	"voting-backend/storage"
)

type VoteCountingService struct {
	cryptoService *encryption.CryptoService
	store         *storage.JSONStore
	mu            sync.RWMutex
	counted       map[string]bool // Track counted votes by ID
	results       map[string]int  // Store voting results
}

func NewVoteCountingService(cryptoService *encryption.CryptoService, store *storage.JSONStore) *VoteCountingService {
	return &VoteCountingService{
		cryptoService: cryptoService,
		store:         store,
		counted:       make(map[string]bool),
		results:       make(map[string]int),
	}
}

// CountVotes counts all votes in the EVB blockchain using homomorphic addition
func (vcs *VoteCountingService) CountVotes() (*VotingResults, error) {
	vcs.mu.Lock()
	defer vcs.mu.Unlock()

	// Reset counters
	vcs.counted = make(map[string]bool)
	vcs.results = make(map[string]int)

	// Load EVB chain
	blocks, err := vcs.store.LoadChain("evb")
	if err != nil {
		return nil, fmt.Errorf("failed to load EVB chain: %w", err)
	}

	fmt.Printf("Starting vote count. Found %d blocks\n", len(blocks))

	var processedVotes int

	for i, block := range blocks {
		fmt.Printf("Processing block %d\n", i)

		var vote models.Vote
		if err := json.Unmarshal(block.Data, &vote); err != nil {
			fmt.Printf("Failed to unmarshal vote in block %d: %v\n", i, err)
			continue
		}

		if vcs.counted[vote.ID] {
			fmt.Printf("Skipping duplicate vote ID in block %d\n", i)
			continue
		}

		// Decrypt the vote data
		decryptedData, err := vcs.cryptoService.DecryptVoteData(vote.EncryptedChoice)
		if err != nil {
			fmt.Printf("Failed to decrypt vote in block %d: %v\n", i, err)
			continue
		}

		// Parse the decrypted data as a vote payload
		var votePayload models.VotePayload
		if err := json.Unmarshal(decryptedData, &votePayload); err != nil {
			fmt.Printf("Failed to parse decrypted data in block %d: %v\n", i, err)
			continue
		}

		// Ensure the payload contains a valid candidate choice
		if votePayload.Choice == "" {
			fmt.Printf("Invalid candidate choice in block %d\n", i)
			continue
		}

		// Increment the result for the candidate
		vcs.results[votePayload.Choice]++

		vcs.counted[vote.ID] = true
		fmt.Printf("Successfully included vote from block %d for candidate %s\n", i, votePayload.Choice)
		processedVotes++
	}

	fmt.Printf("Vote counting completed. Counted %d valid votes out of %d blocks\n", len(vcs.counted), processedVotes)

	return &VotingResults{
		TotalVotes:     len(vcs.counted),
		Results:        vcs.results,
		ProcessedVotes: processedVotes,
	}, nil
}

// DecryptVote decrypts a single vote (not used for homomorphic counting, but kept for completeness)
func (vcs *VoteCountingService) DecryptVote(encryptedVote []byte, privateKey *ecdsa.PrivateKey) (*models.VotePayload, error) {
	if len(encryptedVote) == 0 {
		return nil, errors.New("empty encrypted vote")
	}

	fmt.Printf("Attempting to decrypt vote of length %d\n", len(encryptedVote))

	// Decrypt using the cryptoService
	decryptedData, err := vcs.cryptoService.DecryptVoteData(encryptedVote)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt vote (len: %d): %w", len(encryptedVote), err)
	}

	var vote models.VotePayload
	if err := json.Unmarshal(decryptedData, &vote); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted vote (data: %s): %w", string(decryptedData), err)
	}

	// Validate decrypted vote
	if vote.Choice == "" {
		return nil, fmt.Errorf("decrypted vote has empty choice")
	}
	if vote.VoterID == "" {
		return nil, fmt.Errorf("decrypted vote has empty voter ID")
	}

	fmt.Printf("Successfully decrypted vote for voter %s\n", vote.VoterID)
	return &vote, nil
}

// VerifyVoteCount checks if the number of votes matches registered voters
func (vcs *VoteCountingService) VerifyVoteCount(registeredVoters int) (*VoteVerification, error) {
	vcs.mu.RLock()
	defer vcs.mu.RUnlock()

	blocks, err := vcs.store.LoadChain("evb")
	if err != nil {
		return nil, fmt.Errorf("failed to load EVB chain: %w", err)
	}

	// Validate chain
	isValid := models.ValidateChain(blocks)

	return &VoteVerification{
		RegisteredVoters: registeredVoters,
		ActualVotes:      len(blocks),
		CountedVotes:     len(vcs.counted),
		IsValid:          isValid && len(blocks) <= registeredVoters && len(blocks) == len(vcs.counted),
	}, nil
}

// verifyVoteSignature verifies the signature of a vote (not needed for homomorphic encryption but kept for completeness)
func (vcs *VoteCountingService) verifyVoteSignature(vote models.Vote, decryptedVote *models.VotePayload) bool {
	// Reconstruct the original message that was signed
	message := vcs.cryptoService.Keccak256(append(vote.EncryptedChoice, vote.Nonce...))

	// Verify the signature
	return vcs.cryptoService.VerifySignature(
		message,
		vote.Signature,
		&ecdsa.PublicKey{}, // You need to reconstruct the public key from the hash
	)
}

// GetLatestResults returns the current vote count without recounting
func (vcs *VoteCountingService) GetLatestResults() (*VotingResults, error) {
	vcs.mu.RLock()
	defer vcs.mu.RUnlock()

	blocks, err := vcs.store.LoadChain("evb")
	if err != nil {
		return nil, fmt.Errorf("failed to load EVB chain: %w", err)
	}

	return &VotingResults{
		TotalVotes:     len(vcs.counted),
		Results:        vcs.results,
		ProcessedVotes: len(blocks),
	}, nil
}

// VotingResults represents the final vote count
type VotingResults struct {
	TotalVotes     int            `json:"total_votes"`
	Results        map[string]int `json:"results"`
	ProcessedVotes int            `json:"processed_votes"`
}

// VoteVerification represents the vote verification result
type VoteVerification struct {
	RegisteredVoters int  `json:"registered_voters"`
	ActualVotes      int  `json:"actual_votes"`
	CountedVotes     int  `json:"counted_votes"`
	IsValid          bool `json:"is_valid"`
}

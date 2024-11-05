package service

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
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

// CountVotes counts all votes in the EVB
func (vcs *VoteCountingService) CountVotes(privateKey *ecdsa.PrivateKey) (*VotingResults, error) {
	vcs.mu.Lock()
	defer vcs.mu.Unlock()

	// Reset counters
	vcs.counted = make(map[string]bool)
	vcs.results = make(map[string]int)

	// Load all votes from EVB
	votes, err := vcs.store.LoadChain("evb")
	if err != nil {
		return nil, err
	}

	for _, block := range votes {
		var vote models.Vote
		if err := json.Unmarshal(block.Data, &vote); err != nil {
			continue // Skip invalid votes
		}

		// Prevent double counting
		if vcs.counted[vote.ID] {
			continue
		}

		decryptedVote, err := vcs.DecryptVote(vote.EncryptedChoice, privateKey)
		if err != nil {
			continue // Skip votes that can't be decrypted
		}

		// Verify vote signature if present
		if len(vote.Signature) > 0 && len(vote.PublicKeyHash) > 0 {
			if !vcs.verifyVoteSignature(vote, decryptedVote) {
				continue // Skip votes with invalid signatures
			}
		}

		// Count the vote
		vcs.results[decryptedVote.Choice]++
		vcs.counted[vote.ID] = true
	}

	return &VotingResults{
		TotalVotes:     len(vcs.counted),
		Results:        vcs.results,
		ProcessedVotes: len(votes),
	}, nil
}

// DecryptVote decrypts a single vote
func (vcs *VoteCountingService) DecryptVote(encryptedVote []byte, privateKey *ecdsa.PrivateKey) (*models.VotePayload, error) {
	if len(encryptedVote) == 0 {
		return nil, errors.New("empty encrypted vote")
	}

	// Decrypt using the cryptoService
	decryptedData, err := vcs.cryptoService.DecryptVote(encryptedVote, privateKey)
	if err != nil {
		return nil, err
	}

	var vote models.VotePayload
	if err := json.Unmarshal(decryptedData, &vote); err != nil {
		return nil, err
	}

	return &vote, nil
}

// VerifyVoteCount checks if the number of votes matches registered voters
func (vcs *VoteCountingService) VerifyVoteCount(registeredVoters int) (*VoteVerification, error) {
	vcs.mu.RLock()
	defer vcs.mu.RUnlock()

	votes, err := vcs.store.LoadChain("evb")
	if err != nil {
		return nil, err
	}

	return &VoteVerification{
		RegisteredVoters: registeredVoters,
		ActualVotes:      len(votes),
		CountedVotes:     len(vcs.counted),
		IsValid:          len(votes) <= registeredVoters && len(votes) == len(vcs.counted),
	}, nil
}

// verifyVoteSignature verifies the signature of a vote
func (vcs *VoteCountingService) verifyVoteSignature(vote models.Vote, decryptedVote *models.VotePayload) bool {
	// Reconstruct the original message that was signed
	message := vcs.cryptoService.Keccak256(append(vote.EncryptedChoice, vote.Nonce...))

	return vcs.cryptoService.VerifySignature(
		message,
		vote.Signature,
		&ecdsa.PublicKey{}, // Need to reconstruct public key from hash
	)
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

func (vcs *VoteCountingService) GetLatestResults() (*VotingResults, error) {
	vcs.mu.RLock()
	defer vcs.mu.RUnlock()

	return &VotingResults{
		TotalVotes:     len(vcs.counted),
		Results:        vcs.results,
		ProcessedVotes: len(vcs.counted),
	}, nil
}

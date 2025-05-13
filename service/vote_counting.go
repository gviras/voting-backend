package service

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"runtime/debug"
	"strings"
	"sync"
	"voting-backend/encryption"
	"voting-backend/models"
	"voting-backend/storage"
)

type VoteCountingService struct {
	cryptoService      *encryption.CryptoService
	store              *storage.JSONStore
	mu                 sync.RWMutex
	counted            map[string]bool
	results            map[string]int64 // Final decrypted results
	encryptedVectorSum [][]byte         // Encrypted vote sum vector
	metricsCollector   *MetricsCollector
	isVotingActiveFunc func() bool
	resultsCounted     bool // Flag to indicate if votes have been counted
}

type SingleVoteVerification struct {
	VoteID          string   `json:"vote_id"`
	IsValid         bool     `json:"is_valid"`
	BlockIndex      uint64   `json:"block_index"`
	Timestamp       int64    `json:"timestamp"`
	SignatureValid  bool     `json:"signature_valid"`
	DecryptionValid bool     `json:"decryption_valid"`
	Issues          []string `json:"issues,omitempty"`
}

type SingleVoteVerificationResult struct {
	BlockIndex      uint64   `json:"block_index"`
	IsValid         bool     `json:"is_valid"`
	BlockValid      bool     `json:"block_valid"`
	ChainLinkValid  bool     `json:"chain_link_valid"`
	EncryptionValid bool     `json:"encryption_valid"`
	NonceValid      bool     `json:"nonce_valid"`
	Issues          []string `json:"issues,omitempty"`
	Timestamp       int64    `json:"timestamp"`
}

func NewVoteCountingService(
	cryptoService *encryption.CryptoService,
	store *storage.JSONStore,
	metricsCollector *MetricsCollector,
	isVotingActiveFunc func() bool,
) *VoteCountingService {
	return &VoteCountingService{
		cryptoService:      cryptoService,
		store:              store,
		counted:            make(map[string]bool),
		results:            make(map[string]int64),
		metricsCollector:   metricsCollector,
		isVotingActiveFunc: isVotingActiveFunc,
	}
}

// CountVotes counts all votes in the EVB blockchain using homomorphic addition
func (vcs *VoteCountingService) CountVotes() (*VotingResults, error) {
	vcs.metricsCollector.RecordCountingStart()

	vcs.mu.Lock()
	defer vcs.mu.Unlock()

	// Recover from any panics that might occur
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from panic in vote counting: %v\n", r)
			debug.PrintStack()
		}
	}()

	// Clear previous results
	vcs.counted = make(map[string]bool)
	vcs.encryptedVectorSum = nil
	vcs.results = make(map[string]int64)

	blocks, err := vcs.store.LoadChain("evb")
	if err != nil {
		return nil, fmt.Errorf("failed to load EVB chain: %w", err)
	}

	fmt.Printf("Starting homomorphic vote count. Found %d blocks\n", len(blocks))

	// Get registry to determine vector size
	registry, err := vcs.cryptoService.GetOrCreateCandidateRegistry()
	if err != nil {
		return nil, fmt.Errorf("failed to get candidate registry: %w", err)
	}

	// Initialize the vote sum vector with the correct size
	vectorSum := make([][]byte, len(registry.Candidates))

	for _, block := range blocks {
		var vote models.Vote
		if err := json.Unmarshal(block.Data, &vote); err != nil {
			fmt.Printf("Failed to unmarshal vote data: %v\n", err)
			continue
		}

		if vcs.counted[vote.ID] {
			continue
		}

		// Skip votes with empty encrypted choice
		if vote.EncryptedChoice == nil || len(vote.EncryptedChoice) == 0 {
			fmt.Printf("Skipping vote with empty encrypted choice: %s\n", vote.ID)
			continue
		}

		// Parse the vote package
		var votePackage encryption.VoteEncryptionPackage
		if err := json.Unmarshal(vote.EncryptedChoice, &votePackage); err != nil {
			fmt.Printf("Failed to unmarshal vote package: %v\n", err)
			continue
		}

		// Process vector-based vote
		if votePackage.EncryptedVoteVector == nil || len(votePackage.EncryptedVoteVector) == 0 {
			fmt.Printf("Vote %s does not contain a valid vote vector, skipping\n", vote.ID)
			continue
		}

		// Ensure vector length matches registry
		if len(votePackage.EncryptedVoteVector) != len(registry.Candidates) {
			fmt.Printf("Warning: vote %s has incorrect vector length (%d vs %d), skipping\n",
				vote.ID, len(votePackage.EncryptedVoteVector), len(registry.Candidates))
			continue
		}

		// Add this vote to the running sum
		for i, encrypted := range votePackage.EncryptedVoteVector {
			if encrypted == nil {
				continue
			}

			if vectorSum[i] == nil {
				vectorSum[i] = encrypted
			} else {
				summed, err := vcs.cryptoService.AddHomomorphicValues(vectorSum[i], encrypted)
				if err != nil {
					fmt.Printf("Failed to add vote vector element %d: %v\n", i, err)
					continue
				}
				vectorSum[i] = summed
			}
		}

		vcs.counted[vote.ID] = true
	}

	// Store the encrypted sum but don't decrypt it
	vcs.encryptedVectorSum = vectorSum
	vcs.resultsCounted = true

	vcs.metricsCollector.RecordCountingEnd()

	// Return a result with just the count of votes, no decrypted results yet
	return &VotingResults{
		TotalVotes:     len(vcs.counted),
		ProcessedVotes: len(blocks),
		Results:        make(map[string]int64), // Empty results
	}, nil
}

func (vcs *VoteCountingService) GetFinalResults() (*VotingResults, error) {
	// Check if voting has ended
	if vcs.isVotingActiveFunc != nil && vcs.isVotingActiveFunc() {
		return nil, fmt.Errorf("cannot retrieve final results while voting is still active")
	}

	vcs.mu.Lock()
	defer vcs.mu.Unlock()

	// If votes haven't been counted yet, count them first
	if !vcs.resultsCounted {
		vcs.mu.Unlock() // Unlock before calling CountVotes
		if _, err := vcs.CountVotes(); err != nil {
			return nil, fmt.Errorf("failed to count votes: %w", err)
		}
		vcs.mu.Lock() // Lock again
	}

	// If results are already decrypted, return them
	if len(vcs.results) > 0 {
		return &VotingResults{
			TotalVotes:     len(vcs.counted),
			Results:        vcs.results,
			ProcessedVotes: len(vcs.counted),
		}, nil
	}

	// No encrypted vector sum to decrypt
	if vcs.encryptedVectorSum == nil || len(vcs.encryptedVectorSum) == 0 {
		return &VotingResults{
			TotalVotes:     len(vcs.counted),
			Results:        make(map[string]int64),
			ProcessedVotes: len(vcs.counted),
		}, nil
	}

	// Get the candidate registry
	registry, err := vcs.cryptoService.GetOrCreateCandidateRegistry()
	if err != nil {
		return nil, fmt.Errorf("failed to get candidate registry: %w", err)
	}

	// Decrypt the vector sum
	results := make(map[string]int64)

	for i, encryptedSum := range vcs.encryptedVectorSum {
		if encryptedSum == nil {
			continue
		}

		count, err := vcs.cryptoService.DecryptToInt(encryptedSum)
		if err != nil {
			fmt.Printf("Failed to decrypt sum for vector element %d: %v\n", i, err)
			continue
		}

		// Use candidate name from registry
		candidateName := fmt.Sprintf("Candidate %d", i+1) // Default fallback
		if i < len(registry.Candidates) {
			candidateName = registry.Candidates[i]
		}

		results[candidateName] = count
	}

	// Store the decrypted results
	vcs.results = results

	return &VotingResults{
		TotalVotes:     len(vcs.counted),
		Results:        results,
		ProcessedVotes: len(vcs.counted),
	}, nil
}

func debugPrintBytes(prefix string, data []byte) {
	fmt.Printf("%s (len=%d): %x\n", prefix, len(data), data)
}

// Helper function to convert int64 map to int map for backwards compatibility
func convertToIntMap(int64Map map[string]int64) map[string]int64 {
	intMap := make(map[string]int64)
	for k, v := range int64Map {
		intMap[k] = v
	}
	return intMap
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

func (vcs *VoteCountingService) VerifyVote(privateKeyHex string) (*SingleVoteVerificationResult, error) {
	vcs.mu.RLock()
	defer vcs.mu.RUnlock()

	result := &SingleVoteVerificationResult{
		Issues: make([]string, 0),
	}

	// Parse private key
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key format: %w", err)
	}

	// Generate public key hash
	privateKeyHash := vcs.cryptoService.Keccak256(crypto.FromECDSA(privateKey))

	blocks, err := vcs.store.LoadChain("evb")
	if err != nil {
		return nil, fmt.Errorf("failed to load EVB chain: %w", err)
	}

	// Find the vote using public key hash
	var foundBlock *models.Block
	var foundVote models.Vote
	var previousBlock *models.Block

	for i, block := range blocks {
		var vote models.Vote
		if err := json.Unmarshal(block.Data, &vote); err != nil {
			continue
		}

		if bytes.Equal(vote.PrivateKeyHash, privateKeyHash) {
			foundBlock = block
			foundVote = vote
			if i > 0 {
				previousBlock = blocks[i-1]
			}
			result.BlockIndex = block.Index
			result.Timestamp = block.Timestamp
			break
		}
	}

	if foundBlock == nil {
		result.Issues = append(result.Issues, "No vote found for this private key")
		return result, nil
	}

	// Verify the VoteEncryptionPackage
	var pkg encryption.VoteEncryptionPackage
	if err := json.Unmarshal(foundVote.EncryptedChoice, &pkg); err != nil {
		result.Issues = append(result.Issues, "Invalid vote encryption package")
	} else {
		// Check both vector-based and legacy formats
		result.EncryptionValid = pkg.EncryptedVoteVector != nil && len(pkg.EncryptedVoteVector) > 0

		// Additional verification for vector-based votes
		if pkg.EncryptedVoteVector != nil && len(pkg.EncryptedVoteVector) > 0 {
			// Get candidate registry
			registry, err := vcs.cryptoService.GetOrCreateCandidateRegistry()
			if err == nil {
				if len(pkg.EncryptedVoteVector) != len(registry.Candidates) {
					result.Issues = append(result.Issues, fmt.Sprintf(
						"Vote vector length (%d) does not match candidate count (%d)",
						len(pkg.EncryptedVoteVector), len(registry.Candidates)))
				}
			}
		}
	}

	// Perform other verifications
	result.BlockValid = foundBlock.Validate()
	if previousBlock != nil {
		result.ChainLinkValid = bytes.Equal(foundBlock.PrevHash, previousBlock.Hash)
	} else {
		result.ChainLinkValid = true
	}

	result.NonceValid = len(foundVote.Nonce) == 32

	// Set final validity
	result.IsValid = result.BlockValid &&
		result.ChainLinkValid &&
		result.NonceValid &&
		result.EncryptionValid

	return result, nil
}

// GetLatestResults returns the current vote count without recounting
func (vcs *VoteCountingService) GetLatestResults() (*VotingResults, error) {
	// If results have already been counted, return them
	vcs.mu.RLock()
	if len(vcs.results) > 0 {
		results := &VotingResults{
			TotalVotes:     len(vcs.counted),
			Results:        vcs.results,
			ProcessedVotes: 0, // Will be set later
		}
		vcs.mu.RUnlock()

		// Get processed vote count
		blocks, err := vcs.store.LoadChain("evb")
		if err != nil {
			return results, fmt.Errorf("warning: failed to get processed vote count: %w", err)
		}
		results.ProcessedVotes = len(blocks)

		return results, nil
	}
	vcs.mu.RUnlock()

	// If no cached results, count them fresh
	return vcs.CountVotes()
}

// VotingResults represents the final vote count
type VotingResults struct {
	TotalVotes     int              `json:"total_votes"`
	Results        map[string]int64 `json:"results"` // Changed to uint64
	ProcessedVotes int              `json:"processed_votes"`
}

// VoteVerification represents the vote verification result
type VoteVerification struct {
	RegisteredVoters int  `json:"registered_voters"`
	ActualVotes      int  `json:"actual_votes"`
	CountedVotes     int  `json:"counted_votes"`
	IsValid          bool `json:"is_valid"`
}

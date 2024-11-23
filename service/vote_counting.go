package service

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"strings"
	"sync"
	"time"
	"voting-backend/encryption"
	"voting-backend/models"
	"voting-backend/storage"
)

type VoteCountingService struct {
	cryptoService *encryption.CryptoService
	store         *storage.JSONStore
	mu            sync.RWMutex
	counted       map[string]bool
	results       map[string]int64 // Changed to int64 for homomorphic counting
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
	TimestampValid  bool     `json:"timestamp_valid"`
	ChainLinkValid  bool     `json:"chain_link_valid"`
	EncryptionValid bool     `json:"encryption_valid"`
	NonceValid      bool     `json:"nonce_valid"`
	Issues          []string `json:"issues,omitempty"`
	Timestamp       int64    `json:"timestamp"`
}

func NewVoteCountingService(cryptoService *encryption.CryptoService, store *storage.JSONStore) *VoteCountingService {
	return &VoteCountingService{
		cryptoService: cryptoService,
		store:         store,
		counted:       make(map[string]bool),
		results:       make(map[string]int64),
	}
}

// CountVotes counts all votes in the EVB blockchain using homomorphic addition
func (vcs *VoteCountingService) CountVotes() (*VotingResults, error) {
	vcs.mu.Lock()
	defer vcs.mu.Unlock()

	vcs.counted = make(map[string]bool)
	vcs.results = make(map[string]int64)

	blocks, err := vcs.store.LoadChain("evb")
	if err != nil {
		return nil, fmt.Errorf("failed to load EVB chain: %w", err)
	}

	fmt.Printf("Starting homomorphic vote count. Found %d blocks\n", len(blocks))

	// Track encrypted sums by choice hash
	var currentSum []byte

	for _, block := range blocks {
		var vote models.Vote
		if err := json.Unmarshal(block.Data, &vote); err != nil {
			continue
		}

		if vcs.counted[vote.ID] {
			continue
		}

		// Add to running sum
		if currentSum == nil {
			currentSum = vote.EncryptedChoice
		} else {
			summedVote, err := vcs.cryptoService.AddEncryptedVotes(currentSum, vote.EncryptedChoice)
			if err != nil {
				continue
			}
			currentSum = summedVote
		}

		vcs.counted[vote.ID] = true
	}

	// Decrypt final sums
	if currentSum != nil {
		decryptedData, err := vcs.cryptoService.DecryptVoteData(currentSum)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt final tally: %v", err)
		}

		// Results are now mapped by choice hash
		if err := json.Unmarshal(decryptedData, &vcs.results); err != nil {
			return nil, fmt.Errorf("failed to parse results: %v", err)
		}
	}

	return &VotingResults{
		TotalVotes:     len(vcs.counted),
		Results:        vcs.results, // Results are now mapped by choice hash
		ProcessedVotes: len(blocks),
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
	publicKeyHash := vcs.cryptoService.Keccak256(
		vcs.cryptoService.FromECDSAPub(&privateKey.PublicKey),
	)

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

		if bytes.Equal(vote.PublicKeyHash, publicKeyHash) {
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
		result.EncryptionValid = len(pkg.HomomorphicVoteData) > 0
	}

	// Perform other verifications
	result.BlockValid = foundBlock.Validate()
	if previousBlock != nil {
		result.ChainLinkValid = bytes.Equal(foundBlock.PrevHash, previousBlock.Hash)
	} else {
		result.ChainLinkValid = true
	}

	result.TimestampValid = foundVote.Timestamp > 0 &&
		foundVote.Timestamp <= time.Now().Unix() &&
		(previousBlock == nil || foundVote.Timestamp > previousBlock.Timestamp)

	result.NonceValid = len(foundVote.Nonce) == 32

	// Set final validity
	result.IsValid = result.BlockValid &&
		result.ChainLinkValid &&
		result.TimestampValid &&
		result.NonceValid &&
		result.EncryptionValid

	return result, nil
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

package service

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"strings"
	"sync"
	"time"
	"voting-backend/encryption"
	"voting-backend/models"
	"voting-backend/storage"

	"github.com/google/uuid"
)

type VotingService struct {
	store                *storage.JSONStore
	cryptoService        *encryption.CryptoService
	dkbBlocks            []*models.Block
	evbBlocks            []*models.Block
	mu                   sync.RWMutex
	anonymizationService *AnonymizationService
	votingSession        *VotingSession
	countingService      *VoteCountingService
	voteBuffer           []models.Vote
	registeredVoters     map[string]bool
	votedVoters          map[string]bool
}

func NewVotingService(storagePath string) (*VotingService, error) {
	store, err := storage.NewJSONStore(storagePath)
	if err != nil {
		return nil, err
	}

	// Load existing chains
	dkbBlocks, err := store.LoadChain("dkb")
	if err != nil {
		return nil, err
	}

	evbBlocks, err := store.LoadChain("evb")
	if err != nil {
		return nil, err
	}

	// Initialize services
	cryptoService := encryption.NewCryptoService()
	session := NewVotingSession(24 * time.Hour)
	anonymizer := NewAnonymizationService(10, 30*time.Minute)
	countingService := NewVoteCountingService(cryptoService)

	vs := &VotingService{
		store:                store,
		cryptoService:        cryptoService,
		dkbBlocks:            dkbBlocks,
		evbBlocks:            evbBlocks,
		anonymizationService: anonymizer,
		votingSession:        session,
		countingService:      countingService,
		registeredVoters:     make(map[string]bool),
		votedVoters:          make(map[string]bool),
		voteBuffer:           make([]models.Vote, 0),
	}

	// Load registered voters from DKB
	if err := vs.loadRegisteredVoters(); err != nil {
		return nil, err
	}

	return vs, nil
}

func (vs *VotingService) loadRegisteredVoters() error {
	for _, block := range vs.dkbBlocks {
		var registration models.VoterRegistration
		if err := json.Unmarshal(block.Data, &registration); err != nil {
			return err
		}
		vs.registeredVoters[registration.VoterID] = true
	}
	return nil
}

func (vs *VotingService) verifyVoter(voterID string) error {
	if !vs.registeredVoters[voterID] {
		return errors.New("voter not registered")
	}
	if vs.votedVoters[voterID] {
		return errors.New("voter has already voted")
	}
	return nil
}

func (vs *VotingService) RegisterVoter(voterID string) (*ecdsa.PrivateKey, error) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	fmt.Println("Lock received")

	if !vs.votingSession.IsActive() {
		return nil, errors.New("voting registration has ended")
	}

	if vs.registeredVoters[voterID] {
		return nil, errors.New("voter already registered")
	}
	fmt.Println("Generating key pair")
	privateKey, err := vs.cryptoService.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	fmt.Println("Saving voter registration")
	registration := &models.VoterRegistration{
		VoterID:   voterID,
		PublicKey: vs.cryptoService.FromECDSAPub(&privateKey.PublicKey),
		Timestamp: time.Now().Unix(),
	}

	if err := vs.store.SaveVoter(registration); err != nil {
		return nil, err
	}

	registrationData, err := json.Marshal(registration)
	if err != nil {
		return nil, err
	}
	fmt.Println("Creating block")
	block := models.NewBlock(
		uint64(len(vs.dkbBlocks)),
		registrationData,
		vs.getLastDKBHash(),
		4,
	)

	fmt.Println("Saving block")
	if err := vs.store.SaveBlock("dkb", block); err != nil {
		return nil, err
	}

	vs.dkbBlocks = append(vs.dkbBlocks, block)
	vs.registeredVoters[voterID] = true

	fmt.Println("Voter %s registered\n", voterID)
	return privateKey, nil
}

func (vs *VotingService) CastVote(voterID string, vote *models.VotePayload, privateKey *ecdsa.PrivateKey) error {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	if !vs.votingSession.IsActive() {
		return errors.New("voting session has ended")
	}

	if err := vs.verifyVoter(voterID); err != nil {
		return err
	}

	voteData, err := json.Marshal(vote)
	if err != nil {
		return err
	}

	nonce, err := vs.cryptoService.GenerateNonce()
	if err != nil {
		return err
	}

	encryptedVote, err := vs.cryptoService.EncryptVote(voteData, &privateKey.PublicKey)
	if err != nil {
		return err
	}

	voteRecord := &models.Vote{
		ID:              uuid.New().String(),
		EncryptedChoice: encryptedVote,
		Nonce:           nonce,
		Timestamp:       time.Now().Unix(),
		PublicKeyHash:   vs.cryptoService.Keccak256(vs.cryptoService.FromECDSAPub(&privateKey.PublicKey)),
	}

	signature, err := vs.cryptoService.Sign(vs.cryptoService.Keccak256(append(encryptedVote, nonce...)), privateKey)
	if err != nil {
		return err
	}
	voteRecord.Signature = signature

	vs.voteBuffer = append(vs.voteBuffer, *voteRecord)

	if len(vs.voteBuffer) >= vs.anonymizationService.batchSize {
		if err := vs.processBatchedVotes(); err != nil {
			return err
		}
	}

	vs.votedVoters[voterID] = true
	return nil
}

func (vs *VotingService) processBatchedVotes() error {
	anonymizedVotes := vs.anonymizationService.AnonymizeVotes(vs.voteBuffer)

	for _, av := range anonymizedVotes {
		cleanVote := vs.anonymizationService.RemoveVoterSignatures(av)

		voteData, err := json.Marshal(cleanVote)
		if err != nil {
			return err
		}

		block := models.NewBlock(
			uint64(len(vs.evbBlocks)),
			voteData,
			vs.getLastEVBHash(),
			4,
		)

		if err := vs.store.SaveBlock("evb", block); err != nil {
			return err
		}

		vs.evbBlocks = append(vs.evbBlocks, block)
	}

	vs.voteBuffer = nil
	return nil
}

func (vs *VotingService) getLastDKBHash() []byte {
	if len(vs.dkbBlocks) == 0 {
		fmt.Println("Returning empty hash")
		return make([]byte, 32)
	}
	fmt.Println("Returning hash")
	return vs.dkbBlocks[len(vs.dkbBlocks)-1].Hash
}

func (vs *VotingService) getLastEVBHash() []byte {
	if len(vs.evbBlocks) == 0 {
		return make([]byte, 32)
	}
	return vs.evbBlocks[len(vs.evbBlocks)-1].Hash
}

func (vs *VotingService) EndVotingSession() error {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	vs.votingSession.End()

	if len(vs.voteBuffer) > 0 {
		return vs.processBatchedVotes()
	}

	return nil
}

type VoterStatistics struct {
	RegisteredCount int                    `json:"registered_count"`
	VotedCount      int                    `json:"voted_count"`
	VoterDetails    map[string]interface{} `json:"voter_details"`
}

func (vs *VotingService) GetVoterStatistics() *VoterStatistics {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	stats := &VoterStatistics{
		RegisteredCount: len(vs.registeredVoters),
		VotedCount:      len(vs.votedVoters),
		VoterDetails:    make(map[string]interface{}),
	}

	// Add details for each voter
	for voterID := range vs.registeredVoters {
		stats.VoterDetails[voterID] = map[string]interface{}{
			"registered": true,
			"voted":      vs.votedVoters[voterID],
		}
	}

	return stats
}

func ParsePrivateKey(keyStr string) (*ecdsa.PrivateKey, error) {
	// Remove any "0x" prefix if present
	keyStr = strings.TrimPrefix(keyStr, "0x")

	// Decode the hex string to bytes
	keyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key hex string: %w", err)
	}

	// Create private key struct
	privateKey := new(ecdsa.PrivateKey)
	// Using the same curve as in GenerateKeyPair (secp256k1)
	privateKey.Curve = crypto.S256()

	// Set the private key value
	privateKey.D = new(big.Int).SetBytes(keyBytes)

	// Calculate the public key
	privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.Curve.ScalarBaseMult(keyBytes)

	return privateKey, nil
}

func (vs *VotingService) getVoterDetails() map[string]interface{} {
	// Already under mutex lock from GetVoterStatistics
	details := make(map[string]interface{})

	for voterID := range vs.registeredVoters {
		// Get registration from blockchain
		registration, err := vs.getVoterRegistration(voterID)
		if err != nil {
			continue // Skip if we can't find registration details
		}

		details[voterID] = map[string]interface{}{
			"registered":      true,
			"voted":           vs.votedVoters[voterID],
			"timestamp":       registration.Timestamp,
			"public_key_hash": vs.cryptoService.Keccak256(registration.PublicKey),
		}
	}

	return details
}

func (vs *VotingService) GetCountingService() *VoteCountingService {
	return vs.countingService
}

func (vs *VotingService) getVoterRegistration(voterID string) (*models.VoterRegistration, error) {
	for _, block := range vs.dkbBlocks {
		var registration models.VoterRegistration
		if err := json.Unmarshal(block.Data, &registration); err != nil {
			continue
		}
		if registration.VoterID == voterID {
			return &registration, nil
		}
	}
	return nil, errors.New("voter registration not found")
}

func (vs *VotingService) GetRegisteredVoters() map[string]bool {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	// Return a copy of the map
	voters := make(map[string]bool)
	for k, v := range vs.registeredVoters {
		voters[k] = v
	}
	return voters
}

type VoterStats struct {
	RegisteredCount int
	VotedCount      int
	VoterDetails    map[string]interface{}
}

func (vs *VotingService) IsVotingActive() bool {
	return vs.votingSession.IsActive()
}

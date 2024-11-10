package service

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"voting-backend/encryption"
	"voting-backend/models"
	"voting-backend/registry"
	"voting-backend/storage"
)

// Types
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
	adminKey             *ecdsa.PrivateKey
	storagePath          string
	verificationService  *VoterVerificationService
}

type RegisteredVoter struct {
	VoterID    string
	PrivateKey *ecdsa.PrivateKey
}

type AdminCredentials struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type VoterStatistics struct {
	RegisteredCount int                    `json:"registered_count"`
	VotedCount      int                    `json:"voted_count"`
	VoterDetails    map[string]interface{} `json:"voter_details"`
}

type BlockchainResponse struct {
	ChainType  string          `json:"chain_type"`
	BlockCount int             `json:"block_count"`
	Blocks     []*models.Block `json:"blocks"`
	IsValid    bool            `json:"is_valid"`
	LastHash   string          `json:"last_hash"`
}

func loadOrGenerateAdminKey(storagePath string) (*ecdsa.PrivateKey, error) {
	adminKeyPath := filepath.Join(storagePath, "admin_credentials.json")

	// Try to load existing admin credentials
	if data, err := os.ReadFile(adminKeyPath); err == nil {
		var creds AdminCredentials
		if err := json.Unmarshal(data, &creds); err != nil {
			return nil, fmt.Errorf("failed to parse admin credentials: %v", err)
		}

		// Remove "0x" prefix if present
		privateKeyHex := strings.TrimPrefix(creds.PrivateKey, "0x")
		privateKey, err := crypto.HexToECDSA(privateKeyHex)
		if err != nil {
			return nil, fmt.Errorf("failed to restore admin private key: %v", err)
		}

		return privateKey, nil
	}

	// Generate new admin key if none exists
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate admin key: %v", err)
	}

	// Convert keys to hex strings for storage
	privateKeyBytes := crypto.FromECDSA(privateKey)
	publicKeyBytes := crypto.FromECDSAPub(&privateKey.PublicKey)

	// Create and save credentials
	creds := AdminCredentials{
		PublicKey:  hexutil.Encode(publicKeyBytes),
		PrivateKey: hexutil.Encode(privateKeyBytes),
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal admin credentials: %v", err)
	}

	if err := os.WriteFile(adminKeyPath, data, 0600); err != nil {
		return nil, fmt.Errorf("failed to save admin credentials: %v", err)
	}

	return privateKey, nil
}

// Constructor
// Constructor
func NewVotingService(storagePath string) (*VotingService, error) {
	store, err := storage.NewJSONStore(storagePath)
	if err != nil {
		return nil, err
	}

	adminKey, err := loadOrGenerateAdminKey(storagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to setup admin key: %v", err)
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
	cryptoService, err := encryption.NewCryptoService()
	if err != nil {
		return nil, err
	}

	// Initialize mock registry with configuration
	registryConfig := officialRegistryMock.RegistryConfig{
		VotersFilePath: filepath.Join(storagePath, "assets/voters_registry.json"),
		AutoSave:       true,
	}
	registry, err := officialRegistryMock.NewMockVoterRegistry(registryConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize voter registry: %v", err)
	}

	// Load test data into registry
	if err := registry.LoadTestData(); err != nil {
		return nil, fmt.Errorf("failed to load voter registry data: %v", err)
	}

	// Initialize verification service
	verificationService := NewVoterVerificationService(registry)

	session := NewVotingSession(24 * time.Hour)
	anonymizer := NewAnonymizationService(1, 30*time.Minute)
	countingService := NewVoteCountingService(cryptoService, store)

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
		adminKey:             adminKey,
		storagePath:          storagePath,
		verificationService:  verificationService,
	}

	if err := vs.loadInitialVoters(); err != nil {
		return nil, err
	}

	return vs, nil
}

// Load initial voters from blockchain
func (vs *VotingService) loadInitialVoters() error {
	for _, block := range vs.dkbBlocks {
		var registration models.VoterRegistration
		if err := json.Unmarshal(block.Data, &registration); err != nil {
			return err
		}
		vs.registeredVoters[registration.VoterID] = true
	}
	return nil
}

// Voter Registration Methods
func (vs *VotingService) RegisterVoter(identity *models.VoterIdentity) (*RegisteredVoter, error) {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	// 1. Check if voting session is active
	if !vs.votingSession.IsActive() {
		return nil, errors.New("voting registration has ended")
	}

	// 2. Verify voter through verification service
	if err := vs.verificationService.VerifyVoter(identity); err != nil {
		return nil, fmt.Errorf("voter verification failed: %w", err)
	}

	// 3. Get voter details from registry to get unique code
	voterDetails, err := vs.verificationService.officialRegistry.GetVoterDetails(identity.PersonalCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get voter details: %w", err)
	}

	// 4. Check if voter has already registered for voting
	if vs.registeredVoters[voterDetails.UniqueCode] {
		return nil, errors.New("voter has already registered for voting")
	}

	// 5. Generate key pair for the voter
	privateKey, err := vs.cryptoService.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// 6. Create a minimal registration record with only anonymous data
	registration := models.VoterRegistration{
		VoterID:   voterDetails.UniqueCode,
		PublicKey: vs.cryptoService.FromECDSAPub(&privateKey.PublicKey),
		Timestamp: time.Now().Unix(),
	}

	// Save registration and update state
	registrationData, err := json.Marshal(registration)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration data: %w", err)
	}

	block := models.NewBlock(
		uint64(len(vs.dkbBlocks)),
		registrationData,
		vs.getLastDKBHash(),
		1,
	)

	if err := vs.store.SaveBlock("dkb", block); err != nil {
		return nil, fmt.Errorf("failed to save registration to DKB: %w", err)
	}

	vs.dkbBlocks = append(vs.dkbBlocks, block)
	vs.registeredVoters[voterDetails.UniqueCode] = true

	// Return the unique code along with the private key
	return &RegisteredVoter{
		VoterID:    voterDetails.UniqueCode,
		PrivateKey: privateKey,
	}, nil
}

// Vote Casting Methods
func (vs *VotingService) CastVote(voterID string, vote *models.VotePayload, privateKey *ecdsa.PrivateKey) error {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	if !vs.votingSession.IsActive() {
		return errors.New("voting session has ended")
	}

	if err := vs.verifyVoter(voterID); err != nil {
		return err
	}

	// Validate voter-provided nonce
	if err := vs.cryptoService.ValidateNonce(vote.Nonce); err != nil {
		return fmt.Errorf("invalid nonce: %w", err)
	}

	encryptedVote, err := vs.cryptoService.EncryptVoteData(*vote)
	if err != nil {
		return fmt.Errorf("failed to encrypt vote data: %v", err)
	}

	voteRecord := &models.Vote{
		ID:              uuid.New().String(),
		EncryptedChoice: encryptedVote,
		Nonce:           vote.Nonce,
		Timestamp:       time.Now().Unix(),
		PublicKeyHash:   vs.cryptoService.Keccak256(vs.cryptoService.FromECDSAPub(&privateKey.PublicKey)),
	}

	signature, err := vs.cryptoService.Sign(vs.cryptoService.Keccak256(append(encryptedVote, vote.Nonce...)), privateKey)
	if err != nil {
		return err
	}
	voteRecord.Signature = signature

	// Add the vote record to the buffer
	vs.voteBuffer = append(vs.voteBuffer, *voteRecord)
	vs.votedVoters[voterID] = true

	fmt.Printf("Vote buffer size: %d, Batch size: %d\n", len(vs.voteBuffer), vs.anonymizationService.batchSize)

	// Process votes if the buffer size meets the batch requirement
	if len(vs.voteBuffer) >= vs.anonymizationService.batchSize {
		fmt.Println("Processing vote batch...")
		if err := vs.processBatchedVotes(); err != nil {
			return fmt.Errorf("failed to process vote batch: %v", err)
		}
		fmt.Println("Vote batch processed successfully")
	}

	return nil
}

// Blockchain Methods
func (vs *VotingService) GetDKBChain() ([]*models.Block, error) {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	return vs.dkbBlocks, nil
}

func (vs *VotingService) GetEVBChain() ([]*models.Block, error) {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	return vs.evbBlocks, nil
}

func (vs *VotingService) GetBlock(chainType string, index uint64) (*models.Block, error) {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	var blocks []*models.Block
	switch chainType {
	case "dkb":
		blocks = vs.dkbBlocks
	case "evb":
		blocks = vs.evbBlocks
	default:
		return nil, fmt.Errorf("invalid chain type: %s", chainType)
	}

	for _, block := range blocks {
		if block.Index == index {
			return block, nil
		}
	}

	return nil, fmt.Errorf("block not found")
}

func (vs *VotingService) ValidateChains() (bool, bool, error) {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	dkbValid := models.ValidateChain(vs.dkbBlocks)
	evbValid := models.ValidateChain(vs.evbBlocks)

	return dkbValid, evbValid, nil
}

// Helper Methods
func (vs *VotingService) processBatchedVotes() error {
	if len(vs.voteBuffer) == 0 {
		return nil
	}

	fmt.Printf("Processing %d votes\n", len(vs.voteBuffer))

	currentBatch := make([]models.Vote, len(vs.voteBuffer))
	copy(currentBatch, vs.voteBuffer)
	vs.voteBuffer = make([]models.Vote, 0)

	anonymizedVotes := vs.anonymizationService.AnonymizeVotes(currentBatch)

	lastTimestamp := int64(0)
	if len(vs.evbBlocks) > 0 {
		lastTimestamp = vs.evbBlocks[len(vs.evbBlocks)-1].Timestamp
	}

	for _, av := range anonymizedVotes {
		cleanVote := vs.anonymizationService.RemoveVoterSignatures(av)

		voteData, err := json.Marshal(cleanVote)
		if err != nil {
			return fmt.Errorf("failed to marshal vote: %v", err)
		}

		// Ensure unique timestamp
		lastTimestamp = ensureUniqueTimestamp(lastTimestamp)

		block := &models.Block{
			Index:      uint64(len(vs.evbBlocks)),
			Timestamp:  lastTimestamp,
			Data:       voteData,
			PrevHash:   vs.getLastEVBHash(),
			Difficulty: 1,
		}

		block.Mine()

		if err := vs.store.SaveBlock("evb", block); err != nil {
			return fmt.Errorf("failed to save vote block: %v", err)
		}

		vs.evbBlocks = append(vs.evbBlocks, block)
		fmt.Printf("Added block %d to EVB chain with timestamp %d\n",
			block.Index, block.Timestamp)
	}

	fmt.Println("Batch processing completed")
	return nil
}

func ensureUniqueTimestamp(lastTimestamp int64) int64 {
	currentTime := time.Now().Unix()
	if currentTime <= lastTimestamp {
		return lastTimestamp + 1
	}
	return currentTime
}

func (vs *VotingService) FlushVoteBuffer() error {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	if len(vs.voteBuffer) > 0 {
		return vs.processBatchedVotes()
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

func (vs *VotingService) getLastDKBHash() []byte {
	if len(vs.dkbBlocks) == 0 {
		return make([]byte, 32)
	}
	return vs.dkbBlocks[len(vs.dkbBlocks)-1].Hash
}

func (vs *VotingService) getLastEVBHash() []byte {
	if len(vs.evbBlocks) == 0 {
		return make([]byte, 32)
	}
	return vs.evbBlocks[len(vs.evbBlocks)-1].Hash
}

// Admin Methods
func (vs *VotingService) GetAdminCredentials() (*AdminCredentials, error) {
	adminKeyPath := filepath.Join(vs.storagePath, "admin_credentials.json")
	data, err := os.ReadFile(adminKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read admin credentials: %v", err)
	}

	var creds AdminCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse admin credentials: %v", err)
	}

	return &creds, nil
}

func (vs *VotingService) GetAdminPublicKey() string {
	return crypto.PubkeyToAddress(vs.adminKey.PublicKey).Hex()
}

// Status Methods
func (vs *VotingService) GetVoterStatistics() *VoterStatistics {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	stats := &VoterStatistics{
		RegisteredCount: len(vs.registeredVoters),
		VotedCount:      len(vs.votedVoters),
		VoterDetails:    make(map[string]interface{}),
	}

	for voterID := range vs.registeredVoters {
		stats.VoterDetails[voterID] = map[string]interface{}{
			"registered": true,
			"voted":      vs.votedVoters[voterID],
		}
	}

	return stats
}

func (vs *VotingService) IsVotingActive() bool {
	return vs.votingSession.IsActive()
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
func (vs *VotingService) GetCountingService() *VoteCountingService {
	return vs.countingService
}

func (vs *VotingService) GetRegisteredVoters() map[string]bool {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	voters := make(map[string]bool)
	for k, v := range vs.registeredVoters {
		voters[k] = v
	}
	return voters
}

// ParsePrivateKey helper function
func ParsePrivateKey(keyStr string) (*ecdsa.PrivateKey, error) {
	// Remove "0x" prefix if present
	keyStr = strings.TrimPrefix(keyStr, "0x")

	// Decode the hex string to bytes
	keyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key hex string: %w", err)
	}

	privateKey, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

func (vs *VotingService) GetVoterUniqueCode(personalCode string) (string, error) {
	voterDetails, err := vs.verificationService.officialRegistry.GetVoterDetails(personalCode)
	if err != nil {
		return "", fmt.Errorf("failed to get voter details: %w", err)
	}
	return voterDetails.UniqueCode, nil
}

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

type VoteCastResult struct {
	VoteID    string `json:"vote_id"`
	Timestamp int64  `json:"timestamp"`
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
	cryptoService, err := encryption.NewCryptoService(filepath.Join(storagePath, "assets"))
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
	anonymizer := NewAnonymizationService(5, 30*time.Minute)
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

	// 1. Check voting session and voter verification
	if !vs.votingSession.IsActive() {
		return errors.New("voting session has ended")
	}

	if err := vs.verifyVoter(voterID); err != nil {
		return err
	}

	// 2. Validate nonce
	if err := vs.cryptoService.ValidateNonce(vote.Nonce); err != nil {
		return fmt.Errorf("invalid nonce: %w", err)
	}

	// 3. Encrypt vote with homomorphic encryption
	encryptedVote, err := vs.cryptoService.EncryptVoteData(*vote)
	if err != nil {
		return fmt.Errorf("failed to encrypt vote data: %v", err)
	}

	// 4. Create vote record
	voteID := uuid.New().String()
	timestamp := time.Now().Unix()

	voteRecord := &models.Vote{
		ID:              voteID,
		EncryptedChoice: encryptedVote, // This now contains the VoteEncryptionPackage
		Nonce:           vote.Nonce,
		Timestamp:       timestamp,
		PrivateKeyHash:  vs.cryptoService.Keccak256(crypto.FromECDSA(privateKey)),
	}

	// 5. Sign the encrypted vote
	signatureData := append(encryptedVote, vote.Nonce...)
	signature, err := vs.cryptoService.Sign(vs.cryptoService.Keccak256(signatureData), privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign vote: %v", err)
	}
	voteRecord.Signature = signature

	// 6. Add to buffer for batch processing
	vs.voteBuffer = append(vs.voteBuffer, *voteRecord)
	vs.votedVoters[voterID] = true

	// 7. Process batch if buffer is full
	if len(vs.voteBuffer) >= vs.anonymizationService.batchSize {
		if err := vs.processBatchedVotes(); err != nil {
			return fmt.Errorf("failed to process vote batch: %v", err)
		}
	}

	return nil
}

func (vs *VotingService) GetFinalResults() (*VotingResults, error) {
	if vs.votingSession.IsActive() {
		return nil, errors.New("voting is still active, final results not available")
	}

	// Get the encrypted results first
	results, err := vs.GetCountingService().CountVotes()
	if err != nil {
		return nil, err
	}

	// Debug: Dump the current mappings
	vs.cryptoService.DumpChoiceMapping()

	// Create new results with revealed choices
	revealedResults := make(map[string]int64)

	// Get the mapping
	choiceMapping := vs.cryptoService.GetChoiceMapping()

	fmt.Printf("\nProcessing final results:\n")
	for hash, count := range results.Results {
		fmt.Printf("Processing hash: %s (count: %d)\n", hash, count)

		if candidateName, exists := choiceMapping[hash]; exists {
			fmt.Printf("Found mapping: %s -> %s\n", hash, candidateName)
			revealedResults[candidateName] = count
		} else {
			fmt.Printf("No mapping found for hash: %s\n", hash)
			revealedResults[fmt.Sprintf("Unknown-%s", hash)] = count
		}
	}

	return &VotingResults{
		TotalVotes:     results.TotalVotes,
		Results:        revealedResults,
		ProcessedVotes: results.ProcessedVotes,
	}, nil
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

	fmt.Printf("Processing batch of %d votes\n", len(vs.voteBuffer))

	// 1. Create a copy of current batch
	currentBatch := make([]models.Vote, len(vs.voteBuffer))
	copy(currentBatch, vs.voteBuffer)
	vs.voteBuffer = make([]models.Vote, 0)

	// 2. Anonymize the votes (shuffling timestamps, etc.)
	anonymizedVotes := vs.anonymizationService.AnonymizeVotes(currentBatch)

	lastTimestamp := int64(0)
	if len(vs.evbBlocks) > 0 {
		lastTimestamp = vs.evbBlocks[len(vs.evbBlocks)-1].Timestamp
	}

	// 3. Process each anonymized vote
	for _, av := range anonymizedVotes {
		// Debug log
		fmt.Printf("Processing vote ID: %s\n", av.ID)

		var votePackage encryption.VoteEncryptionPackage
		// First unmarshal the current encryption package
		if err := json.Unmarshal(av.EncryptedChoice, &votePackage); err != nil {
			fmt.Printf("Failed to unmarshal vote package: %v\n", err)
			return fmt.Errorf("failed to unmarshal vote package: %v", err)
		}

		// Create stripped package with only homomorphic data
		strippedPackage := encryption.VoteEncryptionPackage{
			HomomorphicVoteData: votePackage.HomomorphicVoteData,
			Nonce:               av.Nonce,
			// Omit other fields to strip voter data
		}

		// Marshal the stripped package
		strippedData, err := json.Marshal(strippedPackage)
		if err != nil {
			fmt.Printf("Failed to marshal stripped package: %v\n", err)
			return fmt.Errorf("failed to marshal stripped package: %v", err)
		}

		// Create clean vote
		cleanVote := models.Vote{
			ID:              av.ID,
			EncryptedChoice: strippedData,
			Nonce:           av.Nonce,
			Timestamp:       ensureUniqueTimestamp(lastTimestamp),
			PrivateKeyHash:  av.PrivateKeyHash,
		}

		// Debug log
		fmt.Printf("Created clean vote with ID: %s\n", cleanVote.ID)

		voteData, err := json.Marshal(cleanVote)
		if err != nil {
			fmt.Printf("Failed to marshal clean vote: %v\n", err)
			return fmt.Errorf("failed to marshal vote: %v", err)
		}

		// Create and mine new block
		block := &models.Block{
			Index:      uint64(len(vs.evbBlocks)),
			Timestamp:  cleanVote.Timestamp,
			Data:       voteData,
			PrevHash:   vs.getLastEVBHash(),
			Difficulty: 2,
		}

		block.Mine()

		// Save block
		if err := vs.store.SaveBlock("evb", block); err != nil {
			fmt.Printf("Failed to save block: %v\n", err)
			return fmt.Errorf("failed to save vote block: %v", err)
		}

		vs.evbBlocks = append(vs.evbBlocks, block)
		lastTimestamp = block.Timestamp

		fmt.Printf("Successfully processed and saved vote ID: %s\n", cleanVote.ID)
	}

	fmt.Printf("Successfully processed batch of %d votes\n", len(anonymizedVotes))
	return nil
}

func (vs *VotingService) ReloadChains() error {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	// Force reload from disk
	if err := vs.store.ReloadAllChains(); err != nil {
		return fmt.Errorf("failed to reload chains from disk: %w", err)
	}

	// Reload DKB chain
	dkbBlocks, err := vs.store.LoadChain("dkb")
	if err != nil {
		return fmt.Errorf("failed to reload DKB chain: %w", err)
	}

	//// Validate DKB chain
	//if !models.ValidateChain(dkbBlocks) {
	//	return fmt.Errorf("reloaded DKB chain is invalid")
	//}
	vs.dkbBlocks = dkbBlocks

	// Reload EVB chain
	evbBlocks, err := vs.store.LoadChain("evb")
	if err != nil {
		return fmt.Errorf("failed to reload EVB chain: %w", err)
	}

	//// Validate EVB chain
	//if !models.ValidateChain(evbBlocks) {
	//	return fmt.Errorf("reloaded EVB chain is invalid")
	//}
	vs.evbBlocks = evbBlocks

	// Rebuild the registered voters map from DKB
	vs.registeredVoters = make(map[string]bool)
	vs.votedVoters = make(map[string]bool)

	// Reload registered voters from DKB chain
	if err := vs.loadInitialVoters(); err != nil {
		return fmt.Errorf("failed to reload registered voters: %w", err)
	}

	// Rebuild voted voters from EVB chain
	for _, block := range evbBlocks {
		var vote models.Vote
		if err := json.Unmarshal(block.Data, &vote); err != nil {
			continue
		}
		// Mark voter as having voted based on their public key hash
		if len(vote.PrivateKeyHash) > 0 {
			vs.votedVoters[hex.EncodeToString(vote.PrivateKeyHash)] = true
		}
	}

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

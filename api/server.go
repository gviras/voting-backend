// File: api/server.go
package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"log"

	"github.com/roasbeef/go-go-gadget-paillier"
	"voting-backend/anonymizer"
	"voting-backend/blockchain/dkb"
	"voting-backend/blockchain/evb"
	"voting-backend/models"
	"voting-backend/storage"
)

type ECDSASignature struct {
	R, S *big.Int
}

type BlockVerification struct {
	CalculatedHash string `json:"calculated_hash"`
	StoredHash     string `json:"stored_hash"`
	HashMatch      bool   `json:"hash_match"`
}

type BlockDetailsResponse struct {
	BlockType    string            `json:"block_type"`
	Block        interface{}       `json:"block"`
	IsValid      bool              `json:"is_valid"`
	Verification BlockVerification `json:"verification"`
}

type Server struct {
	dkbChain        *dkb.DKB
	evbChain        *evb.EVB
	anon            *anonymizer.Anonymizer
	mutex           sync.RWMutex
	candidates      map[string]bool // Track valid candidates
	storage         *storage.BlockchainStorage
	paillierPrivKey *paillier.PrivateKey
	paillierPubKey  *paillier.PublicKey
}

type VoterCredentials struct {
	PrivateKey []byte
	PublicKey  []byte
	VoterID    string
}

type RegisterVoterRequest struct {
	VoterID string `json:"voter_id"`
}

type RegisterVoterResponse struct {
	VoterID    string `json:"voter_id"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type CastVoteRequest struct {
	VoterID       string `json:"voter_id"`
	SignedBallot  []byte `json:"signed_ballot"`  // Ballot signed with voter's private key
	VoteSignature []byte `json:"vote_signature"` // Digital signature of the vote
	Candidate     string `json:"candidate"`
}

type VotingResults struct {
	Results map[string]int `json:"results"`
	Total   int            `json:"total_votes"`
}

type BlockchainResponse struct {
	DKBChain struct {
		Blocks   []models.DistributedKeyBlock `json:"blocks"`
		Length   int                          `json:"length"`
		IsValid  bool                         `json:"is_valid"`
		LastHash string                       `json:"last_hash"`
	} `json:"dkb_chain"`
	EVBChain struct {
		Blocks   []models.EncryptedVoteBlock `json:"blocks"`
		Length   int                         `json:"length"`
		IsValid  bool                        `json:"is_valid"`
		LastHash string                      `json:"last_hash"`
	} `json:"evb_chain"`
}

type ValidationError struct {
	BlockIndex int    `json:"block_index"`
	Chain      string `json:"chain"`
	Error      string `json:"error"`
	Expected   string `json:"expected,omitempty"`
	Actual     string `json:"actual,omitempty"`
	VoterID    string `json:"voter_id,omitempty"`
	VoteHash   string `json:"vote_hash,omitempty"`
}

func NewServer() *Server {
	storage, err := storage.New("blockchain_data")
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	// Initialize candidates
	initialCandidates := []string{"candidate1", "candidate2", "candidate3"}
	candidateMap := make(map[string]bool)
	for _, c := range initialCandidates {
		candidateMap[c] = true
	}

	// Generate Paillier key pair
	paillierPrivKey, err := paillier.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate Paillier key pair: %v", err)
	}
	paillierPubKey := &paillierPrivKey.PublicKey // Extract public key from private key

	// Create DKB chain
	dkbChain := dkb.New(storage)
	// Load existing DKB chain if available
	existingDKBChain, err := storage.LoadLatestDKBChain()
	if err != nil {
		log.Printf("Warning: Failed to load DKB chain: %v", err)
	} else if existingDKBChain != nil && len(existingDKBChain) > 0 {
		log.Printf("Loaded DKB chain with %d blocks", len(existingDKBChain))
		dkbChain.Chain = existingDKBChain
	}

	// Create EVB chain
	evbChain := evb.New(storage)
	// Load existing EVB chain if available
	existingEVBChain, err := storage.LoadLatestEVBChain()
	if err != nil {
		log.Printf("Warning: Failed to load EVB chain: %v", err)
	} else if existingEVBChain != nil && len(existingEVBChain) > 0 {
		log.Printf("Loaded EVB chain with %d blocks", len(existingEVBChain))
		evbChain.Chain = existingEVBChain
	}

	server := &Server{
		dkbChain:        dkbChain,
		evbChain:        evbChain,
		anon:            anonymizer.New(),
		candidates:      candidateMap,
		storage:         storage,
		paillierPubKey:  paillierPubKey,  // Public key for encrypting votes
		paillierPrivKey: paillierPrivKey, // Private key for decryption
	}

	// Force initial save to ensure file exists
	if err := storage.SaveDKBChain(dkbChain.Chain); err != nil {
		log.Printf("Warning: Failed to save initial DKB chain: %v", err)
	}
	if err := storage.SaveEVBChain(evbChain.Chain); err != nil {
		log.Printf("Warning: Failed to save initial EVB chain: %v", err)
	}

	return server
}

func (s *Server) startPeriodicSave() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			s.mutex.Lock()
			if err := s.storage.SaveDKBChain(s.dkbChain.Chain); err != nil {
				log.Printf("Failed to save DKB chain: %v", err)
			}
			if err := s.storage.SaveEVBChain(s.evbChain.Chain); err != nil {
				log.Printf("Failed to save EVB chain: %v", err)
			}
			s.mutex.Unlock()
		}
	}()
}

func (s *Server) Start() error {
	s.startPeriodicSave()

	// Register routes
	http.HandleFunc("/api/register", s.handleRegisterVoter)
	http.HandleFunc("/api/vote", s.handleCastVote)
	http.HandleFunc("/api/results", s.handleGetResults)
	http.HandleFunc("/api/voters", s.handleGetVoters)
	http.HandleFunc("/api/candidates", s.handleGetCandidates)
	http.HandleFunc("/api/blockchain", s.handleGetBlockchain)
	http.HandleFunc("/api/block", s.handleGetBlockDetails)
	http.HandleFunc("/api/validate", s.handleValidateBlockchain) // Add validation endpoint
	http.HandleFunc("/api/verify_vote", s.handleVerifyVote)

	return http.ListenAndServe(":8080", nil)
}

func (s *Server) handleRegisterVoter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterVoterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	publicKey, privateKey, err := s.dkbChain.GenerateVoterKeyPair(req.VoterID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create response with public key stored and private key sent to the client
	response := RegisterVoterResponse{
		VoterID:    req.VoterID,
		PublicKey:  hex.EncodeToString(elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)),
		PrivateKey: hex.EncodeToString(privateKey.D.Bytes()), // This should only be sent to the client
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleGetBlockDetails(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	blockHash := r.URL.Query().Get("hash")
	if blockHash == "" {
		http.Error(w, "Block hash is required", http.StatusBadRequest)
		return
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Search in DKB Chain
	for _, block := range s.dkbChain.Chain {
		if block.Hash == blockHash {
			calculatedHash := calculateBlockHash(block)
			response := BlockDetailsResponse{
				BlockType: "DKB",
				Block:     block,
				IsValid:   calculatedHash == block.Hash,
				Verification: BlockVerification{
					CalculatedHash: calculatedHash,
					StoredHash:     block.Hash,
					HashMatch:      calculatedHash == block.Hash,
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}
	}

	// Search in EVB Chain
	for _, block := range s.evbChain.Chain {
		if block.Hash == blockHash {
			calculatedHash := calculateBlockHash(block)
			response := BlockDetailsResponse{
				BlockType: "EVB",
				Block:     block,
				IsValid:   calculatedHash == block.Hash,
				Verification: BlockVerification{
					CalculatedHash: calculatedHash,
					StoredHash:     block.Hash,
					HashMatch:      calculatedHash == block.Hash,
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}
	}

	http.Error(w, "Block not found", http.StatusNotFound)
}

func (s *Server) handleCastVote(w http.ResponseWriter, r *http.Request) {
	var req CastVoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate voter
	voter, err := s.dkbChain.GetVoter(req.VoterID)
	if err != nil {
		http.Error(w, "Invalid voter", http.StatusBadRequest)
		return
	}

	if voter.HasVoted {
		http.Error(w, "Voter has already voted", http.StatusBadRequest)
		return
	}

	// Encrypt the candidate using the Paillier public key
	encryptedVote, err := paillier.Encrypt(s.paillierPubKey, []byte(req.Candidate))
	if err != nil {
		log.Printf("Failed to encrypt vote: %v", err)
		http.Error(w, "Encryption error", http.StatusInternalServerError)
		return
	}

	// Generate a hash for the encrypted vote for verification purposes
	voteHash := hashVote(encryptedVote)

	// Submit the encrypted vote to the blockchain
	s.evbChain.SubmitVote(models.EncryptedVote{
		EncryptedBallot: encryptedVote,
		VoteHash:        voteHash,
		Timestamp:       time.Now().Unix(),
	})

	// Mark voter as having voted
	if err := s.dkbChain.MarkVoterHasVoted(req.VoterID); err != nil {
		log.Printf("Failed to mark voter as voted: %v", err)
		http.Error(w, "Failed to update voter status", http.StatusInternalServerError)
		return
	}

	// Respond with success and vote verification hash
	response := struct {
		Success  bool   `json:"success"`
		VoteHash string `json:"vote_hash"` // Return the hash to verify vote submission
	}{
		Success:  true,
		VoteHash: voteHash,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func hashVote(ballot []byte) string {
	hash := sha256.Sum256(ballot)
	return hex.EncodeToString(hash[:])
}

func (s *Server) validateVoteStructure(vote models.EncryptedVote) error {
	if len(vote.EncryptedBallot) == 0 {
		return fmt.Errorf("empty encrypted ballot")
	}

	// Use dummy key to create GCM just for nonce size check
	block, err := aes.NewCipher(generateRandomBytes(32))
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %v", err)
	}

	if len(vote.Nonce) != gcm.NonceSize() {
		return fmt.Errorf("invalid nonce size: expected %d, got %d",
			gcm.NonceSize(), len(vote.Nonce))
	}

	if vote.Timestamp == 0 {
		return fmt.Errorf("missing timestamp")
	}

	if vote.VoteHash == "" {
		return fmt.Errorf("missing vote hash")
	}

	// Verify timestamp is not in future
	if vote.Timestamp > time.Now().Add(5*time.Minute).Unix() {
		return fmt.Errorf("vote timestamp is in future")
	}

	return nil
}

func (s *Server) RegisterCandidate(candidate string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.candidates[candidate] = true
}

func (s *Server) handleGetResults(w http.ResponseWriter, r *http.Request) {
	results := s.countVotes()

	totalVotes := 0
	for _, count := range results {
		totalVotes += count
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Results    map[string]int `json:"results"`
		TotalVotes int            `json:"total_votes"`
	}{
		Results:    results,
		TotalVotes: totalVotes,
	})
}

func (s *Server) handleGetVoters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	type VoterInfo struct {
		VoterID  string `json:"voter_id"`
		HasVoted bool   `json:"has_voted"`
		IssuedAt int64  `json:"issued_at"`
	}

	voters := make([]VoterInfo, 0)

	// Get all voters using the new method
	for _, key := range s.dkbChain.GetAllVoters() {
		voters = append(voters, VoterInfo{
			VoterID:  key.VoterID,
			HasVoted: key.HasVoted,
			IssuedAt: key.IssuedAt,
		})
	}

	response := struct {
		Voters []VoterInfo `json:"voters"`
		Count  int         `json:"total_voters"`
	}{
		Voters: voters,
		Count:  len(voters),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleGetCandidates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	candidates := make([]string, 0, len(s.candidates))
	for candidate := range s.candidates {
		candidates = append(candidates, candidate)
	}

	response := struct {
		Candidates []string `json:"candidates"`
		Count      int      `json:"total_candidates"`
	}{
		Candidates: candidates,
		Count:      len(candidates),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) countVotes() map[string]int {
	aggregatedResults := make(map[string]*big.Int)

	// Initialize counts for each candidate
	for candidate := range s.candidates {
		aggregatedResults[candidate] = big.NewInt(0)
	}

	for _, vote := range s.evbChain.GetAllVotes() {
		decryptedVote, err := paillier.Decrypt(s.paillierPrivKey, vote.EncryptedBallot)
		if err != nil {
			log.Printf("Failed to decrypt vote: %v", err)
			continue
		}

		// Convert the decrypted bytes to string representation of the candidate
		candidate := string(decryptedVote)
		if _, exists := aggregatedResults[candidate]; exists {
			aggregatedResults[candidate].Add(aggregatedResults[candidate], big.NewInt(1))
		} else {
			log.Printf("Invalid candidate detected in decrypted vote: %s", candidate)
		}
	}

	// Convert result to a simple map of counts
	finalResults := make(map[string]int)
	for candidate, count := range aggregatedResults {
		finalResults[candidate] = int(count.Int64())
	}

	return finalResults
}
func (s *Server) encryptBallot(ballotBytes []byte) []byte {
	// Generate a random key for encryption
	key := generateRandomBytes(32)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("Warning: Failed to create cipher: %v", err)
		return nil
	}

	// Create GCM - handle error properly
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("Warning: Failed to create GCM: %v", err)
		return nil
	}

	nonce := generateRandomBytes(gcm.NonceSize())

	// Encrypt and combine nonce with ciphertext
	return gcm.Seal(nonce, nonce, ballotBytes, nil)
}

func (s *Server) decryptVote(vote models.EncryptedVote) models.Ballot {
	// Example AES key for illustration purposes (ensure this is securely handled in practice)
	key := generateRandomBytes(32) // Replace with the correct key retrieval

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("Error creating cipher: %v", err)
		return models.Ballot{}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("Error creating GCM: %v", err)
		return models.Ballot{}
	}

	if len(vote.EncryptedBallot) < gcm.NonceSize() {
		log.Printf("Invalid encrypted data size")
		return models.Ballot{}
	}

	nonce, ciphertext := vote.EncryptedBallot[:gcm.NonceSize()], vote.EncryptedBallot[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Printf("Decryption failed: %v", err)
		return models.Ballot{}
	}

	var ballot models.Ballot
	if err := json.Unmarshal(plaintext, &ballot); err != nil {
		log.Printf("Failed to unmarshal decrypted ballot: %v", err)
		log.Printf("Raw plaintext: %s", plaintext)
		return models.Ballot{}
	}

	return ballot
}

func (s *Server) createEncryptedVote(ballot *models.Ballot, publicKey []byte) models.EncryptedVote {
	// Convert ballot to bytes
	ballotBytes, err := json.Marshal(ballot)
	if err != nil {
		log.Printf("Warning: Failed to marshal ballot: %v", err)
		return models.EncryptedVote{}
	}

	// Generate AES key
	aesKey := generateRandomBytes(32)

	// Encrypt ballot
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := generateRandomBytes(gcm.NonceSize())
	ciphertext := gcm.Seal(nil, nonce, ballotBytes, nil)

	// Create vote record
	return models.EncryptedVote{
		EncryptedBallot: ciphertext,
		Nonce:           nonce,
		VoteHash:        hashVote(ballotBytes),
		Timestamp:       time.Now().Unix(),
	}
}

// Helper functions
func generateRandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func hashPrivateKey(privateKey []byte) string {
	hash := sha256.Sum256(privateKey)
	return hex.EncodeToString(hash[:])
}

func (s *Server) validateDKBChain() bool {
	return s.dkbChain.ValidateChain()
}

func (s *Server) validateEVBChain() bool {
	return s.evbChain.ValidateChain()
}

func (s *Server) handleGetBlockchain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	dkbValid := s.validateDKBChain()
	evbValid := s.validateEVBChain()

	response := BlockchainResponse{}

	// DKB Chain
	response.DKBChain.Blocks = s.dkbChain.Chain
	response.DKBChain.Length = len(s.dkbChain.Chain)
	response.DKBChain.IsValid = dkbValid
	if len(s.dkbChain.Chain) > 0 {
		response.DKBChain.LastHash = s.dkbChain.Chain[len(s.dkbChain.Chain)-1].Hash
	}

	// EVB Chain
	response.EVBChain.Blocks = s.evbChain.Chain
	response.EVBChain.Length = len(s.evbChain.Chain)
	response.EVBChain.IsValid = evbValid
	if len(s.evbChain.Chain) > 0 {
		response.EVBChain.LastHash = s.evbChain.Chain[len(s.evbChain.Chain)-1].Hash
	}

	if !dkbValid {
		log.Println("Warning: DKB chain validation failed")
	}
	if !evbValid {
		log.Println("Warning: EVB chain validation failed")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func calculateBlockHash(block interface{}) string {
	data, err := json.Marshal(block)
	if err != nil {
		return ""
	}

	// Create a copy of the data without the hash field to prevent circular reference
	var blockMap map[string]interface{}
	if err := json.Unmarshal(data, &blockMap); err != nil {
		return ""
	}

	// Remove the hash field before calculating
	delete(blockMap, "Hash")

	// Marshal again without the hash field
	data, err = json.Marshal(blockMap)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (s *Server) handleValidateBlockchain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	isValid, errors := s.verifyBlockchainValidity()

	response := struct {
		IsValid bool              `json:"is_valid"`
		Errors  []ValidationError `json:"errors,omitempty"`
	}{
		IsValid: isValid,
		Errors:  errors,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) verifyBlockchainValidity() (bool, []ValidationError) {
	var errors []ValidationError

	// 1. Verify DKB Chain
	for i := 1; i < len(s.dkbChain.Chain); i++ {
		block := s.dkbChain.Chain[i]
		prevBlock := s.dkbChain.Chain[i-1]

		// Check hash linking
		if block.PrevHash != prevBlock.Hash {
			errors = append(errors, ValidationError{
				BlockIndex: i,
				Chain:      "DKB",
				Error:      "Invalid hash link",
				Expected:   prevBlock.Hash,
				Actual:     block.PrevHash,
			})
		}

		// Verify block hash
		calculatedHash := calculateBlockHash(block)
		if calculatedHash != block.Hash {
			errors = append(errors, ValidationError{
				BlockIndex: i,
				Chain:      "DKB",
				Error:      "Invalid block hash",
				Expected:   block.Hash,
				Actual:     calculatedHash,
			})
		}

		// Verify voter records
		for _, voter := range block.VoterKeys {
			if !dkb.ValidatePublicKey(voter.PublicKey) {
				errors = append(errors, ValidationError{
					BlockIndex: i,
					Chain:      "DKB",
					Error:      "Invalid public key",
					VoterID:    voter.VoterID,
				})
			}
		}
	}

	// 2. Verify EVB Chain
	for i := 1; i < len(s.evbChain.Chain); i++ {
		block := s.evbChain.Chain[i]
		prevBlock := s.evbChain.Chain[i-1]

		if block.PrevHash != prevBlock.Hash {
			errors = append(errors, ValidationError{
				BlockIndex: i,
				Chain:      "EVB",
				Error:      "Invalid hash link",
				Expected:   prevBlock.Hash,
				Actual:     block.PrevHash,
			})
		}

		// Verify each vote in the block
		for _, vote := range block.EncryptedVotes {
			if err := s.validateVoteStructure(vote); err != nil {
				errors = append(errors, ValidationError{
					BlockIndex: i,
					Chain:      "EVB",
					Error:      err.Error(),
					VoteHash:   vote.VoteHash,
				})
			}
		}
	}

	return len(errors) == 0, errors
}

func (s *Server) handleVerifyVote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	voteHash := r.URL.Query().Get("vote_hash")
	if voteHash == "" {
		http.Error(w, "Vote hash is required", http.StatusBadRequest)
		return
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Search for the vote in the blockchain
	for _, block := range s.evbChain.Chain {
		for _, vote := range block.EncryptedVotes {
			if vote.VoteHash == voteHash {
				// Vote found, respond with the vote details and validation status
				response := struct {
					Found        bool   `json:"found"`
					VoteHash     string `json:"vote_hash"`
					BlockHash    string `json:"block_hash"`
					Timestamp    int64  `json:"timestamp"`
					Verification bool   `json:"verification"`
				}{
					Found:        true,
					VoteHash:     vote.VoteHash,
					BlockHash:    block.Hash,
					Timestamp:    vote.Timestamp,
					Verification: true, // If found in the blockchain, it's valid
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
				return
			}
		}
	}

	// Vote not found
	response := struct {
		Found bool   `json:"found"`
		Error string `json:"error"`
	}{
		Found: false,
		Error: "Vote not found in the blockchain",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

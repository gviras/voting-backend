package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"voting-backend/encryption"
	"voting-backend/models"
	"voting-backend/service"
)

// AlgorithmPerformanceMetrics tracks detailed metrics about cryptographic operations
type AlgorithmPerformanceMetrics struct {
	SchemeDescription   string
	RegistrationMetrics OperationMetrics
	VotingMetrics       OperationMetrics
	CountingMetrics     OperationMetrics
	TotalProcessingTime time.Duration
	ResponseTimes       []time.Duration // Client-perceived response times
	MemoryUsage         uint64
}

// OperationMetrics stores timing metrics for a specific cryptographic operation
type OperationMetrics struct {
	APILatency     time.Duration // Time to get API response (client-perceived)
	ProcessingTime time.Duration // Actual server processing time
	Success        int
	Failure        int
	ThroughputAPI  float64 // Operations per second (client-perceived)
	ThroughputProc float64 // Operations per second (actual processing)
}

type Config struct {
	StorageDir      string
	SessionDuration time.Duration
	BatchSize       int
	MixWindow       time.Duration
	Difficulty      uint8
	Port            int
}

type RegisterVoterRequest struct {
	PersonalCode string `json:"personal_code"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	DateOfBirth  string `json:"date_of_birth"` // Format: "2006-01-02"
	Citizenship  string `json:"citizenship"`
	Address      string `json:"address"`
	Declaration  bool   `json:"declaration"`
}

type RegisterVoterResponse struct {
	VoterID    string `json:"voter_id"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type CastVoteRequest struct {
	VoterID    string `json:"voter_id"`
	Candidate  string `json:"candidate"`
	PrivateKey string `json:"private_key"`
	Nonce      string `json:"nonce"`
}

type CountVotesRequest struct {
	PrivateKey string `json:"private_key"` // Election admin's private key
}

type Server struct {
	votingService *service.VotingService
}

type AdminCredsResponse struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type BlockchainStatusResponse struct {
	DKBChain *ChainInfo `json:"dkb_chain"`
	EVBChain *ChainInfo `json:"evb_chain"`
}

type BlockchainResponse struct {
	ChainType  string          `json:"chain_type"`
	BlockCount int             `json:"block_count"`
	Blocks     []*models.Block `json:"blocks"`
	IsValid    bool            `json:"is_valid"`
	LastHash   string          `json:"last_hash"`
}

type BlockResponse struct {
	Index       uint64 `json:"index"`
	Timestamp   int64  `json:"timestamp"`
	DataHex     string `json:"data_hex"`
	DataDecoded string `json:"data_decoded,omitempty"`
	PrevHash    string `json:"prev_hash"`
	Hash        string `json:"hash"`
	Nonce       uint64 `json:"nonce"`
	Difficulty  uint8  `json:"difficulty"`
}

type ChainInfo struct {
	Length   int         `json:"length"`
	IsValid  bool        `json:"is_valid"`
	LastHash string      `json:"last_hash"`
	Blocks   []BlockInfo `json:"blocks"`
}

type BlockInfo struct {
	Index     uint64 `json:"index"`
	Timestamp int64  `json:"timestamp"`
	Hash      string `json:"hash"`
	PrevHash  string `json:"prev_hash"`
	Data      string `json:"data"`
	Nonce     uint64 `json:"nonce"`
}

type VerifyVoteRequest struct {
	PrivateKey string `json:"private_key"`
}

func main() {
	config := parseFlags()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if err := setupStorageDirectory(config.StorageDir); err != nil {
		log.Fatalf("Failed to setup storage: %v", err)
	}

	votingService, err := initializeVotingService(config)
	//votingService.EnableQueueProcessing(1, 1000, 0)
	if err != nil {
		log.Fatalf("Failed to initialize voting service: %v", err)
	}

	server := &Server{votingService: votingService}

	// Set up HTTP routes
	http.HandleFunc("/api/register", server.handleRegisterVoter)
	http.HandleFunc("/api/vote", server.handleCastVote)
	http.HandleFunc("/api/status", server.handleGetStatus)
	http.HandleFunc("/api/end-session", server.handleEndSession)
	// Vote counting endpoints
	http.HandleFunc("/api/count-votes", server.handleCountVotes)
	http.HandleFunc("/api/results", server.handleGetResults)
	http.HandleFunc("/api/verify-count", server.handleVerifyCount)
	http.HandleFunc("/api/verify/vote-details", server.handleVerifyVoteDetails)
	http.HandleFunc("/api/final-results", server.handleGetFinalResults)

	// Admin
	http.HandleFunc("/api/admin/credentials", server.handleGetAdminCredentials)

	//Chain
	http.HandleFunc("/api/blockchain/dkb", server.handleGetDKBChain)
	http.HandleFunc("/api/blockchain/evb", server.handleGetEVBChain)
	http.HandleFunc("/api/blockchain/block", server.handleGetBlock)
	http.HandleFunc("/api/blockchain/validate", server.handleValidateChains)
	http.HandleFunc("/api/blockchain/status", server.handleGetBlockchainStatus)
	http.HandleFunc("/api/blockchain/reload", server.handleReloadChains)

	//Metrics
	// Metrics and performance endpoints
	http.HandleFunc("/api/metrics", server.handleGetMetrics)
	http.HandleFunc("/api/metrics/reset", server.handleResetMetrics)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	// Start server in a goroutine
	serverChan := make(chan error, 1)
	go func() {
		log.Printf("Starting server on port %d...\n", config.Port)
		serverChan <- http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil)
	}()

	// Wait for shutdown signal or server error
	select {
	case err := <-serverChan:
		log.Fatalf("Server error: %v", err)
	case sig := <-sigChan:
		log.Printf("Received signal: %v\n", sig)
		if err := votingService.EndVotingSession(); err != nil {
			log.Printf("Error during session cleanup: %v", err)
		}
		log.Println("Server shutdown completed")
	}
}

func (s *Server) handleRegisterVoter(w http.ResponseWriter, r *http.Request) {
	var req RegisterVoterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validation steps remain the same
	if err := validateRegistrationRequest(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Parse date
	dateOfBirth, err := time.Parse("2006-01-02", req.DateOfBirth)
	if err != nil {
		http.Error(w, "Invalid date format. Use YYYY-MM-DD", http.StatusBadRequest)
		return
	}

	// Create VoterIdentity
	voterIdentity := &models.VoterIdentity{
		PersonalCode: req.PersonalCode,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		DateOfBirth:  dateOfBirth,
		Citizenship:  req.Citizenship,
		Address:      req.Address,
	}

	// Check if queue processing is enabled
	if s.votingService.IsQueueProcessingEnabled() {
		// Queue the registration request
		resultCh := s.votingService.GetQueueProcessor().QueueRegistration(voterIdentity)

		// Wait for result
		result := <-resultCh

		if !result.Success {
			http.Error(w, result.ErrorMessage, http.StatusBadRequest)
			return
		}

		// Format and return response
		privKeyBytes := crypto.FromECDSA(result.PrivateKey)
		pubKeyBytes := crypto.FromECDSAPub(&result.PrivateKey.PublicKey)

		response := RegisterVoterResponse{
			VoterID:    result.VoterID,
			PublicKey:  hex.EncodeToString(pubKeyBytes),
			PrivateKey: hex.EncodeToString(privKeyBytes),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	} else {
		// Synchronous processing (original code)
		registeredVoter, err := s.votingService.RegisterVoter(voterIdentity)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		privKeyBytes := crypto.FromECDSA(registeredVoter.PrivateKey)
		pubKeyBytes := crypto.FromECDSAPub(&registeredVoter.PrivateKey.PublicKey)

		response := RegisterVoterResponse{
			VoterID:    registeredVoter.VoterID,
			PublicKey:  hex.EncodeToString(pubKeyBytes),
			PrivateKey: hex.EncodeToString(privKeyBytes),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}
}

func validateRegistrationRequest(req *RegisterVoterRequest) error {
	if req.PersonalCode == "" {
		return fmt.Errorf("personal code is required")
	}
	if req.FirstName == "" {
		return fmt.Errorf("first name is required")
	}
	if req.LastName == "" {
		return fmt.Errorf("last name is required")
	}
	if req.DateOfBirth == "" {
		return fmt.Errorf("date of birth is required")
	}
	if req.Citizenship == "" {
		return fmt.Errorf("citizenship is required")
	}
	if req.Address == "" {
		return fmt.Errorf("address is required")
	}
	if !req.Declaration {
		return fmt.Errorf("declaration must be accepted")
	}

	// Basic format validation
	if len(req.PersonalCode) != 11 {
		return fmt.Errorf("personal code must be exactly 11 digits")
	}
	if len(req.FirstName) < 2 {
		return fmt.Errorf("first name must be at least 2 characters")
	}
	if len(req.LastName) < 2 {
		return fmt.Errorf("last name must be at least 2 characters")
	}
	if req.Citizenship != "LT" {
		return fmt.Errorf("only Lithuanian citizens (LT) are eligible")
	}
	if len(req.Address) < 5 {
		return fmt.Errorf("address must be at least 5 characters")
	}

	// Date format validation
	if _, err := time.Parse("2006-01-02", req.DateOfBirth); err != nil {
		return fmt.Errorf("invalid date format. Use YYYY-MM-DD")
	}

	return nil
}

func (s *Server) handleCastVote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CastVoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if !regexp.MustCompile(`^\d{6}$`).MatchString(req.Nonce) {
		http.Error(w, "Nonce must be exactly 6 digits", http.StatusBadRequest)
		return
	}

	fmt.Printf("Received vote request for voter: %s\n", req.VoterID)

	// Convert private key string back to ECDSA private key
	privateKey, err := service.ParsePrivateKey(req.PrivateKey)
	if err != nil {
		http.Error(w, "Invalid private key", http.StatusBadRequest)
		return
	}

	// Convert uint64 nonce to bytes
	nonceBytes := make([]byte, 32)
	copy(nonceBytes[26:], []byte(req.Nonce)) // Put 6 digits at the end, leaving rest as zeros

	vote := &models.VotePayload{
		Choice:     req.Candidate,
		VoterID:    req.VoterID,
		ElectionID: "election-2024",
		Nonce:      nonceBytes,
	}

	fmt.Printf("Processing vote for candidate: %s\n", req.Candidate)

	// Check if queue processing is enabled
	if s.votingService.IsQueueProcessingEnabled() {
		// Queue the vote request but don't wait for the result
		// Just put it in the queue and respond immediately
		s.votingService.GetQueueProcessor().QueueVoteNoWait(req.VoterID, vote, privateKey)

		fmt.Println("Vote successfully queued for processing")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	} else {
		// Synchronous processing (original code)
		if err := s.votingService.CastVote(req.VoterID, vote, privateKey); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		fmt.Println("Vote successfully cast and saved")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}
}

// New endpoint to count votes
func (s *Server) handleCountVotes(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Starting vote counting process")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CountVotesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	fmt.Println("Counting votes with admin key")

	err := s.votingService.FlushVoteBuffer()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to flush vote buffer: %v", err), http.StatusInternalServerError)
		return
	}

	// Count the votes using the getter
	results, err := s.votingService.GetCountingService().CountVotes()
	if err != nil {
		fmt.Printf("Error counting votes: %v\n", err)
		http.Error(w, fmt.Sprintf("Failed to count votes: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Vote counting complete. Total votes: %d\n", results.TotalVotes)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleGetResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Use the getter
	results, err := s.votingService.GetCountingService().GetLatestResults()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get results: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleVerifyCount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	registeredVoters := len(s.votingService.GetRegisteredVoters())
	// Use the getter
	verification, err := s.votingService.GetCountingService().VerifyVoteCount(registeredVoters)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to verify vote count: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(verification)
}

func (s *Server) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	voterStats := s.votingService.GetVoterStatistics()

	response := struct {
		RegisteredVoters int                    `json:"registered_voters"`
		VotedVoters      int                    `json:"voted_voters"`
		Voters           map[string]interface{} `json:"voters"`
		VotingActive     bool                   `json:"voting_active"`
	}{
		RegisteredVoters: voterStats.RegisteredCount,
		VotedVoters:      voterStats.VotedCount,
		Voters:           voterStats.VoterDetails,
		VotingActive:     s.votingService.IsVotingActive(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := s.votingService.EndVotingSession(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.StorageDir, "storage", "data", "Directory for blockchain storage")
	flag.DurationVar(&config.SessionDuration, "session", 24*time.Hour, "Voting session duration")
	flag.IntVar(&config.BatchSize, "batch", 9, "Vote batch size for anonymization")
	flag.DurationVar(&config.MixWindow, "mixwindow", 30*time.Minute, "Time window for vote mixing")
	flag.IntVar(&config.Port, "port", 8080, "Server port")

	var difficultyInt int
	flag.IntVar(&difficultyInt, "difficulty", 4, "Mining difficulty (0-255)")

	flag.Parse()

	if difficultyInt < 0 || difficultyInt > 255 {
		log.Fatal("Difficulty must be between 0 and 255")
	}
	config.Difficulty = uint8(difficultyInt)

	return config
}

func setupStorageDirectory(baseDir string) error {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return err
	}

	return nil
}

func initializeVotingService(config *Config) (*service.VotingService, error) {
	absPath, err := filepath.Abs(config.StorageDir)
	if err != nil {
		return nil, err
	}

	//return service.NewVotingService(absPath, encryption.SchemeElGamal, 256)
	//return service.NewVotingService(absPath, encryption.SchemeElGamal, 384)
	//return service.NewVotingService(absPath, encryption.SchemeElGamal, 521)

	return service.NewVotingService(absPath, encryption.SchemePaillier, 2048)
	//return service.NewVotingService(absPath, encryption.SchemePaillier, 3072)
	//return service.NewVotingService(absPath, encryption.SchemePaillier, 4096)
}

func (s *Server) handleGetAdminCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// This should only be called once during setup
	creds, err := s.votingService.GetAdminCredentials()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get admin credentials: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(creds)
}

func (s *Server) handleGetDKBChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	blocks, err := s.votingService.GetDKBChain()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get DKB chain: %v", err), http.StatusInternalServerError)
		return
	}

	response := BlockchainResponse{
		ChainType:  "dkb",
		BlockCount: len(blocks),
		Blocks:     blocks,
		IsValid:    models.ValidateChain(blocks),
	}

	if len(blocks) > 0 {
		response.LastHash = hex.EncodeToString(blocks[len(blocks)-1].Hash)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleGetEVBChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	blocks, err := s.votingService.GetEVBChain()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get EVB chain: %v", err), http.StatusInternalServerError)
		return
	}

	response := BlockchainResponse{
		ChainType:  "evb",
		BlockCount: len(blocks),
		Blocks:     blocks,
		IsValid:    models.ValidateChain(blocks),
	}

	if len(blocks) > 0 {
		response.LastHash = hex.EncodeToString(blocks[len(blocks)-1].Hash)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleGetBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	chainType := r.URL.Query().Get("chain")
	indexStr := r.URL.Query().Get("index")
	if chainType == "" || indexStr == "" {
		http.Error(w, "Missing chain type or block index", http.StatusBadRequest)
		return
	}

	index, err := strconv.ParseUint(indexStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid block index", http.StatusBadRequest)
		return
	}

	block, err := s.votingService.GetBlock(chainType, index)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get block: %v", err), http.StatusNotFound)
		return
	}

	response := BlockResponse{
		Index:      block.Index,
		Timestamp:  block.Timestamp,
		DataHex:    hex.EncodeToString(block.Data),
		PrevHash:   hex.EncodeToString(block.PrevHash),
		Hash:       hex.EncodeToString(block.Hash),
		Nonce:      block.Nonce,
		Difficulty: block.Difficulty,
	}

	// Try to decode the data if possible
	var decodedData interface{}
	if err := json.Unmarshal(block.Data, &decodedData); err == nil {
		decodedJSON, _ := json.MarshalIndent(decodedData, "", "  ")
		response.DataDecoded = string(decodedJSON)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleValidateChains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dkbValid, evbValid, err := s.votingService.ValidateChains()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to validate chains: %v", err), http.StatusInternalServerError)
		return
	}

	response := struct {
		DKBValid bool `json:"dkb_valid"`
		EVBValid bool `json:"evb_valid"`
	}{
		DKBValid: dkbValid,
		EVBValid: evbValid,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleGetBlockchainStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get DKB chain
	dkbBlocks, err := s.votingService.GetDKBChain()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get DKB chain: %v", err), http.StatusInternalServerError)
		return
	}

	// Get EVB chain
	evbBlocks, err := s.votingService.GetEVBChain()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get EVB chain: %v", err), http.StatusInternalServerError)
		return
	}

	// Convert blocks to response format
	response := BlockchainStatusResponse{
		DKBChain: convertToChainInfo(dkbBlocks, "dkb"),
		EVBChain: convertToChainInfo(evbBlocks, "evb"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func convertToChainInfo(blocks []*models.Block, chainType string) *ChainInfo {
	info := &ChainInfo{
		Length:  len(blocks),
		IsValid: models.ValidateChain(blocks),
		Blocks:  make([]BlockInfo, len(blocks)),
	}

	if len(blocks) > 0 {
		lastBlock := blocks[len(blocks)-1]
		info.LastHash = hex.EncodeToString(lastBlock.Hash)
	}

	for i, block := range blocks {
		info.Blocks[i] = BlockInfo{
			Index:     block.Index,
			Timestamp: block.Timestamp,
			Hash:      hex.EncodeToString(block.Hash),
			PrevHash:  hex.EncodeToString(block.PrevHash),
			Data:      string(block.Data),
			Nonce:     block.Nonce,
		}
	}

	return info
}

func (s *Server) handleVerifyVoteDetails(w http.ResponseWriter, r *http.Request) {
	// Enable CORS for development
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Change to POST since we're sending private key
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed. Use POST for secure key transfer", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req VerifyVoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate private key
	if req.PrivateKey == "" {
		http.Error(w, "Private key is required", http.StatusBadRequest)
		return
	}

	// Clean private key format
	privateKey := strings.TrimPrefix(req.PrivateKey, "0x")

	// Verify vote using the private key
	result, err := s.votingService.GetCountingService().VerifyVote(privateKey)
	if err != nil {
		if strings.Contains(err.Error(), "invalid private key format") {
			http.Error(w, "Invalid private key format", http.StatusBadRequest)
			return
		}
		http.Error(w, fmt.Sprintf("Failed to verify vote: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleReloadChains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Enable CORS for development
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Attempt to reload chains
	if err := s.votingService.ReloadChains(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to reload chains: %v", err), http.StatusInternalServerError)
		return
	}

	// Get updated chain status after reload
	dkbBlocks, err := s.votingService.GetDKBChain()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get DKB chain after reload: %v", err), http.StatusInternalServerError)
		return
	}

	evbBlocks, err := s.votingService.GetEVBChain()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get EVB chain after reload: %v", err), http.StatusInternalServerError)
		return
	}

	// Prepare response with chain status
	response := BlockchainStatusResponse{
		DKBChain: convertToChainInfo(dkbBlocks, "dkb"),
		EVBChain: convertToChainInfo(evbBlocks, "evb"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleGetFinalResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET")
	w.Header().Set("Content-Type", "application/json")

	// Get final results
	results, err := s.votingService.GetFinalResults()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Format response
	response := struct {
		Results        map[string]int64 `json:"results"`
		TotalVotes     int              `json:"total_votes"`
		ProcessedVotes int              `json:"processed_votes"`
		VotingClosed   bool             `json:"voting_closed"`
	}{
		Results:        results.Results,
		TotalVotes:     results.TotalVotes,
		ProcessedVotes: results.ProcessedVotes,
		VotingClosed:   !s.votingService.IsVotingActive(),
	}

	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleGetMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get phase-specific metrics if requested
	phase := r.URL.Query().Get("phase")
	if phase != "" {
		phaseMetrics := s.votingService.GetPhaseMetrics(phase)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(phaseMetrics)
		return
	}

	// Get all metrics
	metrics := s.votingService.GetMetrics()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// handleResetMetrics resets all performance metrics
func (s *Server) handleResetMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.votingService.ResetMetrics()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

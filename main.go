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
	"strconv"
	"syscall"
	"time"
	"voting-backend/models"
	"voting-backend/service"
)

type Config struct {
	StorageDir      string
	SessionDuration time.Duration
	BatchSize       int
	MixWindow       time.Duration
	Difficulty      uint8
	Port            int
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
	VoterID    string `json:"voter_id"`
	Candidate  string `json:"candidate"`
	PrivateKey string `json:"private_key"`
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

func main() {
	config := parseFlags()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if err := setupStorageDirectory(config.StorageDir); err != nil {
		log.Fatalf("Failed to setup storage: %v", err)
	}

	votingService, err := initializeVotingService(config)
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

	// Admin
	http.HandleFunc("/api/admin/credentials", server.handleGetAdminCredentials)

	//Chain
	http.HandleFunc("/api/blockchain/dkb", server.handleGetDKBChain)
	http.HandleFunc("/api/blockchain/evb", server.handleGetEVBChain)
	http.HandleFunc("/api/blockchain/block", server.handleGetBlock)
	http.HandleFunc("/api/blockchain/validate", server.handleValidateChains)
	http.HandleFunc("/api/blockchain/status", server.handleGetBlockchainStatus)

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
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterVoterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	privateKey, err := s.votingService.RegisterVoter(req.VoterID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Format keys as hex strings
	privKeyBytes := crypto.FromECDSA(privateKey)
	pubKeyBytes := crypto.FromECDSAPub(&privateKey.PublicKey)

	response := RegisterVoterResponse{
		VoterID:    req.VoterID,
		PublicKey:  hex.EncodeToString(pubKeyBytes),
		PrivateKey: hex.EncodeToString(privKeyBytes),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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

	fmt.Printf("Received vote request for voter: %s\n", req.VoterID)

	// Convert private key string back to ECDSA private key
	privateKey, err := service.ParsePrivateKey(req.PrivateKey)
	if err != nil {
		http.Error(w, "Invalid private key", http.StatusBadRequest)
		return
	}

	vote := &models.VotePayload{
		Choice:     req.Candidate,
		VoterID:    req.VoterID,
		ElectionID: "election-2024",
	}

	fmt.Printf("Processing vote for candidate: %s\n", req.Candidate)

	if err := s.votingService.CastVote(req.VoterID, vote, privateKey); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("Vote successfully cast and saved")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
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
	flag.IntVar(&config.BatchSize, "batch", 10, "Vote batch size for anonymization")
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

	subdirs := []string{"dkb", "evb", "voters"}
	for _, dir := range subdirs {
		path := filepath.Join(baseDir, dir)
		if err := os.MkdirAll(path, 0755); err != nil {
			return err
		}
	}

	return nil
}

func initializeVotingService(config *Config) (*service.VotingService, error) {
	absPath, err := filepath.Abs(config.StorageDir)
	if err != nil {
		return nil, err
	}

	return service.NewVotingService(absPath)
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

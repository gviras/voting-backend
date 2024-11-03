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

	if err := s.votingService.CastVote(req.VoterID, vote, privateKey); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// New endpoint to count votes
func (s *Server) handleCountVotes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CountVotesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Parse the private key
	privateKey, err := service.ParsePrivateKey(req.PrivateKey)
	if err != nil {
		http.Error(w, "Invalid private key", http.StatusBadRequest)
		return
	}

	// Count the votes using the getter
	results, err := s.votingService.GetCountingService().CountVotes(privateKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to count votes: %v", err), http.StatusInternalServerError)
		return
	}

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

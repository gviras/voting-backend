package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"voting-backend/models"
)

// Chain represents the entire blockchain
type Chain struct {
	Blocks []*models.Block `json:"blocks"`
}

type JSONStore struct {
	basePath string
	mu       sync.RWMutex
	chains   map[string]*Chain // stores different chain types (dkb, evb)
}

func NewJSONStore(basePath string) (*JSONStore, error) {
	// Create storage directory if it doesn't exist
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %v", err)
	}

	store := &JSONStore{
		basePath: basePath,
		chains:   make(map[string]*Chain),
	}

	// Initialize chains from files
	for _, chainType := range []string{"dkb", "evb"} {
		chain, err := store.loadChainFromFile(chainType)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load chain %s: %v", chainType, err)
		}
		if chain == nil {
			chain = &Chain{Blocks: make([]*models.Block, 0)}
		}
		store.chains[chainType] = chain
	}

	return store, nil
}

func (s *JSONStore) SaveBlock(chainType string, block *models.Block) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	chain, exists := s.chains[chainType]
	if !exists {
		chain = &Chain{Blocks: make([]*models.Block, 0)}
		s.chains[chainType] = chain
	}

	// Append block to chain
	chain.Blocks = append(chain.Blocks, block)

	// Save entire chain to file
	return s.saveChainToFile(chainType, chain)
}

func (s *JSONStore) LoadChain(chainType string) ([]*models.Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	chain, exists := s.chains[chainType]
	if !exists || chain == nil {
		return make([]*models.Block, 0), nil
	}

	// Return a copy of the blocks to prevent modification
	blocks := make([]*models.Block, len(chain.Blocks))
	copy(blocks, chain.Blocks)
	return blocks, nil
}

func (s *JSONStore) loadChainFromFile(chainType string) (*Chain, error) {
	path := filepath.Join(s.basePath, fmt.Sprintf("%s_chain.json", chainType))

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Chain{Blocks: make([]*models.Block, 0)}, nil
		}
		return nil, err
	}

	var chain Chain
	if err := json.Unmarshal(data, &chain); err != nil {
		return nil, fmt.Errorf("failed to unmarshal chain: %v", err)
	}

	return &chain, nil
}

func (s *JSONStore) saveChainToFile(chainType string, chain *Chain) error {
	path := filepath.Join(s.basePath, fmt.Sprintf("%s_chain.json", chainType))

	data, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal chain: %v", err)
	}

	// Write to temporary file first
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write chain file: %v", err)
	}

	// Atomic rename to ensure consistency
	if err := os.Rename(tempPath, path); err != nil {
		os.Remove(tempPath) // Clean up temp file if rename fails
		return fmt.Errorf("failed to save chain file: %v", err)
	}

	return nil
}

func (s *JSONStore) SaveVoter(registration *models.VoterRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.basePath, "voters.json")

	// Load existing voters
	var voters []models.VoterRegistration
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &voters); err != nil {
			return fmt.Errorf("failed to unmarshal voters: %v", err)
		}
	}

	// Add new voter
	voters = append(voters, *registration)

	// Save all voters
	data, err = json.MarshalIndent(voters, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal voters: %v", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write voters file: %v", err)
	}

	return nil
}

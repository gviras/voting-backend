package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"voting-backend/models"
)

type JSONStore struct {
	basePath string
	mu       sync.RWMutex
}

func NewJSONStore(basePath string) (*JSONStore, error) {
	// Create storage directories if they don't exist
	dirs := []string{"dkb", "evb", "voters"}
	for _, dir := range dirs {
		path := filepath.Join(basePath, dir)
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %v", path, err)
		}
	}

	return &JSONStore{basePath: basePath}, nil
}

func (s *JSONStore) SaveBlock(chainType string, block *models.Block) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.basePath, chainType, fmt.Sprintf("block_%d.json", block.Index))

	data, err := json.MarshalIndent(block, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal block: %v", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write block file: %v", err)
	}

	return nil
}

func (s *JSONStore) LoadChain(chainType string) ([]*models.Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	path := filepath.Join(s.basePath, chainType)

	files, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %v", err)
	}

	var blocks []*models.Block
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		blockPath := filepath.Join(path, file.Name())
		data, err := os.ReadFile(blockPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read block file %s: %v", blockPath, err)
		}

		var block models.Block
		if err := json.Unmarshal(data, &block); err != nil {
			return nil, fmt.Errorf("failed to unmarshal block from %s: %v", blockPath, err)
		}

		blocks = append(blocks, &block)
	}

	return blocks, nil
}

func (s *JSONStore) SaveVoter(registration *models.VoterRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.basePath, "voters", fmt.Sprintf("%s.json", registration.VoterID))

	data, err := json.MarshalIndent(registration, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal voter registration: %v", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write voter file: %v", err)
	}

	return nil
}
